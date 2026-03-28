# -*- coding: utf-8 -*-
# ============================================================
# SDN QoS + Firewall + Monitoring (Ryu, OpenFlow 1.3)
# Target Environment: Python 2.7 / Ubuntu
# ============================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ryu.lib import hub
import time

class FinalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FinalController, self).__init__(*args, **kwargs)

        # 1. MAC Learning Table: Maps Switch Port to Host MAC address
        self.mac_to_port = {}

        # 2. Protocol Statistics: Counter for specific TCP services
        self.pkt_count = 0
        self.proto_stats = {
            "HTTP": 0, "HTTPS": 0, "FTP": 0, "SSH": 0, "OTHER": 0
        }

        # 3. Latency Monitoring: Tracks time between Controller and Switch
        self.datapaths = {}
        self.latency = 0
        self.echo_send_time = 0
        
        # Start a background thread to "pulse" the network every 10 seconds
        self.monitor_thread = hub.spawn(self._monitor)

# 4. FIXED Priorities for QoS: Assigns a unique priority to each server IP
        # These are manually set to specific values for consistent testing
        self.host_priorities = {
            "10.0.0.1": 863,
            "10.0.0.2": 965,
            "10.0.0.3": 751,
            "10.0.0.4": 914
        }
        print("\033[94m[INIT] Fixed Priorities assigned: h2(965) > h4(914) > h1(863) > h3(751)\033[0m")

    # ------------------------------------------------------------
    # MONITORING BLOCK: Measures Controller-to-Switch Latency
    # ------------------------------------------------------------
    def _monitor(self):
        """ Background loop that sends an Echo Request to measure RTT """
        while True:
            for dp in self.datapaths.values():
                parser = dp.ofproto_parser
                # Create the request and record the exact start time
                echo_req = parser.OFPEchoRequest(dp, data=str(time.time()))
                self.echo_send_time = time.time()
                dp.send_msg(echo_req)
            hub.sleep(10) # Wait 10 seconds before the next check

    @set_ev_cls(ofp_event.EventOFPEchoReply, MAIN_DISPATCHER)
    def echo_reply_handler(self, ev):
        """ Calculates the difference between Send and Receive time """
        self.latency = (time.time() - self.echo_send_time) * 1000
        print("\033[96m[METRIC] Latency (RTT): %.2f ms\033[0m" % self.latency)

    # ------------------------------------------------------------
    # FLOW INSTALLATION: Adds rules to the Switch Flow Table
    # ------------------------------------------------------------
    def add_flow(self, dp, priority, match, actions, idle=60, hard=120):
        """ 
        Configures match-action rules. 
        idle_timeout: Removes rule if no traffic for X seconds.
        hard_timeout: Removes rule after X seconds regardless of traffic.
        """
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=inst, idle_timeout=idle, hard_timeout=hard)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """ Triggered when a switch connects to the controller """
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        
        # Table-miss rule: Sends any unknown packet to the Controller (Priority 0)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(dp, 0, match, actions, 0, 0)

    # ------------------------------------------------------------
    # PACKET_IN HANDLER: The core logic for every new packet
    # ------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        # Parse the raw data into packet protocols
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth: return

        # Learning Switch: Save which port leads to this MAC
        self.mac_to_port.setdefault(dp.id, {})
        self.mac_to_port[dp.id][eth.src] = in_port
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        priority = 10 # Default Priority

        # --- FIREWALL SCENARIOS (NORMAL VS FAILURE) ---
        if ip_pkt:
            src, dst = ip_pkt.src, ip_pkt.dst

            # SCENARIO: Failure - Block Attacker (h6)
            if src == "10.0.0.6" or dst == "10.0.0.6":
                print("\033[91m[FAILURE] BLOCKED: Attacker involvement (%s -> %s)\033[0m" % (src, dst))
                return

            # SCENARIO: Failure - Server-to-Server Isolation (Must involve h5)
            if src != "10.0.0.5" and dst != "10.0.0.5":
                print("\033[93m[FAILURE] BLOCKED: Isolation violation (%s -> %s)\033[0m" % (src, dst))
                return

            # SCENARIO: Normal - Apply Randomized Priority if Destination is h1-h4
            if dst in self.host_priorities:
                priority = self.host_priorities[dst]

        # Determine where to send the packet
        if eth.dst in self.mac_to_port[dp.id]:
            out_port = self.mac_to_port[dp.id][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD # Flood if MAC is unknown
        
        actions = [parser.OFPActionOutput(out_port)]

        # --- RULE INSTALLATION & PACKET STATISTICS ---
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            # Install flow with 60s idle and 120s hard timeouts
            self.add_flow(dp, priority, match, actions, 60, 120)
            
            if ip_pkt:
                self.pkt_count += 1
                # Update Protocol Counters if it is TCP traffic
                if tcp_pkt:
                    p = tcp_pkt.dst_port
                    if p == 80: self.proto_stats["HTTP"] += 1
                    elif p == 443: self.proto_stats["HTTPS"] += 1
                    elif p == 21: self.proto_stats["FTP"] += 1
                    elif p == 22: self.proto_stats["SSH"] += 1
                    else: self.proto_stats["OTHER"] += 1
                
                # Print the "NORMAL" scenario success log
                print("\033[92m[NORMAL] ALLOWED: %s -> %s | Priority: %d | Total: %d\033[0m" % (src, dst, priority, self.pkt_count))
                print("\033[92m[STATS] Current Statistics: %s\033[0m" % str(self.proto_stats))

        # Send the original packet out to its destination
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)