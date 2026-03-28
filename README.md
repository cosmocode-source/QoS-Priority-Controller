# QoS-Priority-Controller
## 📌 Project Objective & Problem Statement
In traditional networks, all traffic is treated equally, leading to congestion where critical services compete with low-priority data. Furthermore, traditional switches lack dynamic security policies. 

The objective of this project is to build a **Software-Defined Networking (SDN) Controller** that intelligently manages a network by combining four core functions:
1. **L2 Forwarding:** Dynamically learning MAC addresses.
2. **Stateful Firewall:** Enforcing access control and host isolation.
3. **Quality of Service (QoS):** Prioritizing specific server traffic to guarantee bandwidth during network congestion.
4. **Telemetry & Monitoring:** Tracking Controller-Switch latency and specific protocol statistics in real-time.

## 🏗️ Topology & Design Justification
* **Controller:** Ryu (Python 2.7) using OpenFlow 1.3. *Justification: Ryu provides granular control over OpenFlow match-action rules and asynchronous event handling (like our background latency monitor).*
* **Simulation:** Mininet.
* **Topology:** Single Switch with 6 Hosts (`--topo single,6`).
  * *Justification:* A star topology around a single Open vSwitch (OVS) is the perfect isolated environment to prove L3/L4 controller logic (Firewall & QoS) without the added complexity of multi-switch routing protocols like spanning-tree.

### 🖥️ Host Architecture & Access Rules
The network consists of 6 hosts with strict logical roles:
* **h1 (10.0.0.1):** Server 1 (QoS Priority: 863)
* **h2 (10.0.0.2):** Server 2 (QoS Priority: 965) - *Highest Priority*
* **h3 (10.0.0.3):** Server 3 (QoS Priority: 751) - *Lowest Priority*
* **h4 (10.0.0.4):** Server 4 (QoS Priority: 914)
* **h5 (10.0.0.5):** Authorized Client (Can access h1-h4)
* **h6 (10.0.0.6):** Attacker / Unauthorized Zone (Strictly blocked)

**Firewall Policy:**
1. **Attacker Block:** `h6` is blocked from communicating with any host.
2. **Server Isolation:** `h1`, `h2`, `h3`, and `h4` cannot communicate with each other directly. Traffic MUST involve the client (`h5`).

---

## ⚙️ Features Implemented (Controller Logic)
* **Correct `packet_in` Handling:** Unknown packets are intercepted, mapped (MAC to Port), and evaluated against security and QoS policies before being forwarded.
* **Match-Action Rule Design:** Flows are installed matching Source/Destination IPs and MACs, with specific actions (Output Port) and priorities.
* **Flow Timeouts:** * `idle_timeout=60`: Rules are cleared if no traffic matches for 60 seconds (frees up switch TCAM memory).
  * `hard_timeout=120`: Rules are forcefully evicted after 2 minutes to ensure security policies are periodically re-validated by the controller.

---


## 🚀 Installation & Prerequisites
You need an Ubuntu environment with Mininet and Ryu installed.
bash
# Install Mininet
sudo apt-get install mininet

# Install Ryu Controller
pip install ryu

---

## 🧠 Detailed System Working & Architecture

The controller acts as the "brain" of the network, transforming a standard Open vSwitch into a smart, self-learning, secure, and prioritized network appliance. Here is the step-by-step breakdown of how the system operates in real-time.

### Phase 1: Controller Initialization & Boot Sequence
When the Ryu controller starts (`ryu-manager controller.py`), it initializes several critical data structures before any traffic flows:
1. **MAC Learning Table (`mac_to_port`):** An empty dictionary is created to map host MAC addresses to specific switch ports.
2. **QoS Priority Map (`host_priorities`):** Fixed OpenFlow priority values are assigned to specific server IPs (e.g., `10.0.0.2` is assigned priority `965`).
3. **Telemetry Thread:** A background thread (`hub.spawn`) is launched to continuously monitor control-plane health.
4. **Table-Miss Flow Entry:** When the switch connects to the controller, the controller proactively installs a default "Table-Miss" rule (Priority `0`). This rule instructs the switch: *"If you receive a packet and don't know what to do with it, send it to the controller."*

### Phase 2: Background Telemetry (Latency Monitoring)
Running parallel to packet processing, the `_monitor` loop acts as a heartbeat monitor:
* Every 10 seconds, the controller sends an `OFPEchoRequest` message to the switch and records the exact timestamp.
* When the switch replies with an `OFPEchoReply`, the controller calculates the Round-Trip Time (RTT).
* This continuously measures the latency between the Control Plane (Ryu) and the Data Plane (Mininet Switch), which is a critical metric for SDN performance evaluation.

### Phase 3: The Packet-In Event (Core Logic)
When a host (e.g., the client `h5`) sends a request (like a `curl` to `h2`), the switch has no matching rules, so it forwards the packet to the controller, triggering the `packet_in_handler`. The controller executes the following logic pipeline:

#### Step A: Layer 2 Learning (Forwarding)
The controller extracts the Ethernet header. It records the packet's Source MAC address and the port it arrived on, storing this in the `mac_to_port` table. The network is effectively mapping itself dynamically without manual configuration.

#### Step B: Layer 3 Stateful Firewall (Filtering)
The controller inspects the IPv4 headers to enforce security policies:
* **Attacker Check:** If the Source or Destination IP is `10.0.0.6` (the designated attacker), the packet is instantly dropped, and a `[FAILURE]` log is generated.
* **Server Isolation Check:** If neither the Source nor Destination IP is `10.0.0.5` (the authorized client), it means servers are trying to talk directly to each other. The controller drops the packet to enforce strict isolation.

#### Step C: Layer 3/4 Quality of Service (QoS) Classification
If the packet passes the firewall, the controller checks the Destination IP against its predefined `host_priorities` list. 
* If the packet is destined for Server 2 (`10.0.0.2`), it assigns it the highest priority (`965`). 
* If it is standard return traffic (e.g., a server replying to `h5`), it receives the default priority (`10`).

#### Step D: Traffic Statistics (Monitoring)
If the packet uses the TCP protocol, the controller checks the Destination Port. It increments the corresponding counter (HTTP for 80, HTTPS for 443, FTP for 21, SSH for 22) to maintain a live dashboard of network usage types.

### Phase 4: Hardware Offloading (Flow Installation)
To ensure the controller doesn't become a bottleneck, it does not want to process every single packet of a connection. 
1. **FlowMod Generation:** The controller generates an `OFPFlowMod` message. This tells the switch to install a new hardware rule matching the specific Source/Destination MAC and IP addresses.
2. **Applying QoS:** The rule is installed with the specific Priority calculated in Step C. If network congestion occurs, the switch hardware will strictly process priority `965` packets before priority `863` packets.
3. **Applying Timeouts:** * `idle_timeout=60`: If the connection goes silent for 60 seconds, the switch automatically deletes the rule to conserve memory (TCAM).
   * `hard_timeout=120`: Regardless of activity, the rule is forcefully deleted after 120 seconds. This ensures that security and QoS policies are periodically re-validated by the controller.
4. **PacketOut:** Finally, the controller sends an `OFPPacketOut` message, injecting the original packet back into the switch to be delivered to its final destination.


---

# 💻 Step-by-Step Execution Guide

## Overview

This project demonstrates a **stateful firewall with QoS enforcement using Ryu + Mininet + Open vSwitch**.

### 🔧 Tools & Stack Used

* **Mininet** → Network emulation (hosts, switches, topology)
* **Ryu Controller** → Control plane (flow rules, QoS, firewall logic, latency monitoring)
* **Open vSwitch (OVS)** → Data plane (flow tables, queues, packet forwarding)
* **iperf / curl / ping** → Traffic generation and validation tools

### 🧠 Key Design Notes

* QoS is enforced via **OpenFlow flow priorities**
* Firewall is **stateful (controller decides allowed flows)**
* Latency measurement is done in the **controller (control-plane RTT)** — *not data-plane latency*
* Mininet is used purely to **simulate a real network environment locally**

---

## Step 1: Start the Ryu Controller

Open a terminal and run:

```bash
ryu-manager controller.py
```

**What happens internally:**

* QoS priorities initialized
* Firewall rules loaded
* Background latency monitor thread starts (EchoRequest/Reply)

---

## Step 2: Start the Mininet Topology

Open a second terminal:

```bash
sudo mn --controller remote --topo single,6 --mac
```

**Topology:**

* 1 switch (`s1`)
* 6 hosts (`h1–h6`)
* `h5` → authorized client
* `h6` → attacker
* `h1–h4` → servers

---

## Step 3: Start the Host Servers

Inside Mininet CLI:

```bash
mininet> h1 python3 -m http.server 80 &
mininet> h2 python3 -m http.server 443 &
mininet> h3 python3 -m http.server 21 &
mininet> h4 python3 -m http.server 22 &
```

---

# 🧪 Testing & Validation Scenarios

## Scenario 1: Normal Traffic (QoS Validation)

**Objective:** Verify allowed traffic + QoS prioritization.

```bash
mininet> h5 bash -c "curl http://10.0.0.1:80 & curl http://10.0.0.2:443 & curl http://10.0.0.3:21 & curl http://10.0.0.4:22 &"
```

**Expected:**

* `[NORMAL]` logs in controller
* `[STATS]` packet counters updating
* Traffic succeeds for all services

### Flow Table Check

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

**Verify:**

* Priorities → `965, 914, 863, 751`
* Timeouts → `idle=60`, `hard=120`

---

## Scenario 2: Unauthorized Access (Attacker Block)

```bash
mininet> h6 ping -c 2 h1
```

**Expected:**

* `100% packet loss`
* `[FAILURE] Blocked Attacker`

---

## Scenario 3: Internal Isolation (Server-to-Server Block)

```bash
mininet> h1 curl 10.0.0.2:443
```

**Expected:**

* Connection fails
* `[FAILURE] Blocked Internal Isolation`

---

## Scenario 4: Throughput Test (QoS Effect)

```bash
mininet> iperf h5 h2
```

**Purpose:**

* Measure bandwidth under high-priority flow
* Confirms QoS queue effectiveness

---

## Scenario 5: Flow Rule Expiry (Timeout Behavior)

Wait for **60–120 seconds**, then:

```bash
sudo ovs-ofctl dump-flows s1
```

**Expected:**

* Old flows removed automatically
* New flows re-installed on fresh traffic

---

## Scenario 6: Concurrent Load Stress Test

```bash
mininet> h5 bash -c "for i in {1..10}; do curl http://10.0.0.1:80 & done"
```

**Expected:**

* No controller crash
* Stable `[STATS]` updates
* QoS still enforced

---

## Scenario 7: Mixed Traffic Validation

```bash
mininet> h5 ping -c 3 h1
mininet> h5 curl http://10.0.0.1:80
```

**Expected:**

* ICMP may be restricted (depending on rules)
* HTTP allowed and prioritized

---

# 📊 Measurement & Metrics

## Latency (Control Plane Only)

* Measured using OpenFlow **EchoRequest / EchoReply**
* Runs every **10 seconds**

Example log:

```
[METRIC] Latency: X ms
```

**Important:**

* This is **controller ↔ switch RTT**
* Not actual host-to-host latency

---

## Throughput

Measured via:

```bash
mininet> iperf h5 h2
```

* Reflects QoS prioritization impact
* Higher priority → better bandwidth consistency

---

## Flow Table Metrics

```bash
sudo ovs-ofctl dump-flows s1
```

Track:

* `n_packets`
* `n_bytes`

**Interpretation:**

* Increasing values = traffic matching QoS rules
* Confirms hardware-level enforcement

---
