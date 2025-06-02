# NetFlow++ Framework Design Document

## 1. Introduction

This document outlines the design and architecture of the NetFlow++ framework. The primary goals of NetFlow++ are to provide a high-performance, modular, and extensible platform for network packet processing and virtual switching. It is designed to leverage modern C++ features and system characteristics like NUMA for optimal efficiency.

## 2. System Architecture

### 2.1. Overall Architecture
(Remains as before)

### 2.2. Key Design Principles
(Remains as before)

## 3. Core Component Design

### 3.1. `PacketBuffer` & `BufferPool`
(Remains as before)

### 3.2. `Packet`
(Remains as before)

### 3.3. `ForwardingDatabase` (FDB)
(Remains as before)

### 3.4. `VlanManager`
(Remains as before)

### 3.5. `InterfaceManager`

*   **Storage:** Manages a collection of port/interface configurations, likely using a `std::map<uint32_t, PortConfig>`. `PortConfig` stores admin state, speed, duplex, MTU, MAC address, and IP configurations.
*   **IP Configuration:** Supports adding/removing multiple IP addresses (with subnet masks) per interface.
*   **ACL Binding:**
    *   The `PortConfig` struct now includes `std::optional<std::string> ingress_acl_name;` and `std::optional<std::string> egress_acl_name;` to store the names of ACLs applied to the interface.
    *   `InterfaceManager` provides methods to manage these bindings:
        *   `apply_acl_to_interface(uint32_t port_id, const std::string& acl_name, AclDirection direction)`: Applies a named ACL (verified to exist in `AclManager`) to the specified port in the given direction (INGRESS or EGRESS).
        *   `remove_acl_from_interface(uint32_t port_id, AclDirection direction)`: Detaches an ACL from the port for the given direction.
        *   `get_applied_acl_name(uint32_t port_id, AclDirection direction) const`: Retrieves the name of the ACL applied in the specified direction.
*   **Statistics:** Statistics (packets/bytes rx/tx, errors, drops) are associated with each interface.
*   **Link State Callbacks:** Uses a callback mechanism to notify other components of physical link state changes.

## 4. Performance-Critical Component Design
(Remains as before)

## 5. Advanced Feature Component Design

### 5.1. `StpManager`
(Remains as before)

### 5.2. `LacpManager`
(Remains as before)

### 5.3. `QosManager`

The `QosManager` component is implemented to provide port-based Quality of Service capabilities. It allows for differentiated packet handling based on configured policies.
*   **Queue Structures:** Supports multiple queues per port (e.g., up to 8). Each port configuration (`QosConfig`) specifies the number of queues and their maximum depth (`max_queue_depth`). Packets are stored by value (copied) within these queues (`std::deque<Packet>`).
*   **Scheduler:** Implements scheduling algorithms to determine the order of packet transmission from queues.
    *   **Strict Priority (SP):** Higher priority queues are always serviced before lower priority ones. This is fully implemented.
    *   **Weighted Round Robin (WRR) / Deficit Round Robin (DRR):** These are available as scheduler types. Currently, they fall back to a basic Round Robin mechanism where queues are serviced in a cyclical order. Full weighted/deficit logic is a future enhancement. `port_last_serviced_queue_` map helps maintain state for RR.
*   **Rate Limiting:** The `QosConfig` structure allows specifying `rate_limits_kbps` per queue. The framework for this is in place, but the actual token bucket logic for enforcement in `should_transmit` and `update_token_buckets` is currently a placeholder.
*   **Classification:** Incoming packets are classified to a specific queue on their egress port. The current implementation uses the packet's VLAN Priority Code Point (PCP) value to map to a queue index. If no PCP is present, it defaults to a lower priority queue. This logic is handled internally by `QosManager` when `enqueue_packet` is called (which now takes only `Packet&` and `port_id`).
*   **CLI Integration:** QoS settings (number of queues, scheduler type, weights, rate limits, max depth) can be configured per interface using CLI commands. Statistics per queue (enqueued, dequeued, dropped, current depth) can also be viewed.

### 5.4. `AclManager`

The `AclManager` component is implemented to provide packet filtering capabilities. It manages named collections of Access Control Lists (ACLs).
*   **Named ACLs**: ACLs are identified by unique string names. `AclManager` uses `std::map<std::string, std::vector<AclRule>> named_acl_rules_` to store rules for each named ACL.
*   **ACL Management**: Methods like `create_acl(name)`, `delete_acl(name)`, `get_acl_names()`, `get_all_named_acls()`, and `clear_all_acls()` are provided for managing these named ACLs.
*   **Rule Storage & Priority**: Within each named ACL, rules (`AclRule`) are stored in a `std::vector`. Each rule has a unique `rule_id` (within that ACL) and an `int priority` (higher value means higher precedence).
*   **Match Criteria**: Rules can match on various L2, L3 (IPv4), and L4 fields, including source/destination MAC, VLAN ID, EtherType, source/destination IP, IP protocol, and TCP/UDP source/destination ports. Fields are optional in a rule, acting as wildcards if not set.
*   **Actions**: Supported actions are `PERMIT`, `DENY`, and `REDIRECT` (to a specified egress port ID).
*   **Evaluation Engine**: The `evaluate(acl_name, packet, out_redirect_port_id)` method processes a packet against the rules of a specified named ACL. If the rules for that ACL are marked as needing compilation, a warning is logged. It iterates through the rules (expected to be sorted by `compile_rules`). The first matching rule determines the action. If no rule matches, a default action of `PERMIT` is taken. If the ACL name itself is not found, it also defaults to `PERMIT`.
*   **Optimization (`compile_rules`)**: The `compile_rules(acl_name)` method sorts the rules for a specific named ACL by priority (descending) and then by rule ID (ascending, for stability). This ensures that higher priority rules are evaluated first. A flag `named_acl_needs_compilation_` tracks if an ACL's rules need re-sorting.
*   **CLI Integration**: Named ACLs and their rules can be managed via CLI commands (e.g., `acl create <name>`, `acl <name> rule add ...`, `acl <name> compile`). These ACLs can then be applied to interfaces.

### 5.5 LldpManager
(Remains as before)

## 6. System Integration Component Design (High-Level)
(Sections 6.1, 6.2, 6.3 remain as before)

## 7. Data Flow (Example: L2 Forwarding)

1.  **Packet Arrival:** Packet arrives at a physical port. `PacketBuffer` obtained from `BufferPool`. `Packet` object created.
2.  **Ingress Port Checks:** Link state of `ingress_port_id` is verified. RX stats incremented.
3.  **Ingress ACL Processing (`InterfaceManager` & `AclManager`):**
    *   `InterfaceManager::get_applied_acl_name(ingress_port_id, INGRESS)` is checked.
    *   If an ACL name is found, `AclManager::evaluate(acl_name, packet, ...)` is called.
    *   If action is DENY, packet is dropped. Processing stops.
    *   If action is REDIRECT, packet is processed for egress on the new redirect port (VLAN egress, then QoS). Processing stops for original path.
    *   If action is PERMIT (or no ACL), processing continues.
4.  **Ingress VLAN Processing (`VlanManager`):** (As before)
5.  **Source MAC Learning (`ForwardingDatabase`):** (As before, if STP state allows)
6.  **STP Check (Ingress Port for Data):** (As before)
7.  **L2 Control Plane Processing (LLDP, STP BPDUs, LACP):** If packet matches control plane criteria (e.g., specific MAC/EtherType), it's dispatched to the respective manager (e.g., `LldpManager`, `StpManager`) and typically not forwarded further.
8.  **Destination Lookup (`ForwardingDatabase`):** (As before)
9.  **Forwarding Decision:**
    *   If a destination port (`egress_port_id`) is found (known MAC):
        *   **L2 Egress Pipeline (`Switch::process_egress_pipeline`):**
            1.  **Egress VLAN Processing (`VlanManager`):** Applies egress VLAN rules (tag stripping/keeping) for `egress_port_id`.
            2.  **Egress ACL Processing (`InterfaceManager` & `AclManager`):**
                *   `InterfaceManager::get_applied_acl_name(egress_port_id, EGRESS)` is checked.
                *   If an ACL name is found, `AclManager::evaluate(acl_name, packet, ...)` is called.
                *   If action is DENY, packet is dropped. No further processing for this port.
                *   If action is REDIRECT (currently treated as PERMIT with warning), or PERMIT, packet proceeds.
            3.  **QoS Enqueueing (`QosManager`):** Packet is enqueued to the appropriate queue on `egress_port_id` based on QoS classification.
    *   If no destination port is found (unknown MAC/broadcast/multicast not handled by L2 control): Packet is flooded.
        *   For each port in the flood list (respecting VLAN, STP, link state):
            *   A *copy* of the packet is created.
            *   The `Switch::process_egress_pipeline` is called for this copy and the specific flood egress port, meaning Egress VLAN, Egress ACL, and QoS are applied independently for each flooded instance.
10. **Transmission:** (Conceptual) Packets dequeued by `QosManager` are sent.
11. **`PacketBuffer` Release:** (As before)

## 8. Layer 3 Networking

### 8.1. IP Interface Configuration (`InterfaceManager`)
(Text remains largely as before, but it's now consistent with ACLs being part of `PortConfig` via `InterfaceManager` update)

### 8.2. Static Routing (`RoutingManager`)
(Remains as before)

### 8.3. IPv4 Forwarding Logic

1.  **Packet Arrival & L2 Processing, Ingress ACL:** (As described in Section 7, up to Ingress ACL PERMIT).
2.  **Routing Determination:** (As before)
3.  **Route Lookup:** (As before)
4.  **No Route Found:** (As before - ICMP Net Unreachable generated, original packet dropped).
5.  **Route Found:**
    *   **TTL Check & Decrement:** (As before - if TTL expires, ICMP Time Exceeded generated, original packet dropped).
    *   **Next-Hop & ARP Resolution:** (As before)
        *   **MAC Found (ARP Cache Hit):**
            1.  Rewrite Ethernet headers (src MAC = egress interface MAC, dst MAC = next-hop MAC).
            2.  Call `Packet::update_checksums()` (for TTL change).
            3.  **L3 Egress Pipeline (`Switch::process_egress_pipeline`):** The packet is passed to this helper for the resolved `route.egress_interface_id`. This includes:
                *   Egress VLAN Processing.
                *   Egress ACL Evaluation: If an egress ACL is applied to `route.egress_interface_id`, it's evaluated. If DENY, packet is dropped. If REDIRECT (treated as PERMIT), or PERMIT, packet proceeds.
                *   QoS Enqueueing: Packet is enqueued on `route.egress_interface_id`.
        *   **MAC Not Found (ARP Cache Miss):** (As before - ARP request sent, original packet dropped, potentially ICMP Host Unreachable generated by ARP module if it fails, or by L3 if queuing and timeout).
6.  **Transmission:** (Conceptual) Packets dequeued by `QosManager` are sent.


### 8.4. Control Plane Packet Processing (ARP & ICMP)
(Remains as before. Note: Self-generated control plane packets currently bypass the `process_egress_pipeline` and are directly enqueued to QoS in `Switch::send_control_plane_packet/frame`. This means they are not subject to egress ACLs by default.)

## 9. Command Line Interface (CLI)

### 9.1. CLI Usage Mechanism
(Remains as before)

### 9.2. Implemented CLI Commands
This section details the CLI commands available through the `ManagementService`.

#### 9.2.1. Global Commands
(Remains as before)

#### 9.2.2. `show` Commands
(Text for existing show commands like `show interface`, `show vlan`, etc. remains. Additions below.)

*   **`show qos interface <id> [config|stats|queues]`**
    *   **Syntax:** `show qos interface <interface_id> [config|stats|queues]`
    *   **Description:** Displays Quality of Service configuration and statistics for a specified interface.
        *   `config` (default): Shows the configured number of queues, scheduler type, queue weights, rate limits, and maximum queue depth.
        *   `stats` or `queues`: Shows per-queue statistics including current depth, total enqueued, total dequeued, and packets dropped due to queue full.
    *   **Example:** (as provided in previous subtask)

*   **`show acl-rules [<acl_name>] [id <rule_id>]`**
    *   **Syntax:** `show acl-rules [<acl_name>] [id <rule_id>]`
    *   **Description:** Displays Access Control List rules.
        *   Without arguments (`show acl-rules`): Lists the names of all configured ACLs.
        *   With `<acl_name>`: Shows all rules for the specified named ACL, sorted by priority.
        *   With `<acl_name> id <rule_id>`: Shows details for a specific rule ID within the named ACL.
    *   **Output Format (example for rules in an ACL):** (as provided in previous subtask)
    *   **Example:**
        ```
        > show acl-rules
        Configured ACLs:
          MY_INGRESS_ACL
          STANDARD_DENY_LIST
        > show acl-rules MY_INGRESS_ACL
        > show acl-rules MY_INGRESS_ACL id 10
        ```

#### 9.2.3. `clear` Commands
(Text for existing clear commands remains. Additions below.)

*   **`clear qos interface <id> stats`**
    *   **Syntax:** `clear qos interface <interface_id> stats`
    *   **Description:** Clears QoS statistics for the specified interface by re-applying its current configuration, which resets queue statistics.
    *   **Example:** (as provided)

#### 9.2.4. `interface <id>` Commands (Physical Interface Configuration)
(Text for existing interface subcommands remains. Additions below.)

*   **QoS Commands (within `interface <id>` context):**
    *   `qos enable`
    *   `qos disable`
    *   `qos scheduler <strict-priority|weighted-round-robin|deficit-round-robin>`
    *   `qos num-queues <1-8>`
    *   `qos max-depth <depth_value>`
    *   `qos queue <queue_id> weight <weight_value>`
    *   `qos queue <queue_id> rate-limit <kbps_value>`
    *   **(Descriptions and Examples as provided in previous subtask)**

*   **ACL Binding Commands (within `interface <id>` context):**
    *   `ip access-group <acl_name> <in|out>`
        *   **Description:** Applies a pre-defined named ACL to the interface in the specified direction (ingress or egress). The ACL must exist (created via `acl create <acl_name>`).
        *   **Example:** `> interface Gi0/1 ip access-group MY_INGRESS_ACL in`
    *   *(The `no` form for this is handled under global `no` command)*

#### 9.2.5. `interface port-channel <id>` Commands
(Remains as before)

#### 9.2.6. `mac address-table` Commands
(Remains as before)

#### 9.2.7. `no` Commands
(Text for existing `no` commands remains. Additions below.)

*   **`no interface <id> ip access-group <in|out>`**
    *   **Syntax:** `no interface <interface_id> ip access-group <in|out>`
    *   **Description:** Removes an ACL from the specified interface and direction.
    *   **Example:** `> no interface Gi0/1 ip access-group in`

#### 9.2.8. LLDP Commands
(Remains as before)

#### 9.2.9. Access Control List (ACL) Commands (Global ACL Configuration)

These commands manage named Access Control Lists and their rules globally.

*   **`acl create <acl_name>`**
    *   **Syntax:** `acl create <acl_name>`
    *   **Description:** Creates a new, empty named ACL.
    *   **Example:** `> acl create MY_INGRESS_ACL`

*   **`acl delete <acl_name>`**
    *   **Syntax:** `acl delete <acl_name>`
    *   **Description:** Deletes a named ACL and all its rules. The ACL must not be currently applied to any interface. (Note: Current `ManagementService` implementation might not check for active applications before deletion; this is a potential refinement).
    *   **Example:** `> acl delete MY_UNUSED_ACL`

*   **`acl <acl_name> rule add id <rule_id> priority <prio> action <permit|deny|redirect <fwd_port_id>> [match_options...]`**
    *   **Description:** Adds or updates a rule within the specified named ACL.
    *   **Match Options:** (as detailed in previous subtask)
    *   **Example:** `> acl MY_INGRESS_ACL rule add id 10 priority 100 action deny protocol tcp src-ip 10.0.0.10 dst-port 80`

*   **`acl <acl_name> rule remove id <rule_id>`**
    *   **Syntax:** `acl <acl_name> rule remove id <rule_id>`
    *   **Description:** Removes a rule by its ID from the specified named ACL.
    *   **Example:** `> acl MY_INGRESS_ACL rule remove id 10`

*   **`acl <acl_name> compile`**
    *   **Syntax:** `acl <acl_name> compile`
    *   **Description:** Sorts the rules within the specified named ACL by priority to optimize evaluation. Recommended after rule changes.
    *   **Example:** `> acl MY_INGRESS_ACL compile`

(The rest of the document remains as is)
