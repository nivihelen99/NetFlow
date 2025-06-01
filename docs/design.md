# NetFlow++ Framework Design Document

## 1. Introduction

This document outlines the design and architecture of the NetFlow++ framework. The primary goals of NetFlow++ are to provide a high-performance, modular, and extensible platform for network packet processing and virtual switching. It is designed to leverage modern C++ features and system characteristics like NUMA for optimal efficiency.

## 2. System Architecture

### 2.1. Overall Architecture

NetFlow++ adopts a component-based architecture, where distinct networking functionalities (e.g., packet parsing, FDB management, VLAN processing) are encapsulated within specific C++ classes or modules. The system is designed to support a packet processing pipeline concept, where packets flow through various components for inspection, modification, and forwarding decisions.

*   **C++ Standard:** The framework is built using C++17, leveraging features like `std::optional`, `std::string_view`, and `if constexpr`.
*   **Key Libraries:** Standard C++ Library. GoogleTest is used for unit testing.
*   **Modularity:** Components are designed to be as independent as possible, interacting through well-defined interfaces. This allows for easier testing, maintenance, and potential replacement or extension of individual parts.

### 2.2. Key Design Principles

*   **Zero-Copy (Minimize Copy):** Packet data is managed to minimize copies. `PacketBuffer` and `Packet` objects aim to manipulate packet data in place or by sharing buffer ownership via reference counting.
*   **Header-Only for Core Data Structures:** Some core data structures (like protocol header definitions in `packet.hpp`) are header-only for ease of inclusion and potential compiler optimization. Larger, more complex components are compiled into libraries (e.g., `netflow_switching_lib`).
*   **Template Metaprogramming:** Used judiciously, for example, in `Packet::get_header<T>()` for type-safe access to protocol headers.
*   **NUMA Awareness:** `BufferPool` is designed to allocate `PacketBuffer` instances with NUMA node affinity to optimize memory access for applications running on multi-socket servers.
*   **Lock-Free Data Structures:** Where concurrent access is critical (e.g., potentially for hash tables or shared counters in the future), lock-free designs are preferred to avoid contention. (Current implementation details of `LockFreeHashTable` are not fully specified but this is a guiding principle).
*   **Cache Efficiency:** Data structures and algorithms are designed with CPU cache performance in mind (e.g., batch operations, contiguous memory for packet data).

## 3. Core Component Design

### 3.1. `PacketBuffer` & `BufferPool`

*   **`PacketBuffer` Design:**
    *   Encapsulates raw packet data in a dynamically allocated `unsigned char* raw_data_ptr_`.
    *   Manages `capacity_` (total allocated size), `data_offset_` (start of actual packet data, allowing for headroom), and `data_len_` (length of the packet data).
    *   Supports zero-copy operations by allowing direct pointer access (`get_data_start_ptr()`) and manipulation of data length and offsets without copying the underlying packet bytes.
    *   Methods like `prepend_data`, `append_data`, `consume_data_front`, `consume_data_end` adjust `data_offset_` and `data_len_` to manage headroom and tailroom effectively.
    *   Includes an `std::atomic<int> ref_count` to support shared ownership of the buffer, typically managed by a `BufferPool` or `Packet` instances.
*   **`BufferPool` Role (Conceptual - based on README):**
    *   Manages the lifecycle of `PacketBuffer` instances.
    *   Handles allocation and deallocation, potentially from NUMA-local memory pools.
    *   Implements the primary logic for incrementing and decrementing reference counts on `PacketBuffer`s. When a `PacketBuffer`'s reference count reaches zero, the pool reclaims it.

### 3.2. `Packet`

*   **Representation:** Represents a network packet by holding a pointer to a `PacketBuffer` (`PacketBuffer* buffer_`). It does not own the buffer directly but participates in its reference counting.
*   **Protocol Header Access:**
    *   Provides specific accessor methods like `ethernet()`, `vlan()`, `ipv4()`, `ipv6()`, `tcp()`, `udp()`. These methods parse the packet data on-demand (or cache pointers to headers) starting from the current known offset.
    *   These accessors are responsible for interpreting EtherTypes, IP protocols, etc., to locate the correct header. They handle complexities like VLAN tags affecting L3 offset.
    *   The `get_header<HeaderType>(size_t offset)` template method provides a more generic way to cast a part of the packet buffer to a specific header type at a given offset, but lacks the semantic parsing of the specific accessors.
    *   Header structures (e.g., `EthernetHeader`, `IPv4Header`) are defined directly within `packet.hpp`.
*   **Packet Manipulation:**
    *   `set_dst_mac(const MacAddress& mac)`: Modifies the destination MAC address directly in the Ethernet header of the packet buffer.
    *   `push_vlan(uint16_t vlan_id, uint8_t priority)`: Inserts a VLAN tag into the packet. If the packet is already VLAN-tagged, it modifies the existing tag. Otherwise, it shifts existing L3 data to make space for the new VLAN tag and updates the Ethernet ethertype. This operation requires careful buffer space management.
    *   `pop_vlan()`: Removes an existing VLAN tag, shifting L3 data and updating the Ethernet ethertype.
    *   `update_checksums()`: Recalculates IPv4 header checksum and L4 (TCP/UDP) checksums. For L4 checksums, it constructs the necessary pseudo-header.

### 3.3. `ForwardingDatabase` (FDB)

*   **Internal Data Structure:** Uses `std::vector<FdbEntry> entries_` to store MAC table entries. Each `FdbEntry` contains the MAC address, port, VLAN ID, a timestamp for aging, and a boolean `is_static` flag.
*   **MAC Learning:**
    *   `learn_mac(mac, port, vlan_id)`: Adds a new dynamic entry or updates an existing dynamic entry. If an entry for the MAC/VLAN pair exists, its port and timestamp are updated. Static entries are not affected by `learn_mac`.
*   **Static Entries:**
    *   `add_static_entry(mac, port, vlan_id)`: Adds an entry with `is_static = true`. These entries are not subject to aging.
*   **Lookup:**
    *   `lookup_port(mac, vlan_id)`: Iterates through the `entries_` vector to find a matching MAC address and VLAN ID. Returns the associated port ID if found, otherwise `std::nullopt`. Static entries take precedence if a MAC/VLAN pair somehow exists as both static and dynamic (though the add/learn logic should prevent this for the same MAC/VLAN).
*   **Aging Mechanism:**
    *   `age_entries(max_age)`: Iterates through dynamic entries. If an entry's `timestamp` is older than the current time minus `max_age`, it is removed from the vector. Static entries are skipped.
*   **Flush Operations:**
    *   `flush_port(port)`: Removes all entries (static and dynamic) associated with the given port.
    *   `flush_vlan(vlan_id)`: Removes all entries associated with the given VLAN ID.
    *   `flush_all()`: Clears the entire `entries_` vector.
*   **Entry Retrieval:**
    *   `get_all_entries()`: Returns a const reference to the internal `entries_` vector, allowing external components to view the FDB state.
    *   `remove_entry(mac, vlan_id)`: Finds and removes an FDB entry (static or dynamic) matching MAC and VLAN ID. Returns `true` if an entry was removed.

### 3.4. `VlanManager`

*   **Storage:** Likely uses a `std::map<uint32_t, PortVlanConfig>` (or similar) to store per-port VLAN configurations. `PortVlanConfig` would store the port type (Access, Trunk), PVID for access ports, native VLAN for trunk ports, and a list of allowed VLANs for trunk ports.
*   **`process_ingress` Logic:**
    1.  Retrieves the port's VLAN configuration.
    2.  If Access Port:
        *   If packet is untagged: Adds a VLAN tag with the port's PVID and default priority. Action: FORWARD.
        *   If packet is tagged: If tag matches PVID, Action: FORWARD. Else, Action: DROP.
    3.  If Trunk Port:
        *   If packet is untagged: If native VLAN is configured, tags packet with native VLAN ID. Action: FORWARD. Else, Action: DROP.
        *   If packet is tagged: If VLAN ID is in allowed list for the trunk, Action: FORWARD. Else, Action: DROP.
    4.  (Hybrid port logic would be more complex).
*   **`process_egress` Logic:**
    1.  Retrieves the port's VLAN configuration and the packet's VLAN ID.
    2.  If Access Port: If packet's VLAN ID matches PVID, strips the VLAN tag.
    3.  If Trunk Port:
        *   If packet's VLAN ID is the native VLAN and `tag_native` is false (or similar setting), strips the tag.
        *   Otherwise, keeps the tag if it's in the allowed VLAN list.
*   **`should_forward` Logic:** This method likely consults the port's STP state and potentially other port status flags to determine if a packet, already processed for ingress VLAN rules, should be allowed to proceed to FDB lookup and egress processing.

### 3.5. `InterfaceManager`

*   **Storage:** Manages a collection of port/interface configurations, likely using a `std::map<uint32_t, InterfaceConfig>` where `uint32_t` is the port ID. `InterfaceConfig` would store admin state, speed, duplex, MTU, and potentially pointers to statistics counters.
*   **Statistics:** Statistics (packets/bytes rx/tx, errors) would be associated with each interface, updated by the packet processing pipeline.
*   **Link State Callbacks:** Could use a callback mechanism (e.g., `std::function`) or an observer pattern to notify other components (like STP or LACP) of physical link state changes.

## 4. Performance-Critical Component Design

### 4.1. `PacketClassifier`

*   **`FlowKey` Structure:** A struct containing fields extracted from packet headers, such as source/destination IP addresses, L4 ports, protocol, and potentially VLAN ID or MAC addresses.
*   **`extract_flow_key`:** A function that takes a `Packet&`, parses it up to the required layer (e.g., L4), and populates the `FlowKey` fields. This needs to be highly efficient.
*   **Hashing Strategy (`hash_flow`):** Employs a fast and well-distributed hash function (e.g., CRC32 variants, CityHash, or MurmurHash) on the `FlowKey` bytes.
*   **Rule Management:** Classification rules (matching a `FlowKey` or parts of it to an action or class ID) would be stored, potentially in a hash table or a list for sequential matching if rule counts are small. For high performance with many rules, more advanced structures like TCAM-like software emulations (e.g., using set-pruning tries or hierarchical hash tables) might be considered.

### 4.2. `LockFreeHashTable` (Conceptual)

*   **Approach:** Common techniques for lock-free hash tables include using atomic compare-and-swap (CAS) operations for insertions, lookups, and removals. Linear probing or other open addressing schemes can be adapted for lock-free access. Managing memory reclamation for removed nodes without locks is a key challenge (e.g., using epoch-based reclamation, hazard pointers, or reference counting if applicable).
*   **Batch Operations:** Designed to process arrays or lists of keys/items in a single call to reduce per-item overhead and improve cache utilization by keeping data hot.

## 5. Advanced Feature Component Design (High-Level)

### 5.1. `StpManager`

*   **State Machine:** Manages the STP state (Blocking, Listening, Learning, Forwarding, Disabled) for each port.
*   **BPDU Logic:**
    *   Generates Configuration BPDUs based on the bridge's understanding of the topology (Root Bridge, Root Path Cost) and port roles.
    *   Processes received BPDUs: Compares them with current port/bridge information to update STP parameters, elect the Root Bridge, and determine port roles (Root Port, Designated Port, Blocking Port).
    *   Handles Topology Change Notification (TCN) BPDUs.
*   **Timers:** Manages STP timers (Hello Time, Max Age, Forward Delay).
*   **Configuration:**
    *   `set_bridge_priority_and_reinit(priority)`: Sets the global bridge priority.
    *   `set_port_path_cost(port_id, cost)`: Sets the STP path cost for a specific port.
    *   `set_port_priority(port_id, priority)`: Sets the STP priority for a specific port.

### 5.2. `LacpManager`

*   **LAG Membership:** Manages the configuration of Link Aggregation Groups, including which physical ports are members of which LAG.
*   **LACPDU Handling:**
    *   Sends LACPDU packets containing Actor and Partner information (system ID, port priority, operational key, state flags).
    *   Processes received LACPDUs to synchronize state with link partners, select active member ports based on port priorities and consistent configurations.
*   **Egress Port Selection:** Implements a hash function (based on configured L2/L3/L4 criteria) to select a physical member port for egress traffic destined for a LAG, ensuring load distribution.
*   **Configuration:**
    *   `set_actor_system_priority(priority)`: Sets the global LACP system priority.
    *   `set_port_lacp_priority(port_id, priority)`: Sets the LACP priority for a specific port.
    *   `create_lag(config)`: Creates a new LAG.
    *   `configure_lag_setting(lag_id, modifier_fn)`: Modifies existing LAG settings (e.g., mode, rate).

### 5.3. `QosManager`

The `QosManager` component is implemented to provide port-based Quality of Service capabilities. It allows for differentiated packet handling based on configured policies.
*   **Queue Structures:** Supports multiple queues per port (e.g., up to 8). Each port configuration (`QosConfig`) specifies the number of queues and their maximum depth (`max_queue_depth`). Packets are stored as copies within these queues.
*   **Scheduler:** Implements scheduling algorithms to determine the order of packet transmission from queues.
    *   **Strict Priority (SP):** Higher priority queues are always serviced before lower priority ones. This is fully implemented.
    *   **Weighted Round Robin (WRR) / Deficit Round Robin (DRR):** These are available as scheduler types in the configuration. Currently, they fall back to a basic Round Robin mechanism where queues are serviced in a cyclical order. Full weighted/deficit logic is a future enhancement.
*   **Rate Limiting:** The `QosConfig` structure allows specifying `rate_limits_kbps` per queue. The framework for this is in place, but the actual token bucket logic for enforcement in `should_transmit` and `update_token_buckets` is a placeholder for future implementation.
*   **Classification:** Incoming packets are classified to a specific queue on their egress port. The current implementation uses the packet's VLAN Priority Code Point (PCP) value to map to a queue index. If no PCP is present, it defaults to a lower priority queue. This logic is handled internally when `enqueue_packet` is called.
*   **CLI Integration:** QoS settings (number of queues, scheduler type, weights, rate limits, max depth) can be configured per interface using CLI commands. Statistics per queue (enqueued, dropped, depth) can also be viewed.

### 5.4. `AclManager`

The `AclManager` component is implemented to provide packet filtering capabilities based on Access Control Lists (ACLs). It allows defining rules to permit, deny, or redirect packets.
*   **Rule Storage:** ACL rules (`AclRule`) are stored in a `std::vector`. Each rule has a unique ID, a priority (integer, higher value means higher precedence), match criteria, and an action.
*   **Match Criteria:** Rules can match on various L2, L3, and L4 fields:
    *   L2: Source/Destination MAC, VLAN ID, EtherType.
    *   L3 (IPv4): Source/Destination IP address (exact match), IP protocol.
    *   L4: Source/Destination Port (for TCP/UDP).
    All match fields in a rule are optional; if a field is not set in a rule, it acts as a wildcard for that criterion.
*   **Actions:**
    *   `PERMIT`: Allows the packet.
    *   `DENY`: Drops the packet.
    *   `REDIRECT`: Forwards the packet to a specified `redirect_port_id`.
*   **Evaluation Engine:** The `evaluate` method iterates through the rules. If `compile_rules` has been called, the rules are processed in priority order (higher priority value first). The first rule that matches the packet determines the action. If no rule matches, a default action of `PERMIT` is taken.
*   **Optimization (`compile_rules`):** The `compile_rules` method sorts the ACL rules by their priority (descending) and then by rule ID (ascending, for stability). This ensures that higher priority rules are evaluated first. Further optimizations (e.g., TCAM-like structures) are conceptual at this stage.
*   **CLI Integration:** ACL rules can be managed (added, removed, viewed) via CLI commands. A command to trigger rule compilation is also available.

### 5.5 LldpManager
The `LldpManager` class is responsible for handling the Link Layer Discovery Protocol (LLDP, IEEE 802.1AB). LLDP is a Layer 2 neighbor discovery protocol that allows network devices to advertise their identity and capabilities to adjacent devices and learn information about their neighbors. This information is crucial for network topology mapping, troubleshooting, and management.
*   **Key Functionalities:** (details as before)
*   **Interactions:** (details as before)

## 6. System Integration Component Design (High-Level)
(Sections 6.1, 6.2, 6.3 remain as before)

## 7. Data Flow (Example: L2 Forwarding)
(Remains as before)

## 8. Layer 3 Networking
(Remains as before)

## 9. Command Line Interface (CLI)

### 9.1. CLI Usage Mechanism
(Remains as before)

### 9.2. Implemented CLI Commands
This section details the CLI commands available through the `ManagementService`.

#### 9.2.1. Global Commands
(Remains as before)

#### 9.2.2. `show` Commands
(Remains as before, with additions for QoS and ACLs to be inserted)

*   **`show qos interface <id> [config|stats|queues]`**
    *   **Syntax:** `show qos interface <interface_id> [config|stats|queues]`
    *   **Description:** Displays Quality of Service configuration and statistics for a specified interface.
        *   `config` (default): Shows the configured number of queues, scheduler type, queue weights, rate limits, and maximum queue depth.
        *   `stats` or `queues`: Shows per-queue statistics including current depth, total enqueued, total dequeued, and packets dropped due to queue full.
    *   **Example:**
        ```
        > show qos interface 1 config
        QoS Configuration for Interface 1:
          Enabled: Yes
          Scheduler: Strict Priority
          Number of Queues: 4
          Max Queue Depth: 1000 packets
          Queue 0: Rate Limit None
          Queue 1: Rate Limit None
          ...
        > show qos interface 1 stats
        QoS Statistics for Interface 1:
          Queue 0:
            Current Depth: 0 packets
            Enqueued:      150 packets
            Dequeued:      150 packets
            Dropped (Full):0 packets
          ...
        ```

*   **`show acl-rules [id <rule_id>]`**
    *   **Syntax:** `show acl-rules [id <rule_id>]`
    *   **Description:** Displays Access Control List rules.
        *   Without arguments, shows all configured ACL rules, typically sorted by priority.
        *   With `id <rule_id>`, shows details for the specified rule ID.
    *   **Output Format (example for all rules):**
        ```
        ID   Priority  Action    Src MAC              Dst MAC              VLAN  EtherType  Src IP            Dst IP            Protocol  Src Port  Dst Port  Redirect
        -----------------------------------------------------------------------------------------------------------------------------------------------------------
        1    100       Permit    Any                  Any                  Any   0x0800     192.168.1.10      Any               TCP       Any       80        N/A
        2    90        Deny      00:11:22:aa:bb:cc    Any                  100   Any        Any               Any               Any       Any       Any       N/A
        ```
    *   **Example:**
        ```
        > show acl-rules
        > show acl-rules id 1
        ```

#### 9.2.3. `clear` Commands
(Remains as before, with addition for QoS)

*   **`clear qos interface <id> stats`**
    *   **Syntax:** `clear qos interface <interface_id> stats`
    *   **Description:** Clears QoS statistics for the specified interface. This is typically done by re-applying the current QoS configuration to the port, which resets the associated queue statistics structures.
    *   **Example:**
        ```
        > clear qos interface 1 stats
        QoS statistics cleared for interface 1.
        ```

#### 9.2.4. `interface <id>` Commands (Physical Interface Configuration)
(Remains as before, with addition for QoS)

*   **QoS Commands (within `interface <id>` context):**
    *   `qos enable`
        *   **Description:** Ensures QoS is active on the interface, applying a default configuration if none exists or re-activating the current one.
        *   **Example:** `> interface Gi0/1 qos enable`
    *   `qos disable`
        *   **Description:** Effectively disables QoS by applying a basic pass-through configuration (e.g., single queue, SP).
        *   **Example:** `> interface Gi0/1 qos disable`
    *   `qos scheduler <strict-priority|weighted-round-robin|deficit-round-robin>`
        *   **Description:** Sets the scheduling policy for the interface's queues.
        *   **Example:** `> interface Gi0/1 qos scheduler weighted-round-robin`
    *   `qos num-queues <1-8>`
        *   **Description:** Sets the number of QoS queues for the interface.
        *   **Example:** `> interface Gi0/1 qos num-queues 4`
    *   `qos max-depth <depth_value>`
        *   **Description:** Sets the maximum depth (in packets) for all queues on this interface.
        *   **Example:** `> interface Gi0/1 qos max-depth 500`
    *   `qos queue <queue_id> weight <weight_value>`
        *   **Description:** Assigns a weight to a specific queue (for WRR/DRR schedulers).
        *   **Example:** `> interface Gi0/1 qos queue 1 weight 50`
    *   `qos queue <queue_id> rate-limit <kbps_value>`
        *   **Description:** Sets a rate limit (in Kbps) for a specific queue. `0` means no limit.
        *   **Example:** `> interface Gi0/1 qos queue 0 rate-limit 10000` (10 Mbps)


#### 9.2.5. `interface port-channel <id>` Commands (LAG Configuration)
(Remains as before)

#### 9.2.6. `mac address-table` Commands
(Remains as before)

#### 9.2.7. `no` Commands
(Remains as before)

#### 9.2.8. LLDP Commands
(Remains as before)

#### 9.2.9. Access Control List (ACL) Commands (New Section)

These commands manage the global Access Control List rules.

*   **`acl-rule add id <rule_id> priority <priority_value> action <permit|deny|redirect <fwd_port_id>> [match_options...]`**
    *   **Description:** Adds or updates an ACL rule. Rules are processed based on priority (higher numeric value means higher precedence). If a rule with the same `rule_id` exists, it is updated.
    *   **Match Options (any combination):**
        *   `src-mac <mac_address>` (e.g., `00:11:22:aa:bb:cc`)
        *   `dst-mac <mac_address>`
        *   `vlan <vlan_id>` (e.g., `100`)
        *   `ethertype <hex_value>` (e.g., `0x0800` for IPv4, `0x0806` for ARP)
        *   `src-ip <ip_address>` (e.g., `192.168.1.10`; mask/prefix length not supported in this basic version)
        *   `dst-ip <ip_address>`
        *   `protocol <tcp|udp|icmp|ip|number>` (e.g., `tcp`, `17` for UDP)
        *   `src-port <port_number>` (for TCP/UDP)
        *   `dst-port <port_number>` (for TCP/UDP)
    *   **Example:**
        ```
        > acl-rule add id 10 priority 100 action permit src-ip 10.0.0.1 dst-ip 10.0.0.2 protocol tcp dst-port 80
        ACL rule 10 added/updated.
        > acl-rule add id 20 priority 90 action deny src-mac 00:DE:AD:BE:EF:00
        ACL rule 20 added/updated.
        > acl-rule add id 30 priority 110 action redirect 5 src-ip 172.16.0.5
        ACL rule 30 added/updated.
        ```

*   **`acl-rule remove id <rule_id>`**
    *   **Syntax:** `acl-rule remove id <rule_id>`
    *   **Description:** Removes an ACL rule specified by its ID.
    *   **Example:**
        ```
        > acl-rule remove id 20
        ACL rule 20 removed.
        ```

*   **`acl-compile`**
    *   **Syntax:** `acl-compile`
    *   **Description:** Sorts the ACL rules by priority to optimize evaluation. It's recommended to run this after adding or removing rules.
    *   **Example:**
        ```
        > acl-compile
        ACL rules compiled (sorted by priority).
        ```

(The rest of the document remains as is)
