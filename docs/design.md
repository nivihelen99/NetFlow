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

### 5.3. `QosManager` (Conceptual)

*   **Queue Structures:** Per-port, multiple queues (e.g., 8 queues). Each queue might have its own buffer limits.
*   **Scheduler:** Implements scheduling algorithms like Strict Priority (higher priority queues always serviced first) and Weighted Round Robin (WRR) or Deficit Round Robin (DRR) for distributing bandwidth among queues of the same priority level.
*   **Rate Limiting:** Token bucket mechanisms per queue or per port for enforcing bandwidth limits.
*   **Classification:** Relies on `PacketClassifier` output (or a dedicated QoS classifier) to map incoming packets to specific QoS queues based on DSCP, PCP, or flow information.

### 5.4. `AclManager` (Conceptual)

*   **Rule Storage:** Stores ACL rules, each specifying match criteria (e.g., source/destination IP, MAC, L4 port, protocol) and an action (permit/deny). Rules typically have priorities.
*   **Evaluation Engine:** For each packet, iterates through applicable ACLs. The first matching rule (based on priority) determines the action.
*   **Optimization:** For performance, especially with many rules, ACLs might be compiled into a more efficient data structure (e.g., a decision tree, tuple space search, or a software TCAM emulation) rather than simple linear matching.

### 5.5 LldpManager

The `LldpManager` class is responsible for handling the Link Layer Discovery Protocol (LLDP, IEEE 802.1AB). LLDP is a Layer 2 neighbor discovery protocol that allows network devices to advertise their identity and capabilities to adjacent devices and learn information about their neighbors. This information is crucial for network topology mapping, troubleshooting, and management.

**Key Functionalities:**

*   **LLDPDU Transmission:** Periodically sends LLDP Data Units (LLDPDUs) on all LLDP-enabled ports. These frames contain information about the switch itself.
*   **LLDPDU Reception & Processing:** Receives and parses LLDPDUs from neighboring devices.
*   **TLV Handling:** Constructs and parses standard LLDP TLVs (Type-Length-Value structures), including:
    *   Chassis ID TLV (using the switch's MAC address).
    *   Port ID TLV (using interface MAC address or name).
    *   Time-to-Live (TTL) TLV.
    *   System Name TLV (e.g., hostname of the switch).
    *   System Description TLV.
    *   (Optional) Port Description TLV.
    *   (Optional) Management Address TLV.
*   **Neighbor Information Storage:** Stores information about discovered neighbors in an `LldpNeighborInfo` structure, associated with the ingress port. This includes Chassis ID, Port ID, TTL, and any optional information received.
*   **Neighbor Aging:** Neighbors are aged out based on the TTL value received in their LLDPDUs. If a neighbor's information is not refreshed before its TTL expires, it is removed from the list of active neighbors.
*   **Configuration:** LLDP can be configured per port:
    *   Enable/Disable LLDP on an interface.
    *   Set the transmission interval (`tx_interval_seconds`): How often LLDP frames are sent.
    *   Set the TTL multiplier (`ttl_multiplier`): The TTL advertised in LLDP frames is typically `tx_interval_seconds * ttl_multiplier`.

**Interactions:**

*   **`InterfaceManager`:** `LldpManager` queries `InterfaceManager` to get local interface information required for LLDP TLVs, such as MAC addresses and interface names (for Port ID TLV), and to check if a port is operationally up.
*   **`Switch`:**
    *   The `Switch` class is responsible for dispatching incoming packets with the LLDP EtherType (0x88CC) to the `LldpManager` for processing.
    *   `LldpManager` uses a method provided by the `Switch` class (e.g., `send_control_plane_frame`) to construct and transmit LLDPDUs.
    *   The `Switch` class's main timer/event loop calls `LldpManager::handle_timer_tick()` periodically to trigger LLDPDU transmissions and neighbor aging.
*   **`lldp_defs.hpp`:** This header file contains definitions for LLDP constants (EtherType, multicast MAC), TLV types, subtypes, and structures like `LldpTlvHeader` and `LldpNeighborInfo`.

The `LldpManager` helps build a dynamic view of the directly connected network devices, which is essential for network management and operational awareness.

## 6. System Integration Component Design (High-Level)

### 6.1. `ConfigManager`

*   **Data Structure:** Likely uses an internal representation (e.g., nested maps or a dedicated class structure) to hold the entire switch configuration.
*   **Loading/Saving:** Implements parsing for a chosen format (JSON/YAML) to populate its internal structures on load, and serialization to write them back on save.
*   **Application:** Provides methods for other components to query their relevant configuration sections. May use an observer pattern to notify components of runtime configuration changes.

### 6.2. `SwitchLogger`

*   **Mechanism:** A centralized logging facility. Could be a simple wrapper around `stdout/stderr` or integrate with a more advanced logging library (e.g., spdlog, glog).
*   **Levels:** Supports different log severity levels (DEBUG, INFO, WARN, ERROR, CRITICAL).
*   **Filtering:** Allows runtime configuration of log levels per component or globally.
*   **Specialized Logging:** `log_packet()` for detailed packet content logging, `log_performance_stats()` for structured performance data.

### 6.3. `ManagementInterface` (Conceptual)

*   **Registration:** Components (FDB, InterfaceManager, etc.) register their manageable attributes or callable functions with the ManagementInterface.
*   **OID Mapping:** For SNMP-like access, it would map registered attributes to unique OIDs.
*   **Endpoint Handling:** For REST APIs, it would map HTTP requests (e.g., GET /fdb/entries) to calls on the registered components.
*   **CLI Dispatch:** For a CLI, it would parse commands and dispatch them to registered command handlers in the respective components. This is the primary focus of the current CLI implementation within `ManagementService`.

## 7. Data Flow (Example: L2 Forwarding)

1.  **Packet Arrival:** Packet arrives at a physical port. NIC driver (or kernel bypass library) places packet data into a `PacketBuffer` obtained from a NUMA-local `BufferPool`.
2.  **`Packet` Object Creation:** A `Packet` object is created, referencing the `PacketBuffer`.
3.  **Ingress VLAN Processing (`VlanManager`):**
    *   `VlanManager::process_ingress(packet, ingress_port_id)` is called.
    *   VLAN tags are processed (added/checked) based on port configuration. If dropped, processing stops.
4.  **Source MAC Learning (`ForwardingDatabase`):**
    *   `ForwardingDatabase::learn_mac(packet.src_mac(), ingress_port_id, packet.vlan_id())` is called.
5.  **STP Check (`StpManager`):**
    *   `StpManager::get_port_state(ingress_port_id)` is checked. If not forwarding, packet might be dropped (unless it's a BPDU for STP processing).
6.  **Destination Lookup (`ForwardingDatabase`):**
    *   `ForwardingDatabase::lookup_port(packet.dst_mac(), packet.vlan_id())` is called.
7.  **Forwarding Decision:**
    *   If a destination port is found:
        *   **Egress STP Check (`StpManager`):** `StpManager::get_port_state(egress_port_id)` is checked. If not forwarding, packet is dropped.
        *   **Egress VLAN Processing (`VlanManager`):** `VlanManager::process_egress(packet, egress_port_id)` is called to apply egress VLAN rules (tag stripping/keeping).
        *   Packet is queued for transmission on the egress port.
    *   If no destination port is found (unknown MAC): Packet is flooded to all other ports in the same VLAN that are in a forwarding STP state (excluding ingress port). Egress VLAN processing is applied per port.
8.  **Transmission:** Packet data (from `PacketBuffer`) is sent out via the NIC.
9.  **`PacketBuffer` Release:** `Packet` object is destroyed, decrementing `PacketBuffer`'s reference count. If count reaches zero, `BufferPool` reclaims it.

## 8. Layer 3 Networking

Layer 3 networking capabilities enable the switch to route IP packets between different networks or subnets. This involves IP interface configuration, routing table management, and the handling of L3-specific protocols like ARP and ICMP.

### 8.1. IP Interface Configuration (`InterfaceManager`)

The `InterfaceManager` is extended to manage Layer 3 properties of switch interfaces. While it already handles L2 properties like MAC addresses and port status, L3 configuration associates IP addresses with these interfaces, allowing the switch to participate in IP networks.

*   **IP Address Management:**
    *   `add_ip_address(port_id, ip_address, subnet_mask)`: Assigns an IP address and subnet mask to a specific interface (port or VLAN interface).
    *   `remove_ip_address(port_id, ip_address, subnet_mask)`: Removes an IP address configuration from an interface.
    *   `get_interface_ip_configs(port_id)`: Retrieves all IP configurations (IP address, subnet mask) for a given interface.
    *   An interface can be configured with one or more IP addresses, each with its own subnet mask. This allows an interface to belong to multiple logical IP subnets.
*   **MAC Address Association:** The MAC address configured for an interface (e.g., via `PortConfig` or for a VLAN interface) is crucial for L3 operations. It serves as the source MAC address for ARP requests/replies generated by the switch for that interface and for packets routed out of that interface.
*   **Interface Identification:** `InterfaceManager` helps in identifying if a given IP address is local to one of the switch's configured interfaces (`is_my_ip(ip_address)`) and in retrieving the MAC address associated with a local IP (`get_mac_for_ip(ip_address)`).

### 8.2. Static Routing (`RoutingManager`)

The `RoutingManager` is responsible for maintaining the IP routing table, which the switch uses to make decisions about where to forward IP packets.

*   **RouteEntry Structure:** The routing table consists of `RouteEntry` objects, each typically containing:
    *   `destination_network`: The IP address of the destination network (e.g., `192.168.2.0`).
    *   `subnet_mask`: The subnet mask for the destination network (e.g., `255.255.255.0`).
    *   `next_hop_ip`: The IP address of the next-hop router to reach the destination. If `0.0.0.0`, it usually indicates a directly connected network.
    *   `egress_interface_id`: The logical ID of the switch interface (e.g., port ID or VLAN interface ID) through which packets to this destination should be sent.
    *   `metric` (optional): A cost associated with the route, used for selecting among multiple routes to the same destination.
*   **Route Management:**
    *   `add_static_route(destination_network, subnet_mask, next_hop_ip, egress_interface_id, metric)`: Adds a static route to the table.
    *   `remove_static_route(destination_network, subnet_mask, next_hop_ip, egress_interface_id)`: Removes a specific static route.
*   **Route Lookup:**
    *   `lookup_route(destination_ip)`: This is a critical function that searches the routing table for the best match for a given destination IP address. It performs a **longest prefix match (LPM)**. For example, a route to `192.168.1.0/24` would be a better match for `192.168.1.5` than a route to `192.168.0.0/16`. If multiple routes have the same prefix length, other factors like metric or administrative distance (if implemented) might be used. Returns `std::optional<RouteEntry>`.

### 8.3. IPv4 Forwarding Logic

When an IP packet arrives at the switch and is destined for a non-local IP address (or needs routing for other reasons), the following L3 forwarding process typically occurs:

1.  **Packet Arrival & L2 Processing:** The packet is received on an ingress port. Initial L2 processing (e.g., VLAN tagging/stripping via `VlanManager`) is performed.
2.  **Routing Determination:** The switch determines that the packet requires L3 forwarding. This usually happens if:
    *   The destination MAC address in the Ethernet frame is the MAC address of a switch interface.
    *   The destination IP address is not one of the switch's own interface IPs (checked via `InterfaceManager::is_my_ip()`).
3.  **Route Lookup:** `RoutingManager::lookup_route(destination_ip)` is called with the packet's destination IP address.
4.  **No Route Found:** If `lookup_route` returns no matching route:
    *   The `IcmpProcessor` is invoked to generate an ICMP Destination Unreachable (Type 3, Code 0 - Network Unreachable) message.
    *   This ICMP error message is sent back to the source IP address of the original packet.
    *   The original packet is dropped.
5.  **Route Found:** If a route is found:
    *   **TTL Check:** The Time-To-Live (TTL) field in the packet's IPv4 header is decremented.
        *   If TTL becomes 0: The `IcmpProcessor` generates an ICMP Time Exceeded (Type 11, Code 0 - TTL expired in transit) message, which is sent back to the source IP. The original packet is dropped.
    *   **Next-Hop Determination:** The `next_hop_ip` and `egress_interface_id` are extracted from the `RouteEntry`.
    *   **Target for ARP:**
        *   If `next_hop_ip` in the route entry is `0.0.0.0` (or a similar indicator for directly connected networks), the `target_arp_ip` is the original packet's `destination_ip`.
        *   Otherwise, the `target_arp_ip` is the `next_hop_ip` from the route entry.
    *   **ARP Resolution (`ArpProcessor`):** `ArpProcessor::lookup_mac(target_arp_ip)` is called to find the MAC address of the `target_arp_ip`.
        *   **MAC Found (ARP Cache Hit):**
            1.  The packet's source MAC address (in the Ethernet header) is rewritten to the MAC address of the `egress_interface_id` (obtained from `InterfaceManager`).
            2.  The packet's destination MAC address is rewritten to the MAC address retrieved from the ARP cache.
            3.  The (modified) packet is then queued for transmission on the `egress_interface_id`.
        *   **MAC Not Found (ARP Cache Miss):**
            1.  `ArpProcessor::send_arp_request(target_arp_ip, egress_interface_id)` is called to send an ARP request out of the `egress_interface_id` to resolve the `target_arp_ip`.
            2.  The original packet is typically either:
                *   **Queued:** Stored temporarily, awaiting ARP resolution. If ARP resolves, the packet is then processed as per "MAC Found". If ARP fails (e.g., timeout), the packet is dropped, and potentially an ICMP Destination Unreachable (Host Unreachable) is sent.
                *   **Dropped:** Simpler implementations might drop the packet immediately. An ICMP Host Unreachable might be sent.
                (The exact behavior for pending ARP resolution is a specific design choice for the switch's control plane.)
6.  **Packet Transmission:** The packet (with modified L2 headers and decremented TTL) is sent out the egress interface.

### 8.4. Control Plane Packet Processing (ARP & ICMP)

The switch itself generates and processes certain L3 control plane packets using `ArpProcessor` and `IcmpProcessor`. These self-generated packets are typically handed off to `Switch::send_control_plane_packet()` for transmission. This method is assumed to encapsulate the packet appropriately (using the provided headers) and send it out the specified egress port, potentially bypassing parts of the normal ingress processing pipeline (like FDB lookup or ingress VLAN processing for self-generated packets).

#### 8.4.1. ARP (`ArpProcessor`)

*   **`process_arp_packet(packet, ingress_port)`:**
    *   Handles incoming ARP packets.
    *   If it's an ARP Request:
        *   Checks if the `target_ip` in the ARP request matches an IP address configured on one of the switch's interfaces (via `InterfaceManager::is_my_ip()` and `InterfaceManager::get_mac_for_ip()`).
        *   If it's a match, `ArpProcessor::send_arp_reply()` is called to construct and send an ARP reply using the MAC address of the matched interface.
    *   If it's an ARP Reply:
        *   The `sender_ip` and `sender_mac` from the ARP reply are learned and used to update the ARP cache (`arp_cache_[sender_ip] = sender_mac`).
*   **`send_arp_request(target_ip, egress_port_hint)`:**
    *   Triggered typically by the L3 forwarding process when the next-hop MAC is unknown.
    *   Source IP/MAC Selection:
        *   The source IP and MAC for the ARP request are determined from the `egress_port_hint` (which is the egress interface for the original data packet). `InterfaceManager::get_interface_ip(egress_port_hint)` and `InterfaceManager::get_interface_mac(egress_port_hint)` are used.
        *   If the hint is insufficient or no IP is configured, a fallback mechanism might select another L3 interface, or the request might fail.
    *   Construction: An Ethernet header (Dest MAC: broadcast, Src MAC: chosen interface MAC, Ethertype: ARP) and an ARP header (Opcode: Request, Sender MAC/IP: chosen interface's, Target MAC: 00s, Target IP: `target_ip`) are constructed.
    *   Sending: The constructed ARP packet is sent via `Switch::send_control_plane_packet(arp_request_packet, egress_port_hint)`.
*   **`send_arp_reply(original_requester_ip, original_requester_mac, our_ip_for_reply, our_mac_for_reply, egress_port)`:**
    *   Triggered by `process_arp_packet` when an ARP request is received for one of the switch's own interface IPs.
    *   Construction:
        *   Ethernet Header: Dest MAC is `original_requester_mac`, Src MAC is `our_mac_for_reply`.
        *   ARP Header: Opcode: Reply, Sender MAC/IP: `our_mac_for_reply`/`our_ip_for_reply`, Target MAC/IP: `original_requester_mac`/`original_requester_ip`.
    *   Sending: The ARP reply is sent via `Switch::send_control_plane_packet(arp_reply_packet, egress_port)`.

#### 8.4.2. ICMP (`IcmpProcessor`)

*   **`process_icmp_packet(packet, ingress_port)`:**
    *   Handles incoming ICMP packets.
    *   Primarily, if it's an ICMP Echo Request (ping) and the `destination_ip` in the IP header is one of the switch's interface IPs (checked via `InterfaceManager::is_my_ip()`), it triggers `IcmpProcessor::send_icmp_echo_reply()`.
    *   Other ICMP types (e.g., replies to switch-originated pings) might also be processed.
*   **`send_icmp_echo_reply(original_request_packet, egress_port, new_src_ip, new_src_mac, new_dst_ip, new_dst_mac)`:**
    *   Triggered by `process_icmp_packet` for an incoming Echo Request to the switch.
    *   Source/Destination Determination:
        *   `new_src_ip` is the switch's IP that was pinged (original request's destination IP).
        *   `new_src_mac` is the MAC of the interface owning `new_src_ip`.
        *   `new_dst_ip` is the original request's source IP.
        *   `new_dst_mac` is the original request's source MAC.
    *   Construction: An Ethernet header, an IPv4 header (Src IP: `new_src_ip`, Dst IP: `new_dst_ip`, Protocol: ICMP), and an ICMP Echo Reply header (Type: 0, Code: 0) are constructed. The ICMP identifier, sequence number, and payload from the original request are copied to the reply.
    *   Sending: The reply is sent via `Switch::send_control_plane_packet(echo_reply_packet, egress_port)`.
*   **`send_icmp_error_packet_base(original_packet, icmp_type, icmp_code)` (used by `send_time_exceeded`, `send_destination_unreachable`):**
    *   Triggered by various conditions in the forwarding path (e.g., TTL expiry, no route, ARP failure leading to host unreachable).
    *   Source IP Determination: The source IP for the ICMP error message is the IP address of the switch interface through which the error message will be routed back to the `original_packet`'s source. This is found by looking up the route to `original_packet.src_ip` using `RoutingManager::lookup_route()` to determine the egress interface for the error message, then getting that interface's IP using `InterfaceManager::get_interface_ip()`.
    *   Next-Hop MAC for Error Packet: The MAC address for the next hop (towards `original_packet.src_ip`) is resolved using `ArpProcessor::lookup_mac()` or by sending an ARP request if needed.
    *   Construction:
        *   Ethernet Header: Src MAC is the egress interface's MAC for the error, Dst MAC is the resolved next-hop MAC.
        *   IPv4 Header: Src IP is the determined switch interface IP, Dst IP is `original_packet.src_ip`, Protocol: ICMP.
        *   ICMP Header: Type and Code as specified (e.g., Type 11/Code 0 for Time Exceeded, Type 3/Code 0 for Net Unreachable, Type 3/Code 1 for Host Unreachable). Identifier and Sequence Number are zeroed.
        *   ICMP Payload: Includes the full IP header of the `original_packet` plus the first 8 bytes of the `original_packet`'s L4 payload.
    *   Sending: The ICMP error packet is sent via `Switch::send_control_plane_packet(icmp_error_packet, egress_port_for_error)`.

## 9. Command Line Interface (CLI)

### 9.1. CLI Usage Mechanism

The Command Line Interface (CLI) provides a text-based mechanism for users to interact with and manage the NetFlow++ switch. It is facilitated by the `ManagementInterface` and `ManagementService` classes.

1.  **Command Registration:**
    *   The `ManagementService` instance, during its initialization (specifically within `register_cli_commands()`), registers various command strings (e.g., "show", "interface", "mac") with the `ManagementInterface`.
    *   Each registered command is associated with a handler lambda function. This lambda captures `this` (pointing to the `ManagementService` instance) to access underlying managers (`InterfaceManager`, `VlanManager`, `FdbManager`, `StpManager`, `LacpManager`, `RoutingManager`).
2.  **Input Processing:**
    *   The main application loop (e.g., in `main.cpp`) reads a line of text from the user (e.g., `std::cin`).
    *   The input line is passed to `ManagementInterface::handle_cli_command(const std::string& line)`.
3.  **Command Parsing & Dispatch (`ManagementInterface`):**
    *   `ManagementInterface` parses the input line into a command token and a vector of argument tokens. For example, "show interface 1 stats" becomes command "show" and arguments {"interface", "1", "stats"}.
    *   It then looks up the primary command token (e.g., "show") in its map of registered command handlers.
    *   If a handler is found, it's invoked with the vector of arguments.
4.  **Command Execution (`ManagementService` lambda):**
    *   The invoked lambda within `ManagementService` receives the arguments.
    *   It performs further parsing of these arguments to determine the specific sub-commands and parameters.
    *   It interacts with the appropriate manager components (`InterfaceManager`, `FdbManager`, etc.) to retrieve data (for `show` commands) or apply configurations (for configuration commands).
    *   It constructs a response string (output or error message).
5.  **Output Display:**
    *   The string returned by the handler is then printed to the user's console (e.g., `std::cout`).

**Example `main.cpp` Interaction Loop:**
```cpp
// Conceptual main.cpp
#include "netflow++/management_interface.hpp"
#include "netflow++/management_service.hpp"
// ... other necessary includes for managers ...
#include <iostream>
#include <string>
#include <vector>

int main() {
    // Initialization of managers (InterfaceManager, VlanManager, FdbManager, StpManager, LacpManager, RoutingManager)
    // For example:
    netflow::InterfaceManager im;
    netflow::VlanManager vm;
    netflow::ForwardingDatabase fdb;
    // StpManager constructor might need parameters like number of ports, switch MAC, priority
    // LacpManager constructor might need switch MAC, system priority
    // For simplicity, assume they are default constructible or have params provided:
    uint32_t num_ports = 32; // Example
    uint64_t switch_mac = 0x001122334455; // Example
    uint16_t default_stp_priority = 32768;
    uint16_t default_lacp_priority = 32768;

    netflow::StpManager stp(num_ports, switch_mac, default_stp_priority);
    netflow::LacpManager lacp(switch_mac, default_lacp_priority);
    netflow::RoutingManager rm(im); // Assuming RoutingManager needs InterfaceManager

    netflow::ManagementInterface mi;
    netflow::ManagementService ms(rm, im, mi, vm, fdb, stp, lacp); // Assuming LldpManager is added here if needed by ManagementService
    ms.register_cli_commands(); // ManagementService registers its commands with ManagementInterface

    std::string line;
    std::cout << "NetFlow++ CLI. Type 'help' for a list of commands.\n";
    while (true) {
        std::cout << "> ";
        if (!std::getline(std::cin, line)) {
            break; // EOF or error
        }
        if (line == "exit" || line == "quit") {
            break;
        }
        if (line.empty()) {
            continue;
        }

        std::string output = mi.handle_cli_command(line);
        std::cout << output << std::endl;
    }
    return 0;
}
```

### 9.2. Implemented CLI Commands

This section details the CLI commands available through the `ManagementService`.

#### 9.2.1. Global Commands

*   **`help`**
    *   **Syntax:** `help`
    *   **Description:** Displays a summary of available commands and their basic usage.
    *   **Example:**
        ```
        > help
        Available commands:
          show <feature> [options]        : Display system information.
        ... (etc.) ...
        ```

*   **`spanning-tree priority <priority>`**
    *   **Syntax:** `spanning-tree priority <0-61440>`
    *   **Description:** Sets the global bridge priority for Spanning Tree Protocol. The priority must be a multiple of 4096.
    *   **Example:**
        ```
        > spanning-tree priority 4096
        Spanning-tree bridge priority set to 4096.
        ```

*   **`lacp system-priority <priority>`**
    *   **Syntax:** `lacp system-priority <0-65535>`
    *   **Description:** Sets the global system priority for LACP.
    *   **Example:**
        ```
        > lacp system-priority 30000
        LACP system priority set to 30000.
        ```

#### 9.2.2. `show` Commands

The `show` command is used to display system information.

*   **`show interface [<interface_id>] [stats]`**
    *   **Syntax:**
        *   `show interface`
        *   `show interface <interface_id>`
        *   `show interface stats`
        *   `show interface <interface_id> stats`
    *   **Description:** Displays information about network interfaces.
        *   Without arguments, shows details for all interfaces.
        *   With `<interface_id>`, shows details for the specified interface.
        *   With `stats`, shows only statistics (for all or a specific interface).
    *   **Example:**
        ```
        > show interface 1
        Interface 1:
          Admin status: Up
          Link status: Up
          MTU: 1500
          ... (etc.) ...
        > show interface 1 stats
        Interface 1:
          Stats:
            RX Packets: 1024, Bytes: 123456
            ... (etc.) ...
        ```

*   **`show vlan [<vlan_id>]`**
    *   **Syntax:**
        *   `show vlan`
        *   `show vlan <vlan_id>`
    *   **Description:** Displays VLAN information and port membership.
        *   Without arguments, lists all configured VLANs and their member ports with roles (access, trunk native, trunk allowed).
        *   With `<vlan_id>`, shows port membership for the specified VLAN.
    *   **Example:**
        ```
        > show vlan 10
        VLAN 10:
          Interface 1 (trunk, allowed)
          Interface 2 (access)
        ```

*   **`show mac address-table [vlan <v_id>] [interface <p_id>] [mac <m_addr>] [type <static|dynamic>]`**
    *   **Syntax:** `show mac address-table [vlan <vlan_id>] [interface <interface_id>] [mac <mac_address>] [type <static|dynamic>]`
    *   **Description:** Displays MAC address table (FDB) entries. Output can be filtered by VLAN, interface, MAC address, or entry type.
    *   **Output Format:**
        ```
        VLAN  MAC Address        Type    Ports
        ----  -----------------  ------  -----
        10    00:11:22:33:44:55  Dynamic Gi0/1
        ```
    *   **Example:**
        ```
        > show mac address-table vlan 10 type static
        ```

*   **`show spanning-tree [interface <interface_id>] [detail]`**
    *   **Syntax:** `show spanning-tree [interface <interface_id>] [detail]`
    *   **Description:** Displays Spanning Tree Protocol (STP) status.
        *   Shows global bridge information (ID, Root ID, timers).
        *   Lists port information (Role, State, Cost, Priority).
        *   If `interface <interface_id>` is specified, shows information for that port only.
        *   The `detail` keyword provides more verbose output for each port.
    *   **Example:**
        ```
        > show spanning-tree
        Bridge Information:
          Bridge ID: 8000.001122334455
          ...
        Port Information:
        Interface   Role        State       Cost    Priority
        ------------------------------------------------------
        Gi0/1       ROOT        FORWARDING  19      128
        ...
        ```

*   **`show lacp [<lag_id>] [internal]`**
    *   **Syntax:** `show lacp [<lag_id>] [internal]`
    *   **Description:** Displays Link Aggregation Control Protocol (LACP) information.
        *   Without arguments, shows a summary of all LAGs.
        *   With `<lag_id>`, shows detailed configuration and status for the specified LAG, including member ports and active members.
        *   With `internal`, also shows detailed LACP protocol information for each member port (Actor/Partner system IDs, keys, states, state machine states).
    *   **Example:**
        ```
        > show lacp 1 internal
        LAG ID: 1
          Mode: Active
          Rate: Fast
          ...
          LACP Internal Port Details:
            Port   Pri  ActorSysID          AcKey AcState  PartnerSysID        PaKey PaState  RxState MuxState
            Gi0/1  128  ...                 100   ASCD--   ...                 200   ASCD--   CURRENT COLL_DIST
        ```

*   **`show etherchannel [<lag_id>] summary`**
    *   **Syntax:** `show etherchannel [<lag_id>] summary`
    *   **Description:** Displays a summary of Link Aggregation Groups (Port-channels). Functionally similar to `show lacp [<lag_id>]` but without the `internal` option.
    *   **Example:**
        ```
        > show etherchannel 1 summary
        LAG ID: 1
          Mode: Active
          Rate: Fast
          ...
        ```

#### 9.2.3. `clear` Commands

The `clear` command is used to reset statistics or dynamic table entries.

*   **`clear interface [<interface_id>] stats`**
    *   **Syntax:**
        *   `clear interface stats`
        *   `clear interface <interface_id> stats`
    *   **Description:** Clears interface statistics. For all interfaces or a specific one.
    *   **Example:**
        ```
        > clear interface 1 stats
        Statistics cleared for interface 1.
        ```

*   **`clear mac address-table dynamic [vlan <v_id>] [interface <p_id>] [mac <m_addr>]`**
    *   **Syntax:** `clear mac address-table dynamic [vlan <vlan_id>] [interface <interface_id>] [mac <mac_address>]`
    *   **Description:** Clears dynamic MAC address table entries. Can be filtered by VLAN, interface, or specific MAC address.
    *   **Example:**
        ```
        > clear mac address-table dynamic vlan 10
        Cleared 5 dynamic MAC address-table entries matching criteria: vlan 10.
        ```

#### 9.2.4. `interface <id>` Commands (Physical Interface Configuration)

These commands configure physical interfaces (e.g., `interface Gi0/1`).

*   **`shutdown` / `no shutdown`**
    *   **Syntax:**
        *   `interface <id> shutdown`
        *   `interface <id> no shutdown`
    *   **Description:** Administratively enables or disables the interface.
    *   **Example:**
        ```
        > interface Gi0/1 shutdown
        Interface Gi0/1 administratively set to down.
        ```

*   **`ip address <ip_address> <subnet_mask>` / `no ip address <ip_address> <subnet_mask>`**
    *   **Syntax:**
        *   `interface <id> ip address <ip_address> <subnet_mask>`
        *   `interface <id> no ip address <ip_address> <subnet_mask>`
    *   **Description:** Assigns or removes an IP address and subnet mask from the interface.
    *   **Example:**
        ```
        > interface Gi0/1 ip address 192.168.1.1 255.255.255.0
        IP address 192.168.1.1/255.255.255.0 added to interface Gi0/1.
        ```

*   **`mtu <value>`**
    *   **Syntax:** `interface <id> mtu <64-9216>`
    *   **Description:** Sets the Maximum Transmission Unit (MTU) for the interface.
    *   **Example:**
        ```
        > interface Gi0/1 mtu 9000
        MTU for interface Gi0/1 set to 9000.
        ```

*   **`speed <10|100|1000|auto>`**
    *   **Syntax:** `interface <id> speed <10|100|1000|auto>`
    *   **Description:** Configures the interface speed. Setting a specific speed disables auto-negotiation for speed.
    *   **Example:**
        ```
        > interface Gi0/1 speed 1000
        Speed for interface Gi0/1 configured to 1000.
        ```

*   **`duplex <half|full|auto>`**
    *   **Syntax:** `interface <id> duplex <half|full|auto>`
    *   **Description:** Configures the interface duplex mode. Setting a specific duplex disables auto-negotiation for duplex.
    *   **Example:**
        ```
        > interface Gi0/1 duplex full
        Duplex for interface Gi0/1 configured to full.
        ```

*   **VLAN (Switchport) Commands (within `interface <id>` context):**
    *   **`switchport mode <access|trunk>`**
        *   **Description:** Sets the VLAN mode of the interface.
        *   **Example:** `> interface Gi0/1 switchport mode trunk`
    *   **`switchport access vlan <vlan_id>`**
        *   **Description:** Assigns the interface to an access VLAN. Only effective if in access mode.
        *   **Example:** `> interface Gi0/1 switchport access vlan 100`
    *   **`switchport trunk native vlan <vlan_id>`**
        *   **Description:** Sets the native VLAN for a trunk interface.
        *   **Example:** `> interface Gi0/1 switchport trunk native vlan 1`
    *   **`switchport trunk allowed vlan <add|remove|all|none> [<vlan_list>]`**
        *   **Description:** Configures allowed VLANs on a trunk interface. `<vlan_list>` is comma-separated (e.g., "10,20,30-35").
        *   **Example:** `> interface Gi0/1 switchport trunk allowed vlan add 100,200`
    *   **`switchport trunk tag-native <enable|disable>`**
        *   **Description:** Enables or disables tagging of the native VLAN on trunk ports.
        *   **Example:** `> interface Gi0/1 switchport trunk tag-native enable`

*   **STP (Spanning Tree) Commands (within `interface <id>` context):**
    *   **`spanning-tree cost <value>`**
        *   **Description:** Sets the STP path cost for the interface (1-200,000,000).
        *   **Example:** `> interface Gi0/1 spanning-tree cost 100`
    *   **`spanning-tree port-priority <value>`**
        *   **Description:** Sets the STP port priority (0-240, multiple of 16).
        *   **Example:** `> interface Gi0/1 spanning-tree port-priority 112`

*   **LACP (Link Aggregation) Commands (within `interface <id>` context):**
    *   **`channel-group <lag_id> [mode <active|passive>]`**
        *   **Description:** Assigns the physical interface to a Link Aggregation Group (Port-channel). Optionally sets the LACP mode for the LAG. If the LAG doesn't exist, it's created.
        *   **Example:** `> interface Gi0/1 channel-group 1 mode active`
    *   **`lacp port-priority <value>`**
        *   **Description:** Sets the LACP port priority for the physical interface (0-65535).
        *   **Example:** `> interface Gi0/1 lacp port-priority 100`

#### 9.2.5. `interface port-channel <id>` Commands (LAG Configuration)

These commands configure logical Port-channel interfaces.

*   **`mode <active|passive>`**
    *   **Syntax:** `interface port-channel <id> mode <active|passive>`
    *   **Description:** Sets the LACP mode for the Port-channel interface (active or passive).
    *   **Example:**
        ```
        > interface port-channel 1 mode active
        Port-channel 1 mode set to active.
        ```

*   **`rate <fast|slow>`**
    *   **Syntax:** `interface port-channel <id> rate <fast|slow>`
    *   **Description:** Sets the LACP transmission rate for control packets (fast: 1s, slow: 30s).
    *   **Example:**
        ```
        > interface port-channel 1 rate fast
        Port-channel 1 rate set to fast.
        ```
    *   *(Note: Switchport commands like `switchport mode access/trunk` can also be applied to `interface port-channel <id>` to configure L2 properties of the LAG interface itself, e.g., making the LAG an access or trunk interface for VLANs.)*

#### 9.2.6. `mac address-table` Commands

*   **`mac address-table static <mac_address> vlan <vlan_id> interface <interface_id>`**
    *   **Syntax:** `mac address-table static <mac_address> vlan <vlan_id> interface <interface_id>`
    *   **Description:** Adds a static MAC address entry to the FDB.
    *   **Example:**
        ```
        > mac address-table static 00:de:ad:be:ef:00 vlan 10 interface Gi0/2
        Static MAC entry 00:de:ad:be:ef:00 for VLAN 10 on interface Gi0/2 added.
        ```

#### 9.2.7. `no` Commands

The `no` command is used to negate or remove configurations.

*   **`no mac address-table static <mac_address> vlan <vlan_id>`**
    *   **Syntax:** `no mac address-table static <mac_address> vlan <vlan_id>`
    *   **Description:** Removes a static MAC address entry from the FDB.
    *   **Example:**
        ```
        > no mac address-table static 00:de:ad:be:ef:00 vlan 10
        Static MAC entry 00:de:ad:be:ef:00 for VLAN 10 removed.
        ```
*   Other `no` commands typically mirror the configuration commands, e.g., `no interface <id> shutdown`.

#### 9.2.8. LLDP Commands

The Link Layer Discovery Protocol (LLDP) commands allow for the configuration and monitoring of LLDP on the switch.

*   **`show lldp neighbors [interface <interface_id>] [detail]`**
    *   **Syntax:** `show lldp neighbors [interface <interface_id>] [detail]`
    *   **Description:** Displays discovered LLDP neighbors.
        *   Without `interface <interface_id>`, shows a summary of all neighbors on all active ports.
        *   With `interface <interface_id>`, filters neighbors discovered on that specific port.
        *   The `detail` keyword provides a more verbose output for each neighbor, including all learned TLVs like System Description, Management Addresses, etc.
    *   **Example:**
        ```
        > show lldp neighbors
        Port ID  Chassis ID           Remote Port ID       Remote System Name   TTL
        Gi0/1    00:1a:2b:3c:4d:5e    Gi0/5                NeighborSwitch1      120
        Gi0/2    00:aa:bb:cc:dd:ee    Eth2                 ServerA              90

        > show lldp neighbors interface Gi0/1 detail
        Neighbor on port Gi0/1:
          Chassis ID Subtype: MAC address
          Chassis ID: 00:1a:2b:3c:4d:5e
          Port ID Subtype: Interface Name
          Port ID: Gi0/5
          TTL: 120s
          Time Remaining: 115s
          System Name: NeighborSwitch1
          System Description: Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE, RELEASE SOFTWARE (fc1)
          Management Address: 192.168.1.10
          ... (other TLVs) ...
        ```

*   **`show lldp interface [<interface_id>]`**
    *   **Syntax:** `show lldp interface [<interface_id>]`
    *   **Description:** Displays LLDP configuration and operational status for network interfaces.
        *   Without `<interface_id>`, shows information for all interfaces.
        *   With `<interface_id>`, shows information for the specified interface.
    *   **Output Format:** Port ID, Admin Status (Enabled/Disabled), Tx Interval, Tx Multiplier (TTL = Interval * Multiplier), Next Tx Time.
    *   **Example:**
        ```
        > show lldp interface Gi0/1
        Interface Gi0/1:
          LLDP Admin Status: Enabled
          Tx Interval: 30 seconds
          TTL Multiplier: 4 (TTL: 120 seconds)
          Next Tx scheduled in: 25 seconds
        ```

*   **`lldp enable`**
    *   **Syntax:** `lldp enable`
    *   **Description:** Globally enables LLDP on all interfaces. This applies the default LLDP configuration (or last configured per-interface settings if previously modified) and enables transmission and reception of LLDP frames.
    *   **Example:** `> lldp enable`

*   **`lldp disable`**
    *   **Syntax:** `lldp disable`
    *   **Description:** Globally disables LLDP on all interfaces. No LLDP frames will be sent, and received LLDP frames will be ignored.
    *   **Example:** `> lldp disable`

*   **`interface <id> lldp enable`**
    *   **Syntax:** `interface <id> lldp enable`
    *   **Description:** Enables LLDP on the specified interface.
    *   **Example:** `> interface Gi0/1 lldp enable`

*   **`interface <id> lldp disable`**
    *   **Syntax:** `interface <id> lldp disable`
    *   **Description:** Disables LLDP on the specified interface.
    *   **Example:** `> interface Gi0/1 lldp disable`

*   **`interface <id> lldp tx-interval <seconds>`**
    *   **Syntax:** `interface <id> lldp tx-interval <5-32768>`
    *   **Description:** Configures the transmission interval for LLDP frames on the specified interface. Default is 30 seconds.
    *   **Example:** `> interface Gi0/1 lldp tx-interval 15`

*   **`interface <id> lldp ttl-multiplier <value>`**
    *   **Syntax:** `interface <id> lldp ttl-multiplier <2-10>`
    *   **Description:** Configures the TTL multiplier. The actual TTL value advertised in LLDP frames is `tx-interval * ttl-multiplier`. Default is 4.
    *   **Example:** `> interface Gi0/1 lldp ttl-multiplier 5`
