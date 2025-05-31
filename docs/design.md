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

### 5.2. `LacpManager`

*   **LAG Membership:** Manages the configuration of Link Aggregation Groups, including which physical ports are members of which LAG.
*   **LACPDU Handling:**
    *   Sends LACPDU packets containing Actor and Partner information (system ID, port priority, operational key, state flags).
    *   Processes received LACPDUs to synchronize state with link partners, select active member ports based on port priorities and consistent configurations.
*   **Egress Port Selection:** Implements a hash function (based on configured L2/L3/L4 criteria) to select a physical member port for egress traffic destined for a LAG, ensuring load distribution.

### 5.3. `QosManager` (Conceptual)

*   **Queue Structures:** Per-port, multiple queues (e.g., 8 queues). Each queue might have its own buffer limits.
*   **Scheduler:** Implements scheduling algorithms like Strict Priority (higher priority queues always serviced first) and Weighted Round Robin (WRR) or Deficit Round Robin (DRR) for distributing bandwidth among queues of the same priority level.
*   **Rate Limiting:** Token bucket mechanisms per queue or per port for enforcing bandwidth limits.
*   **Classification:** Relies on `PacketClassifier` output (or a dedicated QoS classifier) to map incoming packets to specific QoS queues based on DSCP, PCP, or flow information.

### 5.4. `AclManager` (Conceptual)

*   **Rule Storage:** Stores ACL rules, each specifying match criteria (e.g., source/destination IP, MAC, L4 port, protocol) and an action (permit/deny). Rules typically have priorities.
*   **Evaluation Engine:** For each packet, iterates through applicable ACLs. The first matching rule (based on priority) determines the action.
*   **Optimization:** For performance, especially with many rules, ACLs might be compiled into a more efficient data structure (e.g., a decision tree, tuple space search, or a software TCAM emulation) rather than simple linear matching.

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
*   **CLI Dispatch:** For a CLI, it would parse commands and dispatch them to registered command handlers in the respective components.

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
