# NetFlow++ Framework Requirements

## 1. Introduction

The NetFlow++ framework is designed as a high-performance, flexible, and extensible software suite for network packet processing and virtual switching. It aims to provide a foundational library for building custom network functions, virtual switches, and packet analysis tools that require efficient handling of network traffic, particularly in NUMA (Non-Uniform Memory Access) environments. The framework emphasizes zero-copy operations, detailed protocol parsing, and a comprehensive set of switching features.

## 2. Core Functional Requirements

### 2.1. Packet Buffer Management

*   **Zero-Copy Operations:** The framework must minimize or eliminate packet data copies during processing to enhance performance.
*   **NUMA Awareness:** Buffer allocation and management should be NUMA-aware to optimize memory access patterns on multi-socket systems.
*   **Configurable Sizes:** Packet buffer pools and individual buffer sizes must be configurable to suit different network MTUs and application needs.
*   **Reference Counting:** Implement efficient reference counting for shared packet instances to manage buffer lifecycle and prevent premature deallocation or leaks.
*   **Scatter-Gather I/O:** Support for handling fragmented packets through scatter-gather lists, allowing for efficient processing of jumbo frames or packets spread across multiple buffers.
*   **Huge Pages Support:** Optionally utilize huge pages for packet buffer memory to reduce TLB misses and improve memory access performance.
*   **Dynamic Allocation:** Ability to dynamically allocate and deallocate buffers as needed.
*   **Buffer Pooling:** Maintain pools of pre-allocated buffers per NUMA node to reduce allocation overhead.

### 2.2. Protocol Stack Parsing

*   **Supported Protocols:**
    *   Ethernet II (including MAC address parsing, EtherType)
    *   VLAN (IEEE 802.1Q, including single and double tagging if applicable)
    *   IPv4 (including header fields, options if necessary, checksum validation)
    *   IPv6 (including header fields, extension headers if necessary)
    *   TCP (including header fields, options, checksum validation)
    *   UDP (including header fields, checksum validation)
*   **Header Access:** Provide clear and efficient methods to access parsed protocol headers at each layer.
*   **Specific Field Extraction:**
    *   Source and Destination MAC addresses.
    *   VLAN ID and Priority Code Point (PCP).
    *   Source and Destination IPv4/IPv6 addresses.
    *   IP Protocol / IPv6 Next Header field.
    *   TCP/UDP Source and Destination Ports.
*   **Packet Manipulation:**
    *   Ability to set Source and Destination MAC addresses.
    *   Ability to push a new VLAN tag (or tags).
    *   Ability to pop an existing VLAN tag (or tags).
    *   Ability to update L3/L4 checksums after packet modification.
*   **Extensibility:** Allow for easy addition of new protocol parsers.

### 2.3. MAC Address Learning & Forwarding Database (FDB) Management

*   **Dynamic Learning:** Automatically learn source MAC addresses and associated VLANs on ingress ports.
*   **Static Entries:** Allow configuration of static MAC address entries that bypass dynamic learning and are not subject to aging.
*   **Port Lookup:** Provide efficient lookup of destination ports based on MAC address and VLAN ID.
*   **Aging:** Implement configurable aging for dynamic MAC entries, removing them if not seen within a specified timeout.
*   **Flushing:**
    *   Ability to flush all dynamic entries.
    *   Ability to flush entries by port.
    *   Ability to flush entries by VLAN.
    *   Ability to flush all entries (dynamic and static).
*   **Statistics:** Maintain and expose statistics such as total entry count, static vs. dynamic counts, and potentially load factor or capacity.
*   **VLAN-Awareness:** FDB lookups and learning must be VLAN-specific.

### 2.4. VLAN Processing

*   **Port Types:**
    *   **Access Port:** Assigns a default VLAN ID to untagged ingress packets; strips VLAN tags on egress for its assigned VLAN.
    *   **Trunk Port:** Allows tagged packets for multiple specified VLANs; forwards untagged packets to a native VLAN if configured.
    *   **Hybrid Port:** (Optional, if advanced configuration is needed) A combination of access and trunk behavior.
*   **Configuration:** Allow per-port configuration of VLAN membership, port type (access/trunk), native VLAN (for trunks), and default PVID (for access).
*   **Ingress Processing:**
    *   Handle tagged and untagged packets according to port configuration.
    *   Add VLAN tags for access ports.
    *   Filter packets based on VLAN membership for trunk ports.
*   **Egress Processing:**
    *   Strip VLAN tags for access ports if the packet's VLAN matches the PVID.
    *   Ensure correct tagging for trunk ports.
*   **Forwarding Logic:** Forwarding decisions must consider VLAN tags in conjunction with FDB lookups.

### 2.5. Spanning Tree Protocol (STP) Support

*   **Port States:** Implement and manage standard STP port states (Disabled, Blocking, Listening, Learning, Forwarding).
*   **Bridge Configuration:** Allow configuration of bridge priority and other STP parameters.
*   **BPDU Handling:**
    *   Generate and transmit BPDUs based on STP state and configuration.
    *   Process received BPDUs to participate in STP topology calculation (Root Bridge election, Root Path Cost, Port Roles).
*   **Forwarding Rules:** Packet forwarding on ports must adhere to their current STP state (e.g., no forwarding in Blocking/Listening states).
*   **Compatibility:** Aim for compatibility with IEEE 802.1D STP, with optional considerations for RSTP/MSTP if specified as an extension.

## 3. Performance-Critical Feature Requirements

### 3.1. Fast Packet Classification

*   **Flow Key Extraction:** Ability to define and extract custom flow keys from packet headers (e.g., 5-tuple: Src/Dst IP, Src/Dst Port, Protocol).
*   **Hashing:** Efficient hashing mechanisms for extracted flow keys.
*   **Rule-Based Classification:** Support for classification based on predefined rules matching packet header fields.
*   **Programmability:** Allow dynamic addition/removal of classification rules.

### 3.2. High-Performance Hash Tables

*   **Lock-Free Operations:** Prioritize lock-free or minimal-locking hash table designs for concurrent insertion, lookup, and removal of entries (e.g., for flow tables, FDB).
*   **Batch Operations:** Support for batch processing of lookups/insertions/deletions to amortize overhead.
*   **Collision Resolution:** Implement efficient collision resolution strategies.
*   **Statistics:** Expose hash table statistics (e.g., entry count, collisions, load factor).

### 3.3. Port and Interface Management

*   **Configuration:**
    *   Administrative state (up/down).
    *   Speed and duplex settings.
    *   MTU (Maximum Transmission Unit).
*   **Statistics Retrieval:** Provide counters for received/transmitted packets/bytes, errors, discards per interface.
*   **Link State Monitoring:** Ability to detect and report changes in physical link state.

## 4. Advanced Switch Feature Requirements

### 4.1. Quality of Service (QoS)

*   **Scheduler Types:** Support for different scheduling disciplines (e.g., Strict Priority, Weighted Fair Queuing).
*   **Queue Configuration:** Allow configuration of multiple egress queues per port, with parameters for weight, priority, and buffer size.
*   **Rate Limiting:** Per-port or per-queue ingress/egress rate limiting.
*   **Packet Classification for QoS:** Classify packets based on header fields (e.g., DSCP, PCP, 5-tuple) to map them to appropriate internal traffic classes and queues.
*   **Enqueueing:** Mechanism to enqueue packets into appropriate QoS queues based on classification.
*   **Traffic Shaping:** Control egress traffic flow to meet desired bandwidth profiles.

### 4.2. Access Control Lists (ACLs)

*   **Rule Structure:** Define ACL rules with match fields (e.g., MAC addresses, IP addresses, L4 ports, VLAN ID) and actions (e.g., permit, deny, log, redirect).
*   **Adding/Removing Rules:** Allow dynamic management of ACL rules.
*   **Evaluation Logic:** Efficiently evaluate packets against configured ACL rules, respecting rule priority/order.
*   **Rule Compilation/Optimization:** (Optional) Consider mechanisms for optimizing ACL rule sets for faster lookups (e.g., TCAM-like software implementations).

### 4.3. LACP (Link Aggregation Control Protocol - IEEE 802.3ad)

*   **LAG Configuration:** Allow creation of Link Aggregation Groups (LAGs) and assignment of physical ports to LAGs.
*   **Port Membership:** Manage active/standby status of ports within a LAG.
*   **Hash Modes:** Support configurable hash modes (e.g., based on L2, L2+L3, L3+L4 headers) for distributing traffic across LAG member ports.
*   **LACPDU Processing:** Implement LACPDU generation, transmission, and reception for negotiating and maintaining LAGs with connected peers.
*   **Egress Port Selection:** Logic to select an appropriate physical member port for egress traffic based on the configured hash mode.

## 5. System Integration Feature Requirements

### 5.1. Configuration Management

*   **Loading/Saving:** Ability to load switch configuration from and save to a file (e.g., JSON or YAML format).
*   **Runtime Parameter Get/Set:** Provide an API or mechanism for getting and setting configuration parameters at runtime.
*   **Validation:** Implement validation for configuration parameters to ensure consistency and correctness.

### 5.2. Logging and Diagnostics

*   **Log Levels:** Support for configurable log levels (e.g., DEBUG, INFO, WARNING, ERROR).
*   **Component-Specific Logging:** Allow enabling/disabling or setting different log levels for individual framework components.
*   **Packet Event Logging:** (Optional) Ability to log specific packet events or trace packet paths for debugging.
*   **Performance Stats Logging:** Periodically log key performance indicators and statistics.

### 5.3. Management Interface

*   **SNMP-like OID Handling:** (Conceptual) Internal structure that allows mapping of internal states and statistics to OID-like identifiers for easy exposure via management protocols.
*   **REST API Endpoints:** (Conceptual) Define a structure that facilitates wrapping core functionalities with REST API endpoints for external management.
*   **CLI Command Registration:** Provide a mechanism for switch components to register CLI commands for interactive management and diagnostics.

## 6. Non-Functional Requirements

### 6.1. Performance Targets

*   **Throughput:** Target multi-million packets per second (MPPS) per CPU core for L2 forwarding.
*   **Latency:** Aim for low packet processing latency, typically in the order of microseconds for core forwarding paths.
*   **Scalability:** Design to scale efficiently with the number of CPU cores.
*   **Memory Usage:** Optimize for efficient memory usage, especially for per-packet metadata and forwarding tables.

### 6.2. Optimization Features

*   **CPU Affinity:** Allow pinning of processing threads to specific CPU cores.
*   **Huge Pages:** Support for using huge pages for critical data structures and packet buffers.
*   **Prefetching:** Utilize software prefetching where beneficial to hide memory latency.
*   **Batch Processing:** Process packets in batches whenever possible to improve throughput and cache utilization.
*   **Performance Monitoring:** Integrate hooks or mechanisms for monitoring internal performance counters and identifying bottlenecks.

## 7. Implementation Guideline Requirements

### 7.1. Architecture

*   **Header-Only Core:** Where feasible, core data structures and algorithms may be header-only for flexibility, but compiled libraries for stable ABI are also expected for larger components.
*   **Template Usage:** Employ C++ templates judiciously for generic programming without sacrificing performance or clarity.
*   **NUMA-Awareness:** Design data structures and processing pipelines to be NUMA-aware.
*   **Lock-Free Data Structures:** Utilize lock-free data structures for performance-critical shared resources.
*   **Cache-Friendly Layouts:** Design data structures with consideration for CPU cache line alignment and access patterns.

### 7.2. Platform Support

*   **Primary Platform:** Linux (specific kernel versions may be targeted for advanced features).
*   **Kernel Bypass Options:** Design with eventual integration with kernel bypass technologies (e.g., DPDK, XDP) in mind.
*   **Socket Fallback:** Provide a standard socket-based I/O mechanism as a fallback or for development/testing.
*   **Architectures:** Primarily target ARM64 and x86_64 architectures.

### 7.3. Build System

*   **CMake:** Utilize CMake as the primary build system.
*   **Optional Dependencies:** Clearly define and manage optional dependencies for features like kernel bypass libraries.
*   **Benchmarking Suite:** Include a suite of benchmarks for performance testing of critical components.

### 7.4. Testing Strategy

*   **Comprehensive Unit Tests:** Each module and class should have thorough unit tests (e.g., using GTest).
*   **Integration Tests:** Tests to verify interactions between different components.
*   **Performance Tests:** Dedicated tests to measure throughput, latency, and scalability.
*   **Code Coverage:** Aim for high code coverage.
*   **Continuous Integration:** Setup CI pipelines for automated building and testing.
