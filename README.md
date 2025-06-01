# C++ Network Packet Processing Framework (NetFlow++)

## Project Overview
A high-performance, zero-copy C++ framework specifically designed for Layer 2/3 network switch software development. This library provides optimized packet parsing, manipulation, and forwarding capabilities with DPDK-style performance but simpler integration for traditional switch software stacks.

## Core Requirements

### 1. Packet Buffer Management
- Zero-copy packet buffer pools with NUMA awareness
- Configurable buffer sizes (64B to 9KB+ for jumbo frames)
- Reference counting for shared packet instances
- Scatter-gather I/O support for fragmented packets
- Memory-mapped buffer allocation with huge pages

### 2. Protocol Stack Parsing
```cpp
// Fast packet parsing with template-based header access
class Packet {
public:
    template<typename HeaderType>
    HeaderType* get_header() const;
    
    EthernetHeader* ethernet() const;
    VlanHeader* vlan() const;
    IPv4Header* ipv4() const;
    IPv6Header* ipv6() const;
    TcpHeader* tcp() const;
    UdpHeader* udp() const;
    
    // Layer 2 specific
    bool has_vlan() const;
    uint16_t vlan_id() const;
    uint8_t vlan_priority() const;
    MacAddress src_mac() const;
    MacAddress dst_mac() const;
    
    // Packet manipulation
    void set_dst_mac(const MacAddress& mac);
    void push_vlan(uint16_t vlan_id, uint8_t priority = 0);
    void pop_vlan();
    void update_checksums();
};
```

### 3. MAC Address Learning & FDB Management
```cpp
class ForwardingDatabase {
public:
    struct FdbEntry {
        MacAddress mac;
        uint32_t port;
        uint16_t vlan_id;
        std::chrono::steady_clock::time_point timestamp;
        bool is_static;
    };
    
    bool learn_mac(const MacAddress& mac, uint32_t port, uint16_t vlan_id);
    std::optional<uint32_t> lookup_port(const MacAddress& mac, uint16_t vlan_id);
    void age_entries(std::chrono::seconds max_age = std::chrono::seconds(300));
    void flush_port(uint32_t port);
    void flush_vlan(uint16_t vlan_id);
    
    // Statistics
    size_t entry_count() const;
    size_t capacity() const;
    double load_factor() const;
};
```

### 4. VLAN Processing
```cpp
class VlanManager {
public:
    enum class PortType { ACCESS, TRUNK, HYBRID };
    
    struct PortConfig {
        PortType type;
        uint16_t native_vlan;
        std::set<uint16_t> allowed_vlans;
        bool tag_native;
    };
    
    void configure_port(uint32_t port, const PortConfig& config);
    bool should_forward(uint32_t ingress_port, uint32_t egress_port, uint16_t vlan_id);
    PacketAction process_ingress(const Packet& pkt, uint32_t port);
    void process_egress(Packet& pkt, uint32_t port);
};
```

### 5. Spanning Tree Protocol Support
```cpp
class StpManager {
public:
    enum class PortState { DISABLED, BLOCKING, LISTENING, LEARNING, FORWARDING };
    
    struct BridgeConfig {
        uint64_t bridge_id;
        uint32_t hello_time;
        uint32_t forward_delay;
        uint32_t max_age;
    };
    
    void set_bridge_config(const BridgeConfig& config);
    void set_port_state(uint32_t port, PortState state);
    PortState get_port_state(uint32_t port) const;
    bool should_forward(uint32_t port) const;
    
    // BPDU handling
    void process_bpdu(const Packet& bpdu, uint32_t port);
    std::vector<Packet> generate_bpdus();
};
```

## Performance-Critical Features

### 1. Fast Packet Classification
```cpp
class PacketClassifier {
public:
    struct FlowKey {
        MacAddress src_mac;
        MacAddress dst_mac;
        uint16_t vlan_id;
        uint16_t ethertype;
        // IPv4/IPv6 fields when applicable
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t protocol;
        uint16_t src_port;
        uint16_t dst_port;
    };
    
    FlowKey extract_flow_key(const Packet& pkt);
    uint32_t hash_flow(const FlowKey& key) const;
    
    // Rule-based classification
    uint32_t classify(const Packet& pkt) const;
    void add_rule(const ClassificationRule& rule);
};
```

### 2. High-Performance Hash Tables
```cpp
template<typename Key, typename Value>
class LockFreeHashTable {
public:
    explicit LockFreeHashTable(size_t initial_capacity);
    
    bool insert(const Key& key, const Value& value);
    std::optional<Value> lookup(const Key& key) const;
    bool remove(const Key& key);
    
    // Batch operations for better cache efficiency
    void batch_lookup(const std::vector<Key>& keys, 
                     std::vector<std::optional<Value>>& results) const;
    
    // Statistics
    size_t size() const;
    double load_factor() const;
    void get_stats(HashTableStats& stats) const;
};
```

### 3. Port and Interface Management
```cpp
class InterfaceManager {
public:
    struct PortStats {
        uint64_t rx_packets;
        uint64_t tx_packets;
        uint64_t rx_bytes;
        uint64_t tx_bytes;
        uint64_t rx_errors;
        uint64_t tx_errors;
        uint64_t rx_drops;
        uint64_t tx_drops;
    };
    
    struct PortConfig {
        bool admin_up;
        uint32_t speed_mbps;  // 10, 100, 1000, 10000, etc.
        bool full_duplex;
        bool auto_negotiation;
        uint32_t mtu;
    };
    
    void configure_port(uint32_t port, const PortConfig& config);
    PortStats get_port_stats(uint32_t port) const;
    void clear_port_stats(uint32_t port);
    bool is_port_up(uint32_t port) const;
    
    // Link state change callbacks
    void on_link_up(std::function<void(uint32_t)> callback);
    void on_link_down(std::function<void(uint32_t)> callback);
};
```

## Advanced Switch Features

### 1. Quality of Service (QoS)
The `QosManager` is implemented to provide port-based Quality of Service. It supports configuration of multiple queues per port, various scheduling strategies like Strict Priority and basic Weighted Round Robin (with a simple round-robin fallback for now), and configurable maximum queue depths. Packet classification, for instance based on VLAN Priority Code Point (PCP), directs packets to appropriate queues. The manager handles enqueueing packets based on classification and dequeueing them based on the configured scheduling policy. CLI commands are available for configuring QoS parameters and monitoring queue statistics.

```cpp
class QosManager {
public:
    enum class SchedulerType { STRICT_PRIORITY, WEIGHTED_ROUND_ROBIN, DEFICIT_ROUND_ROBIN };
    
    struct QosConfig {
        uint8_t num_queues;
        SchedulerType scheduler;
        std::vector<uint32_t> queue_weights;
        std::vector<uint32_t> rate_limits_kbps;
        // uint32_t max_queue_depth; // Added in implementation
    };
    
    void configure_port_qos(uint32_t port, const QosConfig& config);
    // uint8_t classify_packet(const Packet& pkt, uint32_t port); // Now internal
    // void enqueue_packet(const Packet& pkt, uint32_t port, uint8_t queue); // Signature changed
    void enqueue_packet(const Packet& pkt, uint32_t port);
    std::optional<Packet> select_packet_to_dequeue(uint32_t port_id); // New dequeue method
    
    // Traffic shaping
    bool should_transmit(uint32_t port, uint8_t queue);
    void update_token_buckets();
};
```

### 2. Access Control Lists (ACL)
The `AclManager` has been implemented to support rule-based packet filtering. It allows for the creation and management of Access Control Lists (ACLs) where rules are processed based on priority. Rules can match on various L2, L3, and L4 packet header fields, including source/destination MAC and IP addresses, VLAN ID, EtherType, IP protocol, and L4 ports. Supported actions for matching packets include PERMIT, DENY, and REDIRECT to a specified port. A `compile_rules` method is provided to sort rules by priority for efficient evaluation. CLI commands are available for adding, removing, viewing, and compiling ACL rules.

```cpp
class AclManager {
public:
    enum class ActionType { PERMIT, DENY, REDIRECT };
    
    struct AclRule {
        uint32_t rule_id;
        int priority; // Changed from uint32_t to int in implementation, higher value = higher prio
        
        // Match fields (optional)
        std::optional<MacAddress> src_mac;
        std::optional<MacAddress> dst_mac;
        std::optional<uint16_t> vlan_id;
        std::optional<uint16_t> ethertype;
        std::optional<uint32_t> src_ip; // Changed from IpAddress to uint32_t in implementation
        std::optional<uint32_t> dst_ip; // Changed from IpAddress to uint32_t in implementation
        std::optional<uint8_t> protocol;
        std::optional<uint16_t> src_port;
        std::optional<uint16_t> dst_port;
        
        ActionType action;
        std::optional<uint32_t> redirect_port_id; // Renamed from redirect_port
    };
    
    void add_rule(const AclRule& rule);
    void remove_rule(uint32_t rule_id);
    // AclActionType evaluate(const Packet& pkt, uint32_t& redirect_port); // Signature changed
    AclActionType evaluate(const Packet& pkt, uint32_t& out_redirect_port_id) const;

    
    // Performance optimization
    void compile_rules(); // Convert to optimized lookup structure
};
```

### 3. LACP (Link Aggregation)
```cpp
class LacpManager {
public:
    struct LagConfig {
        uint32_t lag_id;
        std::vector<uint32_t> member_ports;
        HashMode hash_mode;
        bool active_mode;
    };
    
    void create_lag(const LagConfig& config);
    void add_port_to_lag(uint32_t lag_id, uint32_t port);
    void remove_port_from_lag(uint32_t lag_id, uint32_t port);
    
    uint32_t select_egress_port(uint32_t lag_id, const Packet& pkt);
    void process_lacpdu(const Packet& lacpdu, uint32_t port);
    
    bool is_port_in_lag(uint32_t port) const;
    uint32_t get_lag_for_port(uint32_t port) const;
};
```

### 4. LLDP (Link Layer Discovery Protocol)
The `LldpManager` class handles the Link Layer Discovery Protocol (LLDP, IEEE 802.1AB), allowing devices to advertise their identity and capabilities to neighbors and learn about adjacent devices.

Key functionalities:
*   Periodic transmission of LLDPDUs.
*   Reception and parsing of LLDPDUs from neighbors.
*   Construction and parsing of standard LLDP TLVs (Chassis ID, Port ID, TTL, System Name, System Description).
*   Storage and aging of neighbor information.
*   Per-port configuration (enable/disable, tx_interval, ttl_multiplier).

```cpp
class LldpManager {
public:
    // Constructor
    explicit LldpManager(Switch& owner_switch, InterfaceManager& if_mgr);

    // Configures LLDP behavior for a specific port
    void configure_port(uint32_t port_id, bool enabled,
                        uint32_t tx_interval = 30,
                        uint32_t ttl_multiplier = 4);

    // Retrieves LLDP neighbors discovered on a specific port
    std::vector<LldpNeighborInfo> get_neighbors(uint32_t port_id) const;

    // ... other methods ...
};

// Example Usage (conceptual):
// Switch sw; /* ... initialize switch ... */
// InterfaceManager if_mgr; /* ... initialize interface manager ... */
// LldpManager lldp_mgr(sw, if_mgr);
//
// lldp_mgr.configure_port(1, true, 15, 4); // Enable LLDP on port 1, tx_interval 15s, TTL 60s
// std::vector<LldpNeighborInfo> neighbors_on_port1 = lldp_mgr.get_neighbors(1);
```

### 5. Layer 3 Routing
The framework supports Layer 3 routing capabilities, enabling the switch to forward IP packets between different subnets.

**`RoutingManager`:**
The `RoutingManager` handles the IP routing table, enabling static route configuration and longest prefix match lookups for packet forwarding decisions.
```cpp
class RoutingManager {
public:
    RoutingManager();
    void add_static_route(const IpAddress& destination_network,
                          const IpAddress& subnet_mask,
                          const IpAddress& next_hop_ip,
                          uint32_t egress_interface_id,
                          int metric = 1);
    void remove_static_route(const IpAddress& destination_network,
                             const IpAddress& subnet_mask);
    std::optional<RouteEntry> lookup_route(const IpAddress& destination_ip) const;
    std::vector<RouteEntry> get_routing_table() const;
};

// Example Usage (conceptual):
// RoutingManager rm;
// IpAddress network_addr("192.168.2.0");
// IpAddress subnet_mask("255.255.255.0");
// IpAddress next_hop("10.0.0.2");
// uint32_t egress_if_id = 3; // Example interface ID
// rm.add_static_route(network_addr, subnet_mask, next_hop, egress_if_id);
// auto route_info = rm.lookup_route(IpAddress("192.168.2.10"));
```

**`ArpProcessor`:**
The `ArpProcessor` manages the Address Resolution Protocol (ARP), resolving IP addresses to MAC addresses for directly connected networks and handling ARP requests/replies.

**`IcmpProcessor`:**
The `IcmpProcessor` handles Internet Control Message Protocol (ICMP) messages, such as responding to ICMP Echo Requests (pings) destined for the switch's interfaces and generating ICMP error messages (e.g., Destination Unreachable, Time Exceeded).

**IP Interface Configuration:**
Layer 3 functionality requires IP addresses to be configured on switch interfaces (physical ports or VLAN interfaces) using the `InterfaceManager`.
```cpp
// Conceptual example from InterfaceManager for IP configuration:
// class InterfaceManager {
// public:
//    // ... other methods ...
//    void add_ip_address(uint32_t port_id,
//                        const IpAddress& ip_address,
//                        const IpAddress& subnet_mask);
//    void remove_ip_address(uint32_t port_id,
//                           const IpAddress& ip_address,
//                           const IpAddress& subnet_mask);
// };
//
// InterfaceManager if_mgr; /* ... */
// if_mgr.add_ip_address(1, IpAddress("192.168.1.1"), IpAddress("255.255.255.0"));
```

## System Integration Features

### 1. Configuration Management
```cpp
class ConfigManager {
public:
    // JSON/YAML configuration support
    void load_config(const std::string& filename);
    void save_config(const std::string& filename);
    void apply_config(const Configuration& config);
    
    // Runtime configuration
    void set_parameter(const std::string& path, const ConfigValue& value);
    ConfigValue get_parameter(const std::string& path) const;
    
    // Configuration validation
    std::vector<std::string> validate_config(const Configuration& config);
};
```

### 2. Logging and Diagnostics
```cpp
class SwitchLogger {
public:
    enum class LogLevel { DEBUG, INFO, WARNING, ERROR, CRITICAL };
    
    void log(LogLevel level, const std::string& component, 
             const std::string& message);
    
    // Packet-specific logging
    void log_packet_drop(const Packet& pkt, uint32_t port, 
                        const std::string& reason);
    void log_mac_learning(const MacAddress& mac, uint32_t port, 
                         uint16_t vlan_id);
    void log_stp_event(uint32_t port, const std::string& event);
    
    // Performance logging
    void log_performance_stats(const PerformanceCounters& counters);
};
```

### 3. Management Interface
```cpp
class ManagementInterface {
public:
    // SNMP-like interface
    void register_oid_handler(const std::string& oid, 
                             std::function<std::string()> getter,
                             std::function<void(const std::string&)> setter);
    
    // REST API support
    void register_rest_endpoint(const std::string& path,
                               HttpMethod method,
                               std::function<HttpResponse(const HttpRequest&)> handler);
    
    // CLI command registration
    void register_command(const std::string& command,
                         std::function<std::string(const std::vector<std::string>&)> handler);
};
```

## Performance Requirements

### 1. Throughput Targets
- Handle 10+ million packets per second on modern hardware
- Sub-microsecond packet processing latency
- Linear scaling with number of CPU cores
- Memory usage under 1GB for typical configurations

### 2. Optimization Features
```cpp
class PerformanceOptimizer {
public:
    // CPU affinity management
    void bind_thread_to_core(std::thread::id tid, int core);
    void set_rx_queue_affinity(uint32_t port, uint32_t queue, int core);
    
    // Memory optimization
    void configure_huge_pages(size_t page_size);
    void prefetch_packet_data(const Packet& pkt);
    
    // Batch processing
    void process_packet_batch(const std::vector<Packet>& packets);
    
    // Performance monitoring
    PerformanceCounters get_counters() const;
    void reset_counters();
};
```

## Implementation Guidelines

### 1. Architecture Requirements
- Header-only core with optional compiled extensions
- Template-heavy design for compile-time optimization
- NUMA-aware memory allocation
- Lock-free data structures where possible
- Cache-friendly data layouts

### 2. Platform Support
- Linux primary target (DPDK integration optional)
- Support for kernel bypass (UIO/VFIO)
- Standard socket fallback mode
- ARM64 and x86_64 architecture support

### 3. Build System
- CMake with find_package support
- Optional dependencies (DPDK, huge pages, etc.)
- Extensive benchmarking suite
- Integration with common switch SDKs

### 4. Testing Strategy
- Unit tests for all components
- Performance regression tests
- Hardware-in-the-loop testing
- Stress testing with synthetic traffic
- Interoperability testing with real switches

## Usage Example
```cpp
#include <netflow++/switch.hpp>

int main() {
    using namespace netflow;
    
    // Initialize switch with 48 ports
    Switch sw(48);
    
    // Configure VLANs
    sw.vlan_manager().create_vlan(100, "Development");
    sw.vlan_manager().configure_port(1, {PortType::ACCESS, 100});
    
    // Set up packet processing pipeline
    sw.set_packet_handler([&](const Packet& pkt, uint32_t ingress_port) {
        // Learn MAC address
        sw.fdb().learn_mac(pkt.src_mac(), ingress_port, pkt.vlan_id());
        
        // Forward packet
        if (auto egress_port = sw.fdb().lookup_port(pkt.dst_mac(), pkt.vlan_id())) {
            sw.forward_packet(pkt, *egress_port);
        } else {
            sw.flood_packet(pkt, ingress_port);
        }
    });
    
    // Start processing
    sw.start();
    
    return 0;
}
```
