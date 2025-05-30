#include "netflow++/switch.hpp"
#include <iostream>
#include <vector>

// Example packet handler function (optional)
void handle_cpu_packet(netflow::Packet& pkt, uint32_t ingress_port) {
    std::cout << "[CPU Handler] Received packet on port " << ingress_port
              << " (size: " << pkt.get_buffer()->size << " bytes)." << std::endl;
    // Potentially inspect the packet further
    // netflow::EthernetHeader* eth = pkt.ethernet();
    // if (eth) {
    //     std::cout << "  EthType: 0x" << std::hex << ntohs(eth->ethertype) << std::dec << std::endl;
    // }
}

int main(int argc, char* argv[]) {
    std::cout << "Netflow++ Software Switch Simulation" << std::endl;

    // Create a switch with a specific number of ports
    uint32_t num_ports = 8; // Example: 8 ports
    netflow::Switch sw(num_ports);

    // Configure packet handler (optional)
    sw.set_packet_handler(handle_cpu_packet);

    // --- Example Configuration ---

    // 1. Bridge Configuration (STP)
    netflow::StpManager::BridgeConfig bridge_cfg;
    bridge_cfg.bridge_id = 0x8000000000000001ULL; // Example bridge ID (priority + MAC)
    sw.stp_manager.set_bridge_config(bridge_cfg);
    std::cout << "STP Bridge ID set to: 0x" << std::hex << sw.stp_manager.get_bridge_config().bridge_id << std::dec << std::endl;

    // 2. Port Configuration (VLANs)
    netflow::VlanManager::PortConfig access_port_cfg;
    access_port_cfg.type = netflow::PortType::ACCESS;
    access_port_cfg.native_vlan = 10; // VLAN 10 for port 0
    sw.vlan_manager.configure_port(0, access_port_cfg);
    std::cout << "Port 0 configured as ACCESS, Native VLAN 10." << std::endl;

    netflow::VlanManager::PortConfig trunk_port_cfg;
    trunk_port_cfg.type = netflow::PortType::TRUNK;
    trunk_port_cfg.native_vlan = 1; // Native VLAN 1 for port 1
    trunk_port_cfg.allowed_vlans = {1, 10, 20}; // Allowed VLANs on trunk
    trunk_port_cfg.tag_native = false; // Do not tag native VLAN 1 on egress
    sw.vlan_manager.configure_port(1, trunk_port_cfg);
    std::cout << "Port 1 configured as TRUNK, Native VLAN 1, Allowed: 1,10,20." << std::endl;

    // Configure other ports as simple access ports in VLAN 1 for testing
    netflow::VlanManager::PortConfig default_access_config;
    default_access_config.type = netflow::PortType::ACCESS;
    default_access_config.native_vlan = 1;
    for(uint32_t i = 2; i < num_ports; ++i) {
        sw.vlan_manager.configure_port(i, default_access_config);
        sw.stp_manager.set_port_state(i, netflow::StpManager::PortState::FORWARDING); // Assume STP converged
    }
    sw.stp_manager.set_port_state(0, netflow::StpManager::PortState::FORWARDING);
    sw.stp_manager.set_port_state(1, netflow::StpManager::PortState::FORWARDING);


    // --- Start the switch ---
    sw.start(); // Calls the placeholder start method

    // --- Interface Manager Example Usage ---
    std::cout << "\n--- Interface Manager Examples ---" << std::endl;
    netflow::InterfaceManager::PortConfig port1_config;
    port1_config.admin_up = true;
    port1_config.speed_mbps = 10000; // 10 Gbps
    port1_config.mtu = 9000;        // Jumbo frame
    sw.interface_manager_.configure_port(1, port1_config);
    std::cout << "Port 1 configured: admin_up=" << std::boolalpha << port1_config.admin_up
              << ", speed=" << port1_config.speed_mbps << " Mbps, MTU=" << port1_config.mtu << std::endl;

    sw.interface_manager_.on_link_up([](uint32_t port_id){
        std::cout << "[Callback] Port " << port_id << " link is UP." << std::endl;
    });
    sw.interface_manager_.on_link_down([](uint32_t port_id){
        std::cout << "[Callback] Port " << port_id << " link is DOWN." << std::endl;
    });

    sw.interface_manager_.simulate_port_link_down(1); // Should call link_down_callbacks
    sw.interface_manager_.simulate_port_link_up(1);   // Should call link_up_callbacks
    std::cout << "Port 1 link status (simulated): " << std::boolalpha
              << sw.interface_manager_.is_port_link_up(1) << std::endl;


    // --- Packet Classifier and Flow Table Example Usage ---
    std::cout << "\n--- Packet Classifier & Flow Table Examples ---" << std::endl;
    netflow::PacketClassifier::FlowKey rule_key_template;
    rule_key_template.src_ip = ntohl(0xC0A80101); // 192.168.1.1
    rule_key_template.dst_ip = ntohl(0xC0A8010A); // 192.168.1.10
    rule_key_template.protocol = 6; // TCP
    rule_key_template.dst_port = ntohs(80); // Port 80 (HTTP)

    netflow::PacketClassifier::FlowKey rule_mask; // Mask for specific fields
    // For IP and port matching, typically use all 1s in mask for fields to match
    rule_mask.src_ip = 0xFFFFFFFF;
    rule_mask.dst_ip = 0xFFFFFFFF;
    rule_mask.protocol = 0xFF;
    rule_mask.dst_port = 0xFFFF;
    // Other fields in mask are 0 (wildcard) by default in FlowKey constructor

    uint32_t rule_action_id = 1001; // Custom action ID for this rule
    netflow::PacketClassifier::ClassificationRule http_rule(rule_key_template, rule_mask, rule_action_id, 100); // Priority 100
    sw.packet_classifier_.add_rule(http_rule);
    std::cout << "Added HTTP classification rule for 192.168.1.1 -> 192.168.1.10:80, action_id=" << rule_action_id << std::endl;

    // Example FlowKey for table insertion (can be extracted from a packet or created manually)
    netflow::Switch::FlowKey flow_key_example = rule_key_template; // Use the same key for simplicity
    uint32_t flow_action_id = 2002;
    if (sw.flow_table_.insert(flow_key_example, flow_action_id)) {
        std::cout << "Inserted flow into FlowTable. Key (src_ip=" << std::hex << flow_key_example.src_ip
                  << ", dst_port=" << std::dec << ntohs(flow_key_example.dst_port) // Display in host order for readability
                  << "), action_id=" << flow_action_id << std::endl;
    }
    auto looked_up_action = sw.flow_table_.lookup(flow_key_example);
    if (looked_up_action) {
        std::cout << "Lookup in FlowTable successful. Action ID: " << *looked_up_action << std::endl;
    }


    // --- Simulate Packet Processing (Example) ---
    std::cout << "\n--- Simulating Packet Processing ---" << std::endl;
    // Ensure port 0 (ingress for first test packet) is also link up for packet to pass
    netflow::InterfaceManager::PortConfig port0_config;
    port0_config.admin_up = true;
    sw.interface_manager_.configure_port(0, port0_config);
    sw.interface_manager_.simulate_port_link_up(0);
    std::cout << "Port 0 link status (simulated): " << std::boolalpha
              << sw.interface_manager_.is_port_link_up(0) << std::endl;


    // Create a dummy packet buffer (normally from NIC driver or another source)
    // This packet is untagged, destined for a MAC address.
    size_t buffer_size = 128; // Increased for potential headers
    netflow::PacketBuffer* pb1 = sw.buffer_pool.allocate_buffer(buffer_size);
    if (pb1) {
        // Fill with some dummy Ethernet frame data
        // Dst MAC: 00:00:00:00:00:AA, Src MAC: 00:00:00:00:00:BB
        // EtherType: IPv4 (0x0800)
        // IP: 192.168.1.1 -> 192.168.1.10
        // Protocol: TCP (6)
        // TCP Ports: 12345 -> 80 (HTTP)
        uint8_t dummy_frame[] = {
            // Ethernet Header
            0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, // Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xBB, // Src MAC
            0x08, 0x00,                         // EtherType (IPv4)
            // IPv4 Header (20 bytes)
            0x45, 0x00,                         // Version (4) IHL (5), DSCP/ECN
            0x00, 0x28,                         // Total Length (40 bytes: 20 IP + 20 TCP)
            0x12, 0x34, 0x00, 0x00,             // Identification, Flags/Fragment Offset
            0x40, 0x06,                         // TTL (64), Protocol (TCP=6)
            0x00, 0x00,                         // Header Checksum (placeholder)
            192, 168, 1, 1,                   // Src IP (192.168.1.1)
            192, 168, 1, 10,                  // Dst IP (192.168.1.10)
            // TCP Header (20 bytes)
            (12345 >> 8), (12345 & 0xFF),       // Src Port (12345)
            (80 >> 8), (80 & 0xFF),             // Dst Port (80)
            0x00, 0x00, 0x00, 0x00,             // Sequence Number
            0x00, 0x00, 0x00, 0x00,             // Ack Number
            0x50, 0x00,                         // Data Offset (5), Reserved, Flags
            0x00, 0x00,                         // Window Size (placeholder)
            0x00, 0x00,                         // Checksum (placeholder)
            0x00, 0x00                          // Urgent Pointer
        };
        memcpy(pb1->data, dummy_frame, sizeof(dummy_frame));
        pb1->size = sizeof(dummy_frame); // Actual data size

        std::cout << "\nSimulating packet (matching HTTP rule) ingress on Port 0 (Access VLAN 10):" << std::endl;
        sw.process_received_packet(0, pb1); // Ingress on port 0
        // pb1's ref_count will be handled by Packet and BufferPool within process_received_packet lifecycle
    }

    // Simulate another packet, this time one that might be a BPDU
    netflow::PacketBuffer* pb2 = sw.buffer_pool.allocate_buffer(buffer_size);
    if(pb2) {
        uint8_t bpdu_frame[] = {
            0x01, 0x80, 0xC2, 0x00, 0x00, 0x00, // BPDU Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, // Src MAC
            0x00, 0x26, // Length field for LLC (example, actual BPDU is more complex)
            0x42, 0x42, 0x03, // LLC DSAP, SSAP, Control
            // ... Rest of BPDU data (highly simplified)
        };
        memcpy(pb2->data, bpdu_frame, sizeof(bpdu_frame));
        pb2->size = sizeof(bpdu_frame);
        std::cout << "\nSimulating BPDU packet ingress on Port 1 (Trunk, Link Up):" << std::endl;
        // Ensure port 1 is admin up for this test (already done by configure_port)
        // sw.interface_manager_.simulate_port_link_up(1); // Already done above
        sw.process_received_packet(1, pb2);
    }


    std::cout << "\n--- Simulation Finished ---" << std::endl;
    // Switch object sw goes out of scope here, its destructor will be called.

    return 0;
}
