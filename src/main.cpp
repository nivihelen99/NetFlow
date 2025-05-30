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

    // --- Simulate Packet Processing (Example) ---
    std::cout << "\n--- Simulating Packet Processing ---" << std::endl;

    // Create a dummy packet buffer (normally from NIC driver or another source)
    // This packet is untagged, destined for a MAC address.
    size_t buffer_size = 128;
    netflow::PacketBuffer* pb1 = sw.buffer_pool.allocate_buffer(buffer_size);
    if (pb1) {
        // Fill with some dummy Ethernet frame data
        // Dst MAC: 00:00:00:00:00:AA, Src MAC: 00:00:00:00:00:BB, EtherType: IPv4 (0x0800)
        uint8_t dummy_frame[] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, // Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xBB, // Src MAC
            0x08, 0x00,                         // EtherType (IPv4)
            // ... rest of IPv4 packet data (dummy)
        };
        memcpy(pb1->data, dummy_frame, sizeof(dummy_frame));
        pb1->size = sizeof(dummy_frame); // Actual data size

        std::cout << "\nSimulating packet ingress on Port 0 (Access VLAN 10):" << std::endl;
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
        std::cout << "\nSimulating BPDU packet ingress on Port 1 (Trunk):" << std::endl;
        sw.process_received_packet(1, pb2);
    }


    std::cout << "\n--- Simulation Finished ---" << std::endl;
    // Switch object sw goes out of scope here, its destructor will be called.

    return 0;
}
