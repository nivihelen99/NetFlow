#include "netflow/core/PacketBuffer.h"
#include "netflow/packet/Packet.h"
#include "netflow/switch/ForwardingDatabase.h"
#include "netflow/switch/VlanManager.h"
#include "netflow/switch/StpManager.h" // Included for completeness, minimal usage
#include <iostream>
#include <vector>
#include <array>
#include <cstring> // For std::memcpy
#include <arpa/inet.h> // For htons, ntohs

// Forward declaration for make_bridge_id from StpManager.cpp
// This is often defined in StpManager.cpp. If examples/main.cpp is compiled
// separately and StpManager.cpp is linked, this works.
// Otherwise, make_bridge_id would need to be in a shared utility header or StpManager.h.
BridgeId make_bridge_id(uint32_t priority, const MACAddress& mac);

// Helper function to print MAC addresses
void print_mac(const MACAddress& mac) {
    for (size_t i = 0; i < mac.size(); ++i) {
        std::cout << std::hex << static_cast<int>(mac[i]) << std::dec;
        if (i < mac.size() - 1) {
            std::cout << ":";
        }
    }
}

// Helper function to create a simple Ethernet II frame for testing
// Packet structure: DstMAC | SrcMAC | EtherType | Payload
Packet create_test_packet(PacketBufferPool& pool, 
                           const MACAddress& dst_mac, 
                           const MACAddress& src_mac, 
                           uint16_t ethertype, 
                           const std::vector<uint8_t>& payload) {
    // Corrected packet_len calculation using .size() for std::array
    size_t packet_len = dst_mac.size() + src_mac.size() + sizeof(ethertype) + payload.size();
    PacketBuffer* pb = pool.acquire_buffer();
    if (!pb) {
        throw std::runtime_error("Failed to acquire packet buffer from pool for test packet.");
    }
    if (packet_len > pb->size()) {
        pool.release_buffer(pb); // Release before throwing
        throw std::runtime_error("Test packet data exceeds buffer capacity.");
    }

    unsigned char* buf_ptr = static_cast<unsigned char*>(pb->data());
    size_t offset = 0;

    std::memcpy(buf_ptr + offset, dst_mac.data(), dst_mac.size());
    offset += dst_mac.size();
    std::memcpy(buf_ptr + offset, src_mac.data(), src_mac.size());
    offset += src_mac.size();
    uint16_t net_ethertype = htons(ethertype); // Ensure network byte order
    std::memcpy(buf_ptr + offset, &net_ethertype, sizeof(net_ethertype));
    offset += sizeof(net_ethertype);
    if (!payload.empty()){ // Added check from user's version
        std::memcpy(buf_ptr + offset, payload.data(), payload.size());
        offset += payload.size();
    }
    
    pb->set_data_len(offset);

    return Packet(pb); // Packet takes ownership via ref count increment
}


int main() {
    std::cout << "--- NetFlow++ Basic Usage Example ---" << std::endl;

    // 1. Packet Buffer Pool Initialization
    std::cout << "\n[1. Packet Buffer Management]" << std::endl;
    const size_t buffer_size = 2048; // 2KB buffers
    const size_t pool_size = 10;     // Pool of 10 buffers
    PacketBufferPool buffer_pool(buffer_size, pool_size);
    std::cout << "PacketBufferPool created with " << buffer_pool.total_buffers() 
              << " buffers (initially available: " << buffer_pool.available_buffers() 
              << ") of size " << buffer_size << " bytes." << std::endl;

    // Acquire and release a buffer
    PacketBuffer* buf1 = buffer_pool.acquire_buffer();
    if (buf1) {
        std::cout << "Acquired a buffer. Ref count: " << buf1->ref_count() 
                  << ". Available in pool: " << buffer_pool.available_buffers() << std::endl;
        // Simulate writing some data
        buf1->set_data_len(128); 
        buffer_pool.release_buffer(buf1); // buf1's ref_count should become 0 and returned to pool
        std::cout << "Released buffer. Available in pool: " << buffer_pool.available_buffers() << std::endl;
    } else {
        std::cerr << "Failed to acquire buffer from pool." << std::endl;
    }


    // 2. Packet Creation and Basic Header Access
    std::cout << "\n[2. Packet Creation & Access]" << std::endl;
    MACAddress test_dst_mac = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    MACAddress test_src_mac = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint16_t test_ethertype_ipv4 = 0x0800;
    std::vector<uint8_t> test_payload(64, 0xAA); // 64 bytes of payload

    Packet test_pkt1 = create_test_packet(buffer_pool, test_dst_mac, test_src_mac, test_ethertype_ipv4, test_payload);
    std::cout << "Created test packet. Length: " << test_pkt1.length() << " bytes." << std::endl;

    auto eth_hdr = test_pkt1.ethernet();
    if (eth_hdr) {
        std::cout << "  Dst MAC: "; print_mac(eth_hdr->dst_mac); std::cout << std::endl;
        std::cout << "  Src MAC: "; print_mac(eth_hdr->src_mac); std::cout << std::endl;
        std::cout << "  EtherType: 0x" << std::hex << ntohs(eth_hdr->ethertype) << std::dec << std::endl;
    }

    // 3. Forwarding Database (FDB) Example
    std::cout << "\n[3. Forwarding Database (FDB)]" << std::endl;
    ForwardingDatabase fdb(300); // 5-minute aging time
    uint16_t vlan10 = 10;
    uint16_t port1 = 1, port2 = 2;

    fdb.learn_mac(test_src_mac, vlan10, port1);
    std::cout << "Learned MAC "; print_mac(test_src_mac); 
    std::cout << " on VLAN " << vlan10 << " -> Port " << port1 << ". FDB count: " << fdb.entry_count() << std::endl;

    uint16_t lookup_port = fdb.lookup_port(test_src_mac, vlan10);
    if (lookup_port != ForwardingDatabase::FDB_PORT_NOT_FOUND) {
        std::cout << "Lookup MAC "; print_mac(test_src_mac); 
        std::cout << " on VLAN " << vlan10 << " -> Found Port " << lookup_port << std::endl;
    } else {
        std::cout << "Lookup MAC "; print_mac(test_src_mac); 
        std::cout << " on VLAN " << vlan10 << " -> Not Found" << std::endl;
    }
    fdb.flush_all_dynamic();
    std::cout << "Flushed dynamic FDB entries. FDB count: " << fdb.entry_count() << std::endl;


    // 4. VLAN Manager Example
    std::cout << "\n[4. VLAN Manager]" << std::endl;
    VlanManager vlan_mgr;

    // Configure Port 1 as Access Port in VLAN 10
    VlanManager::PortConfig p1_cfg;
    p1_cfg.type = VlanManager::PortType::ACCESS;
    p1_cfg.access_vlan_id = vlan10;
    vlan_mgr.configure_port(port1, p1_cfg);
    std::cout << "Configured Port " << port1 << " as ACCESS, VLAN " << vlan10 << std::endl;

    // Configure Port 2 as Trunk Port, allowing VLAN 10 and 20, Native VLAN 1
    VlanManager::PortConfig p2_cfg;
    p2_cfg.type = VlanManager::PortType::NATIVE_VLAN; // Trunk with native VLAN
    p2_cfg.native_vlan_id = 1;
    p2_cfg.allowed_vlans = {10, 20};
    vlan_mgr.configure_port(port2, p2_cfg);
    std::cout << "Configured Port " << port2 << " as TRUNK, Native VLAN 1, Allowed VLANs: 10, 20" << std::endl;

    // Create a new untagged packet for ingress processing
    Packet untagged_pkt = create_test_packet(buffer_pool, test_dst_mac, test_src_mac, test_ethertype_ipv4, test_payload);
    std::cout << "  Untagged packet created. Has VLAN before ingress on P1: " << std::boolalpha << untagged_pkt.has_vlan() << std::endl;
    
    uint16_t effective_vlan = vlan_mgr.process_ingress(untagged_pkt, port1); // Ingress on Access Port 1
    if (effective_vlan != VlanManager::VLAN_DROP) {
        std::cout << "  Ingress on P1 (Access VLAN 10): Effective VLAN ID: " << effective_vlan 
                  << ". Packet has VLAN tag now: " << std::boolalpha << untagged_pkt.has_vlan() 
                  << " (Tag VID: " << (untagged_pkt.has_vlan() ? untagged_pkt.vlan_id() : 0) << ")" << std::endl;

        // Egress processing on Port 2 (Trunk)
        bool should_fwd = vlan_mgr.process_egress(untagged_pkt, port2, effective_vlan);
        std::cout << "  Egress on P2 (Trunk): Should forward: " << std::boolalpha << should_fwd 
                  << ". Packet has VLAN tag now: " << std::boolalpha << untagged_pkt.has_vlan() 
                  << " (Tag VID: " << (untagged_pkt.has_vlan() ? untagged_pkt.vlan_id() : 0) << ")" << std::endl;
    } else {
        std::cout << "  Ingress on P1 (Access VLAN 10): Packet dropped." << std::endl;
    }


    // 5. STP Manager (Minimal Example - Initialization)
    std::cout << "\n[5. STP Manager]" << std::endl;
    StpManager stp_mgr;
    StpManager::BridgeConfig bridge_stp_cfg;
    // Use a unique MAC for STP Bridge ID for this example if possible
    MACAddress stp_bridge_mac = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    bridge_stp_cfg.bridge_mac = stp_bridge_mac;
    bridge_stp_cfg.bridge_priority = 0x8000; // Default priority
    bridge_stp_cfg.bridge_id = make_bridge_id(bridge_stp_cfg.bridge_priority, bridge_stp_cfg.bridge_mac); 
    stp_mgr.set_bridge_config(bridge_stp_cfg);
    std::cout << "STP Manager initialized. Bridge ID: 0x" << std::hex << stp_mgr.get_bridge_config().bridge_id << std::dec << std::endl;
    stp_mgr.configure_port(port1, 19, true); // Configure port 1 for STP, path cost 19
    std::cout << "Port " << port1 << " STP state: " << static_cast<int>(stp_mgr.get_port_state(port1)) << std::endl;
    stp_mgr.run_stp_iteration(); // Run one iteration
    std::cout << "Port " << port1 << " STP state after iteration: " << static_cast<int>(stp_mgr.get_port_state(port1)) << std::endl;


    std::cout << "\n--- Example Finished ---" << std::endl;

    // Packet objects will release their buffers upon destruction.
    // PacketBufferPool will release all its initially allocated buffers upon destruction.
    return 0;
}

// Note: The `make_bridge_id` function is defined in StpManager.cpp. 
// For this example to compile directly as a single file, you'd need to move its definition
// or declare it. Since we are building with CMake, it should link correctly if StpManager.cpp is compiled.
// However, for a simple example build, it's better if main.cpp is self-contained or uses only headers.
// For now, let's assume CMake handles linking.
// If StpManager.cpp is not part of the same target executable as this main,
// then make_bridge_id would need to be exposed in a header or duplicated.
// For this example, we'll assume it links.
