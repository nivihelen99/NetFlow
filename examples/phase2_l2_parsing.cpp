#include "netflow_plus_plus/core/packet.hpp"
#include "netflow_plus_plus/core/packet_buffer.hpp"
#include "netflow_plus_plus/proto/ethernet.hpp"
#include "netflow_plus_plus/proto/vlan.hpp"
#include <iostream>
#include <vector>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <arpa/inet.h> // For htons

// Helper function to print MAC addresses
void print_mac(const netflow_plus_plus::core::MacAddress& mac) {
    std::cout << mac.toString();
}

int main() {
    std::cout << "--- Phase 2: L2 Parsing Example ---" << std::endl;

    // 1. Ethernet II Frame (IPv4 payload)
    // Destination MAC: 00:11:22:33:44:55
    // Source MAC: AA:BB:CC:DD:EE:FF
    // EtherType: 0x0800 (IPv4)
    // Payload: "This is IPv4 payload" (example)
    unsigned char raw_eth_frame[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Src MAC
        0x08, 0x00,                         // EtherType (IPv4)
        // Example payload (18 bytes)
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'I', 'P', 'v', '4', ' ', 'p', 'a', 'y', 'l', 'd'
    };
    size_t raw_eth_frame_size = sizeof(raw_eth_frame);

    // Create PacketBuffer by copying data
    auto pb1 = std::make_shared<netflow_plus_plus::core::PacketBuffer>(raw_eth_frame, raw_eth_frame_size);
    netflow_plus_plus::core::Packet packet1(pb1);

    std::cout << "\n[Packet 1: Standard Ethernet Frame]" << std::endl;
    if (packet1.ethernet()) {
        std::cout << "  Destination MAC: "; print_mac(packet1.dst_mac()); std::cout << std::endl;
        std::cout << "  Source MAC:      "; print_mac(packet1.src_mac()); std::cout << std::endl;
        std::cout << "  EtherType:       0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(packet1.ethernet()->ether_type) << std::dec << std::endl;

        // Test setting MAC
        packet1.set_dst_mac(netflow_plus_plus::core::MacAddress("01:02:03:04:05:06"));
        std::cout << "  New Dest MAC:    "; print_mac(packet1.dst_mac()); std::cout << std::endl;


    } else {
        std::cerr << "  Error: Could not parse Ethernet header for packet1." << std::endl;
    }
    std::cout << "  Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;


    // 2. Ethernet II Frame with 802.1Q VLAN Tag (IPv4 payload)
    // Destination MAC: 00:1A:2B:3C:4D:5E
    // Source MAC: BB:CC:DD:EE:FF:00
    // TPID: 0x8100 (VLAN)
    // TCI: Priority 5, DEI 0, VLAN ID 101 (0x065) -> 0xA065
    //   PCP = 5 (101b), DEI = 0 (0b), VID = 101 (00001100101b)
    //   TCI = 1010 0000 0110 0101 = 0xA065
    // Original EtherType: 0x0800 (IPv4)
    // Payload: "VLAN tagged data"
    unsigned char raw_vlan_frame[] = {
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Dest MAC
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, // Src MAC
        0x81, 0x00,                         // EtherType (VLAN_TPID)
        0xA0, 0x65,                         // TCI (Prio 5, VLAN ID 101)
        0x08, 0x00,                         // Original EtherType (IPv4)
        // Example payload (16 bytes)
        'V', 'L', 'A', 'N', ' ', 't', 'a', 'g', 'g', 'e', 'd', ' ', 'd', 'a', 't', 'a'
    };
    size_t raw_vlan_frame_size = sizeof(raw_vlan_frame);

    auto pb2 = std::make_shared<netflow_plus_plus::core::PacketBuffer>(raw_vlan_frame, raw_vlan_frame_size);
    netflow_plus_plus::core::Packet packet2(pb2);

    std::cout << "\n[Packet 2: VLAN-tagged Frame]" << std::endl;
    if (packet2.ethernet()) {
        std::cout << "  Destination MAC: "; print_mac(packet2.dst_mac()); std::cout << std::endl;
        std::cout << "  Source MAC:      "; print_mac(packet2.src_mac()); std::cout << std::endl;
        std::cout << "  Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(packet2.ethernet()->ether_type) << std::dec << std::endl;
    } else {
        std::cerr << "  Error: Could not parse Ethernet header for packet2." << std::endl;
    }

    std::cout << "  Has VLAN: " << (packet2.has_vlan() ? "Yes" : "No") << std::endl;
    if (packet2.has_vlan()) {
        netflow_plus_plus::proto::VlanHeader* vlan_hdr = packet2.vlan();
        if (vlan_hdr) {
            std::cout << "  VLAN ID:         " << packet2.vlan_id() << std::endl;
            std::cout << "  VLAN Priority:   " << static_cast<int>(packet2.vlan_priority()) << std::endl;
            std::cout << "  VLAN DEI:        " << static_cast<int>((ntohs(vlan_hdr->tag.tci) >> 12) & 0x01) << std::endl;
            std::cout << "  VLAN TPID:       0x" << std::hex << std::setw(4) << std::setfill('0')
                      << ntohs(vlan_hdr->tag.tpid) << std::dec << std::endl;
            std::cout << "  Original EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                      << ntohs(vlan_hdr->original_ether_type) << std::dec << std::endl;
        } else {
             std::cerr << "  Error: Could not get VLAN header despite has_vlan() being true." << std::endl;
        }
    }

    // 3. Test push_vlan and pop_vlan on packet1
    std::cout << "\n[Modifying Packet 1: push_vlan then pop_vlan]" << std::endl;
    std::cout << "  Initial Packet 1 size: " << packet1.get_buffer()->get_size() << std::endl;
    std::cout << "  Initial Packet 1 EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
              << (packet1.ethernet() ? ntohs(packet1.ethernet()->ether_type) : 0) << std::dec << std::endl;
    
    packet1.push_vlan(202, 3); // VLAN ID 202, Prio 3
    std::cout << "  After push_vlan(202, 3):" << std::endl;
    std::cout << "    Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;
    if (packet1.has_vlan()) {
        std::cout << "    VLAN ID: " << packet1.vlan_id() << std::endl;
        std::cout << "    VLAN Priority: " << static_cast<int>(packet1.vlan_priority()) << std::endl;
        std::cout << "    Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << (packet1.ethernet() ? ntohs(packet1.ethernet()->ether_type) : 0) << std::dec << std::endl;
        netflow_plus_plus::proto::VlanHeader* vh = packet1.vlan();
        if (vh) {
             std::cout << "    Original EtherType (in VLAN): 0x" << std::hex << std::setw(4) << std::setfill('0')
                       << ntohs(vh->original_ether_type) << std::dec << std::endl;
        }
    }
    std::cout << "    Packet 1 size: " << packet1.get_buffer()->get_size() << std::endl;

    packet1.pop_vlan();
    std::cout << "  After pop_vlan():" << std::endl;
    std::cout << "    Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;
    std::cout << "    Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
              << (packet1.ethernet() ? ntohs(packet1.ethernet()->ether_type) : 0) << std::dec << std::endl;
    std::cout << "    Packet 1 size: " << packet1.get_buffer()->get_size() << std::endl;


    return 0;
}
