#include "netflow++/packet.hpp"       // Updated include
#include "netflow++/packet_buffer.hpp" // Updated include
#include <iostream>
#include <vector>
#include <iomanip> // For std::hex, std::setw, std::setfill
#include <cstring> // For memcpy
// <arpa/inet.h> is included by packet.hpp for ntohs/htons if available

// Helper function to print MAC addresses (similar to one in SwitchLogger)
std::string mac_to_string_local_ex2(const netflow::MacAddress& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                  mac.bytes[0], mac.bytes[1], mac.bytes[2],
                  mac.bytes[3], mac.bytes[4], mac.bytes[5]);
    return std::string(buf);
}

void print_mac_ex2(const netflow::MacAddress& mac) { // Changed to accept netflow::MacAddress
    std::cout << mac_to_string_local_ex2(mac);
}

int main() {
    std::cout << "--- Phase 2: L2 Parsing Example (Updated) ---" << std::endl;

    // 1. Ethernet II Frame (IPv4 payload)
    unsigned char raw_eth_frame[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dest MAC
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Src MAC
        0x08, 0x00,                         // EtherType (IPv4)
        'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'I', 'P', 'v', '4', ' ', 'p', 'a', 'y', 'l', 'd'
    };
    size_t raw_eth_frame_size = sizeof(raw_eth_frame);

    netflow::PacketBuffer* pb1_ptr = new netflow::PacketBuffer(raw_eth_frame_size);
    std::memcpy(pb1_ptr->data, raw_eth_frame, raw_eth_frame_size);
    // pb1_ptr->size is already raw_eth_frame_size from constructor, but if only partially filled, adjust here.

    netflow::Packet packet1(pb1_ptr);

    std::cout << "\n[Packet 1: Standard Ethernet Frame]" << std::endl;
    netflow::EthernetHeader* eth1 = packet1.ethernet();
    if (eth1) {
        if (auto dmac = packet1.dst_mac()) { std::cout << "  Destination MAC: "; print_mac_ex2(dmac.value()); std::cout << std::endl; }
        if (auto smac = packet1.src_mac()) { std::cout << "  Source MAC:      "; print_mac_ex2(smac.value()); std::cout << std::endl; }
        std::cout << "  EtherType:       0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(eth1->ethertype) << std::dec << std::endl;

        // Test setting MAC
        uint8_t new_mac_bytes[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        packet1.set_dst_mac(netflow::MacAddress(new_mac_bytes));
        if (auto dmac = packet1.dst_mac()) { std::cout << "  New Dest MAC:    "; print_mac_ex2(dmac.value()); std::cout << std::endl; }

    } else {
        std::cerr << "  Error: Could not parse Ethernet header for packet1." << std::endl;
    }
    std::cout << "  Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;


    // 2. Ethernet II Frame with 802.1Q VLAN Tag (IPv4 payload)
    unsigned char raw_vlan_frame[] = {
        0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, // Dest MAC
        0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, // Src MAC
        0x81, 0x00,                         // EtherType (VLAN_TPID)
        0xA0, 0x65,                         // TCI (Prio 5, VLAN ID 101)
        0x08, 0x00,                         // Original EtherType (IPv4)
        'V', 'L', 'A', 'N', ' ', 't', 'a', 'g', 'g', 'e', 'd', ' ', 'd', 'a', 't', 'a'
    };
    size_t raw_vlan_frame_size = sizeof(raw_vlan_frame);

    netflow::PacketBuffer* pb2_ptr = new netflow::PacketBuffer(raw_vlan_frame_size);
    std::memcpy(pb2_ptr->data, raw_vlan_frame, raw_vlan_frame_size);
    netflow::Packet packet2(pb2_ptr);

    std::cout << "\n[Packet 2: VLAN-tagged Frame]" << std::endl;
    netflow::EthernetHeader* eth2 = packet2.ethernet();
    if (eth2) {
        if (auto dmac = packet2.dst_mac()) { std::cout << "  Destination MAC: "; print_mac_ex2(dmac.value()); std::cout << std::endl; }
        if (auto smac = packet2.src_mac()) { std::cout << "  Source MAC:      "; print_mac_ex2(smac.value()); std::cout << std::endl; }
        std::cout << "  Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(eth2->ethertype) << std::dec << std::endl;
    } else {
        std::cerr << "  Error: Could not parse Ethernet header for packet2." << std::endl;
    }

    std::cout << "  Has VLAN: " << (packet2.has_vlan() ? "Yes" : "No") << std::endl;
    if (packet2.has_vlan()) {
        netflow::VlanHeader* vlan_hdr = packet2.vlan(); // vlan() method in Packet returns VlanHeader*
        if (vlan_hdr) {
            // Use optional returning methods from Packet
            if(auto vid = packet2.vlan_id()) std::cout << "  VLAN ID:         " << vid.value() << std::endl;
            if(auto prio = packet2.vlan_priority()) std::cout << "  VLAN Priority:   " << static_cast<int>(prio.value()) << std::endl;

            // TCI direct access for DEI as an example (DEI is bit 12 of TCI, or bit 4 of first TCI byte)
            // TCI = PCP(3) DEI(1) VID(12). ntohs(vlan_hdr->tci) gives host order.
            // DEI is (val >> 12) & 0x1 if val is (PCP<<13 | DEI<<12 | VID)
            uint16_t tci_val_host = ntohs(vlan_hdr->tci);
            std::cout << "  VLAN DEI:        " << ((tci_val_host >> 12) & 0x01) << std::endl;
            std::cout << "  Inner EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                      << ntohs(vlan_hdr->ethertype) << std::dec << std::endl; // Renamed from original_ether_type
        } else {
             std::cerr << "  Error: Could not get VLAN header despite has_vlan() being true." << std::endl;
        }
    }

    // 3. Test push_vlan and pop_vlan on packet1
    std::cout << "\n[Modifying Packet 1: push_vlan then pop_vlan]" << std::endl;
    if (packet1.get_buffer()) std::cout << "  Initial Packet 1 size: " << packet1.get_buffer()->size << std::endl;
    if (auto eth_hdr_p1 = packet1.ethernet()) {
         std::cout << "  Initial Packet 1 EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                   << ntohs(eth_hdr_p1->ethertype) << std::dec << std::endl;
    }
    
    packet1.push_vlan(202, 3); // VLAN ID 202, Prio 3
    std::cout << "  After push_vlan(202, 3):" << std::endl;
    std::cout << "    Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;
    if (packet1.has_vlan()) {
        if(auto vid = packet1.vlan_id()) std::cout << "    VLAN ID: " << vid.value() << std::endl;
        if(auto prio = packet1.vlan_priority()) std::cout << "    VLAN Priority: " << static_cast<int>(prio.value()) << std::endl;
        if (auto eth_hdr_p1_vlan = packet1.ethernet()) { // Re-fetch ethernet header as it might have changed (TPID)
            std::cout << "    Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                      << ntohs(eth_hdr_p1_vlan->ethertype) << std::dec << std::endl;
        }
        netflow::VlanHeader* vh = packet1.vlan();
        if (vh) {
             std::cout << "    Inner EtherType (in VLAN): 0x" << std::hex << std::setw(4) << std::setfill('0')
                       << ntohs(vh->ethertype) << std::dec << std::endl;
        }
    }
    if (packet1.get_buffer()) std::cout << "    Packet 1 size: " << packet1.get_buffer()->size << std::endl;

    packet1.pop_vlan();
    std::cout << "  After pop_vlan():" << std::endl;
    std::cout << "    Has VLAN: " << (packet1.has_vlan() ? "Yes" : "No") << std::endl;
    if (auto eth_hdr_p1_pop = packet1.ethernet()) {
        std::cout << "    Outer EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(eth_hdr_p1_pop->ethertype) << std::dec << std::endl;
    }
    if (packet1.get_buffer()) std::cout << "    Packet 1 size: " << packet1.get_buffer()->size << std::endl;

    // Clean up manually allocated PacketBuffers for this example
    pb1_ptr->decrement_ref(); // Packet1's destructor would have called it once
    pb2_ptr->decrement_ref(); // Packet2's destructor would have called it once

    return 0;
}
