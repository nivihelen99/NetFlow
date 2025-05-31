#include "netflow++/switch.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/routing_manager.hpp"
#include "netflow++/arp_processor.hpp"
#include "netflow++/icmp_processor.hpp"
#include "netflow++/packet_buffer.hpp" // For creating test packets
#include "netflow++/logger.hpp"       // For logging
#include <iostream>
#include <thread> // For std::this_thread::sleep_for
#include <chrono> // For std::chrono::seconds

// Helper function to create a simple IPv4/UDP packet for testing
// The Packet object takes ownership of the returned PacketBuffer raw pointer.
netflow::Packet create_test_udp_packet(netflow::MacAddress src_mac, netflow::MacAddress dst_mac,
                                       netflow::IpAddress src_ip, netflow::IpAddress dst_ip,
                                       uint16_t src_port, uint16_t dst_port,
                                       const std::string& payload_str,
                                       uint16_t vlan_id = 0) {
    size_t payload_len = payload_str.length();
    size_t headers_size = netflow::EthernetHeader::SIZE +
                          (vlan_id ? netflow::VlanHeader::SIZE : 0) +
                          netflow::IPv4Header::MIN_SIZE +
                          netflow::UdpHeader::SIZE;
    size_t total_size = headers_size + payload_len;

    auto buffer_raw_ptr = new netflow::PacketBuffer(total_size); // Switch might typically use a pool
    buffer_raw_ptr->set_data_len(total_size); // Set actual data length

    netflow::Packet packet(buffer_raw_ptr);

    // Ethernet Header
    netflow::EthernetHeader* eth_hdr = packet.ethernet();
    eth_hdr->src_mac = src_mac;
    eth_hdr->dst_mac = dst_mac;
    eth_hdr->ethertype = htons(vlan_id ? netflow::ETHERTYPE_VLAN : netflow::ETHERTYPE_IPV4);

    uint8_t* current_header_ptr = (uint8_t*)eth_hdr + netflow::EthernetHeader::SIZE;

    // Optional VLAN Header
    if (vlan_id) {
        netflow::VlanHeader* vlan_hdr = reinterpret_cast<netflow::VlanHeader*>(current_header_ptr);
        vlan_hdr->tci = htons((0 << 13) | (0 << 12) | vlan_id); // Priority 0, CFI 0
        vlan_hdr->ethertype = htons(netflow::ETHERTYPE_IPV4);
        current_header_ptr += netflow::VlanHeader::SIZE;
        // packet.set_vlan_id(vlan_id); // Removed: Packet::vlan_id() will parse this.
    }

    // IPv4 Header
    netflow::IPv4Header* ip_hdr = reinterpret_cast<netflow::IPv4Header*>(current_header_ptr);
    ip_hdr->version_ihl = (4 << 4) | (netflow::IPv4Header::MIN_SIZE / 4);
    ip_hdr->dscp_ecn = 0;
    ip_hdr->total_length = htons(netflow::IPv4Header::MIN_SIZE + netflow::UdpHeader::SIZE + payload_len);
    ip_hdr->identification = htons(12345); // Example ID
    ip_hdr->flags_fragment_offset = htons(0);
    ip_hdr->ttl = 64;
    ip_hdr->protocol = netflow::IPPROTO_UDP;
    ip_hdr->header_checksum = 0; // Will be calculated by update_checksums
    ip_hdr->src_ip = src_ip; // Assumed network byte order
    ip_hdr->dst_ip = dst_ip; // Assumed network byte order
    current_header_ptr += netflow::IPv4Header::MIN_SIZE;

    // UDP Header
    netflow::UdpHeader* udp_hdr = reinterpret_cast<netflow::UdpHeader*>(current_header_ptr);
    udp_hdr->src_port = htons(src_port);
    udp_hdr->dst_port = htons(dst_port);
    udp_hdr->length = htons(netflow::UdpHeader::SIZE + payload_len);
    udp_hdr->checksum = 0; // Will be calculated by update_checksums
    current_header_ptr += netflow::UdpHeader::SIZE;

    // Payload
    if (payload_len > 0) {
        std::memcpy(current_header_ptr, payload_str.data(), payload_len);
    }

    packet.update_checksums(); // Calculate IP and UDP checksums
    return packet;
}


// Helper function to convert string IP to IpAddress (uint32_t network byte order)
// This is a simplified version. A robust one would handle errors.
netflow::IpAddress string_to_ip(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        return addr.s_addr; // Already in network byte order
    }
    return 0; // Error or invalid IP
}

int main() {
    // Initialize the switch logger
    netflow::SwitchLogger logger(netflow::LogLevel::DEBUG);
    logger.info("L3Example", "Starting L3 Forwarding Example");

    // Create a switch instance
    // Using placeholder MAC for switch. Real app might derive from base MAC or config.
    netflow::Switch sw(8, 0x0000DEADBEEF00ULL); // 8 ports, example base MAC

    // --- 1. Configure Interfaces with IP Addresses ---
    logger.info("L3Example", "Configuring interfaces...");
    netflow::InterfaceManager::PortConfig port1_config;
    port1_config.admin_up = true;
    const uint8_t port1_mac_bytes[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x01};
    port1_config.mac_address = netflow::MacAddress(port1_mac_bytes);
    sw.interface_manager_.configure_port(1, port1_config);
    sw.interface_manager_.add_ip_address(1, string_to_ip("192.168.1.1"), string_to_ip("255.255.255.0"));
    sw.interface_manager_.simulate_port_link_up(1); // Bring port up

    netflow::InterfaceManager::PortConfig port2_config;
    port2_config.admin_up = true;
    const uint8_t port2_mac_bytes[] = {0x00, 0x00, 0x00, 0x00, 0x01, 0x02};
    port2_config.mac_address = netflow::MacAddress(port2_mac_bytes);
    sw.interface_manager_.configure_port(2, port2_config);
    sw.interface_manager_.add_ip_address(2, string_to_ip("10.0.0.1"), string_to_ip("255.255.255.0"));
    sw.interface_manager_.simulate_port_link_up(2);

    netflow::InterfaceManager::PortConfig port3_config_ext_host; // Simulates connected external host's properties for packet creation
    port3_config_ext_host.admin_up = true;
    const uint8_t port3_mac_bytes_ext_host[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    port3_config_ext_host.mac_address = netflow::MacAddress(port3_mac_bytes_ext_host);
    // Port 3 on the switch doesn't need an IP, it's just where the external host connects.
    // We configure port 3 on the switch as a basic L2 port.
    netflow::InterfaceManager::PortConfig port3_switch_config;
    port3_switch_config.admin_up = true;
    // Give port 3 on switch a MAC for completeness, though not strictly needed for this test if not sourcing L3 from it.
    const uint8_t port3_sw_mac_bytes[] = {0x00,0x00,0x00,0x00,0x01,0x03};
    port3_switch_config.mac_address = netflow::MacAddress(port3_sw_mac_bytes);
    sw.interface_manager_.configure_port(3, port3_switch_config);
    sw.interface_manager_.simulate_port_link_up(3);

    logger.info("L3Example", "Interface configuration complete.");
    logger.info("L3Example", "Port 1 IP: 192.168.1.1/24, MAC: " + logger.mac_to_string(port1_config.mac_address));
    logger.info("L3Example", "Port 2 IP: 10.0.0.1/24, MAC: " + logger.mac_to_string(port2_config.mac_address));


    // --- 2. Add Static Routes ---
    logger.info("L3Example", "Adding static routes...");
    sw.routing_manager_.add_static_route(
        string_to_ip("20.0.0.0"),
        string_to_ip("255.255.255.0"),
        string_to_ip("10.0.0.100"),
        2 // Egress interface ID (port 2)
    );
     sw.routing_manager_.add_static_route(
        string_to_ip("192.168.1.0"),
        string_to_ip("255.255.255.0"),
        string_to_ip("0.0.0.0"), // Directly connected
        1 // Egress interface ID (port 1)
    );
     sw.routing_manager_.add_static_route(
        string_to_ip("10.0.0.0"),
        string_to_ip("255.255.255.0"),
        string_to_ip("0.0.0.0"), // Directly connected
        2 // Egress interface ID (port 2)
    );
    logger.info("L3Example", "Static routes added.");
    for(const auto& route : sw.routing_manager_.get_routing_table()){
        logger.info("L3Example", "Route: " + logger.ip_to_string(route.destination_network) + "/" + logger.ip_to_string(route.subnet_mask) +
                                           " -> " + logger.ip_to_string(route.next_hop_ip) + " via Iface " + std::to_string(route.egress_interface_id));
    }


    // --- 3. Trigger ICMP Echo Reply (Ping switch interface) ---
    logger.info("L3Example", "--- Simulating Ping to Switch Interface 192.168.1.1 ---");
    netflow::Packet ping_request_to_switch = create_test_udp_packet(
        port3_config_ext_host.mac_address,      // Source MAC (external host)
        port1_config.mac_address,               // Destination MAC (switch port 1)
        string_to_ip("192.168.1.100"),          // Source IP (external host)
        string_to_ip("192.168.1.1"),            // Destination IP (switch interface 1)
        1234, 5678, "ICMP Echo Request Payload"
    );
    ping_request_to_switch.ipv4()->protocol = netflow::IPPROTO_ICMP;
    netflow::IcmpHeader* icmp_hdr_for_ping = reinterpret_cast<netflow::IcmpHeader*>((uint8_t*)ping_request_to_switch.ipv4() + ping_request_to_switch.ipv4()->get_header_length());
    icmp_hdr_for_ping->type = netflow::IcmpHeader::TYPE_ECHO_REQUEST;
    icmp_hdr_for_ping->code = 0;
    icmp_hdr_for_ping->identifier = htons(0xABCD);
    icmp_hdr_for_ping->sequence_number = htons(1);
    ping_request_to_switch.update_checksums();

    logger.info("L3Example", "Injecting Ping request to 192.168.1.1 on port 3 (simulating arrival from external host)");
    sw.process_received_packet(3, ping_request_to_switch.get_buffer());

    std::this_thread::sleep_for(std::chrono::seconds(1));


    // --- 4. Trigger ARP Request (Forwarding to unresolved next-hop) ---
    logger.info("L3Example", "--- Simulating L3 Forwarding - ARP for Next-Hop ---");
    netflow::Packet packet_to_unresolved_next_hop = create_test_udp_packet(
        port3_config_ext_host.mac_address,      // Source MAC (external host)
        port1_config.mac_address,               // Destination MAC (switch port 1, initially, will be changed by router)
        string_to_ip("192.168.1.100"),          // Source IP (external host)
        string_to_ip("20.0.0.5"),               // Destination IP (remote network)
        10001, 20002, "Data to 20.0.0.5"
    );
    logger.info("L3Example", "Injecting packet from 192.168.1.100 to 20.0.0.5 on port 3");
    sw.process_received_packet(3, packet_to_unresolved_next_hop.get_buffer());

    std::this_thread::sleep_for(std::chrono::seconds(1));


    // --- 5. Basic L3 Forwarding (ARP for next-hop is now resolved) ---
    logger.info("L3Example", "--- Simulating L3 Forwarding - Next-Hop ARP Resolved ---");
    const uint8_t next_hop_mac_bytes[] = {0x10, 0x00, 0x00, 0x00, 0x01, 0x64}; // MAC for 10.0.0.100
    netflow::MacAddress next_hop_mac(next_hop_mac_bytes);

    size_t arp_reply_size = netflow::EthernetHeader::SIZE + netflow::ArpHeader::SIZE;
    auto arp_reply_buffer_raw = new netflow::PacketBuffer(arp_reply_size);
    arp_reply_buffer_raw->set_data_len(arp_reply_size);
    netflow::Packet arp_reply_from_nexthop(arp_reply_buffer_raw);

    netflow::EthernetHeader* reply_eth = arp_reply_from_nexthop.ethernet();
    reply_eth->src_mac = next_hop_mac;
    reply_eth->dst_mac = port2_config.mac_address;
    reply_eth->ethertype = htons(netflow::ETHERTYPE_ARP);

    netflow::ArpHeader* reply_arp = reinterpret_cast<netflow::ArpHeader*>((uint8_t*)reply_eth + netflow::EthernetHeader::SIZE);
    reply_arp->hardware_type = htons(1);
    reply_arp->protocol_type = htons(netflow::ETHERTYPE_IPV4);
    reply_arp->hardware_addr_len = 6;
    reply_arp->protocol_addr_len = 4;
    reply_arp->opcode = htons(2); // ARP_OPCODE_REPLY (using literal 2)
    reply_arp->sender_mac = next_hop_mac;
    reply_arp->sender_ip = string_to_ip("10.0.0.100");
    reply_arp->target_mac = port2_config.mac_address;
    reply_arp->target_ip = string_to_ip("10.0.0.1");

    logger.info("L3Example", "Manually injecting ARP reply from 10.0.0.100 on port 2");
    // ARP processing is typically part of the main packet processing path if it's an ARP packet.
    // If ArpProcessor::process_arp_packet is the entry point, use it.
    // For this example, let's assume process_received_packet will dispatch ARP packets correctly.
    sw.process_received_packet(2, arp_reply_from_nexthop.get_buffer());

    std::this_thread::sleep_for(std::chrono::seconds(1));

    logger.info("L3Example", "Re-injecting packet from 192.168.1.100 to 20.0.0.5 on port 3");
    netflow::Packet packet_to_resolved_next_hop = create_test_udp_packet(
        port3_config_ext_host.mac_address,      // Source MAC (external host)
        port1_config.mac_address,               // Destination MAC (switch port 1, initially)
        string_to_ip("192.168.1.100"),          // Source IP (external host)
        string_to_ip("20.0.0.5"),               // Destination IP (remote network)
        10001, 20002, "Data to 20.0.0.5"
    );
    sw.process_received_packet(3, packet_to_resolved_next_hop.get_buffer());

    std::this_thread::sleep_for(std::chrono::seconds(1));


    // --- 6. Simulate ICMP Destination Unreachable (No Route) ---
    logger.info("L3Example", "--- Simulating ICMP Destination Unreachable (No Route) ---");
    netflow::Packet packet_to_unroutable = create_test_udp_packet(
        port3_config_ext_host.mac_address,      // Source MAC (external host)
        port1_config.mac_address,               // Destination MAC (switch port 1, initially)
        string_to_ip("192.168.1.100"),          // Source IP (external host)
        string_to_ip("203.0.113.5"),            // Destination IP (unroutable)
        10002, 30003, "Data to unroutable"
    );
    logger.info("L3Example", "Injecting packet from 192.168.1.100 to unroutable 203.0.113.5 on port 3");
    sw.process_received_packet(3, packet_to_unroutable.get_buffer());

    logger.info("L3Example", "L3 Forwarding Example Finished. Check logs for ARP/ICMP/Forwarding messages.");
    return 0;
}
