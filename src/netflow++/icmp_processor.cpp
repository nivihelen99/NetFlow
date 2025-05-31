#include "netflow++/icmp_processor.hpp"
#include "netflow++/packet_buffer.hpp" // For creating new packets
#include <iostream> // For placeholder logging
#include <vector>   // For payload manipulation
#include <cstring>  // For memcpy
#include <memory>   // For std::make_unique
#include "netflow++/switch.hpp" // For full Switch class definition

// Ensure ntohs/htons/htonl are available
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif

namespace netflow {

// Assume Switch class has a method like:
// void send_packet_out(netflow::Packet& packet, uint32_t egress_port, bool is_control_plane_generated);
// And InterfaceManager has methods like:
// std::optional<MacAddress> get_interface_mac(uint32_t port_id);
// std::optional<IpAddress> get_interface_ip(uint32_t port_id); // Returns IP in network byte order
// bool is_ip_local_to_interface(IpAddress ip, uint32_t port_id); // or global check
// std::optional<MacAddress> arp_lookup(IpAddress ip); // Potentially via ArpProcessor or FDB

IcmpProcessor::IcmpProcessor(InterfaceManager& if_manager, Switch& packet_sender)
    : interface_manager_(if_manager), switch_ref_(packet_sender) {
    std::cout << "IcmpProcessor initialized." << std::endl;
}

void IcmpProcessor::process_icmp_packet(Packet& packet, uint32_t ingress_port) {
    EthernetHeader* eth_hdr = packet.ethernet();
    IPv4Header* ip_hdr = packet.ipv4(); // Assumes IPv4 for now
    IcmpHeader* icmp_hdr = packet.icmp(); // This should parse ICMP after IP

    if (!eth_hdr || !ip_hdr || !icmp_hdr) {
        std::cerr << "ICMP Processor: Failed to parse Ethernet, IPv4, or ICMP header." << std::endl;
        return;
    }

    // Check if ICMP type is Echo Request (Type 8, Code 0)
    if (icmp_hdr->type == IcmpHeader::TYPE_ECHO_REQUEST && icmp_hdr->code == 0) {
        std::cout << "ICMP Echo Request received on port " << ingress_port
                  << " from IP " << ip_hdr->src_ip << " to IP " << ip_hdr->dst_ip << std::endl;

        // The destination IP of the packet is ip_hdr->dst_ip
        // Check if this dst_ip belongs to any of our interfaces
        if (interface_manager_.is_my_ip(ip_hdr->dst_ip)) {
            std::cout << "ICMP Echo Request is for us (IP: " << ip_hdr->dst_ip << ")." << std::endl;

            // Determine MAC addresses for the reply
            // New source MAC is the MAC of our interface that has ip_hdr->dst_ip
            std::optional<MacAddress> our_mac_opt = interface_manager_.get_mac_for_ip(ip_hdr->dst_ip);
            if (!our_mac_opt) {
                std::cerr << "ICMP Processor: Could not get MAC for our IP " << ip_hdr->dst_ip << std::endl;
                return;
            }
            MacAddress new_src_mac = our_mac_opt.value();
            MacAddress new_dst_mac = eth_hdr->src_mac; // Reply goes back to original sender's MAC

            // IP addresses for the reply
            IpAddress new_src_ip = ip_hdr->dst_ip; // Our IP (original destination) becomes the source
            IpAddress new_dst_ip = ip_hdr->src_ip; // Original source becomes the destination

            // Egress port for the reply is typically the ingress port of the request
            uint32_t egress_port = ingress_port;

            send_icmp_echo_reply(packet, egress_port, new_src_ip, new_src_mac, new_dst_ip, new_dst_mac);

        } else {
            std::cout << "ICMP Echo Request to " << ip_hdr->dst_ip << " is not for us. Ignoring." << std::endl;
            // Or, if this switch were a router, it might forward or send ICMP Destination Unreachable
        }
    } else {
        // Handle other ICMP types if necessary
        std::cout << "ICMP packet received (type " << (int)icmp_hdr->type
                  << ", code " << (int)icmp_hdr->code << "). Not an Echo Request. Ignoring." << std::endl;
    }
}

void IcmpProcessor::send_icmp_echo_reply(Packet& original_request_packet,
                                         uint32_t egress_port,
                                         IpAddress new_src_ip_net, MacAddress new_src_mac,
                                         IpAddress new_dst_ip_net, MacAddress new_dst_mac) {

    IPv4Header* orig_ip_hdr = original_request_packet.ipv4();
    IcmpHeader* orig_icmp_hdr = original_request_packet.icmp();

    if (!orig_ip_hdr || !orig_icmp_hdr) {
        std::cerr << "send_icmp_echo_reply: Original packet missing IP or ICMP header." << std::endl;
        return;
    }

    // Calculate ICMP payload length from original packet
    // Original IP Total Length - Original IP Header Length - ICMP Min Header size
    uint16_t orig_ip_total_len = ntohs(orig_ip_hdr->total_length);
    uint8_t orig_ip_hdr_len = orig_ip_hdr->get_header_length();

    if (orig_ip_total_len < (orig_ip_hdr_len + IcmpHeader::MIN_SIZE)) {
        std::cerr << "send_icmp_echo_reply: Original packet IP total length too small for ICMP header." << std::endl;
        return;
    }
    uint16_t icmp_payload_size = orig_ip_total_len - orig_ip_hdr_len - IcmpHeader::MIN_SIZE;

    const uint8_t* icmp_payload_data = nullptr;
    if (icmp_payload_size > 0 && orig_icmp_hdr) { // Ensure orig_icmp_hdr is not null
        // Payload starts immediately after the ICMP header structure
        icmp_payload_data = reinterpret_cast<const uint8_t*>(orig_icmp_hdr) + IcmpHeader::MIN_SIZE;

        // Boundary check for payload:
        // Ensure that the calculated payload does not extend beyond the packet buffer's actual data length.
        // The offset of the payload from the start of the buffer is
        // (icmp_payload_data - original_request_packet.get_buffer()->get_data_start_ptr()).
        // So, offset_of_payload + icmp_payload_size must be <= total_data_length.
        if (icmp_payload_data < reinterpret_cast<const uint8_t*>(orig_icmp_hdr) || // Check for underflow if MIN_SIZE is huge
            ( (icmp_payload_data - original_request_packet.get_buffer()->get_data_start_ptr()) + icmp_payload_size > original_request_packet.get_buffer()->get_data_length()) ) {
             std::cerr << "send_icmp_echo_reply: Calculated ICMP payload data range is out of bounds for the original packet buffer." << std::endl;
             icmp_payload_size = 0;
             icmp_payload_data = nullptr;
        }
    }


    // Create new packet buffer for the reply
    size_t reply_packet_size = EthernetHeader::SIZE + IPv4Header::MIN_SIZE + IcmpHeader::MIN_SIZE + icmp_payload_size;
    auto buffer_ptr = std::make_unique<PacketBuffer>(reply_packet_size);
    if (!buffer_ptr->set_data_len(reply_packet_size)) {
        std::cerr << "send_icmp_echo_reply: Failed to set data length on new PacketBuffer." << std::endl;
        return;
    }

    Packet reply_packet(buffer_ptr.release()); // Packet takes ownership

    // 1. Ethernet Header
    EthernetHeader* reply_eth_hdr = reply_packet.ethernet(); // This also sets l2_header_size_
    if (!reply_eth_hdr) { std::cerr << "Failed to get Ethernet header for reply" << std::endl; return; }
    reply_eth_hdr->src_mac = new_src_mac;
    reply_eth_hdr->dst_mac = new_dst_mac;
    reply_eth_hdr->ethertype = htons(ETHERTYPE_IPV4);

    // 2. IPv4 Header
    // Need to get pointer after Ethernet header. Packet class doesn't have emplace_ipv4 yet.
    IPv4Header* reply_ip_hdr = reinterpret_cast<IPv4Header*>(reply_packet.get_buffer()->get_data_start_ptr() + EthernetHeader::SIZE);
    reply_ip_hdr->version_ihl = (4 << 4) | (IPv4Header::MIN_SIZE / 4); // IPv4, 20-byte header
    reply_ip_hdr->dscp_ecn = 0;
    reply_ip_hdr->total_length = htons(IPv4Header::MIN_SIZE + IcmpHeader::MIN_SIZE + icmp_payload_size);
    reply_ip_hdr->identification = htons(0); // Or some unique ID
    reply_ip_hdr->flags_fragment_offset = htons(0); // No fragmentation
    reply_ip_hdr->ttl = 64; // Default TTL
    reply_ip_hdr->protocol = IPPROTO_ICMP;
    reply_ip_hdr->header_checksum = 0; // Will be calculated by update_checksums
    reply_ip_hdr->src_ip = new_src_ip_net; // Already in network byte order
    reply_ip_hdr->dst_ip = new_dst_ip_net; // Already in network byte order

    // 3. ICMP Header
    IcmpHeader* reply_icmp_hdr = reinterpret_cast<IcmpHeader*>(reinterpret_cast<uint8_t*>(reply_ip_hdr) + IPv4Header::MIN_SIZE);
    reply_icmp_hdr->type = IcmpHeader::TYPE_ECHO_REPLY; // Echo Reply
    reply_icmp_hdr->code = 0;
    reply_icmp_hdr->checksum = 0; // Will be calculated by update_checksums
    reply_icmp_hdr->identifier = orig_icmp_hdr->identifier; // Copy from request
    reply_icmp_hdr->sequence_number = orig_icmp_hdr->sequence_number; // Copy from request

    // 4. ICMP Payload
    if (icmp_payload_size > 0 && icmp_payload_data) {
        uint8_t* reply_payload_ptr = reinterpret_cast<uint8_t*>(reply_icmp_hdr) + IcmpHeader::MIN_SIZE;
        std::memcpy(reply_payload_ptr, icmp_payload_data, icmp_payload_size);
    }

    // 5. Update checksums
    // This should calculate IPv4 header checksum and ICMP checksum.
    // The Packet::update_checksums() needs to be aware of the L2/L3/L4 structure.
    // For self-constructed packet, ensure l2_header_size_ is set correctly (done by reply_packet.ethernet()).
    // Then, update_checksums should find IP, then ICMP.
    reply_packet.update_checksums();


    std::cout << "Constructed ICMP Echo Reply: SrcIP=" << new_src_ip_net << ", DstIP=" << new_dst_ip_net
              << ". Sending on port " << egress_port << std::endl;

    // Send the packet
    switch_ref_.send_control_plane_packet(reply_packet, egress_port); // Changed to send_control_plane_packet
}

} // namespace netflow
