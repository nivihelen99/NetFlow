#include "netflow++/icmp_processor.hpp"
#include "netflow++/packet_buffer.hpp" // For creating new packets
#include <iostream> // For placeholder logging
#include <vector>   // For payload manipulation
#include <cstring>  // For memcpy
#include <memory>   // For std::make_unique
#include "netflow++/switch.hpp" // For full Switch class definition
#include <cstdlib>  // For rand()
#include <algorithm> // For std::min

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


// --- ICMP Error Sending Methods ---

void IcmpProcessor::send_icmp_error_packet_base(
    Packet& original_packet,
    uint8_t icmp_type,
    uint8_t icmp_code) {

    IPv4Header* original_ipv4_hdr = original_packet.ipv4();
    EthernetHeader* original_eth_hdr = original_packet.ethernet(); // Needed for original MACs if used for routing decision

    if (!original_ipv4_hdr || !original_eth_hdr) {
        // Use switch_ref_.logger_ for logging if available and LOG_ macros are not set up for direct use here.
        // For now, using std::cerr as a fallback if direct logger access is complex.
        std::cerr << "ICMP_ERROR_GEN: Cannot send ICMP error for non-IPv4 or non-Ethernet original packet." << std::endl;
        return;
    }

    // 1. Determine Source IP for the ICMP error message.
    //    The ICMP packet's source IP should be an IP of the interface via which the error packet will be sent.
    //    This requires routing the ICMP error packet (destined for original_ipv4_hdr->src_ip).

    IpAddress icmp_error_destination_ip = original_ipv4_hdr->src_ip; // ICMP error goes to original sender
    std::optional<RouteEntry> route_to_original_src_opt = switch_ref_.routing_manager_.lookup_route(icmp_error_destination_ip);

    if (!route_to_original_src_opt) {
        std::cerr << "ICMP_ERROR_GEN: No route to original source " << icmp_error_destination_ip
                  << " to send ICMP error. Dropping." << std::endl;
        return;
    }
    const RouteEntry& route_to_original_src = route_to_original_src_opt.value();

    std::optional<IpAddress> icmp_error_source_ip_opt = interface_manager_.get_interface_ip(route_to_original_src.egress_interface_id);
    if (!icmp_error_source_ip_opt) {
        std::cerr << "ICMP_ERROR_GEN: No IP configured on interface " << route_to_original_src.egress_interface_id
                  << " to source ICMP error. Dropping." << std::endl;
        return;
    }
    IpAddress icmp_error_source_ip = icmp_error_source_ip_opt.value();

    // 2. Determine Next-Hop MAC for the ICMP error packet
    IpAddress next_hop_for_icmp_error = route_to_original_src.next_hop_ip;
    if (next_hop_for_icmp_error == 0) { // Directly connected to the original source's subnet
        next_hop_for_icmp_error = icmp_error_destination_ip;
    }

    std::optional<MacAddress> icmp_eth_dst_mac_opt = switch_ref_.arp_processor_.lookup_mac(next_hop_for_icmp_error);
    if (!icmp_eth_dst_mac_opt) {
        std::cout << "ICMP_ERROR_GEN: No ARP entry for next-hop " << next_hop_for_icmp_error
                  << " (for original source " << icmp_error_destination_ip << "). Sending ARP request." << std::endl;
        switch_ref_.arp_processor_.send_arp_request(next_hop_for_icmp_error, route_to_original_src.egress_interface_id);
        return; // Cannot send ICMP error without MAC
    }
    MacAddress icmp_eth_dst_mac = icmp_eth_dst_mac_opt.value();

    std::optional<MacAddress> icmp_eth_src_mac_opt = interface_manager_.get_interface_mac(route_to_original_src.egress_interface_id);
    if (!icmp_eth_src_mac_opt) {
         std::cerr << "ICMP_ERROR_GEN: No MAC configured on interface " << route_to_original_src.egress_interface_id
                   << " to source ICMP error Ethernet frame. Dropping." << std::endl;
        return;
    }
    MacAddress icmp_eth_src_mac = icmp_eth_src_mac_opt.value();

    // 3. Construct the ICMP error packet.
    //    Payload: Original IP header + first 8 bytes of original L4 payload.
    const size_t original_ip_header_len = original_ipv4_hdr->get_header_length(); // Use method
    const size_t max_original_l4_data_to_copy = 8;

    const uint8_t* original_l4_data_start = reinterpret_cast<const uint8_t*>(original_ipv4_hdr) + original_ip_header_len;
    size_t available_l4_data_in_original = 0;
    if (original_packet.get_buffer()->get_data_length() > ( (original_l4_data_start - original_packet.get_buffer()->get_data_start_ptr()) ) ) {
        available_l4_data_in_original = original_packet.get_buffer()->get_data_length() -
                                         (original_l4_data_start - original_packet.get_buffer()->get_data_start_ptr());
    }
    size_t actual_l4_data_to_copy = std::min(max_original_l4_data_to_copy, available_l4_data_in_original);
    const size_t icmp_data_payload_len = original_ip_header_len + actual_l4_data_to_copy;

    size_t total_packet_size = EthernetHeader::SIZE + IPv4Header::MIN_SIZE + IcmpHeader::MIN_SIZE + icmp_data_payload_len;

    // Use Switch's buffer pool. Pass total_packet_size as required_data_payload_size and 0 for headroom,
    // as Packet class methods assume Ethernet header is at the start of buffer's "data" region.
    PacketBuffer* pkt_buf_raw = switch_ref_.buffer_pool.allocate_buffer(total_packet_size, 0);
    if (!pkt_buf_raw) {
        std::cerr << "ICMP_ERROR_GEN: Failed to allocate buffer for ICMP error packet." << std::endl;
        return;
    }
    Packet icmp_packet(pkt_buf_raw); // Manages ref count of pkt_buf_raw

    // The allocate_buffer now returns a buffer with data_len = 0.
    // We need to set the actual length of data we are about to write.
    if (!icmp_packet.get_buffer()->set_data_len(total_packet_size)) {
        std::cerr << "ICMP_ERROR_GEN: Failed to set data length on allocated buffer." << std::endl;
        // Packet destructor will handle decrementing ref count of pkt_buf_raw if it was successfully constructed.
        // If Packet construction failed (e.g. null buffer), this point might not be reached.
        // If pkt_buf_raw is not null but set_data_len fails, Packet dtor handles it.
        return;
    }


    // Fill Ethernet Header
    EthernetHeader* new_eth_hdr = reinterpret_cast<EthernetHeader*>(icmp_packet.get_buffer()->get_data_start_ptr());
    new_eth_hdr->dst_mac = icmp_eth_dst_mac;
    new_eth_hdr->src_mac = icmp_eth_src_mac;
    new_eth_hdr->ethertype = htons(ETHERTYPE_IPV4);

    // Fill IPv4 Header for the new ICMP packet
    IPv4Header* new_ipv4_hdr = reinterpret_cast<IPv4Header*>(reinterpret_cast<uint8_t*>(new_eth_hdr) + EthernetHeader::SIZE);
    new_ipv4_hdr->version_ihl = (4 << 4) | (IPv4Header::MIN_SIZE / 4); // IPv4, 20-byte header
    new_ipv4_hdr->dscp_ecn = 0; // DSCP (was tos)
    new_ipv4_hdr->total_length = htons(IPv4Header::MIN_SIZE + IcmpHeader::MIN_SIZE + icmp_data_payload_len);
    new_ipv4_hdr->identification = htons(static_cast<uint16_t>(rand())); // Random ID
    new_ipv4_hdr->flags_fragment_offset = htons(0); // No fragmentation
    new_ipv4_hdr->ttl = 64; // Default TTL for switch-generated packets
    new_ipv4_hdr->protocol = IPPROTO_ICMP;
    new_ipv4_hdr->src_ip = icmp_error_source_ip;     // Network byte order
    new_ipv4_hdr->dst_ip = icmp_error_destination_ip; // Network byte order
    new_ipv4_hdr->header_checksum = 0; // Will be calculated by update_checksums

    // Fill ICMP Header
    IcmpHeader* new_icmp_hdr = reinterpret_cast<IcmpHeader*>(reinterpret_cast<uint8_t*>(new_ipv4_hdr) + IPv4Header::MIN_SIZE);
    new_icmp_hdr->type = icmp_type;
    new_icmp_hdr->code = icmp_code;
    new_icmp_hdr->checksum = 0; // Will be calculated
    new_icmp_hdr->identifier = 0; // Unused for these error types
    new_icmp_hdr->sequence_number = 0; // Unused for these error types

    // Fill ICMP Data Payload (original IP header + first 8 bytes of original L4 data)
    uint8_t* icmp_data_payload_ptr = reinterpret_cast<uint8_t*>(new_icmp_hdr) + IcmpHeader::MIN_SIZE;
    memcpy(icmp_data_payload_ptr, original_ipv4_hdr, original_ip_header_len);
    if (actual_l4_data_to_copy > 0) {
        memcpy(icmp_data_payload_ptr + original_ip_header_len, original_l4_data_start, actual_l4_data_to_copy);
    }

    // Update L2 header size in the new packet object before calling update_checksums
    // This is crucial for update_checksums to find the IP header correctly.
    // The Packet class's ethernet() method usually does this.
    // We've manually casted, so we need to ensure the Packet object state is consistent.
    // Let's rely on the fact that update_checksums will call ethernet() itself.
    // Or, more safely:
    icmp_packet.ethernet(); // This will set l2_header_size_ correctly.

    icmp_packet.update_checksums(); // Calculate IP and ICMP checksums

    std::cout << "ICMP_ERROR_GEN: Sending ICMP Type " << (int)icmp_type << " Code " << (int)icmp_code
              << " to " << icmp_error_destination_ip << " from " << icmp_error_source_ip
              << " via interface " << route_to_original_src.egress_interface_id << std::endl;
    switch_ref_.send_control_plane_packet(icmp_packet, route_to_original_src.egress_interface_id);
}

void IcmpProcessor::send_time_exceeded(Packet& original_packet, uint32_t /*original_ingress_port - not directly used for routing decision of reply*/) {
    // Using std::cout for logging as per existing style in this file, assuming logger_ref_ might not be set up
    std::cout << "ICMP_PROC: Original packet TTL expired. Sending ICMP Time Exceeded." << std::endl;
    send_icmp_error_packet_base(original_packet, 11 /* Type: Time Exceeded */, 0 /* Code: TTL exceeded in transit */);
}

void IcmpProcessor::send_destination_unreachable(Packet& original_packet, uint32_t /*original_ingress_port*/, uint8_t code) {
    std::cout << "ICMP_PROC: Original packet destination unreachable. Sending ICMP Dest Unreachable code " << (int)code << std::endl;
    send_icmp_error_packet_base(original_packet, 3 /* Type: Destination Unreachable */, code);
}

} // namespace netflow
