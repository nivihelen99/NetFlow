#include "netflow++/arp_processor.hpp"
#include "netflow++/packet_buffer.hpp" // For creating new packets
#include <iostream> // For placeholder logging
#include <memory> // For std::make_unique
#include "netflow++/switch.hpp" // For full Switch class definition

// Ensure ntohs/htons are available
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
// std::optional<IpAddress> get_interface_ip(uint32_t port_id);
// bool is_ip_local_to_interface(IpAddress ip, uint32_t port_id); // or global check
// std::optional<uint32_t> get_port_for_ip(IpAddress ip); // Find which port has this IP


ArpProcessor::ArpProcessor(InterfaceManager& if_manager, ForwardingDatabase& fwd_db, Switch& packet_sender)
    : interface_manager_(if_manager), forwarding_database_(fwd_db), switch_ref_(packet_sender) {
    std::cout << "ArpProcessor initialized." << std::endl;
}

void ArpProcessor::update_arp_cache(IpAddress ip, MacAddress mac) {
    // Assumes cache_mutex_ is already locked by the caller
    arp_cache_[ip] = ArpCacheEntry(mac);
    std::cout << "ARP cache updated: IP " << ip << " -> MAC ";
    for(int i=0; i<6; ++i) std::cout << std::hex << (int)mac.bytes[i] << (i==5 ? "" : ":");
    std::cout << std::dec << std::endl;
}

void ArpProcessor::process_arp_packet(Packet& packet, uint32_t ingress_port) {
    ArpHeader* arp_header = packet.arp();
    if (!arp_header) {
        std::cerr << "ARP Processor: Failed to parse ARP header." << std::endl;
        return;
    }

    // ARP headers are in network byte order, convert to host for comparisons/logic
    uint16_t opcode = ntohs(arp_header->opcode);
    IpAddress sender_ip_net = arp_header->sender_ip; // Keep as is for now, assuming IpAddress is uint32_t net order
    MacAddress sender_mac = arp_header->sender_mac;
    IpAddress target_ip_net = arp_header->target_ip;
    // MacAddress target_mac = arp_header->target_mac; // Target MAC in request is often ignored or broadcast

    std::cout << "ARP packet received on port " << ingress_port << ". Opcode: " << opcode << std::endl;
    // Log sender IP/MAC
    // For now, assume IpAddress (uint32_t) is stored in network byte order.
    // If it were host byte order, we'd need ntohl around sender_ip_net and target_ip_net for consistent map keys.

    std::lock_guard<std::mutex> lock(cache_mutex_);

    // Always learn from sender if protocol is IPv4 and hardware is Ethernet
    if (ntohs(arp_header->protocol_type) == ETHERTYPE_IPV4 && arp_header->hardware_addr_len == 6) {
        update_arp_cache(sender_ip_net, sender_mac);
        // Optionally, update forwarding database as well
        // forwarding_database_.add_entry(sender_mac, ingress_port, std::chrono::steady_clock::now() + FDB_TIMEOUT);
    }


    if (opcode == ARP_OPCODE_REQUEST) {
        std::cout << "ARP Request: Who has " << target_ip_net << "? Tell " << sender_ip_net << std::endl;

        // Check if the target IP is one of our interface IPs
        if (interface_manager_.is_my_ip(target_ip_net)) {
            std::optional<MacAddress> my_mac_for_target_ip = interface_manager_.get_mac_for_ip(target_ip_net);

            if (my_mac_for_target_ip) {
                std::cout << "ARP Request is for one of our interfaces (IP: " << target_ip_net
                          << "). Sending ARP Reply." << std::endl;
                // The target_ip_net from the request is our IP.
                // The sender_ip_net and sender_mac from the request become the target for our reply.
                send_arp_reply(sender_ip_net, sender_mac, /*our_ip=*/target_ip_net, *my_mac_for_target_ip, ingress_port);
            } else {
                std::cerr << "ARP Request is for our IP " << target_ip_net << " but could not get MAC for it." << std::endl;
            }
        } else {
            std::cout << "ARP Request is not for us (target_ip: " << target_ip_net
                      << "). Ignoring (or forward if acting as proxy ARP)." << std::endl;
        }

    } else if (opcode == ARP_OPCODE_REPLY) {
        std::cout << "ARP Reply: " << sender_ip_net << " is at MAC ";
        for(int i=0; i<6; ++i) std::cout << std::hex << (int)sender_mac.bytes[i] << (i==5 ? "" : ":");
        std::cout << std::dec << std::endl;
        // Already learned from sender_ip and sender_mac above.
        // Additional logic could go here, e.g., notifying pending requests.
    } else {
        std::cout << "Unknown ARP opcode: " << opcode << std::endl;
    }
}

std::optional<MacAddress> ArpProcessor::lookup_mac(IpAddress ip_address) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    age_arp_cache(); // Perform aging before lookup

    auto it = arp_cache_.find(ip_address);
    if (it != arp_cache_.end()) {
        if (!it->second.is_static && (std::chrono::steady_clock::now() - it->second.last_seen > ARP_CACHE_TIMEOUT)) {
            std::cout << "ARP cache entry for " << ip_address << " expired." << std::endl;
            arp_cache_.erase(it); // Entry expired
            return std::nullopt;
        }
        std::cout << "ARP cache hit for " << ip_address << std::endl;
        it->second.last_seen = std::chrono::steady_clock::now(); // Refresh timestamp on access
        return it->second.mac_address;
    }
    std::cout << "ARP cache miss for " << ip_address << std::endl;
    return std::nullopt;
}

void ArpProcessor::send_arp_request(IpAddress target_ip, uint32_t egress_port_hint) {
    std::cout << "Attempting to send ARP request for target IP: " << target_ip
              << " via port hint: " << egress_port_hint << std::endl;

    // Determine source IP and MAC for the ARP request.
    // This is a critical part and depends heavily on InterfaceManager's capabilities.
    // Option 1: Use egress_port_hint to get interface IP/MAC.
    // Option 2: If egress_port_hint is not valid or not specific enough,
    //           select a suitable interface (e.g., one on the same subnet as target_ip, or a default).

    std::optional<IpAddress> src_ip_opt;
    std::optional<MacAddress> src_mac_opt;
    uint32_t determined_egress_port = 0;

    // Try to use the hinted egress port first
    if (egress_port_hint != 0) { // Assuming 0 might mean no hint or invalid
        if (interface_manager_.is_port_valid(egress_port_hint)) {
            src_ip_opt = interface_manager_.get_interface_ip(egress_port_hint);
            src_mac_opt = interface_manager_.get_interface_mac(egress_port_hint);

            if (src_ip_opt.has_value() && src_mac_opt.has_value()) {
                determined_egress_port = egress_port_hint;
                // Using std::cout for logging as per existing style in this file
                std::cout << "ARP Request for target IP " << target_ip
                          << ": Using hinted egress port " << determined_egress_port
                          << " (Source IP: " << src_ip_opt.value() << ", Source MAC: ";
                for(int i=0; i<6; ++i) std::cout << std::hex << (int)src_mac_opt.value().bytes[i] << (i==5 ? "" : ":");
                std::cout << std::dec << ")" << std::endl;
            } else {
                std::cerr << "ARP Request for target IP " << target_ip
                          << ": Hinted egress port " << egress_port_hint
                          << " is not fully L3 configured (missing IP or MAC). Attempting fallback." << std::endl;
            }
        } else {
            std::cerr << "ARP Request for target IP " << target_ip
                      << ": Hinted egress port " << egress_port_hint
                      << " is not a valid port. Attempting fallback." << std::endl;
        }
    } else {
         std::cout << "ARP Request for target IP " << target_ip
                   << ": No egress port hint provided or hint was 0. Attempting fallback." << std::endl;
    }

    // Fallback logic if hint failed or was not provided/valid
    if (!src_ip_opt.has_value() || !src_mac_opt.has_value() || determined_egress_port == 0) {
        std::cout << "ARP Request for target IP " << target_ip
                  << ": Attempting to find a suitable L3 interface via fallback." << std::endl;
        auto all_l3_ports = interface_manager_.get_all_l3_interface_ids();
        if (!all_l3_ports.empty()) {
            bool found_fallback = false;
            for (uint32_t port_id : all_l3_ports) { // Iterate to find first usable one
                src_ip_opt = interface_manager_.get_interface_ip(port_id);
                src_mac_opt = interface_manager_.get_interface_mac(port_id);
                if (src_ip_opt.has_value() && src_mac_opt.has_value()) {
                    determined_egress_port = port_id;
                    std::cout << "ARP Request for target IP " << target_ip
                              << ": Using fallback L3 interface port " << determined_egress_port
                              << " (Source IP: " << src_ip_opt.value() << ", Source MAC: ";
                    for(int i=0; i<6; ++i) std::cout << std::hex << (int)src_mac_opt.value().bytes[i] << (i==5 ? "" : ":");
                    std::cout << std::dec << ")" << std::endl;
                    found_fallback = true;
                    break;
                }
            }
            if (!found_fallback) {
                 std::cerr << "ARP Request for target IP " << target_ip
                           << ": Fallback failed. No suitable L3 interface found with both IP and MAC." << std::endl;
            }
        } else {
            std::cerr << "ARP Request for target IP " << target_ip
                      << ": Fallback failed. No L3 interfaces configured." << std::endl;
        }
    }

    if (src_ip_opt.has_value() && src_mac_opt.has_value() && determined_egress_port != 0) {
        construct_and_send_arp_request(src_ip_opt.value(), src_mac_opt.value(), target_ip, determined_egress_port);
    } else {
        std::cerr << "ARP Request for target IP " << target_ip
                  << ": Failed to find a suitable source IP/MAC. ARP request not sent." << std::endl;
    }
}


void ArpProcessor::construct_and_send_arp_request(IpAddress source_ip, MacAddress source_mac,
                                                IpAddress target_ip, uint32_t egress_port) {
    // Size of Ethernet header + ARP header
    const size_t packet_size = EthernetHeader::SIZE + ArpHeader::SIZE;
    auto buffer = std::make_unique<PacketBuffer>(packet_size);
    if (!buffer->set_data_len(packet_size)) {
        std::cerr << "Failed to allocate buffer for ARP request" << std::endl;
        return;
    }

    Packet arp_packet(buffer.release()); // Packet takes ownership of buffer raw ptr

    // Ethernet Header
    EthernetHeader* eth_hdr = arp_packet.ethernet();
    if (!eth_hdr) return; // Should not happen with a new buffer

    const uint8_t broadcast_mac_bytes[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    eth_hdr->dst_mac = MacAddress(broadcast_mac_bytes); // Broadcast MAC
    eth_hdr->src_mac = source_mac;
    eth_hdr->ethertype = htons(ETHERTYPE_ARP);

    // ARP Header
    // Need to manually "emplace" or get pointer for ARP after Ethernet.
    // The current Packet::arp() method might assume ARP follows IP or is based on ethertype.
    // For a self-constructed packet, we get the pointer directly after Ethernet.
    // Accessing via eth_hdr pointer is slightly cleaner if eth_hdr is guaranteed to be start of buffer.
    ArpHeader* arp_hdr = reinterpret_cast<ArpHeader*>((uint8_t*)eth_hdr + EthernetHeader::SIZE);

    arp_hdr->hardware_type = htons(1); // Ethernet
    arp_hdr->protocol_type = htons(ETHERTYPE_IPV4); // IPv4
    arp_hdr->hardware_addr_len = 6; // MAC address length
    arp_hdr->protocol_addr_len = 4; // IPv4 address length
    arp_hdr->opcode = htons(ARP_OPCODE_REQUEST);
    arp_hdr->sender_mac = source_mac;
    arp_hdr->sender_ip = source_ip; // Assumed already in network byte order
    // For ARP request, target MAC is often all zeros or ignored.
    // Some implementations use broadcast MAC here too, but typically it's 00:00:00:00:00:00
    std::fill(arp_hdr->target_mac.bytes.begin(), arp_hdr->target_mac.bytes.end(), 0x00);
    arp_hdr->target_ip = target_ip; // Assumed already in network byte order

    std::cout << "Constructed ARP Request: SrcIP=" << source_ip << ", SrcMAC=";
    for(int i=0; i<6; ++i) std::cout << std::hex << (int)source_mac.bytes[i] << (i==5 ? "" : ":");
    std::cout << ", TgtIP=" << target_ip << std::dec << ". Sending on port " << egress_port << std::endl;

    // Send the packet
    switch_ref_.send_control_plane_packet(arp_packet, egress_port); // Changed to send_control_plane_packet
    // The Packet object created here will go out of scope. Its destructor will decrement_ref on PacketBuffer.
    // send_control_plane_packet should increment_ref if it needs to keep the packet alive asynchronously.
}

void ArpProcessor::send_arp_reply( IpAddress original_requester_ip, MacAddress original_requester_mac,
                                   IpAddress our_ip_for_reply, MacAddress our_mac_for_reply,
                                   uint32_t egress_port) {
    const size_t packet_size = EthernetHeader::SIZE + ArpHeader::SIZE;
    auto buffer = std::make_unique<PacketBuffer>(packet_size);
     if (!buffer->set_data_len(packet_size)) {
        std::cerr << "Failed to allocate buffer for ARP reply" << std::endl;
        return;
    }
    Packet arp_reply_packet(buffer.release());


    // Ethernet Header
    EthernetHeader* eth_hdr = arp_reply_packet.ethernet();
    if(!eth_hdr) {
        std::cerr << "Failed to get Ethernet header for ARP reply" << std::endl;
        return;
    }
    eth_hdr->dst_mac = original_requester_mac;
    eth_hdr->src_mac = our_mac_for_reply;
    eth_hdr->ethertype = htons(ETHERTYPE_ARP);

    // ARP Header
    // Accessing via eth_hdr pointer is slightly cleaner if eth_hdr is guaranteed to be start of buffer.
    ArpHeader* arp_hdr = reinterpret_cast<ArpHeader*>((uint8_t*)eth_hdr + EthernetHeader::SIZE);
    arp_hdr->hardware_type = htons(1); // Ethernet
    arp_hdr->protocol_type = htons(ETHERTYPE_IPV4); // IPv4
    arp_hdr->hardware_addr_len = 6;
    arp_hdr->protocol_addr_len = 4;
    arp_hdr->opcode = htons(ARP_OPCODE_REPLY);
    arp_hdr->sender_mac = our_mac_for_reply;
    arp_hdr->sender_ip = our_ip_for_reply; // Assumed network byte order
    arp_hdr->target_mac = original_requester_mac;
    arp_hdr->target_ip = original_requester_ip; // Assumed network byte order

    std::cout << "Constructed ARP Reply: OurIP=" << our_ip_for_reply << ", OurMAC=";
    for(int i=0; i<6; ++i) std::cout << std::hex << (int)our_mac_for_reply.bytes[i] << (i==5 ? "" : ":");
    std::cout << ", TgtIP=" << original_requester_ip << ", TgtMAC=";
    for(int i=0; i<6; ++i) std::cout << std::hex << (int)original_requester_mac.bytes[i] << (i==5 ? "" : ":");
    std::cout << std::dec << ". Sending on port " << egress_port << std::endl;

    switch_ref_.send_control_plane_packet(arp_reply_packet, egress_port); // Changed to send_control_plane_packet
}

void ArpProcessor::age_arp_cache() {
    // This is a simple aging implementation called during lookup.
    // A more robust solution might use a separate timer thread.
    // Assumes cache_mutex_ is locked by the caller (e.g. lookup_mac)
    // or if called independently, it must lock the mutex.
    auto now = std::chrono::steady_clock::now();
    for (auto it = arp_cache_.begin(); it != arp_cache_.end(); /* no increment */) {
        if (!it->second.is_static && (now - it->second.last_seen > ARP_CACHE_TIMEOUT)) {
            std::cout << "ARP Cache: Aging out entry for IP " << it->first << std::endl;
            it = arp_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace netflow
