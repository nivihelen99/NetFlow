#include "netflow/switch/switch.h"
#include "netflow/packet/Packet.h"
#include "netflow/packet/ethernet.h"
#include "netflow/packet/ip.h"
#include "netflow/protocols/arp.h"
#include "netflow/protocols/icmp.h" // Needed for handle_ip_packet_for_us

#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <vector>
#include <functional> // For std::bind

// Helper function to construct an Ethernet frame (e.g., for ARP or ICMP replies)
// This function creates a new Packet object.
// Assumes payload is L3 (e.g., ARP body, IP packet).
// vlan_id_tag_host_order: VLAN ID to tag the packet with (host order). 0 means no VLAN tag.
Packet create_reply_ethernet_frame(
    const std::array<uint8_t, 6>& dst_mac,
    const std::array<uint8_t, 6>& src_mac,
    uint16_t ethertype_host_order, // e.g. ETHERTYPE_ARP, ETHERTYPE_IP
    uint16_t vlan_id_tag_host_order, // 0 for no VLAN tag
    const std::vector<uint8_t>& l3_payload) {

    size_t eth_header_size = sizeof(EthernetHeader); // Corrected namespace
    size_t vlan_tag_size = (vlan_id_tag_host_order != 0) ? sizeof(netflow::packet::VlanTag) : 0;
    size_t total_size = eth_header_size + vlan_tag_size + l3_payload.size();
    
    std::vector<uint8_t> frame_data(total_size);
    unsigned char* ptr = frame_data.data();

    // Ethernet Header
    EthernetHeader* eth_h = reinterpret_cast<EthernetHeader*>(ptr);
    std::copy(dst_mac.begin(), dst_mac.end(), std::begin(eth_h->dest_mac)); // Corrected assignment
    std::copy(src_mac.begin(), src_mac.end(), std::begin(eth_h->src_mac)); // Corrected assignment
    
    ptr += eth_header_size;

    // VLAN Tag (optional)
    if (vlan_id_tag_host_order != 0) {
        eth_h->type = htons(netflow::packet::VLAN_TPID);
        netflow::packet::VlanTag* vlan_tag = reinterpret_cast<netflow::packet::VlanTag*>(ptr);
        vlan_tag->tci = htons(vlan_id_tag_host_order); // Assuming PCP=0, DEI=0 for simplicity
        vlan_tag->ethertype = htons(ethertype_host_order);
        ptr += vlan_tag_size;
    } else {
        eth_h->type = htons(ethertype_host_order);
    }

    // L3 Payload
    if (!l3_payload.empty()) {
        std::memcpy(ptr, l3_payload.data(), l3_payload.size());
    }
    
    return Packet(frame_data.data(), total_size);
}


namespace netflow {
namespace switch_logic {

// Constructor
Switch::Switch(int num_ports)
    : num_ports_(num_ports),
      fdb_(), 
      vlan_manager_(), 
      stp_manager_() // Removed (num_ports)
{
    // Set the default packet processor
    this->packet_processing_handler_ = 
        [this](const Packet& p, uint32_t ip) { 
            this->default_packet_processor(p, ip);
        };

    std::cout << "Switch: Initialized with " << num_ports_ << " ports. Default packet processor set." << std::endl;
}

// Component Accessors
ForwardingDatabase& Switch::fdb() { return fdb_; }
VlanManager& Switch::vlan_manager() { return vlan_manager_; }
StpManager& Switch::stp_manager() { return stp_manager_; }

// Configuration
void Switch::add_interface(int interface_id_int, const std::string& name,
                           uint32_t ip_address, // Host byte order
                           const std::array<uint8_t, 6>& mac_address) {
    uint32_t interface_id = static_cast<uint32_t>(interface_id_int);
    if (interface_id >= static_cast<uint32_t>(num_ports_)) {
        std::cerr << "Switch Error: Cannot add interface, ID " << interface_id << " is out of range (0-" << num_ports_-1 << ")." << std::endl;
        return;
    }
    if (interfaces_.count(interface_id)) {
        std::cerr << "Switch Error: Interface with ID " << interface_id << " already exists." << std::endl;
        return;
    }
    interfaces_[interface_id] = InterfaceInfo(ip_address, mac_address, name, interface_id_int); // Store original int id if needed by InterfaceInfo
    
    stp_manager_.configure_port(interface_id, 19, true); // Replaced StpManager::DEFAULT_PATH_COST with 19

    VlanManager::PortConfig default_port_vlan_config;
    default_port_vlan_config.type = VlanManager::PortType::ACCESS;
    default_port_vlan_config.access_vlan_id = DEFAULT_VLAN_ID; 
    vlan_manager_.configure_port(interface_id, default_port_vlan_config);

    char ip_str[INET_ADDRSTRLEN] = "N/A";
    if (ip_address != 0) {
        uint32_t ip_net_order_for_log = htonl(ip_address);
        inet_ntop(AF_INET, &ip_net_order_for_log, ip_str, INET_ADDRSTRLEN);
    }
    
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_address[0], mac_address[1], mac_address[2],
             mac_address[3], mac_address[4], mac_address[5]);

    std::cout << "Switch: Added interface '" << name << "' (ID: " << interface_id
              << "), IP: " << ip_str << ", MAC: " << mac_str
              << ". STP enabled. VLAN configured (default: Access, VLAN " 
              << DEFAULT_VLAN_ID << ")." << std::endl;
}

void Switch::set_send_packet_callback(
    std::function<void(int interface_id, const std::vector<uint8_t>& packet_data)> cb) {
    send_packet_callback_ = cb;
    std::cout << "Switch: Send packet callback " << (cb ? "set." : "cleared.") << std::endl;
}

void Switch::set_packet_handler(
    std::function<void(const Packet& pkt, uint32_t ingress_port)> handler) { 
    packet_processing_handler_ = handler;
    std::cout << "Switch: Packet processing handler " << (handler ? "set." : "cleared.") << std::endl;
}

// Operations
void Switch::handle_raw_frame(int interface_id_int, const uint8_t* data, size_t length) {
    uint32_t interface_id = static_cast<uint32_t>(interface_id_int);
    if (!data) {
        std::cerr << "Switch Error: Received null data pointer on interface " << interface_id << std::endl;
        return;
    }
    if (interface_id >= static_cast<uint32_t>(num_ports_)) {
        std::cerr << "Switch Error: Received packet on invalid interface ID " << interface_id << ". Dropping." << std::endl;
        return;
    }

    Packet packet_obj(data, length); 

    if (packet_obj.head() == nullptr) { 
        std::cerr << "Switch Error: Failed to construct or parse Packet object from raw data on interface " << interface_id << ". Dropping." << std::endl;
        return;
    }

    if (packet_processing_handler_) {
        packet_processing_handler_(packet_obj, interface_id);
    } else {
        std::cout << "Switch Warning: No packet processing handler set. Packet received on interface " 
                  << interface_id << " will be dropped." << std::endl;
    }
}

void Switch::forward_packet(const Packet& pkt, uint32_t egress_port_id) { 
    if (egress_port_id >= static_cast<uint32_t>(num_ports_)) {
        std::cerr << "Switch Error: Cannot forward packet, egress port ID " << egress_port_id << " is out of range." << std::endl;
        return;
    }
    if (send_packet_callback_) {
        if (pkt.head() && pkt.length() > 0) {
            std::vector<uint8_t> raw_data(pkt.head(), pkt.head() + pkt.length());
            send_packet_callback_(static_cast<int>(egress_port_id), raw_data);
        } else {
            std::cerr << "Switch Error: Cannot forward packet, Packet object has no data or zero length." << std::endl;
        }
    } else {
        // std::cerr << "Switch Warning: send_packet_callback_ not set. Cannot forward packet out of port " 
        //           << egress_port_id << "." << std::endl;
    }
}

void Switch::flood_packet(const Packet& pkt_const, uint32_t ingress_port_id) { 
    // Determine effective_vlan_id based on packet's state (already processed by ingress vlan_manager)
    uint16_t effective_vlan_id = pkt_const.vlan_id(); // This should be the internal, effective VLAN.
    if (effective_vlan_id == 0 && !pkt_const.has_vlan()) { // If truly untagged and ingress didn't assign one
        const VlanManager::PortConfig* port_conf = vlan_manager_.get_port_config(ingress_port_id);
        if (port_conf) {
            if (port_conf->type == VlanManager::PortType::ACCESS) effective_vlan_id = port_conf->access_vlan_id;
            else if (port_conf->type == VlanManager::PortType::NATIVE_VLAN) effective_vlan_id = port_conf->native_vlan_id;
            else { /* Pure trunk, untagged packet - should have been handled or dropped by ingress */ return; }
        } else { /* No port config */ return; }
    }
    if (effective_vlan_id == 0) { /* Still no valid VLAN context */ return; }


    for (uint32_t i = 0; i < static_cast<uint32_t>(num_ports_); ++i) {
        if (i == ingress_port_id) continue;
        if (!vlan_manager_.should_forward(i, effective_vlan_id)) continue;
        if (!stp_manager_.should_forward(i)) continue;
        
        Packet mutable_pkt_for_egress(pkt_const.head(), pkt_const.length()); 
        if (mutable_pkt_for_egress.head() == nullptr) continue;

        if (vlan_manager_.process_egress(mutable_pkt_for_egress, i, effective_vlan_id)) {
            forward_packet(mutable_pkt_for_egress, i);
        }
    }
}

void Switch::start() {
    std::cout << "Switch: Started." << std::endl;
}

// --- Default Packet Processor Implementation ---
InterfaceInfo* Switch::get_interface_info(uint32_t port_id) {
    auto it = interfaces_.find(port_id);
    if (it != interfaces_.end()) {
        return &it->second;
    }
    return nullptr;
}

void Switch::default_packet_processor(const Packet& const_pkt, uint32_t ingress_port) { 
    Packet pkt = const_pkt; // Mutable copy 

    const InterfaceInfo* ingress_if_info = get_interface_info(ingress_port);
    // Note: ingress_if_info can be null if the port is not an L3 interface for the switch.
    // This is fine; L2 forwarding doesn't require the switch to have an IP/MAC on that port.

    // 1. Ingress VLAN Processing
    uint16_t effective_vlan_id = vlan_manager_.process_ingress(pkt, ingress_port);
    if (effective_vlan_id == VlanManager::VLAN_DROP) {
        // std::cout << "DPP: Packet dropped by ingress VLAN rules on port " << ingress_port << std::endl;
        return;
    }
    // After vlan_manager_.process_ingress, pkt might be modified (e.g. VLAN tag pushed).
    // The effective_vlan_id is the VLAN context for further processing.

    // 2. STP Check for Ingress Port - BPDUs are handled by MAC check. Data frames checked at egress.
    // For now, we assume BPDUs are handled by MAC check. Data frames are processed,
    // and STP state is checked before egress.

    // 3. L2 Logic: MAC Learning
    StpPortState ingress_stp_state = stp_manager_.get_port_state(ingress_port); // Changed StpManager::StpPortState
    if (ingress_stp_state == StpPortState::LEARNING ||  // Changed StpManager::StpPortState
        ingress_stp_state == StpPortState::FORWARDING) { // Changed StpManager::StpPortState
        fdb_.learn_mac(pkt.src_mac(), effective_vlan_id, ingress_port);
    }

    // 4. Destination MAC Check
    bool for_us_mac = false;
    const std::array<uint8_t, 6>& dst_mac_arr = pkt.dst_mac();

    // Check for STP BPDU MAC
    const std::array<uint8_t, 6> stp_bpdu_mac = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
    if (dst_mac_arr == stp_bpdu_mac) {
        // Packet::get_l3_header_ptr() and get_l3_payload_len() are not standard.
        // A BPDU is typically not an L3 packet in the IP/ARP sense. It's the payload after Ethernet/VLAN.
        // Let's assume Packet::head() + l3_offset (from parse_packet) gives the start of BPDU payload
        // and Packet::length() - l3_offset gives its length.
        // This needs careful alignment with how Packet parses non-IP/ARP frames.
        // For now, we will pass the raw payload after L2.
        // The Packet::parse_packet() sets l3_offset_ after Ethernet and VLAN.
        if(pkt.get_l3_offset() != -1 && pkt.length() > static_cast<size_t>(pkt.get_l3_offset())) {
             stp_manager_.process_bpdu(pkt.head() + pkt.get_l3_offset(), pkt.length() - pkt.get_l3_offset(), ingress_port);
        } else {
            // std::cerr << "DPP: Could not extract BPDU payload from packet on port " << ingress_port << std::endl;
        }
        return; // BPDU handled
    }

    for (const auto& pair : interfaces_) {
        if (dst_mac_arr == pair.second.mac_address) {
            for_us_mac = true;
            break;
        }
    }
    // Also consider broadcast MAC if applicable for certain L3 protocols (e.g. ARP broadcast part)
    // but ARP is handled by EtherType. For IP routing, broadcast MAC is usually not "for us" unless it's a subnet broadcast.

    // 5. L3 Logic
    uint16_t eth_type = pkt.get_actual_ethertype(); // Host order

    if (eth_type == netflow::packet::ETHERTYPE_ARP) {
        handle_arp_packet(pkt, ingress_port, effective_vlan_id, ingress_if_info);
        return;
    } else if (eth_type == netflow::packet::ETHERTYPE_IP) {
        if (for_us_mac) { // IP packet to one of our interface MACs
            handle_ip_packet_for_us(pkt, ingress_port, effective_vlan_id, ingress_if_info);
        } else { // IP packet to another MAC, potentially needs routing
            route_ip_packet(pkt, ingress_port, effective_vlan_id);
        }
        return;
    }

    // 6. L2 Forwarding (if not handled by L3 and not specifically for our MAC by L3 logic)
    // This is for unknown unicast, multicast, or broadcast that wasn't an STP BPDU or an L3 packet for us.
    if (!for_us_mac) { // If it was for_us_mac but not IP/ARP, it's an unhandled L2 protocol for the switch.
        uint32_t egress_port = fdb_.lookup_port(dst_mac_arr, effective_vlan_id);
        if (egress_port != ForwardingDatabase::FDB_PORT_NOT_FOUND && egress_port != ingress_port) {
            if (stp_manager_.should_forward(egress_port)) {
                // Make a new mutable copy for egress processing
                Packet egress_pkt(pkt.head(), pkt.length()); 
                if (egress_pkt.head() && vlan_manager_.process_egress(egress_pkt, egress_port, effective_vlan_id)) {
                    forward_packet(egress_pkt, egress_port);
                }
            } else {
                // std::cout << "DPP: L2 forwarding to port " << egress_port << " blocked by STP." << std::endl;
            }
        } else { // MAC not found or destination is ingress port (should not happen if FDB is correct)
            // std::cout << "DPP: MAC not found in FDB for VLAN " << effective_vlan_id << " or egress is ingress. Flooding." << std::endl;
            flood_packet(pkt, ingress_port); // flood_packet handles STP and egress VLAN internally
        }
    } else {
        // Packet was for our MAC, but not ARP or IP. Example: L2 ping, CDP, LLDP etc.
        // std::cout << "DPP: Unhandled L2 protocol (EtherType: 0x" << std::hex << eth_type << std::dec
        //           << ") for switch's MAC on port " << ingress_port << ". Dropping." << std::endl;
    }
}


// --- Helper Method Implementations ---

void Switch::handle_arp_packet(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id, const InterfaceInfo* ingress_if_info) { 
    if (!ingress_if_info || ingress_if_info->ip_address == 0) { // Need an IP configured on the ingress L3 interface
        // std::cout << "DPP: ARP received on port " << ingress_port << " which has no L3 config or IP. Dropping ARP." << std::endl;
        return;
    }

    // Assuming Packet::get_l3_offset() gives the start of ARP payload
    const uint8_t* arp_data_ptr = pkt.head() + pkt.get_l3_offset();
    size_t arp_data_len = pkt.length() - pkt.get_l3_offset();

    if (pkt.get_l3_offset() == -1 || arp_data_len < sizeof(netflow::protocols::arp::ArpHeader)) {
        // std::cerr << "DPP: Invalid ARP packet (no L3 offset or too short) on port " << ingress_port << std::endl;
        return;
    }
    
    std::vector<uint8_t> arp_reply_payload_raw; // This is just the ARP body
    auto arp_result = netflow::protocols::arp::process_arp_packet(
        arp_cache_, 
        arp_data_ptr, 
        arp_data_len, 
        ingress_if_info->ip_address, // Host order
        ingress_if_info->mac_address,
        arp_reply_payload_raw
    );

    if (arp_result == netflow::protocols::arp::ArpProcessResult::REQUEST_HANDLED_REPLY_SENT) {
        if (arp_reply_payload_raw.empty()) {
            // std::cerr << "DPP: process_arp_packet indicated reply sent, but payload is empty." << std::endl;
            return;
        }

        // Determine Dst MAC for reply (original sender of request)
        // The arp_reply_payload_raw is the ARP packet itself. Its target MAC field contains original sender's MAC.
        // However, the process_arp_packet already put the correct target MAC in the ARP reply header.
        // We need the Ethernet Dst MAC which is the sender_mac of the original ARP request.
        const netflow::protocols::arp::ArpHeader* original_arp_request = 
            reinterpret_cast<const netflow::protocols::arp::ArpHeader*>(arp_data_ptr);

        Packet reply_pkt = create_reply_ethernet_frame( 
            original_arp_request->sender_mac, // Dst MAC for Ethernet frame
            ingress_if_info->mac_address,     // Src MAC for Ethernet frame
            netflow::packet::ETHERTYPE_ARP,   // EtherType
            vlan_id,                          // Tag with the ingress VLAN ID. process_egress will handle if it needs to be stripped.
            arp_reply_payload_raw             // ARP packet payload
        );
        
        if (reply_pkt.head() && vlan_manager_.process_egress(reply_pkt, ingress_port, vlan_id)) {
            forward_packet(reply_pkt, ingress_port);
        }
    }
}

void Switch::handle_ip_packet_for_us(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id, const InterfaceInfo* ingress_if_info) { 
    IpHeader* ip_hdr = pkt.ipv4(); // Changed netflow::packet::IpHeader to IpHeader
    if (!ip_hdr) return;

    if (ip_hdr->protocol == netflow::packet::IPPROTO_ICMP) {
        // Ensure ingress_if_info is valid if we need its MAC for ICMP reply source MAC.
        if (!ingress_if_info) {
             // This can happen if IP packet is to switch's IP but not via a configured L3 interface's MAC.
             // Or if the dst_mac was broadcast and switch IP matched.
             // For now, we require ingress_if_info to source the reply.
             // A global switch MAC could be used if ingress_if_info is null.
            // std::cerr << "DPP: ICMP for us, but no L3 interface info for ingress port " << ingress_port << ". Cannot reply." << std::endl;
            return;
        }
        
        // L4 header pointer and length from Packet class
        const uint8_t* icmp_data_ptr = pkt.head() + pkt.get_l4_offset();
        size_t icmp_data_len = pkt.length() - pkt.get_l4_offset();

        if (pkt.get_l4_offset() == -1 || icmp_data_len < sizeof(netflow::protocols::icmp::IcmpHeader) /*min ICMP size*/) {
            // std::cerr << "DPP: Invalid ICMP packet (no L4 offset or too short) on port " << ingress_port << std::endl;
            return;
        }

        std::vector<uint8_t> icmp_reply_payload_only; // This is just the ICMP part of the reply
        
        // process_icmp_packet expects source/dest IP from the incoming packet's IP header for context (e.g. for pseudoheader in checksum)
        // but current icmp.h for process_icmp_packet does not take them.
        // Passing the raw ICMP payload.
        auto icmp_result = netflow::protocols::icmp::process_icmp_packet(
            icmp_data_ptr, 
            icmp_data_len,
            icmp_reply_payload_only
        );

        if (icmp_result == netflow::protocols::icmp::IcmpProcessResult::ECHO_REQUEST_RECEIVED_REPLY_GENERATED) {
            if (icmp_reply_payload_only.empty()) {
                // std::cerr << "DPP: process_icmp_packet indicated reply sent, but payload is empty." << std::endl;
                return;
            }

            // Construct full IP reply
            // New IP Header: src=our_ip (dst_ip of original), dst=original_src_ip
            // TTL, checksum.
            std::vector<uint8_t> ip_reply_payload; // This will be the full IP packet (new IP header + ICMP reply)
            
            // Simplified IP header construction for reply
            IpHeader new_ip_hdr; // Changed netflow::packet::IpHeader to IpHeader
            new_ip_hdr.version = 4;
            new_ip_hdr.ihl = 5; // No options
            new_ip_hdr.tos = 0;
            new_ip_hdr.tot_len = htons(sizeof(IpHeader) + icmp_reply_payload_only.size()); // Changed netflow::packet::IpHeader to IpHeader
            new_ip_hdr.id = htons(0); // Simple ID
            new_ip_hdr.frag_off = 0;
            new_ip_hdr.ttl = 64; // Standard TTL
            new_ip_hdr.protocol = netflow::packet::IPPROTO_ICMP;
            new_ip_hdr.check = 0; // Calculate later
            new_ip_hdr.saddr = ip_hdr->daddr; // Our IP is the original destination
            new_ip_hdr.daddr = ip_hdr->saddr; // Reply to original source

            // Calculate IP checksum (standard algorithm)
            // For simplicity, assume calculate_icmp_checksum can be adapted or a similar one exists for IP.
            // new_ip_hdr.check = calculate_ip_header_checksum(&new_ip_hdr, sizeof(new_ip_hdr)); // Placeholder

            // Calculate IP checksum
            new_ip_hdr.check = 0; // Zero out for calculation
            new_ip_hdr.check = calculate_ip_header_checksum(&new_ip_hdr); // Changed netflow::packet::calculate_ip_header_checksum


            ip_reply_payload.resize(sizeof(IpHeader) + icmp_reply_payload_only.size()); // Changed netflow::packet::IpHeader to IpHeader
            std::memcpy(ip_reply_payload.data(), &new_ip_hdr, sizeof(IpHeader)); // Changed netflow::packet::IpHeader to IpHeader
            std::memcpy(ip_reply_payload.data() + sizeof(IpHeader), icmp_reply_payload_only.data(), icmp_reply_payload_only.size()); // Changed netflow::packet::IpHeader to IpHeader
            
            // ARP for original sender's MAC
            std::array<uint8_t, 6> next_hop_mac;
            bool found_mac = arp_cache_.lookup(ntohl(ip_hdr->saddr), next_hop_mac);

            if (found_mac) {
                Packet reply_pkt = create_reply_ethernet_frame( 
                    next_hop_mac,
                    ingress_if_info->mac_address,
                    netflow::packet::ETHERTYPE_IP,
                    vlan_id, // Tag with ingress VLAN
                    ip_reply_payload
                );

                if (reply_pkt.head() && vlan_manager_.process_egress(reply_pkt, ingress_port, vlan_id)) {
                    forward_packet(reply_pkt, ingress_port);
                }
            } else {
                // std::cout << "DPP: ARP miss for ICMP reply destination " << ntohl(ip_hdr->saddr) << std::endl;
                // TODO: Queue packet and send ARP request
            }
        }
    } else {
        // std::cout << "DPP: IP packet for switch's MAC (protocol " << (int)ip_hdr->protocol 
        //           << ") on port " << ingress_port << " - not ICMP, not handled." << std::endl;
    }
}

void Switch::route_ip_packet(Packet& pkt, uint32_t ingress_port, uint16_t vlan_id) { 
    IpHeader* ip_hdr = pkt.ipv4(); // Changed netflow::packet::IpHeader to IpHeader
    if (!ip_hdr) return;

    // Decrement TTL
    if (ip_hdr->ttl <= 1) {
        // std::cout << "DPP: IP packet TTL expired. Dropping." << std::endl;
        // TODO: Send ICMP Time Exceeded
        return;
    }
    // pkt.is_mutable() check would be good here if Packet class supports it.
    // For now, assume we can modify if it's a non-const Packet&.
    ip_hdr->ttl--; 
    pkt.update_ip_checksum(); // Recalculate IP header checksum after TTL change

    netflow::core::Flow flow(
        ntohl(ip_hdr->saddr), 
        ntohl(ip_hdr->daddr), 
        pkt.get_src_port(), // Already host order
        pkt.get_dst_port(), // Already host order
        ip_hdr->protocol
    );
    
    int action_out_port_id_int = -1; 
    if (flow_table_.get_flow_action(flow, action_out_port_id_int) && 
        action_out_port_id_int != -1 && 
        static_cast<uint32_t>(action_out_port_id_int) != ingress_port) {
        
        uint32_t action_out_port_id = static_cast<uint32_t>(action_out_port_id_int);

        if (stp_manager_.should_forward(action_out_port_id)) {
            InterfaceInfo* egress_if_info = get_interface_info(action_out_port_id);
            if (!egress_if_info) { // Should not happen if port is part of switch and configured
                // std::cerr << "DPP Route: Egress interface " << action_out_port_id << " not found for routing." << std::endl;
                return;
            }

            // Determine next-hop IP (simplified: assume DstIP is directly reachable or FlowTable gives final DstIP)
            uint32_t next_hop_ip_host = ntohl(ip_hdr->daddr); // Simplified: target is next hop
            // In a real router, this would come from a routing table lookup.

            std::array<uint8_t, 6> next_hop_mac;
            bool found_mac = arp_cache_.lookup(next_hop_ip_host, next_hop_mac);

            if (found_mac) {
                // Mutate packet: update MAC addresses
                // This mutable 'pkt' is a copy made in default_packet_processor
                pkt.set_src_mac(egress_if_info->mac_address);
                pkt.set_dst_mac(next_hop_mac);
                
                // TODO: Recalculate IP checksum due to TTL change. Packet needs method.
                // pkt.update_ip_checksum(); 

                // Determine egress VLAN. This is complex.
                // If routing from VLAN A to VLAN B, packet needs to be tagged for VLAN B on egress if trunk.
                // For simplicity, assume FlowTable implies the target L3 network, and we find appropriate VLAN for that.
                // Or, if it's an L3 interface, use its native/access VLAN.
                const VlanManager::PortConfig* egress_port_cfg = vlan_manager_.get_port_config(action_out_port_id);
                if(!egress_port_cfg) return; // Should not happen

                uint16_t egress_vlan_id = 0;
                if (egress_port_cfg->type == VlanManager::PortType::ACCESS) {
                    egress_vlan_id = egress_port_cfg->access_vlan_id;
                } else { // TRUNK or NATIVE_VLAN
                    // This is tricky. If routing, the packet is now "owned" by the router.
                    // It should emerge on the egress VLAN associated with the *next hop's network*.
                    // For now, let's assume the original vlan_id context is somehow passed or determined for the egress segment.
                    // Or, if egress L3 interface has a specific VLAN, use that.
                    // For now, use the vlan_id of the *ingress* packet if it's a trunk, or native if untagged.
                    // This is a simplification for L3 routing across VLANs.
                    // A proper solution needs routing table to provide egress VLAN context or L3 interface VLAN.
                
                // The subtask prompt was simplified to: "For now, assume the original vlan_id context is used for egress."
                // If the packet was modified (e.g. MACs), it's already 'pkt'.
                // The egress_vlan_id should be determined based on routing decision for the *next hop's network/interface*.
                // Using ingress 'vlan_id' here is a placeholder as per previous simplifications.
                // A more robust solution would involve the routing table providing the egress L3 interface,
                // and from that, the correct VLAN context for the egress segment.
                egress_vlan_id = vlan_id; // Using ingress vlan_id as a placeholder for egress VLAN context.
                                          // This will likely need to be more sophisticated for real inter-VLAN routing.
                }


                if (vlan_manager_.process_egress(pkt, action_out_port_id, egress_vlan_id)) {
                    forward_packet(pkt, action_out_port_id);
                }
            } else {
                // std::cout << "DPP Route: ARP miss for next hop " << next_hop_ip_host << " on port " << action_out_port_id << ". Dropping." << std::endl;
                // TODO: Queue packet, send ARP request for next_hop_ip_host on action_out_port_id's VLAN context.
            }
        } else {
            // std::cout << "DPP Route: Egress port " << action_out_port_id << " blocked by STP. Dropping." << std::endl;
        }
    } else {
        // std::cout << "DPP Route: Flow miss or invalid egress port for IP packet. Dropping." << std::endl;
        // TODO: Potentially send to CPU/Controller for routing decision / ARP for default gateway etc.
    }
}

// --- Test-specific helper implementations ---
void Switch::add_flow_entry_for_test(const netflow::core::Flow& flow, int action_out_port_id) {
    flow_table_.add_flow(flow, action_out_port_id);
}

void Switch::add_arp_entry_for_test(uint32_t ip_address_host_order, const MACAddress& mac) {
    // ArpCache::add_entry takes IP in host order.
    arp_cache_.add_entry(ip_address_host_order, mac);
}

void Switch::clear_flow_table_for_test() {
    flow_table_.clear_flows();
}

void Switch::clear_arp_cache_for_test() {
    // Re-initialize arp_cache_ to clear it.
    // Assuming default timeout is acceptable for tests, or get it from existing arp_cache_ if needed.
    // For simplicity, using default.
    arp_cache_ = netflow::protocols::arp::ArpCache(std::chrono::seconds(300)); 
}

}  // namespace switch_logic
}  // namespace netflow


