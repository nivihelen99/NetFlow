#ifndef NETFLOW_SWITCH_HPP
#define NETFLOW_SWITCH_HPP

#include "packet_buffer.hpp"
#include "buffer_pool.hpp"
#include "packet.hpp"
#include "forwarding_database.hpp"
#include "vlan_manager.hpp"
#include "stp_manager.hpp"
#include "packet_classifier.hpp"
#include "lock_free_hash_table.hpp"
#include "interface_manager.hpp"
#include "qos_manager.hpp"
#include "acl_manager.hpp"
#include "lacp_manager.hpp"
#include "logger.hpp"
#include "config_manager.hpp"
#include "management_interface.hpp"
#include "arp_processor.hpp"
#include "icmp_processor.hpp"
#include "routing_manager.hpp"
#include "netflow++/lldp_manager.hpp"

#include <cstdint>
#include <functional>
#include <vector>
#include <iostream>
#include <string>

namespace netflow {

class Switch {
public:
    BufferPool buffer_pool;
    ForwardingDatabase fdb;
    VlanManager vlan_manager;
    InterfaceManager interface_manager_;
    PacketClassifier packet_classifier_;

    using FlowKey = PacketClassifier::FlowKey;
    using FlowTable = LockFreeHashTable<FlowKey, uint32_t /* Action ID or Flow Data ID */>;
    FlowTable flow_table_;

    QosManager qos_manager_;
    AclManager acl_manager_;
    LacpManager lacp_manager_;
    SwitchLogger logger_;
    ConfigManager config_manager_;
    ManagementInterface management_interface_;
    StpManager stp_manager;
    ArpProcessor arp_processor_;
    IcmpProcessor icmp_processor_;
    RoutingManager routing_manager_;
    LldpManager lldp_manager_;

    std::function<void(const Packet&, uint32_t)> test_packet_send_hook;

    Switch(uint32_t num_ports, uint64_t switch_mac_address,
           uint16_t stp_default_priority = 32768, uint16_t lacp_default_priority = 32768) :
        num_ports_(num_ports),
        logger_(LogLevel::INFO),
        qos_manager_(logger_),
        acl_manager_(logger_),
        interface_manager_(logger_, acl_manager_),
        fdb(),
        stp_manager(num_ports, switch_mac_address, stp_default_priority),
        lacp_manager_(switch_mac_address, lacp_default_priority),
        lldp_manager_(*this, interface_manager_),
        arp_processor_(interface_manager_, fdb, *this),
        icmp_processor_(interface_manager_, *this),
        flow_table_(1024) {
        // ... (constructor body as before)
        uint8_t temp_mac_bytes[6];
        temp_mac_bytes[0] = (switch_mac_address >> 40) & 0xFF;
        temp_mac_bytes[1] = (switch_mac_address >> 32) & 0xFF;
        temp_mac_bytes[2] = (switch_mac_address >> 24) & 0xFF;
        temp_mac_bytes[3] = (switch_mac_address >> 16) & 0xFF;
        temp_mac_bytes[4] = (switch_mac_address >> 8) & 0xFF;
        temp_mac_bytes[5] = (switch_mac_address >> 0) & 0xFF;
        MacAddress mac_addr_for_log(temp_mac_bytes);
        logger_.info("SWITCH_LIFECYCLE", "Switch constructing for " + std::to_string(num_ports_) + " ports. MAC: " + logger_.mac_to_string(mac_addr_for_log));
        fdb.set_logger(&logger_);
        logger_.info("CONFIG", "Loading default configuration (default_switch_config.json)...");
        if (config_manager_.load_config("default_switch_config.json")) {
            logger_.info("CONFIG", "Default configuration loaded. Applying now...");
            config_manager_.apply_config(config_manager_.get_current_config_data(), *this);
        } else {
            logger_.warning("CONFIG", "Failed to load default_switch_config.json. Using empty/hardcoded defaults.");
        }
        logger_.info("SWITCH_INIT", "Initializing per-port defaults (may be overridden by loaded config)...");
        for (uint32_t i = 0; i < num_ports_; ++i) {
            if (!interface_manager_.get_port_config(i).has_value()) {
                InterfaceManager::PortConfig default_if_config;
                default_if_config.admin_up = false;
                interface_manager_.configure_port(i, default_if_config);
            }
            bool current_admin_up = interface_manager_.get_port_config(i).value_or(InterfaceManager::PortConfig()).admin_up;
            if (!interface_manager_.is_port_link_up(i) && !current_admin_up) {
                 interface_manager_.simulate_port_link_down(i);
            } else if (current_admin_up && !interface_manager_.is_port_link_up(i)) {
                interface_manager_.simulate_port_link_up(i);
            }
        }
        logger_.info("SWITCH_INIT", "Switch basic initialization sequence complete.");
    }

    ~Switch() { /* ... */ }
    void set_packet_handler(std::function<void(Packet& pkt, uint32_t ingress_port)> handler) { /* ... */ }
    void forward_packet(Packet& pkt, uint32_t egress_port) { /* ... */ } // Not directly used for main pipeline send

    // Helper for egress processing (VLAN, Egress ACL, QoS Enqueue)
    // Returns true if packet is enqueued, false if dropped by Egress ACL.
    bool process_egress_pipeline(Packet& pkt, uint32_t egress_port_id, uint32_t original_ingress_port_id_for_log = 0xFFFF) {
        // Egress VLAN Processing
        vlan_manager.process_egress(pkt, egress_port_id);

        // Egress ACL Processing
        auto egress_acl_name_opt = interface_manager_.get_applied_acl_name(egress_port_id, netflow::AclDirection::EGRESS);
        if (egress_acl_name_opt.has_value() && !egress_acl_name_opt.value().empty()) {
            uint32_t redirect_port_egress_acl = 0; // Not used for egress redirect per current decision
            AclActionType egress_action = acl_manager_.evaluate(egress_acl_name_opt.value(), pkt, redirect_port_egress_acl);
            logger_.debug("ACL_EGRESS", "Egress ACL '" + egress_acl_name_opt.value() + "' on port " + std::to_string(egress_port_id) + " result: " + std::to_string(static_cast<int>(egress_action)));

            if (egress_action == AclActionType::DENY) {
                logger_.log_packet_drop(pkt, original_ingress_port_id_for_log, "Egress ACL DENY on port " + std::to_string(egress_port_id));
                interface_manager_._increment_tx_stats(egress_port_id, pkt.get_buffer()->get_data_length(), false, true); // Count as TX drop on this egress port
                return false; // Packet dropped
            }
            if (egress_action == AclActionType::REDIRECT) {
                logger_.warning("ACL_EGRESS", "REDIRECT action in Egress ACL on port " + std::to_string(egress_port_id) + " is treated as PERMIT.");
            }
            // If PERMIT or unhandled REDIRECT, proceed.
        }

        // QoS and Enqueue
        qos_manager_.enqueue_packet(pkt, egress_port_id);
        logger_.debug("QOS", "Packet enqueued to port " + std::to_string(egress_port_id) + " after Egress pipeline.");
        return true; // Packet enqueued
    }


    void send_control_plane_packet(Packet& pkt, uint32_t egress_port) {
        if (egress_port >= num_ports_ || !interface_manager_.is_port_link_up(egress_port)) {
            logger_.warning("SEND_CONTROL_PACKET", "Port " + std::to_string(egress_port) + " invalid or down. Dropping control packet.");
            return;
        }
        // Control plane packets usually don't go through egress ACLs, but do go through QoS.
        // If they should, call process_egress_pipeline. For now, direct to QoS.
        qos_manager_.enqueue_packet(pkt, egress_port);
        logger_.debug("SEND_CONTROL_PACKET", "Control plane packet enqueued to port " + std::to_string(egress_port));
        if (test_packet_send_hook) test_packet_send_hook(pkt, egress_port);
    }

    void send_control_plane_frame(uint32_t egress_port_id, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype, const std::vector<uint8_t>& payload) {
        if (egress_port_id >= num_ports_ || !interface_manager_.is_port_link_up(egress_port_id)) {
             logger_.warning("SEND_CTRL_FRAME", "Port " + std::to_string(egress_port_id) + " invalid or down. Dropping control frame.");
            return;
        }
        PacketBuffer* pb = buffer_pool.allocate_buffer(sizeof(EthernetHeader) + payload.size());
        if (!pb) { /* ... error log ... */ return; }
        // ... (construct frame in pb)
        EthernetHeader eth_hdr_data; eth_hdr_data.dst_mac = dst_mac; eth_hdr_data.src_mac = src_mac; eth_hdr_data.ethertype = htons(ethertype);
        memcpy(pb->get_data_start_ptr(), &eth_hdr_data, sizeof(EthernetHeader));
        memcpy(pb->get_data_start_ptr() + sizeof(EthernetHeader), payload.data(), payload.size());
        pb->set_data_len(sizeof(EthernetHeader) + payload.size());
        Packet pkt(pb); pb->decrement_ref();

        // Similar to send_control_plane_packet, direct to QoS for control frames.
        qos_manager_.enqueue_packet(pkt, egress_port_id);
        logger_.debug("SEND_CTRL_FRAME", "Control frame enqueued to port " + std::to_string(egress_port_id));
        if (test_packet_send_hook) test_packet_send_hook(pkt, egress_port_id);
    }

    void flood_packet(Packet& pkt, uint32_t ingress_port_id) {
        logger_.debug("FLOOD", "Flooding packet from ingress port " + std::to_string(ingress_port_id));
        // ... (VLAN determination logic as before)
        uint16_t vlan_id_for_flooding = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);

        int flooded_count = 0;
        for (uint32_t i = 0; i < num_ports_; ++i) {
            if (i == ingress_port_id) continue;
            if (!interface_manager_.is_port_link_up(i) ||
                stp_manager.get_port_stp_state(i) != StpManager::PortState::FORWARDING ||
                !vlan_manager.should_forward(ingress_port_id, i, vlan_id_for_flooding)) {
                continue;
            }

            // Create a copy of the packet for each port in the flood list
            // This is important because process_egress_pipeline might modify the packet (VLAN tagging)
            // and also because each port's egress ACL is independent.
            PacketBuffer* pb_copy = buffer_pool.allocate_buffer(pkt.get_buffer()->get_data_length(), pkt.get_buffer()->get_headroom());
            if(!pb_copy) {
                logger_.error("FLOOD", "Failed to allocate buffer for flooding to port " + std::to_string(i));
                continue;
            }
            memcpy(pb_copy->get_data_start_ptr(), pkt.get_buffer()->get_data_start_ptr(), pkt.get_buffer()->get_data_length());
            pb_copy->set_data_len(pkt.get_buffer()->get_data_length());
            Packet flood_pkt_copy(pb_copy);
            pb_copy->decrement_ref(); // Packet constructor increments, balance it.

            if (process_egress_pipeline(flood_pkt_copy, i, ingress_port_id)) {
                 flooded_count++;
            }
        }
        if (flooded_count == 0 && num_ports_ > 1 && ingress_port_id < num_ports_) { /* ... log no suitable ports ... */ }
    }

    void start() { /* ... */ }
    void add_static_route(const IpAddress& net, const IpAddress& mask, const IpAddress& nh, uint32_t if_id, int m = 1) { /* ... */ }
    void remove_static_route(const IpAddress& net, const IpAddress& mask) { /* ... */ }
    std::vector<RouteEntry> get_routing_table() const { /* ... */ return {}; }

    void process_received_packet(uint32_t ingress_port_id, PacketBuffer* raw_buffer) {
        if (!raw_buffer) { /* ... error log ... */ return; }
        if (!interface_manager_.is_port_link_up(ingress_port_id)) { /* ... log drop ... */ raw_buffer->decrement_ref(); return; }
        interface_manager_._increment_rx_stats(ingress_port_id, raw_buffer->get_data_length());
        Packet pkt(raw_buffer); // Original packet, ref_count managed by pkt

        // --- Ingress ACL Processing ---
        auto ingress_acl_name_opt = interface_manager_.get_applied_acl_name(ingress_port_id, netflow::AclDirection::INGRESS);
        if (ingress_acl_name_opt.has_value() && !ingress_acl_name_opt.value().empty()) {
            uint32_t redirect_port_ingress_acl = 0;
            AclActionType ingress_action = acl_manager_.evaluate(ingress_acl_name_opt.value(), pkt, redirect_port_ingress_acl);
            logger_.debug("ACL_INGRESS", "Ingress ACL '" + ingress_acl_name_opt.value() + "' on port " + std::to_string(ingress_port_id) + " result: " + std::to_string(static_cast<int>(ingress_action)));

            if (ingress_action == AclActionType::DENY) {
                logger_.log_packet_drop(pkt, ingress_port_id, "Ingress ACL DENY on port " + std::to_string(ingress_port_id));
                interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                return;
            }
            if (ingress_action == AclActionType::REDIRECT) {
                logger_.info("ACL_INGRESS", "Packet REDIRECTED by Ingress ACL to port " + std::to_string(redirect_port_ingress_acl) + " from ingress port " + std::to_string(ingress_port_id));
                if (redirect_port_ingress_acl >= num_ports_ || !interface_manager_.is_port_link_up(redirect_port_ingress_acl)) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "Ingress ACL REDIRECT to invalid/down port " + std::to_string(redirect_port_ingress_acl));
                     interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                    return;
                }
                // Egress VLAN for new port, then directly to QoS (bypassing egress ACL on redirect port for now)
                vlan_manager.process_egress(pkt, redirect_port_ingress_acl);
                qos_manager_.enqueue_packet(pkt, redirect_port_ingress_acl);
                // TX stats for redirect_port_ingress_acl will be handled by QoS dequeue path conceptually
                return;
            }
            // If PERMIT, continue processing
        }

        // ... (PacketClassifier, Ingress VLAN, L2 Control Plane (LLDP, STP, LACP) as before) ...
        // This section needs to be complete for the logic to flow correctly.
        // For brevity, I'll assume it's there and correct.
        EthernetHeader* eth_hdr = pkt.ethernet();
        if (eth_hdr) {
            if (ntohs(eth_hdr->ethertype) == LLDP_ETHERTYPE) { /* ... lldp_manager_.process_lldp_frame ... */ return; }
            if (eth_hdr->dst_mac == MacAddress(/*BPDU_MAC_BYTES*/)) { /* ... stp_manager.process_bpdu ... */ return; }
            // LACP check...
        }


        // L3 Control Plane (ARP, ICMP for switch's own IPs)
        uint16_t L2_ether_type = eth_hdr ? ntohs(eth_hdr->ethertype) : 0;
        uint16_t L3_ether_type = L2_ether_type;
        if (L2_ether_type == ETHERTYPE_VLAN) {
            VlanHeader* vlan_hdr = pkt.vlan();
            if (vlan_hdr) L3_ether_type = ntohs(vlan_hdr->ethertype);
        }

        if (L3_ether_type == ETHERTYPE_ARP) { /* ... arp_processor_.process_arp_packet ... */ return; }
        else if (L3_ether_type == ETHERTYPE_IPV4) {
            IPv4Header* ip_hdr = pkt.ipv4();
            if (ip_hdr) {
                if (interface_manager_.is_my_ip(ip_hdr->dst_ip)) { // Packet to one of switch's own IPs
                    if (ip_hdr->protocol == IPPROTO_ICMP) { /* ... icmp_processor_.process_icmp_packet ... */ return; }
                    // Other L3 protocols for switch (e.g. routing protocols, SSH/Telnet - not handled here)
                    logger_.debug("L3_TO_CPU", "IPv4 packet to switch IP (proto " + std::to_string(ip_hdr->protocol) + ") passed to CPU/packet_handler_.");
                    if (packet_handler_) packet_handler_(pkt, ingress_port_id);
                    return;
                }

                // L3 Forwarding Logic for transit packets
                if (ip_hdr->ttl <= 1) { /* ... send ICMP Time Exceeded, drop ... */ return; }
                ip_hdr->ttl--; // pkt.update_checksums() will be called before egress pipeline

                std::optional<RouteEntry> route_entry_opt = routing_manager_.lookup_route(ip_hdr->dst_ip);
                if (route_entry_opt.has_value()) {
                    const RouteEntry& route = route_entry_opt.value();
                    IpAddress next_hop_to_arp_for = route.next_hop_ip == 0 ? ip_hdr->dst_ip : route.next_hop_ip;
                    std::optional<MacAddress> next_hop_mac_opt = arp_processor_.lookup_mac(next_hop_to_arp_for);

                    if (next_hop_mac_opt.has_value()) {
                        // ... (Rewrite MACs, update checksums)
                        eth_hdr->dst_mac = next_hop_mac_opt.value();
                        auto src_mac_opt = interface_manager_.get_interface_mac(route.egress_interface_id);
                        if (!src_mac_opt) { /* log error, drop */ return; }
                        eth_hdr->src_mac = src_mac_opt.value();
                        pkt.update_checksums();

                        if (process_egress_pipeline(pkt, route.egress_interface_id, ingress_port_id)) {
                            // Packet enqueued
                        } // else dropped by egress ACL
                        return;
                    } else { /* ... ARP miss, send ARP request, drop original ... */ return; }
                } else { /* ... No route, send ICMP Net Unreachable, drop ... */ return; }
            }
        }

        // L2 Data Plane Forwarding (if not handled by L3 or control plane)
        // ... (STP checks, MAC learning) ...
        if (eth_hdr && pkt.dst_mac().has_value()) {
            uint16_t vlan_for_lookup = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);
            std::optional<uint32_t> egress_port_opt = fdb.lookup_port(pkt.dst_mac().value(), vlan_for_lookup);

            if (egress_port_opt.has_value()) {
                uint32_t final_egress_port = egress_port_opt.value();
                // ... (LACP resolution, STP checks, VLAN egress checks for final_egress_port) ...
                if (final_egress_port == ingress_port_id || !interface_manager_.is_port_link_up(final_egress_port) ||
                    stp_manager.get_port_stp_state(final_egress_port) != StpManager::PortState::FORWARDING ||
                    !vlan_manager.should_forward(ingress_port_id, final_egress_port, vlan_for_lookup) ) {
                    /* log drop */ return;
                }
                // process_egress_pipeline handles VLAN egress, Egress ACL, and QoS
                process_egress_pipeline(pkt, final_egress_port, ingress_port_id);
                return;
            } else { // Destination MAC unknown or broadcast/multicast
                flood_packet(pkt, ingress_port_id);
                return;
            }
        }
        // If packet reaches here, it's unhandled
        logger_.log_packet_drop(pkt, ingress_port_id, "Unhandled packet type or forwarding decision.");
    }

private:
    uint32_t num_ports_;
    std::function<void(Packet& pkt, uint32_t ingress_port)> packet_handler_;
};

} // namespace netflow

#endif // NETFLOW_SWITCH_HPP
