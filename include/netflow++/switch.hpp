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
#include "netflow++/lldp_manager.hpp" // Assumes lldp_defs.hpp is included by lldp_manager.hpp for LLDP_ETHERTYPE

#include <cstdint>    // For uintX_t types
#include <functional> // For std::function
#include <vector>     // For std::vector
#include <iostream>   // For std::cout, std::cerr (general I/O, if any direct use)
#include <string>     // For std::string, std::to_string
#include <optional>   // For std::optional, .has_value(), .value_or()
#include <cstring>    // For std::memcpy

// For STP_MULTICAST_MAC_BYTES, ensure stp_manager.hpp provides it or define here if necessary.
// For LLDP_ETHERTYPE, ensure lldp_manager.hpp or lldp_defs.hpp provides it.

namespace netflow {

class Switch {
public:
    BufferPool buffer_pool;
    ForwardingDatabase fdb;
    VlanManager vlan_manager;
    InterfaceManager interface_manager_;
    PacketClassifier packet_classifier_;

    using FlowKey = PacketClassifier::FlowKey;
    using FlowTable = LockFreeHashTable<FlowKey, uint32_t>;
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
        logger_(LogLevel::INFO), // Initialize logger first
        qos_manager_(logger_),
        acl_manager_(logger_),
        interface_manager_(logger_, acl_manager_),
        fdb(), // Default constructor, then set_logger
        vlan_manager(), // Default constructor
        stp_manager(num_ports, switch_mac_address, stp_default_priority),
        packet_classifier_(), // Default constructor
        lacp_manager_(switch_mac_address, lacp_default_priority),
        lldp_manager_(*this, interface_manager_),
        // config_manager_ needs to be initialized before use
        // management_interface_ default
        arp_processor_(interface_manager_, fdb, *this),
        icmp_processor_(interface_manager_, *this),
        routing_manager_(), // Default constructor
        flow_table_(1024) { // Example capacity

        uint8_t temp_mac_bytes[6];
        temp_mac_bytes[0] = (switch_mac_address >> 40) & 0xFF;
        temp_mac_bytes[1] = (switch_mac_address >> 32) & 0xFF;
        temp_mac_bytes[2] = (switch_mac_address >> 24) & 0xFF;
        temp_mac_bytes[3] = (switch_mac_address >> 16) & 0xFF;
        temp_mac_bytes[4] = (switch_mac_address >> 8) & 0xFF;
        temp_mac_bytes[5] = (switch_mac_address >> 0) & 0xFF;
        MacAddress mac_addr_for_log(temp_mac_bytes);
        logger_.info("SWITCH_LIFECYCLE", "Switch constructing for " + std::to_string(num_ports_) + " ports. MAC: " + logger_.mac_to_string(mac_addr_for_log));
        
        fdb.set_logger(&logger_); // Set logger for FDB
        lacp_manager_.set_logger(&logger_); // Set logger for LACP Manager

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
                default_if_config.admin_up = false; // Default to admin down
                interface_manager_.configure_port(i, default_if_config);
            }
            // Reflect admin state to link state if not already correctly set up by simulation/hw
            bool current_admin_up = interface_manager_.get_port_config(i).value_or(InterfaceManager::PortConfig()).admin_up;
            if (!current_admin_up && interface_manager_.is_port_link_up(i)) { // Admin down but link is up
                 interface_manager_.simulate_port_link_down(i);
            } else if (current_admin_up && !interface_manager_.is_port_link_up(i)) { // Admin up but link is down
                interface_manager_.simulate_port_link_up(i);
            }
        }
        logger_.info("SWITCH_INIT", "Switch basic initialization sequence complete.");
    }

    ~Switch() = default; // Default destructor should be fine given members manage their own resources or are references.

    void set_packet_handler(std::function<void(Packet& pkt, uint32_t ingress_port)> handler) {
        packet_handler_ = std::move(handler);
    }
    
    // Not typically called directly for data plane, QoS handles dequeue.
    void forward_packet(Packet& pkt, uint32_t egress_port); 

    bool process_egress_pipeline(Packet& pkt, uint32_t egress_port_id, uint32_t original_ingress_port_id_for_log = 0xFFFF) {
        vlan_manager.process_egress(pkt, egress_port_id);

        auto egress_acl_name_opt = interface_manager_.get_applied_acl_name(egress_port_id, netflow::AclDirection::EGRESS);
        if (egress_acl_name_opt.has_value() && !egress_acl_name_opt.value().empty()) {
            uint32_t redirect_port_egress_acl = 0; 
            AclActionType egress_action = acl_manager_.evaluate(egress_acl_name_opt.value(), pkt, redirect_port_egress_acl);
            logger_.debug("ACL_EGRESS", "Egress ACL '" + egress_acl_name_opt.value() + "' on port " + std::to_string(egress_port_id) + " result: " + std::to_string(static_cast<int>(egress_action)));

            if (egress_action == AclActionType::DENY) {
                logger_.log_packet_drop(pkt, original_ingress_port_id_for_log, "Egress ACL DENY on port " + std::to_string(egress_port_id));
                interface_manager_._increment_tx_stats(egress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                return false; 
            }
            if (egress_action == AclActionType::REDIRECT) {
                logger_.warning("ACL_EGRESS", "REDIRECT action in Egress ACL on port " + std::to_string(egress_port_id) + " is treated as PERMIT.");
            }
        }
        qos_manager_.enqueue_packet(pkt, egress_port_id);
        logger_.debug("QOS", "Packet enqueued to port " + std::to_string(egress_port_id) + " after Egress pipeline.");
        return true;
    }

    void send_control_plane_packet(Packet& pkt, uint32_t egress_port) {
        if (egress_port >= num_ports_ || !interface_manager_.is_port_link_up(egress_port)) {
            logger_.warning("SEND_CONTROL_PACKET", "Port " + std::to_string(egress_port) + " invalid or down. Dropping control packet.");
            return;
        }
        qos_manager_.enqueue_packet(pkt, egress_port);
        logger_.debug("SEND_CONTROL_PACKET", "Control plane packet enqueued to port " + std::to_string(egress_port));
        if (test_packet_send_hook) test_packet_send_hook(pkt, egress_port);
    }

    void send_control_plane_frame(uint32_t egress_port_id, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype, const std::vector<uint8_t>& payload) {
        if (egress_port_id >= num_ports_ || !interface_manager_.is_port_link_up(egress_port_id)) {
             logger_.warning("SEND_CTRL_FRAME", "Port " + std::to_string(egress_port_id) + " invalid or down. Dropping control frame.");
            return;
        }
        PacketBuffer* pb = buffer_pool.allocate_buffer(EthernetHeader::SIZE + payload.size());
        if (!pb) { logger_.error("SEND_CTRL_FRAME", "Buffer allocation failed."); return; }
        
        EthernetHeader eth_hdr_data; 
        eth_hdr_data.dst_mac = dst_mac; 
        eth_hdr_data.src_mac = src_mac; 
        eth_hdr_data.ethertype = htons(ethertype); // Ensure network byte order for ethertype
        
        std::memcpy(pb->get_data_start_ptr(), &eth_hdr_data, EthernetHeader::SIZE);
        std::memcpy(pb->get_data_start_ptr() + EthernetHeader::SIZE, payload.data(), payload.size());
        pb->set_data_len(EthernetHeader::SIZE + payload.size());
        
        Packet pkt(pb); 
        pb->decrement_ref(); // Packet constructor increments ref_count

        qos_manager_.enqueue_packet(pkt, egress_port_id);
        logger_.debug("SEND_CTRL_FRAME", "Control frame enqueued to port " + std::to_string(egress_port_id));
        if (test_packet_send_hook) test_packet_send_hook(pkt, egress_port_id);
    }

    void flood_packet(Packet& pkt, uint32_t ingress_port_id) {
        logger_.debug("FLOOD", "Flooding packet from ingress port " + std::to_string(ingress_port_id));
        
        uint16_t vlan_id_for_flooding = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);

        int flooded_count = 0;
        for (uint32_t i = 0; i < num_ports_; ++i) {
            if (i == ingress_port_id) continue;
            if (!interface_manager_.is_port_link_up(i) ||
                stp_manager.get_port_stp_state(i) != StpManager::PortState::FORWARDING ||
                !vlan_manager.should_forward(ingress_port_id, i, vlan_id_for_flooding)) {
                continue;
            }

            PacketBuffer* pb_copy = buffer_pool.allocate_buffer(pkt.get_buffer()->get_data_length(), pkt.get_buffer()->get_headroom());
            if(!pb_copy) {
                logger_.error("FLOOD", "Failed to allocate buffer for flooding to port " + std::to_string(i));
                continue;
            }
            std::memcpy(pb_copy->get_data_start_ptr(), pkt.get_buffer()->get_data_start_ptr(), pkt.get_buffer()->get_data_length());
            pb_copy->set_data_len(pkt.get_buffer()->get_data_length());
            Packet flood_pkt_copy(pb_copy);
            pb_copy->decrement_ref();

            if (process_egress_pipeline(flood_pkt_copy, i, ingress_port_id)) {
                 flooded_count++;
            }
        }
        if (flooded_count == 0 && num_ports_ > 1 && ingress_port_id < num_ports_) { 
            logger_.debug("FLOOD", "No suitable ports found for flooding packet from port " + std::to_string(ingress_port_id));
        }
    }

    void start(); // To be implemented: start timers, background threads etc.
    
    // Configuration passthroughs or direct access for ManagementService
    void add_static_route(const IpAddress& net, const IpAddress& mask, const IpAddress& nh, uint32_t if_id, int m = 1) {
        routing_manager_.add_static_route(net, mask, nh, if_id, m);
    }
    void remove_static_route(const IpAddress& net, const IpAddress& mask) {
        routing_manager_.remove_static_route(net, mask);
    }
    std::vector<RouteEntry> get_routing_table() const {
        return routing_manager_.get_routing_table();
    }

    void process_received_packet(uint32_t ingress_port_id, PacketBuffer* raw_buffer); // Main pipeline

private:
    uint32_t num_ports_;
    std::function<void(Packet& pkt, uint32_t ingress_port)> packet_handler_; // For packets to CPU
};

} // namespace netflow

#endif // NETFLOW_SWITCH_HPP
