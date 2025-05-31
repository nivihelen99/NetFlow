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
#include "logger.hpp" // Ensure logger is included
#include "config_manager.hpp" // Ensure ConfigManager is included
#include "management_interface.hpp" // Ensure ManagementInterface is included
#include "arp_processor.hpp" // Added for ARP processing
#include "icmp_processor.hpp" // Added for ICMP processing

#include <cstdint>
#include <functional> // For std::function
#include <vector>
#include <iostream>   // For std::cout, std::cerr (though trying to replace them)
#include <string>     // For std::to_string

namespace netflow {

class Switch {
public:
    BufferPool buffer_pool;
    ForwardingDatabase fdb;
    VlanManager vlan_manager;
    // StpManager stp_manager; // Initialized in constructor
    InterfaceManager interface_manager_;
    PacketClassifier packet_classifier_;

    using FlowKey = PacketClassifier::FlowKey;
    using FlowTable = LockFreeHashTable<FlowKey, uint32_t /* Action ID or Flow Data ID */>;
    FlowTable flow_table_;

    QosManager qos_manager_;
    AclManager acl_manager_;
    LacpManager lacp_manager_;
    SwitchLogger logger_;
    ConfigManager config_manager_;             // Added member
    ManagementInterface management_interface_; // Added member
    StpManager stp_manager;
    // ARP and ICMP processors
    ArpProcessor arp_processor_;
    IcmpProcessor icmp_processor_;
    // LacpManager lacp_manager_; // Removed redundant declaration

    Switch(uint32_t num_ports, uint64_t switch_mac_address,
           uint16_t stp_default_priority = 32768, uint16_t lacp_default_priority = 32768) :
        num_ports_(num_ports),
        interface_manager_(), // Ensure InterfaceManager is initialized if it has a default constructor
        fdb(), // Initialize ForwardingDatabase if it has a default constructor or specific params
        stp_manager(num_ports, switch_mac_address, stp_default_priority),
        lacp_manager_(switch_mac_address, lacp_default_priority),
        arp_processor_(interface_manager_, fdb, *this),      // Initialize ArpProcessor with fdb
        icmp_processor_(interface_manager_, *this),     // Initialize IcmpProcessor
        flow_table_(1024),
        logger_(LogLevel::INFO) {

        // Convert uint64_t MAC to MacAddress for logging
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
        // config_manager_.set_logger(&logger_);

        logger_.info("CONFIG", "Loading default configuration (default_switch_config.json)...");
        if (config_manager_.load_config("default_switch_config.json")) {
            logger_.info("CONFIG", "Default configuration loaded. Applying now...");
            config_manager_.apply_config(config_manager_.get_current_config_data(), *this); // Reverted to two-argument call
        } else {
            logger_.warning("CONFIG", "Failed to load default_switch_config.json. Using empty/hardcoded defaults.");
        }

        logger_.info("SWITCH_INIT", "Initializing per-port defaults (may be overridden by loaded config)...");
        // STP and LACP managers now initialize their port states internally.
        // The main loop here should focus on InterfaceManager admin states.
        for (uint32_t i = 0; i < num_ports_; ++i) {
            // Example: ensure all ports are admin up by default, link state can be simulated or dynamic
            if (!interface_manager_.get_port_config(i).has_value()) {
                InterfaceManager::PortConfig default_if_config;
                default_if_config.admin_up = false;
                interface_manager_.configure_port(i, default_if_config);
                logger_.debug("IFACE_INIT", "Port " + std::to_string(i) + " configured with default admin_down state.");
            }
            bool current_admin_up = interface_manager_.get_port_config(i).value_or(InterfaceManager::PortConfig()).admin_up;
            if (!interface_manager_.is_port_link_up(i) && !current_admin_up) {
                 interface_manager_.simulate_port_link_down(i);
                 logger_.debug("IFACE_INIT", "Port " + std::to_string(i) + " link state confirmed/simulated down (default).");
            } else if (current_admin_up && !interface_manager_.is_port_link_up(i)) {
                interface_manager_.simulate_port_link_up(i);
                logger_.debug("IFACE_INIT", "Port " + std::to_string(i) + " link state simulated up due to admin_up config.");
            }
        }
        logger_.info("SWITCH_INIT", "Switch basic initialization sequence complete.");
    }

    ~Switch() {
        logger_.info("SWITCH_SHUTDOWN", "Switch shutting down.");
    }

    void set_packet_handler(std::function<void(Packet& pkt, uint32_t ingress_port)> handler) {
        packet_handler_ = handler;
        logger_.info("SWITCH_CONFIG", "Packet handler set.");
    }

    void forward_packet(Packet& pkt, uint32_t egress_port) {
        if (egress_port >= num_ports_) {
            logger_.error("FORWARDING", "Egress port " + std::to_string(egress_port) + " out of range.");
            return;
        }
        logger_.debug("FORWARDING_QUEUE", "Packet (size " + std::to_string(pkt.get_buffer()->get_data_length())
                  + ") conceptually passed to hardware for transmission on port " + std::to_string(egress_port));
        // This is a conceptual model. Real hardware would handle this.
        // For simulation, we might enqueue to a QosManager or similar.
        // qos_manager_.enqueue_packet(pkt, egress_port, 0); // Example: enqueue to default queue 0
        interface_manager_._increment_tx_stats(egress_port, pkt.get_buffer()->get_data_length());

    }

    // Method for processors to send packets (e.g. ARP/ICMP replies)
    // This bypasses FDB lookup and sends directly to the egress pipeline (QoS, VLAN egress)
    void send_control_plane_packet(Packet& pkt, uint32_t egress_port) {
        if (egress_port >= num_ports_) {
            logger_.error("SEND_CONTROL_PACKET", "Egress port " + std::to_string(egress_port) + " out of range.");
            // Decrement ref count as packet won't be sent by us
            // pkt.get_buffer()->decrement_ref(); // Assuming pkt might be rvalue or we need to manage its lifecycle here
            return;
        }
        if (!interface_manager_.is_port_link_up(egress_port)) {
            logger_.warning("SEND_CONTROL_PACKET", "Egress port " + std::to_string(egress_port) + " link is down. Dropping control packet.");
            // pkt.get_buffer()->decrement_ref();
            return;
        }

        // Apply any necessary egress processing (like VLAN tagging if needed for control packets)
        // For simplicity, assume control packets are ready to go.
        // vlan_manager.process_egress(pkt, egress_port); // May not be needed or different rules for control plane

        uint8_t queue_id = qos_manager_.classify_packet_to_queue(pkt, egress_port); // Use high priority queue?
        qos_manager_.enqueue_packet(pkt, egress_port, queue_id);
        logger_.debug("SEND_CONTROL_PACKET", "Control plane packet enqueued to port " + std::to_string(egress_port) + " queue " + std::to_string(static_cast<int>(queue_id)));
        // TX stats are incremented by the actual sending mechanism after dequeuing from QoS.
        // For simulation here, if enqueue_packet doesn't lead to TX stats, uncomment below:
        // interface_manager_._increment_tx_stats(egress_port, pkt.get_buffer()->get_data_length());
    }


    void flood_packet(Packet& pkt, uint32_t ingress_port) {
        logger_.debug("FLOOD", "Flooding packet from ingress port " + std::to_string(ingress_port));

        std::optional<uint16_t> vlan_id_opt = pkt.vlan_id();
        uint16_t vlan_id_for_flooding = 0;

        std::optional<VlanManager::PortConfig> ingress_port_vlan_config_opt = vlan_manager.get_port_config(ingress_port);
        if (vlan_id_opt.has_value()){
            vlan_id_for_flooding = vlan_id_opt.value();
        } else if (ingress_port_vlan_config_opt.has_value()) {
            vlan_id_for_flooding = ingress_port_vlan_config_opt.value().native_vlan;
        } else {
            logger_.warning("FLOOD", "Could not determine VLAN for flooding for packet from port " + std::to_string(ingress_port) + " (no VLAN config found for port).");
        }

        int flooded_count = 0;
        for (uint32_t i = 0; i < num_ports_; ++i) {
            if (i == ingress_port) continue;

            if (!interface_manager_.is_port_link_up(i)) {
                 logger_.debug("FLOOD_SKIP", "Port " + std::to_string(i) + " link is down.");
                 continue;
            }

            uint32_t actual_flood_egress_port = i;
            if (lacp_manager_.get_lag_config(i).has_value()) {
                actual_flood_egress_port = lacp_manager_.select_egress_port(i, pkt);
                if (actual_flood_egress_port == 0 && i != 0) {
                     logger_.debug("FLOOD_SKIP", "LAG " + std::to_string(i) + " has no active members for flood egress.");
                     continue;
                }
                logger_.debug("LACP", "Flood: LAG ID " + std::to_string(i) + " resolved to physical port " + std::to_string(actual_flood_egress_port));
            }

            StpManager::PortState flood_egress_stp_state = stp_manager.get_port_stp_state(actual_flood_egress_port);
            if (flood_egress_stp_state != StpManager::PortState::FORWARDING) {
                logger_.debug("FLOOD_SKIP", "Port " + std::to_string(actual_flood_egress_port) + " not in STP forwarding state (" + stp_manager.port_state_to_string(flood_egress_stp_state) + ")");
                continue;
            }
            if (!vlan_manager.should_forward(ingress_port, actual_flood_egress_port, vlan_id_for_flooding)) {
                logger_.debug("FLOOD_SKIP", "VLAN " + std::to_string(vlan_id_for_flooding) + " not allowed on port " + std::to_string(actual_flood_egress_port));
                continue;
            }

            logger_.debug("FLOOD_TARGET", "Conceptually flooding to port " + std::to_string(actual_flood_egress_port) + ". Egress processing & QoS for flood is simplified/skipped.");
            interface_manager_._increment_tx_stats(actual_flood_egress_port, pkt.get_buffer()->get_data_length());
            flooded_count++;
        }
        if (flooded_count == 0 && num_ports_ > 1 && ingress_port < num_ports_) {
            logger_.debug("FLOOD", "Packet from port " + std::to_string(ingress_port) + " not flooded to any other suitable ports.");
        }
    }

    void start() {
        logger_.info("SWITCH_LIFECYCLE", "Switch starting...");
        logger_.info("SWITCH_LIFECYCLE", "Switch operational.");
    }

    void process_received_packet(uint32_t ingress_port_id, PacketBuffer* raw_buffer) {
        if (!raw_buffer) {
            logger_.error("PROCESS_PACKET", "Null PacketBuffer received on port " + std::to_string(ingress_port_id));
            return;
        }

        if (!interface_manager_.is_port_link_up(ingress_port_id)) {
            logger_.info("PACKET_DROP", "Packet dropped on ingress port " + std::to_string(ingress_port_id) + ": Link is down.");
            raw_buffer->decrement_ref();
            return;
        }
        interface_manager_._increment_rx_stats(ingress_port_id, raw_buffer->get_data_length());
        logger_.debug("PROCESS_PACKET", "RX on port " + std::to_string(ingress_port_id) + ", size " + std::to_string(raw_buffer->get_data_length()));

        Packet pkt(raw_buffer);

        // L0: Port specific physical layer checks (already done by is_port_link_up)

        // L1/L2 Pre-processing: ACLs can act early
        uint32_t redirect_port_id_acl = 0;
        AclActionType acl_action = acl_manager_.evaluate(pkt, redirect_port_id_acl);

        if (acl_action == AclActionType::DENY) {
            logger_.log_packet_drop(pkt, ingress_port_id, "ACL DENY rule");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
            return;
        }
        if (acl_action == AclActionType::REDIRECT) {
            logger_.info("ACL", "Packet REDIRECTED by ACL to port " + std::to_string(redirect_port_id_acl) + " from ingress port " + std::to_string(ingress_port_id));
            uint8_t queue_id_redirect = qos_manager_.classify_packet_to_queue(pkt, redirect_port_id_acl);
            qos_manager_.enqueue_packet(pkt, redirect_port_id_acl, queue_id_redirect);
            logger_.debug("QOS", "Redirected packet enqueued to port " + std::to_string(redirect_port_id_acl) + " queue " + std::to_string(static_cast<int>(queue_id_redirect)));
            interface_manager_._increment_tx_stats(redirect_port_id_acl, pkt.get_buffer()->get_data_length());
            return;
        }

        uint32_t classification_action_id = packet_classifier_.classify(pkt);
        if (classification_action_id != 0) {
            logger_.debug("PACKET_CLASSIFIER", "Packet on port " + std::to_string(ingress_port_id)
                      + " classified by PacketClassifier with action ID: " + std::to_string(classification_action_id));
            FlowKey current_flow_key = packet_classifier_.extract_flow_key(pkt);
            auto flow_entry = flow_table_.lookup(current_flow_key);
            if(flow_entry.has_value()){
                 logger_.debug("FLOW_TABLE", "  Flow entry found in FlowTable. Action ID: " + std::to_string(flow_entry.value()));
            } else {
                 logger_.debug("FLOW_TABLE", "  No specific flow entry in FlowTable for this packet.");
            }
        }

        // L2 Pre-processing: Ingress VLAN processing
        PacketAction vlan_action = vlan_manager.process_ingress(pkt, ingress_port_id);
        if (vlan_action == PacketAction::DROP) {
            logger_.log_packet_drop(pkt, ingress_port_id, "Ingress VLAN processing");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
            return;
        }

        // L2 Control Plane: STP BPDUs, LACP, etc.
        // Check for BPDUs (STP)
        static const uint8_t bpdu_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00}; // STP/PAUSE
        static const uint8_t lacp_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x02}; // LACP
        MacAddress bpdu_mac(bpdu_mac_bytes);
        MacAddress lacp_slow_mac(lacp_mac_bytes);

        EthernetHeader* eth_hdr = pkt.ethernet(); // Get Ethernet header to check EtherType and Dest MAC

        if (eth_hdr) {
            if (eth_hdr->dst_mac == bpdu_mac) {
                 logger_.debug("STP", "BPDU received on port " + std::to_string(ingress_port_id));
                 stp_manager.process_bpdu(pkt, ingress_port_id, logger_);
                 return; // BPDU processing typically ends here
            }
            // TODO: Add LACPDU handling if eth_hdr->dst_mac == lacp_slow_mac and ethertype is SLOW_PROTOCOL_ETHERTYPE
            // if (eth_hdr->dst_mac == lacp_slow_mac && ntohs(eth_hdr->ethertype) == ETHERTYPE_SLOW_PROTOCOLS) {
            //     logger_.debug("LACP", "LACPDU received on port " + std::to_string(ingress_port_id));
            //     lacp_manager_.process_lacpdu(pkt, ingress_port_id);
            //     return; // LACPDU processing ends here
            // }

            // L3 Control Plane (ARP, ICMP for the switch itself)
            uint16_t ether_type = ntohs(eth_hdr->ethertype);
            if (pkt.has_vlan()) { // If VLAN tagged, the "real" ethertype is after the VLAN header
                VlanHeader* vlan_hdr = pkt.vlan();
                if (vlan_hdr) {
                    ether_type = ntohs(vlan_hdr->ethertype);
                }
            }


            if (ether_type == ETHERTYPE_ARP) {
                logger_.debug("ARP_DISPATCH", "ARP packet received on port " + std::to_string(ingress_port_id) + ". Dispatching to ArpProcessor.");
                arp_processor_.process_arp_packet(pkt, ingress_port_id);
                // ARP packets are typically not forwarded further by this switch path.
                // They are either requests for the switch's own MAC, or replies to populate its cache.
                return;
            } else if (ether_type == ETHERTYPE_IPV4) {
                IPv4Header* ip_hdr = pkt.ipv4(); // Gets IPv4 header based on ethertype
                if (ip_hdr) {
                    if (ip_hdr->protocol == IPPROTO_ICMP) {
                        logger_.debug("ICMP_DISPATCH", "ICMP packet received on port " + std::to_string(ingress_port_id) + ". Dispatching to IcmpProcessor.");
                        icmp_processor_.process_icmp_packet(pkt, ingress_port_id);
                        // ICMP packets for the switch (e.g., echo reply) are handled and not forwarded.
                        // Other ICMP packets (e.g. destined elsewhere, if we were a router) might be.
                        // For now, assume ICMP for us is consumed.
                        return;
                    }
                    // Potentially other IPv4 protocols destined for the switch's control plane here (e.g. OSPF, BGP - future)
                }
            }
            // Add IPv6 handling here in future: else if (ether_type == ETHERTYPE_IPV6) { ... }
        }


        // L2 Data Plane Forwarding Logic (STP state checks, MAC learning, FDB lookup)
        // STP check for data packets (BPDUs are handled above and bypass this)
        StpManager::PortState current_stp_state = stp_manager.get_port_stp_state(ingress_port_id);
        if (current_stp_state == StpManager::PortState::BLOCKING ||
            current_stp_state == StpManager::PortState::LISTENING) { // Or Disabled
            logger_.log_packet_drop(pkt, ingress_port_id, "STP state " + stp_manager.port_state_to_string(current_stp_state) + " (data packet)");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
            return;
        }

        // MAC Learning (if STP state allows)
        if (stp_manager.should_learn(ingress_port_id)) { // Checks if port is in Learning or Forwarding state
            if (eth_hdr && pkt.src_mac().has_value()) { // Ensure eth_hdr is valid
                uint16_t vlan_for_learning = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);
                fdb.learn_mac(pkt.src_mac().value(), ingress_port_id, vlan_for_learning);
            }
        }

        // FDB Lookup and Forwarding Decision
        if (eth_hdr && pkt.dst_mac().has_value()) { // Ensure eth_hdr is valid
            uint16_t vlan_for_lookup = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);
            std::optional<uint32_t> egress_port_opt = fdb.lookup_port(pkt.dst_mac().value(), vlan_for_lookup);

            if (egress_port_opt.has_value()) { // Destination MAC known
                uint32_t egress_port = egress_port_opt.value();
                if (egress_port == ingress_port_id) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "Destination MAC is on ingress port (reflection)");
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                    return;
                }

                uint32_t final_egress_port = egress_port;
                // LACP Port Resolution
                if (lacp_manager_.get_lag_config(egress_port).has_value()) {
                    final_egress_port = lacp_manager_.select_egress_port(egress_port, pkt);
                    logger_.debug("LACP", "LAG ID " + std::to_string(egress_port) + " resolved to physical port " + std::to_string(final_egress_port) + " for packet.");
                    if ((final_egress_port == 0 && egress_port != 0) || !interface_manager_.is_port_link_up(final_egress_port)) {
                        logger_.log_packet_drop(pkt, ingress_port_id, "LACP LAG " + std::to_string(egress_port) + " has no active/valid/up members for egress (selected: " + std::to_string(final_egress_port) + "). Flooding instead.");
                        // Fallback to flooding if LACP selection fails but FDB entry existed for LAG
                        flood_packet(pkt, ingress_port_id);
                        return;
                    }
                } else { // Not a LAG, direct port
                    if(!interface_manager_.is_port_link_up(final_egress_port)){
                        logger_.log_packet_drop(pkt, ingress_port_id, "Egress port " + std::to_string(final_egress_port) + " link is down.");
                        interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                        return;
                    }
                }

                // STP check for egress port
                StpManager::PortState egress_stp_state = stp_manager.get_port_stp_state(final_egress_port);
                if (egress_stp_state != StpManager::PortState::FORWARDING) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "Egress port " + std::to_string(final_egress_port) + " not in STP forwarding state (" + stp_manager.port_state_to_string(egress_stp_state) + ")");
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                    return;
                }

                // VLAN egress check
                if (!vlan_manager.should_forward(ingress_port_id, final_egress_port, vlan_for_lookup)) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "VLAN " + std::to_string(vlan_for_lookup) + " not allowed between port " + std::to_string(ingress_port_id) + " and final egress " + std::to_string(final_egress_port));
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
                    return;
                }

                // L2 Egress Processing (VLAN tagging)
                vlan_manager.process_egress(pkt, final_egress_port);

                // QoS and Enqueue
                uint8_t queue_id = qos_manager_.classify_packet_to_queue(pkt, final_egress_port);
                qos_manager_.enqueue_packet(pkt, final_egress_port, queue_id);
                logger_.debug("QOS", "Packet enqueued to port " + std::to_string(final_egress_port) + " queue " + std::to_string(static_cast<int>(queue_id)));
                // Actual TX stats are handled by the component that dequeues and sends.
                // interface_manager_._increment_tx_stats(final_egress_port, pkt.get_buffer()->get_data_length());

            } else { // Destination MAC unknown or is a broadcast/multicast MAC not handled by L2 control plane
                // L3 processing (Routing) would happen here if it's an IP packet and dest MAC was the switch's router MAC
                // For now, if not known L2 unicast, flood
                logger_.info("FDB_MISS", "Destination MAC unknown or broadcast/multicast. Flooding packet from ingress port " + std::to_string(ingress_port_id) + " on VLAN " + std::to_string(vlan_for_lookup));
                flood_packet(pkt, ingress_port_id);
            }
        } else { // Not Ethernet or no destination MAC (should be rare after initial parsing)
            logger_.log_packet_drop(pkt, ingress_port_id, "Not Ethernet or no destination MAC (after L2 control plane processing)");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->get_data_length(), false, true);
        }
    }

private:
    uint32_t num_ports_;
    std::function<void(Packet& pkt, uint32_t ingress_port)> packet_handler_;
    // PerformanceCounters performance_counters_; // TODO: Add and manage this
};

} // namespace netflow

#endif // NETFLOW_SWITCH_HPP
