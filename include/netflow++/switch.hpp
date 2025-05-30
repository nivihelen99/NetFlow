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
    // LacpManager lacp_manager_; // Initialized in constructor
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
    LacpManager lacp_manager_;

    Switch(uint32_t num_ports, uint64_t switch_mac_address,
           uint16_t stp_default_priority = 32768, uint16_t lacp_default_priority = 32768) :
        num_ports_(num_ports),
        stp_manager(num_ports, switch_mac_address, stp_default_priority),
        lacp_manager_(switch_mac_address, lacp_default_priority),
        flow_table_(1024),
        logger_(LogLevel::INFO) {

        logger_.info("SWITCH_LIFECYCLE", "Switch constructing for " + std::to_string(num_ports_) + " ports. MAC: " + logger_.mac_to_string(switch_mac_address));
        fdb.set_logger(&logger_);
        // config_manager_.set_logger(&logger_);

        logger_.info("CONFIG", "Loading default configuration (default_switch_config.json)...");
        if (config_manager_.load_config("default_switch_config.json")) {
            logger_.info("CONFIG", "Default configuration loaded. Applying now...");
            config_manager_.apply_config(*this); // Corrected signature
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
        logger_.debug("FORWARDING_QUEUE", "Packet (size " + std::to_string(pkt.get_buffer()->size)
                  + ") conceptually passed to hardware for transmission on port " + std::to_string(egress_port));
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
            interface_manager_._increment_tx_stats(actual_flood_egress_port, pkt.get_buffer()->size);
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
        interface_manager_._increment_rx_stats(ingress_port_id, raw_buffer->size);
        logger_.debug("PROCESS_PACKET", "RX on port " + std::to_string(ingress_port_id) + ", size " + std::to_string(raw_buffer->size));

        Packet pkt(raw_buffer);

        uint32_t redirect_port_id_acl = 0;
        AclActionType acl_action = acl_manager_.evaluate(pkt, redirect_port_id_acl);

        if (acl_action == AclActionType::DENY) {
            logger_.log_packet_drop(pkt, ingress_port_id, "ACL DENY rule");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
            return;
        }
        if (acl_action == AclActionType::REDIRECT) {
            logger_.info("ACL", "Packet REDIRECTED by ACL to port " + std::to_string(redirect_port_id_acl) + " from ingress port " + std::to_string(ingress_port_id));
            uint8_t queue_id_redirect = qos_manager_.classify_packet_to_queue(pkt, redirect_port_id_acl);
            qos_manager_.enqueue_packet(pkt, redirect_port_id_acl, queue_id_redirect);
            logger_.debug("QOS", "Redirected packet enqueued to port " + std::to_string(redirect_port_id_acl) + " queue " + std::to_string(static_cast<int>(queue_id_redirect)));
            interface_manager_._increment_tx_stats(redirect_port_id_acl, pkt.get_buffer()->size);
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

        PacketAction vlan_action = vlan_manager.process_ingress(pkt, ingress_port_id);
        if (vlan_action == PacketAction::DROP) {
            logger_.log_packet_drop(pkt, ingress_port_id, "Ingress VLAN processing");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
            return;
        }

        static const uint8_t bpdu_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
        MacAddress bpdu_mac(bpdu_mac_bytes);
        bool is_bpdu = (pkt.ethernet() && pkt.dst_mac() && pkt.dst_mac().value() == bpdu_mac);

        if (is_bpdu) {
            logger_.debug("STP", "BPDU received on port " + std::to_string(ingress_port_id));
            stp_manager.process_bpdu(pkt, ingress_port_id, logger_); // Added logger_ argument
            return;
        }

        StpManager::PortState current_stp_state = stp_manager.get_port_stp_state(ingress_port_id);
        if (current_stp_state == StpManager::PortState::BLOCKING ||
            current_stp_state == StpManager::PortState::LISTENING) {
            logger_.log_packet_drop(pkt, ingress_port_id, "STP state " + stp_manager.port_state_to_string(current_stp_state));
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
            return;
        }

        if (stp_manager.should_learn(ingress_port_id)) {
            if (pkt.ethernet() && pkt.src_mac().has_value()) {
                uint16_t vlan_for_learning = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);
                fdb.learn_mac(pkt.src_mac().value(), ingress_port_id, vlan_for_learning);
            }
        }

        if (pkt.ethernet() && pkt.dst_mac().has_value()) {
            uint16_t vlan_for_lookup = pkt.vlan_id().value_or(vlan_manager.get_port_config(ingress_port_id).value_or(VlanManager::PortConfig()).native_vlan);
            std::optional<uint32_t> egress_port_opt = fdb.lookup_port(pkt.dst_mac().value(), vlan_for_lookup);

            if (egress_port_opt.has_value()) {
                uint32_t egress_port = egress_port_opt.value();
                if (egress_port == ingress_port_id) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "Destination MAC is on ingress port (reflection)");
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
                    return;
                }

                uint32_t final_egress_port = egress_port;
                if (lacp_manager_.get_lag_config(egress_port).has_value()) {
                    final_egress_port = lacp_manager_.select_egress_port(egress_port, pkt);
                    logger_.debug("LACP", "LAG ID " + std::to_string(egress_port) + " resolved to physical port " + std::to_string(final_egress_port) + " for packet.");
                    if ((final_egress_port == 0 && egress_port != 0) || !interface_manager_.is_port_link_up(final_egress_port)) {
                        logger_.log_packet_drop(pkt, ingress_port_id, "LACP LAG " + std::to_string(egress_port) + " has no active/valid/up members for egress (selected: " + std::to_string(final_egress_port) + ").");
                        interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
                        return;
                    }
                } else {
                    if(!interface_manager_.is_port_link_up(final_egress_port)){
                        logger_.log_packet_drop(pkt, ingress_port_id, "Egress port " + std::to_string(final_egress_port) + " link is down.");
                        interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
                        return;
                    }
                }

                StpManager::PortState egress_stp_state = stp_manager.get_port_stp_state(final_egress_port);
                if (egress_stp_state != StpManager::PortState::FORWARDING) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "Egress port " + std::to_string(final_egress_port) + " not in STP forwarding state (" + stp_manager.port_state_to_string(egress_stp_state) + ")");
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
                    return;
                }

                if (!vlan_manager.should_forward(ingress_port_id, final_egress_port, vlan_for_lookup)) {
                    logger_.log_packet_drop(pkt, ingress_port_id, "VLAN " + std::to_string(vlan_for_lookup) + " not allowed between port " + std::to_string(ingress_port_id) + " and final egress " + std::to_string(final_egress_port));
                    interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
                    return;
                }

                vlan_manager.process_egress(pkt, final_egress_port);
                uint8_t queue_id = qos_manager_.classify_packet_to_queue(pkt, final_egress_port);
                qos_manager_.enqueue_packet(pkt, final_egress_port, queue_id);
                logger_.debug("QOS", "Packet enqueued to port " + std::to_string(final_egress_port) + " queue " + std::to_string(static_cast<int>(queue_id)));
                interface_manager_._increment_tx_stats(final_egress_port, pkt.get_buffer()->size);
            } else {
                logger_.info("FDB", "Destination MAC unknown. Flooding packet from ingress port " + std::to_string(ingress_port_id) + " on VLAN " + std::to_string(vlan_for_lookup));
                flood_packet(pkt, ingress_port_id);
            }
        } else {
            logger_.log_packet_drop(pkt, ingress_port_id, "Not Ethernet or no destination MAC");
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true);
        }
    }

private:
    uint32_t num_ports_;
    std::function<void(Packet& pkt, uint32_t ingress_port)> packet_handler_;
    // PerformanceCounters performance_counters_; // TODO: Add and manage this
};

} // namespace netflow

#endif // NETFLOW_SWITCH_HPP
