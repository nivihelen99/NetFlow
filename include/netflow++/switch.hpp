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

#include <cstdint>
#include <functional> // For std::function
#include <vector>
#include <iostream>   // For placeholder messages

namespace netflow {

class Switch {
public:
    BufferPool buffer_pool;
    ForwardingDatabase fdb;
    VlanManager vlan_manager;
    StpManager stp_manager;
    InterfaceManager interface_manager_; // New
    PacketClassifier packet_classifier_; // New

    // Type alias for a common flow table
    using FlowKey = PacketClassifier::FlowKey; // Make FlowKey easily accessible
    using FlowTable = LockFreeHashTable<FlowKey, uint32_t /* Action ID or Flow Data ID */>;
    FlowTable flow_table_; // New

    QosManager qos_manager_;         // New
    AclManager acl_manager_;         // New
    LacpManager lacp_manager_;       // New

    Switch(uint32_t num_ports) :
        num_ports_(num_ports),
        flow_table_(1024) /* Default capacity for FlowTable */ {
        // Default constructors for qos_manager_, acl_manager_, lacp_manager_ are sufficient.
        std::cout << "Switch created with " << num_ports_ << " ports." << std::endl;
        // Initialize port states for STP and InterfaceManager, e.g., to BLOCKING or DISABLED initially
        for (uint32_t i = 0; i < num_ports_; ++i) {
            // Default port configuration for VLANs might be set here or expected to be configured explicitly
            // VlanManager::PortConfig default_vlan_port_config;
            // vlan_manager.configure_port(i, default_vlan_port_config);

            // Default STP state, e.g. BLOCKING until STP converges
            stp_manager.set_port_state(i, StpManager::PortState::BLOCKING);

            // Default port configuration for InterfaceManager (e.g., admin down)
            InterfaceManager::PortConfig default_if_config;
            default_if_config.admin_up = false;
            interface_manager_.configure_port(i, default_if_config);
            // Simulate link down state initially for all ports
            interface_manager_.simulate_port_link_down(i);
        }
        // stp_manager.set_buffer_pool(&buffer_pool); // If StpManager needs to allocate BPDUs
    }

    ~Switch() {
        std::cout << "Switch shutting down." << std::endl;
    }

    // Sets a handler to be called when a packet is received and needs processing by CPU/control plane.
    void set_packet_handler(std::function<void(Packet& pkt, uint32_t ingress_port)> handler) {
        packet_handler_ = handler;
        std::cout << "Packet handler set." << std::endl;
    }

    // Sends a packet out of a specific port.
    // This is a low-level function; actual forwarding decisions use this.
    void forward_packet(Packet& pkt, uint32_t egress_port) {
        if (egress_port >= num_ports_) {
            std::cerr << "Error: Egress port " << egress_port << " out of range." << std::endl;
            return;
        }
        // In a real switch, this would queue the packet for transmission on the hardware port.
        // The Packet's PacketBuffer would be handed off.
        std::cout << "Placeholder: Forwarding packet (size " << pkt.get_buffer()->size
                  << ") out of port " << egress_port << std::endl;

        // Example of how packet handler could be used if packet is for CPU
        // if (packet_handler_ && egress_port == CPU_PORT_PLACEHOLDER) {
        //     packet_handler_(pkt, ingress_port_placeholder);
        // }

        // For simulation, we might just log or call another handler.
        // The packet's buffer would be decremented once sent or copied to hardware queue.
        // pkt.get_buffer()->decrement_ref(); // If this function consumes the packet reference
    }

    // Floods a packet to all active, forwarding ports except the ingress port, respecting VLAN and STP.
    void flood_packet(Packet& pkt, uint32_t ingress_port) {
        std::cout << "Placeholder: Flooding packet from ingress port " << ingress_port << std::endl;

        std::optional<uint16_t> vlan_id_opt = pkt.vlan_id();
        // If untagged on ingress (after ingress VLAN processing), it's associated with native VLAN.
        // This vlan_id needs to be the one determined by ingress processing.
        // For now, let's assume pkt.vlan_id() gives the correct VLAN context.
        uint16_t vlan_id_for_flooding = 0; // Default or unassigned

        const auto* ingress_port_vlan_config = vlan_manager.get_port_config(ingress_port);
        if (vlan_id_opt.has_value()){
            vlan_id_for_flooding = vlan_id_opt.value();
        } else if (ingress_port_vlan_config) {
            // If packet became untagged after ingress processing (e.g. access port native vlan)
            // or was untagged on a trunk and associated with native vlan.
            vlan_id_for_flooding = ingress_port_vlan_config->native_vlan;
        } else {
            std::cerr << "Warning: Could not determine VLAN for flooding for packet from port " << ingress_port << std::endl;
            // Default to vlan 0 or drop, depending on policy
        }


        for (uint32_t i = 0; i < num_ports_; ++i) {
            if (i == ingress_port) {
                continue; // Don't send back to ingress port
            }

            // Check STP state
            if (!stp_manager.should_forward(i)) {
                // std::cout << "Port " << i << " is not in STP forwarding state." << std::endl;
                continue;
            }

            // Check VLAN membership
            if (!vlan_manager.should_forward(ingress_port, i, vlan_id_for_flooding)) {
                 // std::cout << "VLAN " << vlan_id_for_flooding << " not allowed on port " << i << " for egress from ingress " << ingress_port << std::endl;
                continue;
            }

            // Create a new Packet object or copy buffer for each egress port if necessary,
            // or use a mechanism that allows multiple ports to reference the same buffer.
            // For simplicity, assume forward_packet handles ref counting or copying if needed.
            // A real switch might need to replicate the packet buffer if sending to multiple ports
            // unless it's a simple bus or shared medium (not typical for modern switches).

            // We need to potentially modify the packet for egress (e.g. VLAN tag stripping)
            // This implies that `pkt` might need to be cloned or handled carefully if modified per port.
            // Let's assume process_egress modifies a temporary copy or that forward_packet handles it.
            // This is a simplification.

            // Create a temporary Packet object for egress processing for this specific port
            // This is a shallow copy for its state, but shares the PacketBuffer initially.
            // Packet egress_pkt_copy = pkt; // This copy constructor is deleted. TODO: Fix this for proper flood.
                                          // Or, Packet methods should be const if they don't modify,
                                          // or process_egress should work on a copy of data if it modifies.

            // The Packet class as defined doesn't support easy copying for this scenario.
            // Let's assume for this placeholder that forward_packet implicitly handles
            // any necessary per-port modification based on VlanManager's state for that port.
            // Or, we call VlanManager::process_egress on the *original* packet,
            // which is problematic if it modifies it and it needs to be different for other ports.

            // A more realistic approach:
            // PacketBuffer* original_buf = pkt.get_buffer();
            // original_buf->increment_ref(); // For this egress port
            // Packet temp_egress_pkt(original_buf); // New packet instance around same buffer
            // vlan_manager.process_egress(temp_egress_pkt, i); // Modify temp_egress_pkt (and its buffer view)
            // forward_packet(temp_egress_pkt, i); // forward_packet will then call decrement_ref on original_buf
            // original_buf->decrement_ref(); // Decrement our local ref, temp_egress_pkt took its own.

            // Simpler placeholder:
            // We assume forward_packet will internally call vlan_manager.process_egress
            // or that the packet is already in the correct state for this port.
            // This is often true if ingress processing normalizes the packet to a common representation.

            std::cout << "  Flooding to port " << i << " (VLAN " << vlan_id_for_flooding << ") - (Actual send commented due to copy issue)" << std::endl;
            // forward_packet(pkt, i); // TODO: This is problematic as pkt state might change due to process_egress. Needs packet duplication.

            // For now, the flood is very conceptual.
            // A real flood would need to handle buffer replication or careful modification.
        }
    }

    // Placeholder for starting switch operations (e.g., enabling ports, starting STP timers).
    void start() {
        std::cout << "Switch starting..." << std::endl;
        // This could involve:
        // - Initializing all ports (e.g., bringing them up if not done in constructor)
        // - Starting STP timers and logic (e.g., Bridge::run_stp_timers_and_logic() in a loop/thread)
        // - Setting up packet processing loop if this is a software switch handling data plane

        // For now, just a message.
        // In a real system, this might kick off threads for STP, packet polling, etc.
        // stp_manager.run_stp_timers_and_logic(); // Example call
        std::cout << "Switch operational." << std::endl;
    }

    // Main packet processing logic (called when a raw frame/buffer is received on a port)
    void process_received_packet(uint32_t ingress_port_id, PacketBuffer* raw_buffer) {
        if (!raw_buffer) return;

        // 0. Check Interface Link Status
        if (!interface_manager_.is_port_link_up(ingress_port_id)) {
            std::cout << "Packet dropped, ingress port " << ingress_port_id << " link is down." << std::endl;
            // Note: PacketBuffer ref_count will be decremented when raw_buffer is handled by caller
            // or if we create a Packet object and it goes out of scope.
            // If we don't create Packet pkt(raw_buffer), then raw_buffer needs explicit handling here.
            // For simplicity, let's assume raw_buffer's lifecycle is managed if we return early.
            // A common pattern: if Packet takes ownership, then its destructor handles it.
            // If not creating Packet, then: buffer_pool.free_buffer(raw_buffer) or similar would be needed.
            // Let's assume for now that not creating Packet means the buffer is immediately freed/recycled.
            // This detail depends on BufferPool's design which currently expects Packet to decr_ref.
            // So, to be safe with current PacketBuffer design:
            raw_buffer->decrement_ref(); // Manually decrement if Packet object is not created.
            return;
        }
        interface_manager_._increment_rx_stats(ingress_port_id, raw_buffer->size);


        Packet pkt(raw_buffer); // Packet takes ownership (increments ref count)

        // X. ACL Evaluation (early stage)
        uint32_t redirect_port_id_acl = 0; // Will be set by evaluate if REDIRECT
        AclActionType acl_action = acl_manager_.evaluate(pkt, redirect_port_id_acl);

        if (acl_action == AclActionType::DENY) {
            std::cout << "Packet dropped by ACL DENY rule on ingress port " << ingress_port_id << std::endl;
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true); // is_drop = true
            return; // pkt destructor handles buffer ref_count
        }
        if (acl_action == AclActionType::REDIRECT) {
            std::cout << "Packet redirected by ACL to port " << redirect_port_id_acl
                      << " from ingress port " << ingress_port_id << std::endl;
            // For REDIRECT, we might bypass further L2/L3 processing and send directly to the redirect_port.
            // This simplified REDIRECT assumes the redirect_port_id is a physical port.
            // QoS could still be applied on the new egress port.
            uint8_t queue_id_redirect = qos_manager_.classify_packet_to_queue(pkt, redirect_port_id_acl);
            qos_manager_.enqueue_packet(pkt, redirect_port_id_acl, queue_id_redirect);
            interface_manager_._increment_tx_stats(redirect_port_id_acl, pkt.get_buffer()->size); // Assuming it will be sent
            // TODO: A separate scheduler would dequeue and call the actual physical forward_packet.
            return; // pkt destructor handles buffer ref_count
        }
        // If PERMIT, continue normal processing.

        // Y. Packet Classification (can happen before or after L2/L3 logic depending on use case)
        uint32_t classification_action_id = packet_classifier_.classify(pkt);
        if (classification_action_id != 0) { // 0 might mean "no specific rule, continue normal L2/L3"
            std::cout << "Packet on port " << ingress_port_id
                      << " classified by PacketClassifier with action ID: " << classification_action_id
                      << ". (Placeholder: Action not explicitly taken beyond logging/flow table)" << std::endl;

            FlowKey current_flow_key = packet_classifier_.extract_flow_key(pkt);
            auto flow_entry = flow_table_.lookup(current_flow_key);
            if(flow_entry.has_value()){
                 std::cout << "  Flow entry found in FlowTable. Action ID: " << flow_entry.value() << std::endl;
                 // Action could be to use this action_id to override normal forwarding, e.g., if it's a specific egress port or policer.
            } else {
                 std::cout << "  No specific flow entry in FlowTable for this packet." << std::endl;
                 // Potentially add to flow table after L2/L3 processing if it's a new valid flow that should be fast-pathed.
                 // Example: flow_table_.insert(current_flow_key, some_derived_action_or_port_id);
            }
        }

        // 1. Ingress VLAN Processing
        PacketAction vlan_action = vlan_manager.process_ingress(pkt, ingress_port_id);
        if (vlan_action == PacketAction::DROP) {
            std::cout << "Packet dropped by ingress VLAN processing on port " << ingress_port_id << std::endl;
            // pkt's destructor will decrement ref count of raw_buffer
            return;
        }
        // If PacketAction::CONSUME, it might be sent to packet_handler_ directly.

        // 2. STP Check (on ingress port - BPDUs are processed, data might be dropped)
        if (stp_manager.get_port_state(ingress_port_id) == StpManager::PortState::BLOCKING ||
            stp_manager.get_port_state(ingress_port_id) == StpManager::PortState::LISTENING) {
            // Only BPDUs should be processed by CPU if port is BLOCKING/LISTENING.
            // Here we assume BPDUs are handled separately or by packet_handler_ if they reach here.
            // For non-BPDU traffic:
            bool is_bpdu = false; // TODO: Logic to identify BPDUs (e.g. check MAC dst, LLC type)
            if (!is_bpdu) {
                 std::cout << "Packet dropped, port " << ingress_port_id << " not in STP forwarding/learning state." << std::endl;
                 return;
            }
        }

        // If packet is a BPDU, it should be sent to STP manager or CPU
        // Example: Check destination MAC for BPDU multicast address
        static const uint8_t bpdu_mac_bytes[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x00};
        MacAddress bpdu_mac(bpdu_mac_bytes);
        if (pkt.ethernet() && pkt.dst_mac() && pkt.dst_mac().value() == bpdu_mac) {
            stp_manager.process_bpdu(pkt, ingress_port_id);
            // BPDUs are typically not forwarded further in the data plane by this path.
            return;
        }


        // 3. MAC Learning
        if (stp_manager.should_learn(ingress_port_id)) { // Learn only if port is in Learning or Forwarding state
            if (pkt.ethernet() && pkt.src_mac().has_value()) {
                uint16_t vlan_for_learning = 0; // Default if no VLAN
                if (pkt.vlan_id().has_value()) {
                    vlan_for_learning = pkt.vlan_id().value();
                } else {
                    // If packet is untagged after ingress processing, associate with native VLAN of ingress port
                    const auto* port_cfg = vlan_manager.get_port_config(ingress_port_id);
                    if (port_cfg) vlan_for_learning = port_cfg->native_vlan;
                }
                fdb.learn_mac(pkt.src_mac().value(), ingress_port_id, vlan_for_learning);
            }
        }

        // 4. Forwarding Lookup
        if (pkt.ethernet() && pkt.dst_mac().has_value()) {
            uint16_t vlan_for_lookup = 0;
            if (pkt.vlan_id().has_value()) {
                vlan_for_lookup = pkt.vlan_id().value();
            } else {
                const auto* port_cfg = vlan_manager.get_port_config(ingress_port_id);
                if (port_cfg) vlan_for_lookup = port_cfg->native_vlan;
            }

            std::optional<uint32_t> egress_port_opt = fdb.lookup_port(pkt.dst_mac().value(), vlan_for_lookup);

            if (egress_port_opt.has_value()) {
                uint32_t egress_port = egress_port_opt.value();
                if (egress_port == ingress_port_id) {
                    // MAC learned on this port, but destination is also this port (e.g. reflection) - drop
                    std::cout << "Packet dropped, destination MAC is on ingress port " << ingress_port_id << std::endl;
                    return;
                }

                // Check STP state for egress port
                if (!stp_manager.should_forward(egress_port)) {
                    std::cout << "Packet dropped, egress port " << egress_port << " not in STP forwarding state." << std::endl;
                    return;
                }

                // Check VLAN membership for egress (should_forward in VLAN manager checks both ingress and egress permissions)
                if (!vlan_manager.should_forward(ingress_port_id, egress_port, vlan_for_lookup)) {
                    std::cout << "Packet dropped, VLAN " << vlan_for_lookup << " not allowed between port " << ingress_port_id << " and " << egress_port << std::endl;
                    return;
                }

                // Apply egress VLAN processing
                // This is tricky: process_egress might modify the packet.
                // If forward_packet sends the original buffer, this needs careful handling.
                // For now, assume process_egress modifies pkt, and forward_packet sends it.

                // LACP: Determine actual physical port if egress_port is a LAG
                uint32_t final_egress_port = egress_port;
                if (lacp_manager_.get_lag_config(egress_port).has_value()) { // egress_port is a LAG ID
                    final_egress_port = lacp_manager_.select_egress_port(egress_port, pkt);
                    std::cout << "LAG " << egress_port << " resolved to physical port " << final_egress_port << std::endl;
                }

                // Apply egress VLAN processing for the final physical port
                vlan_manager.process_egress(pkt, final_egress_port);

                // QoS: Classify and Enqueue for the final physical port
                uint8_t queue_id = qos_manager_.classify_packet_to_queue(pkt, final_egress_port);
                qos_manager_.enqueue_packet(pkt, final_egress_port, queue_id);
                std::cout << "Packet enqueued to port " << final_egress_port << " queue " << static_cast<int>(queue_id) << std::endl;

                // Original direct forwarding commented out - now handled by enqueue + separate scheduler (conceptual)
                // forward_packet(pkt, final_egress_port);
                interface_manager_._increment_tx_stats(final_egress_port, pkt.get_buffer()->size); // Assume sent by scheduler
            } else {
                // Destination MAC unknown, flood the packet.
                // Flood logic needs to be updated to consider LACP and QoS for each member port.
                // For now, high-level flood_packet call remains; its internals would need LACP/QoS.
                flood_packet(pkt, ingress_port_id);
            }
        } else {
            // Not an Ethernet packet or no destination MAC, decide policy (e.g. drop or limited flood)
            std::cout << "Packet dropped, not Ethernet or no destination MAC." << std::endl;
            interface_manager_._increment_rx_stats(ingress_port_id, pkt.get_buffer()->size, false, true); // false for error, true for drop
        }
        // pkt's destructor will decrement ref count of raw_buffer when it goes out of scope
    }


private:
    uint32_t num_ports_;
    std::function<void(Packet& pkt, uint32_t ingress_port)> packet_handler_;
    // Other switch-wide configurations can go here.
    // Note: _increment_rx_stats/_increment_tx_stats in InterfaceManager are marked with underscore
    // suggesting they are intended for internal use by Switch or data plane handlers.
    // Making them public or providing a proper stats update interface would be better.
    // For now, Switch calls them directly.
};

} // namespace netflow

#endif // NETFLOW_SWITCH_HPP
