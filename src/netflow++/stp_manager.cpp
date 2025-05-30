#include "netflow++/stp_manager.hpp"
#include "netflow++/packet.hpp" // For Packet, EthernetHeader, LLCHeader
#include "netflow++/buffer_pool.hpp" // Required for generate_bpdus access to BufferPool
#include <iostream> // For temporary logging
#include <cstring>  // For memcpy in generate_bpdus

namespace netflow {

// --- StpManager::process_bpdu ---
void StpManager::process_bpdu(const Packet& bpdu_packet, uint32_t ingress_port_id) {
    auto port_it = port_stp_info_.find(ingress_port_id);
    if (port_it == port_stp_info_.end()) {
        // std::cerr << "STP: Received BPDU on unknown port: " << ingress_port_id << std::endl;
        return;
    }

    StpPortInfo& p_info = port_it->second;
    if (p_info.state == PortState::DISABLED) {
        // std::cout << "STP: BPDU received on disabled port " << ingress_port_id << ", ignoring." << std::endl;
        return;
    }

    const PacketBuffer* pb = bpdu_packet.get_buffer();
    if (!pb || pb->size < sizeof(EthernetHeader) + sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE) {
        // std::cerr << "STP: Received packet too small to be a valid BPDU on port " << ingress_port_id << std::endl;
        return;
    }

    // Assuming BPDU is encapsulated in Ethernet + LLC
    // Skip Ethernet header, then LLC header to get to BPDU payload
    const uint8_t* bpdu_payload_start = pb->data + sizeof(EthernetHeader) + sizeof(LLCHeader);
    size_t bpdu_payload_length = pb->size - (sizeof(EthernetHeader) + sizeof(LLCHeader));

    if (bpdu_payload_length < CONFIG_BPDU_PAYLOAD_SIZE) {
        // std::cerr << "STP: BPDU payload too short on port " << ingress_port_id << std::endl;
        return;
    }

    ConfigBpdu received_config_bpdu;
    memcpy(&received_config_bpdu, bpdu_payload_start, CONFIG_BPDU_PAYLOAD_SIZE);

    // Validate BPDU (basic checks)
    if (received_config_bpdu.protocol_id != StpDefaults::PROTOCOL_ID ||
        received_config_bpdu.version_id != StpDefaults::VERSION_ID_STP || // Classic STP/RSTP BPDUs
        received_config_bpdu.bpdu_type != StpDefaults::BPDU_TYPE_CONFIG) {
        // std::cout << "STP: Received non-Config BPDU or invalid version/protocol on port " << ingress_port_id << ", ignoring." << std::endl;
        return;
    }

    // std::cout << "STP: Valid Config BPDU received on port " << ingress_port_id << std::endl;

    ReceivedBpduInfo new_bpdu = received_config_bpdu.to_received_bpdu_info();

    // Update port's received BPDU info
    // The comparison logic (is_superior_to) is in ReceivedBpduInfo, but actual STP standard
    // dictates specific comparison steps. For now, we'll just store the latest.
    // A real implementation would compare new_bpdu with p_info.received_bpdu
    // and only update if new_bpdu is superior or has pertinent changes.
    p_info.received_bpdu = new_bpdu;
    p_info.message_age_timer_seconds = 0; // Reset message age timer for this port's BPDU info
    p_info.new_bpdu_received_flag = true;

    // TODO: Log received BPDU details if necessary using a logger object

    recalculate_stp_roles_and_states();
}

// --- StpManager::generate_bpdus ---
std::vector<Packet> StpManager::generate_bpdus(BufferPool& buffer_pool) {
    std::vector<Packet> bpdus_to_send;
    // This method should be called approximately once per hello_time_seconds for the root bridge,
    // or when a port becomes designated and needs to send BPDUs.

    for (auto& pair : port_stp_info_) {
        uint32_t port_id = pair.first;
        StpPortInfo& p_info = pair.second;

        if (p_info.role == PortRole::DESIGNATED && p_info.state != PortState::DISABLED && p_info.state != PortState::BLOCKING) {
            if (p_info.hello_timer_seconds >= bridge_config_.hello_time_seconds) {
                p_info.hello_timer_seconds = 0; // Reset hello timer

                // Construct BPDU payload using our bridge's current STP information
                ConfigBpdu bpdu_to_send_struct;
                ReceivedBpduInfo source_bpdu_params = bridge_config_.our_bpdu_info;

                // If we are not the root bridge, the BPDUs we send on designated ports are based on
                // our root port's received BPDU, with costs and bridge ID updated.
                // The message_age also needs to be incremented.
                uint16_t effective_message_age = source_bpdu_params.message_age;
                if (!bridge_config_.is_root_bridge()) {
                    // Increment message age by 1 second (256/256ths) when relaying BPDU info
                    // This is a simplification; precise increment depends on actual time passed.
                     effective_message_age += 256;
                }

                // Ensure message age does not exceed max_age from the root's perspective
                if (effective_message_age >= source_bpdu_params.max_age) {
                    // std::cout << "STP: BPDU for port " << port_id << " message age would exceed max age. Not sending." << std::endl;
                    continue;
                }

                bpdu_to_send_struct.from_bpdu_info_for_sending(
                    source_bpdu_params,
                    bridge_config_.bridge_id_value,
                    p_info.stp_port_id_field,
                    effective_message_age,
                    source_bpdu_params.max_age,    // Max Age from root's BPDU
                    source_bpdu_params.hello_time, // Hello Time from root's BPDU
                    source_bpdu_params.forward_delay // Forward Delay from root's BPDU
                );

                // TODO: Set TC/TCA flags correctly based on STP state machine events.
                // bpdu_to_send_struct.set_flags(bridge_config_.our_bpdu_info.tc_flag, bridge_config_.our_bpdu_info.tca_flag);


                // Allocate PacketBuffer
                size_t total_bpdu_size = sizeof(EthernetHeader) + sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE;
                PacketBuffer* pb = buffer_pool.allocate_buffer(total_bpdu_size);
                if (!pb) {
                    // std::cerr << "STP: Failed to allocate buffer for BPDU on port " << port_id << std::endl;
                    continue; // Or handle error appropriately
                }
                pb->size = total_bpdu_size;

                // Construct Ethernet Header
                EthernetHeader* eth_hdr = reinterpret_cast<EthernetHeader*>(pb->data);
                eth_hdr->dst_mac = htonll(0x0180C2000000ULL); // STP Multicast MAC
                // Source MAC should be the MAC of this specific port, or bridge MAC if per-port MACs not used.
                // For now, use bridge_config's MAC.
                eth_hdr->src_mac = htonll(bridge_config_.bridge_mac_address);
                eth_hdr->ethertype = htons(sizeof(LLCHeader) + CONFIG_BPDU_PAYLOAD_SIZE); // Length field for LLC

                // Construct LLC Header (for STP BPDUs)
                LLCHeader* llc_hdr = reinterpret_cast<LLCHeader*>(pb->data + sizeof(EthernetHeader));
                llc_hdr->dsap = 0x42; // Bridge Spanning Tree Protocol Group DSAP
                llc_hdr->ssap = 0x42; // Bridge Spanning Tree Protocol Group SSAP
                llc_hdr->control = 0x03; // Unnumbered Information (UI frame)

                // Copy BPDU payload
                memcpy(pb->data + sizeof(EthernetHeader) + sizeof(LLCHeader), &bpdu_to_send_struct, CONFIG_BPDU_PAYLOAD_SIZE);

                Packet new_bpdu_packet(pb);
                // The packet might need a reference to the originating port for some switch architectures,
                // but for now, the vector of packets is enough. The caller (Switch) would handle sending.
                bpdus_to_send.push_back(new_bpdu_packet);
                buffer_pool.release_buffer(pb); // Release our reference, Packet owns one now.

                // std::cout << "STP: Generated BPDU for port " << port_id << std::endl;
            }
        }
    }
    return bpdus_to_send;
}

// --- StpManager::recalculate_stp_roles_and_states ---
void StpManager::recalculate_stp_roles_and_states() {
    // This is a placeholder for the complex STP logic.
    // A full implementation involves:
    // 1. Update Root Bridge Election:
    //    - Compare our bridge's current root_bridge_info with BPDUs received on all ports.
    //    - If a superior BPDU is found (better root_id, or same root_id with lower path cost, or tie-breaking rules),
    //      update our_bpdu_info to reflect the new root and identify the new root_port_internal_id.
    //    - If our own bridge_id_value is the best, we become/remain the root.

    // 2. Determine Port Roles for each active port:
    //    - Root Port (RP): One port that offers the best path to the elected Root Bridge. Blocked if no path.
    //    - Designated Port (DP): For each LAN segment, one port is elected as DP. This bridge's port becomes DP if it offers
    //      the best path from that segment towards the Root Bridge, or if this bridge is the Root Bridge.
    //    - Alternate Port (AP): Ports that offer a backup path to the Root Bridge (alternative to RP). Blocking state.
    //    - Backup Port (BP): Ports connected to a segment where another port on the same bridge is already DP (rare). Blocking state.
    //    - Disabled Port: Administratively down or failed.

    // 3. Transition Port States based on roles and timers:
    //    - Root and Designated ports transition: BLOCKING -> LISTENING -> LEARNING -> FORWARDING.
    //      Each transition (LISTENING, LEARNING) lasts for forward_delay_seconds.
    //    - Alternate and Backup ports remain in BLOCKING state.
    //    - If a port loses its Root/Designated role, it typically reverts to BLOCKING.

    // --- Simplified Placeholder Logic ---
    bool i_am_root = true; // Assume we are root initially for this recalculation cycle
    ReceivedBpduInfo best_root_bpdu_overall = bridge_config_.our_bpdu_info; // Start with our own info as best

    // Re-evaluate our knowledge of the root bridge based on received BPDUs
    for (auto& pair : port_stp_info_) {
        StpPortInfo& p_info = pair.second;
        if (p_info.state == PortState::DISABLED) continue;

        // Check if BPDU received on this port offers a better root or path to current root
        if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds)) {
            // Compare p_info.received_bpdu with best_root_bpdu_overall
            if (p_info.received_bpdu.is_superior_to(best_root_bpdu_overall)) {
                best_root_bpdu_overall = p_info.received_bpdu;
                i_am_root = false; // We found a better root via a received BPDU
            }
        }
    }

    // Update our bridge's view of the root
    if (i_am_root) { // We are still the root bridge
        bridge_config_.our_bpdu_info.root_id = bridge_config_.bridge_id_value;
        bridge_config_.our_bpdu_info.root_path_cost = 0;
        bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value; // We are the sender of root info
        bridge_config_.our_bpdu_info.sender_port_id = 0; // Port ID 0 indicates from bridge itself
        bridge_config_.root_port_internal_id.reset();
        // Timers (max_age, hello, fwd_delay) in our_bpdu_info are our configured values.
        bridge_config_.our_bpdu_info.message_age = 0; // Message age is 0 when originated by root
    } else { // We are not the root, best_root_bpdu_overall holds the superior root info
        bridge_config_.our_bpdu_info.root_id = best_root_bpdu_overall.root_id;
        // Our root path cost will be the received BPDU's root_path_cost + cost of the port it came in on.
        // This needs to find the actual root port first.
        // For now, just copy, but this is NOT correct for our_bpdu_info if we are not root.
        // bridge_config_.our_bpdu_info.root_path_cost = best_root_bpdu_overall.root_path_cost; // This will be updated after RP selection
        bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value; // We are the sender
        // Timers should be taken from the root's BPDU
        bridge_config_.our_bpdu_info.max_age = best_root_bpdu_overall.max_age;
        bridge_config_.our_bpdu_info.hello_time = best_root_bpdu_overall.hello_time;
        bridge_config_.our_bpdu_info.forward_delay = best_root_bpdu_overall.forward_delay;
        bridge_config_.our_bpdu_info.message_age = best_root_bpdu_overall.message_age; // Will be incremented when sent
    }

    // Determine Root Port (if not root)
    bridge_config_.root_port_internal_id.reset();
    uint32_t best_rpc_to_root_via_port = 0xFFFFFFFF;

    if (!i_am_root) {
        uint32_t current_best_port_id = 0; // Placeholder
        bool root_port_found = false;

        for (auto& pair : port_stp_info_) {
            StpPortInfo& p_info = pair.second;
            if (p_info.state == PortState::DISABLED) continue;

            if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds) && p_info.received_bpdu.root_id == bridge_config_.our_bpdu_info.root_id) {
                uint32_t cost_via_this_port = p_info.received_bpdu.root_path_cost + p_info.path_cost_to_segment;
                if (cost_via_this_port < best_rpc_to_root_via_port) {
                    best_rpc_to_root_via_port = cost_via_this_port;
                    current_best_port_id = p_info.port_id_internal;
                    root_port_found = true;
                } else if (cost_via_this_port == best_rpc_to_root_via_port) {
                    // Tie-breaking: lower sender bridge ID, then lower sender port ID
                    StpPortInfo& current_best_p_info = port_stp_info_.at(current_best_port_id);
                    if (p_info.received_bpdu.sender_bridge_id < current_best_p_info.received_bpdu.sender_bridge_id) {
                         current_best_port_id = p_info.port_id_internal;
                    } else if (p_info.received_bpdu.sender_bridge_id == current_best_p_info.received_bpdu.sender_bridge_id &&
                               p_info.received_bpdu.sender_port_id < current_best_p_info.received_bpdu.sender_port_id) {
                         current_best_port_id = p_info.port_id_internal;
                    }
                }
            }
        }
        if (root_port_found) {
            bridge_config_.root_port_internal_id = current_best_port_id;
            bridge_config_.our_bpdu_info.root_path_cost = best_rpc_to_root_via_port;
            // The sender_port_id for our BPDUs should be our root port's stp_port_id_field
             bridge_config_.our_bpdu_info.sender_port_id = port_stp_info_.at(current_best_port_id).stp_port_id_field;
        } else {
            // No path to the elected root, this is problematic. Maybe stay as root or block all.
            // For now, if we thought there was a better root but have no path, revert to being root.
            // This part of logic needs careful handling for convergence.
            i_am_root = true; // Fallback: declare self as root if no path to the better one.
            bridge_config_.our_bpdu_info.root_id = bridge_config_.bridge_id_value;
            bridge_config_.our_bpdu_info.root_path_cost = 0;
            bridge_config_.our_bpdu_info.sender_bridge_id = bridge_config_.bridge_id_value;
            bridge_config_.our_bpdu_info.sender_port_id = 0;
        }
    }


    // Determine Port Roles and States
    for (auto& pair : port_stp_info_) {
        StpPortInfo& p_info = pair.second;
        if (p_info.state == PortState::DISABLED) {
            p_info.role = PortRole::DISABLED;
            continue;
        }

        if (i_am_root) {
            p_info.role = PortRole::DESIGNATED;
            p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
            p_info.designated_port_id_for_segment = p_info.stp_port_id_field;
            p_info.path_cost_from_designated_bridge_to_root = 0;
        } else {
            if (bridge_config_.root_port_internal_id.has_value() && p_info.port_id_internal == bridge_config_.root_port_internal_id.value()) {
                p_info.role = PortRole::ROOT;
            } else {
                // Is this port a designated port for its segment?
                // It is DP if its path to the root is better than any other bridge on that segment (from received BPDUs)
                // OR if its path is equally good but its bridge_id/port_id is lower (tie-breaking)
                // This requires comparing our bridge's root path cost + this port's cost
                // with p_info.received_bpdu.root_path_cost from other bridges on the segment.

                // Simplified: If not root port, assume alternate for now.
                // Proper DP election per segment is complex.
                // A port is DP if our_bpdu_info for this segment is better than any other received_bpdu on this port.
                ReceivedBpduInfo our_proposal_for_segment = bridge_config_.our_bpdu_info;
                // our_proposal_for_segment.root_path_cost is already set to our cost to root.
                // our_proposal_for_segment.sender_bridge_id is our ID.
                our_proposal_for_segment.sender_port_id = p_info.stp_port_id_field;


                if (p_info.has_valid_bpdu_info(bridge_config_.max_age_seconds) &&
                    p_info.received_bpdu.is_superior_to(our_proposal_for_segment)) {
                    // Another bridge on this segment is a better DP, or offers a better path.
                    p_info.role = PortRole::ALTERNATE; // Or backup, but simplified to alternate
                    p_info.designated_bridge_id_for_segment = p_info.received_bpdu.sender_bridge_id;
                    p_info.designated_port_id_for_segment = p_info.received_bpdu.sender_port_id;
                    p_info.path_cost_from_designated_bridge_to_root = p_info.received_bpdu.root_path_cost;

                } else { // Our bridge is the DP for this segment
                    p_info.role = PortRole::DESIGNATED;
                    p_info.designated_bridge_id_for_segment = bridge_config_.bridge_id_value;
                    p_info.designated_port_id_for_segment = p_info.stp_port_id_field;
                    p_info.path_cost_from_designated_bridge_to_root = bridge_config_.our_bpdu_info.root_path_cost;
                }
            }
        }

        // State transitions based on new roles (simplified)
        // This doesn't implement the forward_delay timers for LISTENING/LEARNING properly yet.
        // It should be handled by run_stp_timers based on these roles.
        switch (p_info.role) {
            case PortRole::ROOT:
            case PortRole::DESIGNATED:
                if (p_info.state == PortState::BLOCKING) {
                    p_info.state = PortState::LISTENING;
                    p_info.forward_delay_timer_seconds = 0; // Reset timer for new transition
                }
                // If already LISTENING/LEARNING/FORWARDING, let timer logic handle it.
                break;
            case PortRole::ALTERNATE:
            case PortRole::BACKUP:
            case PortRole::UNKNOWN: // Should not happen if logic is complete
                p_info.state = PortState::BLOCKING;
                p_info.forward_delay_timer_seconds = 0;
                break;
            case PortRole::DISABLED:
                p_info.state = PortState::DISABLED;
                break;
        }
        // std::cout << "STP Recalc: Port " << p_info.port_id_internal << " Role: " << port_role_to_string(p_info.role) << " State: " << port_state_to_string(p_info.state) << std::endl;
    }
    // std::cout << "STP: Bridge " << std::hex << bridge_config_.bridge_id_value << " is " << (i_am_root ? "ROOT" : "NOT ROOT") << ". Known Root: " << bridge_config_.our_bpdu_info.root_id << std::dec << std::endl;
}

} // namespace netflow
