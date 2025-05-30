#include "netflow++/lacp_manager.hpp"
#include "netflow++/packet.hpp"      // For Packet, EthernetHeader
#include "netflow++/buffer_pool.hpp" // For BufferPool
#include <iostream> // For temporary logging
#include <cstring>  // For memcpy

// Helper for ntohll/htonll if not available elsewhere (e.g. in ConfigBpdu)
// For now, assume they might be needed if not using a global utility.
// static uint64_t lacp_ntohll(uint64_t val) {
//     if (__BYTE_ORDER == __LITTLE_ENDIAN) {
//         return (((uint64_t)ntohl(val & 0xFFFFFFFF)) << 32) | ntohl(val >> 32);
//     }
//     return val;
// }
// static uint64_t lacp_htonll(uint64_t val) {
//     if (__BYTE_ORDER == __LITTLE_ENDIAN) {
//         return (((uint64_t)htonl(val & 0xFFFFFFFF)) << 32) | htonl(val >> 32);
//     }
//     return val;
// }


namespace netflow {

void LacpManager::process_lacpdu(const Packet& lacpdu_packet, uint32_t ingress_port_id) {
    auto port_info_it = port_lacp_info_.find(ingress_port_id);
    if (port_info_it == port_lacp_info_.end()) {
        // std::cout << "LACP: LACPDU received on non-LACP port " << ingress_port_id << std::endl;
        return; // Port not configured for LACP
    }
    LacpPortInfo& p_info = port_info_it->second;

    const PacketBuffer* pb = lacpdu_packet.get_buffer();
    if (!pb || pb->size < (sizeof(EthernetHeader) + LACPDU_MIN_SIZE)) {
        // std::cout << "LACP: Packet too small for LACPDU on port " << ingress_port_id << std::endl;
        return;
    }

    const uint8_t* lacpdu_start = pb->data + sizeof(EthernetHeader);
    Lacpdu received_pdu;
    memcpy(&received_pdu, lacpdu_start, LACPDU_MIN_SIZE); // Copy minimum size

    if (received_pdu.subtype != LacpDefaults::LACP_SUBTYPE || received_pdu.version_number != LacpDefaults::LACP_VERSION) {
        // std::cout << "LACP: Invalid LACPDU subtype or version on port " << ingress_port_id << std::endl;
        return;
    }

    // std::cout << "LACP: Valid LACPDU received on port " << ingress_port_id << std::endl;

    // Update Partner Information from received LACPDU
    // Actor info in the PDU is the sender's (our partner's) perspective of themselves
    p_info.partner_system_id_val = received_pdu.get_actor_system_id(); // Partner's System ID is Actor's System ID in PDU
    p_info.partner_port_id_val = ntohs(received_pdu.actor_port_number);
    p_info.partner_key_val = ntohs(received_pdu.actor_key);
    p_info.partner_state_val = received_pdu.actor_state;

    // Mark that we have current partner info (not defaulted or expired immediately)
    p_info.actor_state_val &= ~static_cast<uint8_t>(LacpStateFlag::DEFAULTED);
    p_info.actor_state_val &= ~static_cast<uint8_t>(LacpStateFlag::EXPIRED);


    // Reset timeout timers based on partner's LACP_TIMEOUT state
    if (p_info.partner_state_val & LacpStateFlag::LACP_TIMEOUT) { // Partner using Short Timeout
        p_info.short_timeout_timer_ticks = 0;
    } else { // Partner using Long Timeout
        p_info.long_timeout_timer_ticks = 0;
    }

    // LACP Rx machine should be called here to process the new partner info
    run_lacp_rx_machine(ingress_port_id);
    // Other machines might be affected as well
    run_lacp_mux_machine(ingress_port_id);
    run_lacp_periodic_tx_machine(ingress_port_id); // Update periodic TX based on new state
}

std::vector<Packet> LacpManager::generate_lacpdus(BufferPool& buffer_pool) {
    std::vector<Packet> lacpdus_to_send;

    for (auto& pair : port_lacp_info_) {
        uint32_t port_id = pair.first;
        LacpPortInfo& p_info = pair.second;

        // Check if LACP is enabled on the port (implicitly by being in port_lacp_info_ and not disabled by state machine)
        // and if periodic transmission is due (PeriodicTxMachine sets PERIODIC_TX state)
        if (p_info.periodic_tx_state != LacpPortInfo::PeriodicTxState::PERIODIC_TX) {
            if (!(p_info.periodic_tx_state == LacpPortInfo::PeriodicTxState::FAST_PERIODIC && p_info.current_while_timer_ticks >= 1) &&
                !(p_info.periodic_tx_state == LacpPortInfo::PeriodicTxState::SLOW_PERIODIC && p_info.current_while_timer_ticks >= 30) )
            {
                 // A more explicit check for p_info.current_while_timer_ticks reaching its limit based on fast/slow would be better.
                 // For now, this simplified check assumes run_lacp_timers_and_statemachines handles the timer expiry and sets PERIODIC_TX.
                 // This function is then called to generate if PERIODIC_TX is set.
                // continue;
            }
        }

        // Or, more simply, if the current_while_timer has expired, time to send.
        // The state machine should manage resetting this timer.
        // For this example, let's assume if current_while_timer is 0, it's time to send (it would be reset after sending).
        // This part needs to align with how run_lacp_timers_and_statemachines updates current_while_timer.
        // A common way: timer counts down to 0. If 0, send and reset.
        // Or counts up to limit. If at limit, send and reset.
        // Let's assume current_while_timer_ticks counts up and is reset by the state machine after sending.
        bool time_to_send = false;
        if (p_info.get_actor_state_flag(LACP_ACTIVITY) || (p_info.partner_state_val & LACP_ACTIVITY)) { // Active mode or partner is active
             if (p_info.get_actor_state_flag(LACP_TIMEOUT)) { // We are using Short Timeout (1s)
                if (p_info.current_while_timer_ticks >= 1) time_to_send = true;
             } else { // We are using Long Timeout (30s)
                if (p_info.current_while_timer_ticks >= 30) time_to_send = true;
             }
        }
        // Also send if partner info has changed significantly (NTT - Need To Transmit)
        // This flag (NTT) would be set by other parts of the state machine. For now, rely on timer.


        if (!time_to_send) { // Simplified check, real logic is in PeriodicTx machine
             // A more robust check: if (p_info.periodic_tx_state != LacpPortInfo::PeriodicTxState::PERIODIC_TX) continue;
             // And ensure the timer in that state has expired.
             // For now, if not time_to_send by this logic, skip.
             // This means run_lacp_timers_and_statemachines MUST set current_while_timer_ticks appropriately.
        }


        Lacpdu pdu_to_send;
        // Fill Actor Info
        pdu_to_send.set_actor_system_id(p_info.actor_system_id_val);
        pdu_to_send.actor_key = htons(p_info.actor_key_val);
        // Actor port ID has priority (high byte) and number (low byte)
        uint16_t actor_port_priority_part = (p_info.actor_port_id_val >> 8) & 0xFF;
        uint16_t actor_port_number_part = p_info.actor_port_id_val & 0xFF;
        pdu_to_send.actor_port_priority = htons(actor_port_priority_part);
        pdu_to_send.actor_port_number = htons(actor_port_number_part);
        pdu_to_send.actor_state = p_info.actor_state_val;

        // Fill Partner Info (from our stored partner data for this port)
        // Partner System ID in PDU: high 2 bytes priority, low 6 bytes MAC
        pdu_to_send.partner_system_priority = htons(static_cast<uint16_t>((p_info.partner_system_id_val >> 48) & 0xFFFF));
        for(int i=0; i<6; ++i) pdu_to_send.partner_system_mac[5-i] = (p_info.partner_system_id_val >> (i*8)) & 0xFF;
        pdu_to_send.partner_key = htons(p_info.partner_key_val);
        // Partner port ID also has priority and number
        uint16_t partner_port_priority_part = (p_info.partner_port_id_val >> 8) & 0xFF;
        uint16_t partner_port_number_part = p_info.partner_port_id_val & 0xFF;
        pdu_to_send.partner_port_priority = htons(partner_port_priority_part);
        pdu_to_send.partner_port_number = htons(partner_port_number_part);
        pdu_to_send.partner_state = p_info.partner_state_val;

        // Collector Info
        pdu_to_send.collector_max_delay = htons(0); // Default, can be configured if switch supports it

        size_t total_lacpdu_size = sizeof(EthernetHeader) + LACPDU_MIN_SIZE;
        PacketBuffer* pb = buffer_pool.allocate_buffer(total_lacpdu_size);
        if (!pb) {
            // std::cerr << "LACP: Failed to allocate buffer for LACPDU on port " << port_id << std::endl;
            continue;
        }
        pb->size = total_lacpdu_size;

        EthernetHeader* eth_hdr = reinterpret_cast<EthernetHeader*>(pb->data);
        eth_hdr->dst_mac = ConfigBpdu::htonll(LacpDefaults::LACP_MULTICAST_MAC); // LACP Multicast MAC
        eth_hdr->src_mac = ConfigBpdu::htonll(switch_mac_address_); // Use switch base MAC as source
        eth_hdr->ethertype = htons(LacpDefaults::LACP_ETHERTYPE);

        memcpy(pb->data + sizeof(EthernetHeader), &pdu_to_send, LACPDU_MIN_SIZE);

        Packet new_lacp_packet(pb);
        lacpdus_to_send.push_back(new_lacp_packet);
        buffer_pool.release_buffer(pb);

        // std::cout << "LACP: Generated LACPDU for port " << port_id << std::endl;
        p_info.current_while_timer_ticks = 0; // Reset timer as we've sent a PDU
        // The periodic TX state machine might adjust the state (e.g. from PERIODIC_TX to FAST_PERIODIC)
    }
    return lacpdus_to_send;
}


// Placeholder for state machines and timers
void LacpManager::run_lacp_rx_machine(uint32_t port_id) {
    // TODO: Implement LACP Receive Machine logic based on IEEE 802.1AX Section 7.3.5
    // This machine updates:
    // - p_info.partner_state_val by clearing EXPIRED and DEFAULTED if a valid LACPDU is received.
    // - p_info.rx_state transitions (e.g., INITIALIZE -> PORT_DISABLED -> LACP_DISABLED -> EXPIRED -> DEFAULTED -> CURRENT)
    // - Timers like short_timeout_timer or long_timeout_timer are reset upon PDU reception.
    // std::cout << "LACP: RX Machine for port " << port_id << " (placeholder)" << std::endl;
    LacpPortInfo& p_info = port_lacp_info_.at(port_id); // Assume port_id is valid

    // Example: if LACPDU received, partner is no longer EXPIRED, reset appropriate timer
    p_info.partner_state_val &= ~static_cast<uint8_t>(LacpStateFlag::EXPIRED);
    if (p_info.get_actor_state_flag(LACP_TIMEOUT)) { // We are on short timeout
        p_info.short_timeout_timer_ticks = 0;
    } else { // We are on long timeout
        p_info.long_timeout_timer_ticks = 0;
    }

    // If actor and partner parameters match for aggregation
    // This is a very simplified check. Real check involves keys, system IDs, etc.
    // And should be part of the MUX machine mostly.
    // Here, we mainly update the partner's state based on the PDU.
    // For now, if we got a PDU, assume partner is CURRENT.
    p_info.rx_state = LacpPortInfo::RxMachineState::CURRENT;

}

void LacpManager::run_lacp_periodic_tx_machine(uint32_t port_id) {
    // TODO: Implement LACP Periodic Transmission Machine logic (IEEE 802.1AX Section 7.3.6)
    // Manages when to send LACPDUs (NO_PERIODIC, FAST_PERIODIC, SLOW_PERIODIC, PERIODIC_TX)
    // std::cout << "LACP: Periodic TX Machine for port " << port_id << " (placeholder)" << std::endl;
     LacpPortInfo& p_info = port_lacp_info_.at(port_id);

    // Simplified logic: if LACP active and port is not disabled, move to fast periodic.
    // Real logic is more complex and depends on partner state, current while timer, etc.
    if (p_info.get_actor_state_flag(LACP_ACTIVITY) && p_info.rx_state != LacpPortInfo::RxMachineState::PORT_DISABLED && p_info.rx_state != LacpPortInfo::RxMachineState::LACP_DISABLED) {
        if (p_info.periodic_tx_state == LacpPortInfo::PeriodicTxState::NO_PERIODIC) {
            p_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::FAST_PERIODIC;
            p_info.current_while_timer_ticks = 0; // Reset timer for the new state
        }
    } else {
        p_info.periodic_tx_state = LacpPortInfo::PeriodicTxState::NO_PERIODIC;
    }

    // If in a periodic state and timer expires, set to PERIODIC_TX (to trigger send)
    // This part is a bit mixed with generate_lacpdus, ideally this machine just sets flags/states.
    // generate_lacpdus then checks these flags.
}

void LacpManager::run_lacp_mux_machine(uint32_t port_id) {
    // TODO: Implement LACP Mux Machine logic (IEEE 802.1AX Section 7.3.7)
    // Determines if a port can be aggregated. Updates:
    // - p_info.mux_state (DETACHED, WAITING, ATTACHED, COLLECTING_DISTRIBUTING)
    // - p_info.actor_state_val flags: SYNCHRONIZATION, COLLECTING, DISTRIBUTING
    // - p_info.is_active_member_of_lag
    // std::cout << "LACP: MUX Machine for port " << port_id << " (placeholder)" << std::endl;
    LacpPortInfo& p_info = port_lacp_info_.at(port_id);

    // Highly simplified: If partner is InSync and our keys match, try to attach.
    bool partner_in_sync = (p_info.partner_state_val & LacpStateFlag::SYNCHRONIZATION);
    bool keys_match = (p_info.actor_key_val == p_info.partner_key_val); // Assuming keys are operational keys
    bool system_ids_match = (p_info.actor_system_id_val == p_info.partner_system_id_val); // This would be for loopback detection or misconfig.
                                                                                        // For aggregation, partner system ID should be DIFFERENT but key the same.

    if (p_info.mux_state == LacpPortInfo::MuxMachineState::DETACHED && !system_ids_match && keys_match) {
         p_info.mux_state = LacpPortInfo::MuxMachineState::WAITING;
         // Start wait_while_timer (not explicitly defined yet)
    }

    // If in WAITING and wait_while_timer expires (simulated by just checking partner state for now)
    if (p_info.mux_state == LacpPortInfo::MuxMachineState::WAITING && partner_in_sync) {
        p_info.mux_state = LacpPortInfo::MuxMachineState::ATTACHED;
        p_info.set_actor_state_flag(LacpStateFlag::SYNCHRONIZATION, true);
    }

    // If ATTACHED and selected (by port selection logic, not yet fully implemented here)
    // For now, assume if ATTACHED and partner is Collecting+Distributing, we can also.
    bool partner_collect_dist = (p_info.partner_state_val & LacpStateFlag::COLLECTING) && (p_info.partner_state_val & LacpStateFlag::DISTRIBUTING);
    if (p_info.mux_state == LacpPortInfo::MuxMachineState::ATTACHED && p_info.get_actor_state_flag(SYNCHRONIZATION) && partner_collect_dist) {
        p_info.mux_state = LacpPortInfo::MuxMachineState::COLLECTING_DISTRIBUTING;
        p_info.set_actor_state_flag(LacpStateFlag::COLLECTING, true);
        p_info.set_actor_state_flag(LacpStateFlag::DISTRIBUTING, true);
        p_info.is_active_member_of_lag = true;
    } else if (p_info.mux_state == LacpPortInfo::MuxMachineState::COLLECTING_DISTRIBUTING) {
        // Condition to move out of C&D state (e.g. partner not C&D anymore, or port unselected)
        if (!p_info.get_actor_state_flag(SYNCHRONIZATION) || !partner_collect_dist) {
            p_info.mux_state = LacpPortInfo::MuxMachineState::ATTACHED; // Revert to ATTACHED
            p_info.set_actor_state_flag(LacpStateFlag::COLLECTING, false);
            p_info.set_actor_state_flag(LacpStateFlag::DISTRIBUTING, false);
            p_info.is_active_member_of_lag = false;
        }
    }
}

void LacpManager::update_port_selection_logic(uint32_t port_id) {
    // TODO: Implement port selection logic based on compatible partners.
    // This would iterate all ports in a LAG, find those with compatible actor/partner parameters
    // (matching keys, system IDs for LAG formation), and then select them to form an aggregator.
    // Sets p_info.is_active_member_of_lag = true for selected ports.
    // This is a complex part, usually involving comparing port priorities, IDs etc. if more ports
    // are available than can be supported by an aggregator, or choosing an aggregator.
    // For now, this is a placeholder. The MUX machine above does a very basic version.
}


void LacpManager::run_lacp_timers_and_statemachines() {
    for (auto& pair : port_lacp_info_) {
        uint32_t port_id = pair.first;
        LacpPortInfo& p_info = pair.second;

        // Increment current_while_timer (used by periodic TX)
        // This timer dictates when to send next LACPDU in FAST/SLOW periodic states.
        p_info.current_while_timer_ticks++;


        // LACP Timeout Timer handling (for partner state EXPIRED)
        bool partner_is_short_timeout = (p_info.partner_state_val & LacpStateFlag::LACP_TIMEOUT);
        if (partner_is_short_timeout) {
            p_info.short_timeout_timer_ticks++;
            if (p_info.short_timeout_timer_ticks >= 3) { // 3 * 1s = 3s for short timeout
                p_info.partner_state_val |= LacpStateFlag::EXPIRED;
                p_info.partner_state_val |= LacpStateFlag::DEFAULTED; // On timeout, revert to defaulted partner info
                // Other fields of partner info should be reset to defaults
                p_info.partner_system_id_val = 0;
                p_info.partner_port_id_val = 0;
                p_info.partner_key_val = 0;
                // rx_state might also change to EXPIRED or DEFAULTED
                p_info.rx_state = LacpPortInfo::RxMachineState::EXPIRED;

            }
        } else { // Partner using Long Timeout
            p_info.long_timeout_timer_ticks++;
            if (p_info.long_timeout_timer_ticks >= 90) { // 3 * 30s = 90s for long timeout
                p_info.partner_state_val |= LacpStateFlag::EXPIRED;
                p_info.partner_state_val |= LacpStateFlag::DEFAULTED;
                p_info.partner_system_id_val = 0;
                p_info.partner_port_id_val = 0;
                p_info.partner_key_val = 0;
                p_info.rx_state = LacpPortInfo::RxMachineState::EXPIRED;
            }
        }

        // Call individual state machines
        // Order can be important. Rx machine first, then periodic, then mux.
        run_lacp_rx_machine(port_id);       // Processes PDU data, updates partner state, rx_state
        run_lacp_periodic_tx_machine(port_id); // Determines if/when to send PDUs
        run_lacp_mux_machine(port_id);        // Determines aggregation status, port's operational state (Sync, Collect, Distribute)
        // update_port_selection_logic(port_id); // Part of MUX logic or called after MUX state changes
    }
}

// select_egress_port implementation (placeholder for now)
uint32_t LacpManager::select_egress_port(uint32_t lag_id, const Packet& pkt) const {
    auto it = lags_.find(lag_id);
    if (it == lags_.end()) return 0; // Invalid LAG

    const LagConfig& lag_config = it->second;
    std::vector<uint32_t> active_members;
    for (uint32_t port_id : lag_config.member_ports) {
        auto p_info_it = port_lacp_info_.find(port_id);
        if (p_info_it != port_lacp_info_.end() && p_info_it->second.is_active_member_of_lag) {
            active_members.push_back(port_id);
        }
    }

    if (active_members.empty()) {
        // std::cout << "LACP: No active members in LAG " << lag_id << " for packet egress." << std::endl;
        return 0;
    }

    // TODO: Implement actual hashing based on lag_config.hash_mode and pkt.
    // Using placeholder: hash of source MAC if available.
    uint32_t hash_val = 0;
    if(pkt.src_mac().has_value()){
        const MacAddress& mac = pkt.src_mac().value();
        for(int i=0; i<6; ++i) hash_val += mac.bytes[i];
    }
     if(pkt.dst_mac().has_value()){ // Add dst mac to hash for more variance
        const MacAddress& mac = pkt.dst_mac().value();
        for(int i=0; i<6; ++i) hash_val += mac.bytes[i];
    }
    // This is a very poor hash. Real hashing needed.
    return active_members[hash_val % active_members.size()];
}


} // namespace netflow
