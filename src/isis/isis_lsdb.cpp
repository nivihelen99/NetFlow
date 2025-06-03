#include "netflow++/isis/isis_lsdb.hpp"
#include "netflow++/isis/isis_pdu_constants.hpp" // For TLV types etc. (should be in isis_common.hpp or similar)
#include "netflow++/byte_swap.hpp" // For ntohs, htons etc.

#include <iostream> // For debugging
#include <algorithm> // For std::remove_if, std::sort (if needed for CSNP/PSNP ordering)

// Assume isis_pdu.cpp provides serialize_link_state_pdu, serialize_csnp, serialize_psnp
// and that LspEntry is defined and handled appropriately by PDU serialization/parsing if used in SNPs.

namespace netflow {
namespace isis {

// --- IsisLsdb Implementation ---

IsisLsdb::IsisLsdb(IsisLevel level, const SystemID& local_sys_id, IsisInterfaceManager* if_mgr)
    : level_(level),
      local_system_id_(local_sys_id),
      isis_interface_manager_(if_mgr),
      send_pdu_callback_(nullptr),
      generate_local_lsp_callback_(nullptr) {
    // Initialize any interface_last_csnp_time_ map if needed, or handle dynamically.
}

void IsisLsdb::register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb) {
    send_pdu_callback_ = cb;
}

void IsisLsdb::register_generate_local_lsp_callback(std::function<LinkStatePdu()> cb) {
    generate_local_lsp_callback_ = cb;
}

LspId IsisLsdb::get_local_lsp_id(uint8_t lsp_number) const {
    LspId id;
    id.systemId = local_system_id_;
    id.pseudonodeIdOrLspNumber = lsp_number; // 0 for router LSP, non-zero for pseudonode LSPs if DIS
    return id;
}


bool IsisLsdb::validate_lsp_checksum(const LinkStatePdu& lsp) const {
    // Placeholder: In a real implementation, this would compute and verify the Fletcher checksum.
    // For now, we can assume checksum is valid or skip check for non-owned LSPs.
    // Owned LSPs should have checksum computed upon generation.
    if (lsp.lspId.systemId == local_system_id_) { // Own LSP
        // TODO: Recompute checksum if needed
    }
    return lsp.checksum != 0; // Basic check: non-zero checksum
}

void IsisLsdb::update_lsp_metadata(LsdbEntry& entry, const LinkStatePdu& lsp, uint32_t on_interface_id, std::optional<SystemID> from_neighbor_id, bool is_own) {
    entry.lsp = lsp;
    entry.arrival_time = std::chrono::steady_clock::now();
    // last_flooded_time will be updated when actually flooded.
    entry.received_on_interface_id = on_interface_id;
    if (from_neighbor_id) {
        entry.received_from_neighbor_system_id = from_neighbor_id.value();
    } else {
        entry.received_from_neighbor_system_id = SystemID{}; // Clear it
    }
    entry.own_lsp = is_own;
    entry.purge_initiated = (ntohs(lsp.remainingLifetime) == 0);
    entry.remaining_lifetime_seconds = ntohs(lsp.remainingLifetime);
    if (is_own) {
        entry.last_refreshed_time = std::chrono::steady_clock::now();
    }
}


bool IsisLsdb::add_or_update_lsp(const LinkStatePdu& received_lsp,
                               uint32_t on_interface_id,
                               std::optional<SystemID> from_neighbor_id,
                               bool is_own_lsp) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!validate_lsp_checksum(received_lsp)) {
        // std::cerr << "LSDB (L" << static_cast<int>(level_) << "): Invalid checksum for LSP "
        //           << system_id_to_string(received_lsp.lspId.systemId) << "-" << (int)received_lsp.lspId.pseudonodeIdOrLspNumber
        //           << std::endl;
        return false;
    }

    // TODO: More validation: e.g. PDU length from common header vs LSP internal length
    // Max age check: if received LSP has lifetime 0 but not purging, or lifetime > MAX_LSP_LIFETIME_SECONDS

    auto it = lsdb_.find(received_lsp.lspId);
    if (it != lsdb_.end()) {
        LsdbEntry& existing_entry = it->second;
        const LinkStatePdu& existing_lsp = existing_entry.lsp;

        // Compare sequence numbers
        uint32_t existing_seq = ntohl(existing_lsp.sequenceNumber);
        uint32_t received_seq = ntohl(received_lsp.sequenceNumber);

        if (received_seq < existing_seq) {
            return false; // Older sequence number
        }
        if (received_seq > existing_seq) {
            // Newer sequence number, accept it
        } else { // Same sequence number
            // If checksums differ, specification is ambiguous. Some prefer higher, some treat as error.
            // For now, let's assume if sequence is same, it's not an update unless lifetimes indicate purge.
            // Or, if checksum is different, could be corruption or a very rare wrap-around.
            // Let's follow: same seq -> check lifetime for purge, otherwise checksum.

            uint16_t existing_lifetime = ntohs(existing_lsp.remainingLifetime);
            uint16_t received_lifetime = ntohs(received_lsp.remainingLifetime);

            if (existing_lifetime == 0 && received_lifetime == 0) {
                return false; // Both are purged, no change
            }
            if (received_lifetime == 0 && existing_lifetime != 0) {
                // Received a purge for an existing LSP, accept it
            } else if (existing_lifetime == 0 && received_lifetime != 0) {
                // We have a purged version, but received a non-purged one with same seq num.
                // This is unusual, might indicate new LSP after purge not completed. Accept.
            } else { // Both non-zero lifetimes, same sequence number
                 if (ntohs(received_lsp.checksum) == ntohs(existing_lsp.checksum)) {
                    // Identical LSP already in DB (seq, lifetime > 0, checksum match)
                    // Update arrival time for SRMAck purposes, but don't re-flood.
                    existing_entry.arrival_time = std::chrono::steady_clock::now();
                    return false; 
                 }
                 // Checksums differ, prefer higher checksum (less common rule, but some use it)
                 // More common: treat as identical if sequence, lifetime, checksum match.
                 // If only checksum differs with same seq/non-zero lifetime, could be an error or data corruption.
                 // For now, if seq is same and lifetime non-zero, only update if checksum is different (treat as possible correction)
                 // This part of the standard can be tricky with multiple interpretations.
                 // A robust approach might involve checking if it's our own LSP being reflected.
                 if (ntohs(received_lsp.checksum) == ntohs(existing_lsp.checksum)) return false; // Truly identical
            }
        }
        
        // If we reach here, the received LSP is considered newer or a valid update.
        // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Updating LSP "
        //           << system_id_to_string(received_lsp.lspId.systemId) << "-" << (int)received_lsp.lspId.pseudonodeIdOrLspNumber
        //           << " Seq: " << received_seq << std::endl;
        update_lsp_metadata(existing_entry, received_lsp, on_interface_id, from_neighbor_id, is_own_lsp);
    
    } else { // LSP not in LSDB
        // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Adding new LSP "
        //           << system_id_to_string(received_lsp.lspId.systemId) << "-" << (int)received_lsp.lspId.pseudonodeIdOrLspNumber
        //           << " Seq: " << ntohl(received_lsp.sequenceNumber) << std::endl;
        LsdbEntry new_entry;
        update_lsp_metadata(new_entry, received_lsp, on_interface_id, from_neighbor_id, is_own_lsp);
        lsdb_[received_lsp.lspId] = new_entry;
    }

    // If LSP is not a self-originated LSP that we just updated (to avoid immediate re-flood of own refresh)
    // Or if it's a purge of our own LSP.
    bool should_flood = true;
    if (is_own_lsp && !lsdb_[received_lsp.lspId].purge_initiated) {
         // If this is our own LSP and we just generated/refreshed it,
         // flood_lsp will be called by regenerate_own_lsp or similar.
         // However, if add_or_update_lsp is called externally for our own LSP (e.g. initial generation),
         // it should be flooded. This logic needs care.
         // For now, assume if is_own_lsp is true, it's a fresh one that needs flooding.
    }

    if (should_flood) {
         // Optimization: if received_lsp.remainingLifetime is 0 and it's not our own,
         // we should flood this purge. If it *is* our own, originate_lsp_purge handles it.
        flood_lsp(received_lsp.lspId, on_interface_id);
    }
    return true;
}


void IsisLsdb::flood_lsp(const LspId& lsp_id, std::optional<uint32_t> received_on_interface_id_to_skip) {
    if (!send_pdu_callback_ || !isis_interface_manager_) return;

    std::optional<LsdbEntry> entry_opt;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = lsdb_.find(lsp_id);
        if (it == lsdb_.end() || it->second.lsp.pduLengthLsp == 0) { // pduLengthLsp check for valid LSP
            return; // LSP not found or invalid
        }
        entry_opt = it->second; // Make a copy to use outside lock if needed for serialization
        it->second.last_flooded_time = std::chrono::steady_clock::now();
    }
    
    LsdbEntry& entry = entry_opt.value();
    std::vector<uint8_t> pdu_bytes = serialize_link_state_pdu(entry.lsp); // Assumes this exists

    auto interfaces = isis_interface_manager_->get_interface_ids_by_level(level_); // Needs this method in InterfaceManager

    for (uint32_t interface_id : interfaces) {
        if (received_on_interface_id_to_skip.has_value() && interface_id == received_on_interface_id_to_skip.value()) {
            // Don't flood back to the interface it was received on (split horizon for LSPs)
            // However, on LANs, if we are DIS and receive from non-DIS, we must flood to other non-DIS.
            // If we are non-DIS and receive from DIS, we don't flood back to DIS.
            // This logic needs to be more nuanced with DIS.
            // For now, simple split horizon.
            // A better check: don't send to `received_from_neighbor_system_id` if on the same interface.
            continue;
        }

        auto if_config_opt = isis_interface_manager_->get_interface_config(interface_id);
        if (!if_config_opt || !if_config_opt->isis_enabled) continue;

        MacAddress dest_mac;
        if (if_config_opt->circuit_type == CircuitType::BROADCAST) {
            bool is_dis_on_this_if = isis_interface_manager_->is_elected_dis(interface_id);
            // On LANs:
            // - DIS floods to AllL1ISs/AllL2ISs.
            // - Non-DIS floods only to DIS (unicast MAC of DIS).
            // The received_on_interface_id_to_skip helps prevent flooding back to sender.
            // If we are DIS, we flood to everyone except sender's interface (if that's how it's interpreted).
            // If we are not DIS, we should only flood to the DIS.
            if (is_dis_on_this_if) {
                dest_mac = (level_ == IsisLevel::L1) ? ALL_L1_ISS_MAC : ALL_L2_ISS_MAC;
            } else {
                // Non-DIS only sends LSPs to the DIS.
                // Find DIS MAC address. This is complex.
                // For now, non-DIS will not flood here. Flooding to DIS is part of SRM.
                // This simplified flood_lsp is more like "flood to everyone except source interface".
                // Proper SRM (Send Routing Message) / SBM (Send Broadcast Message) is more complex.
                // Let's assume for now non-DIS does not use this generic flood_lsp for LSPs from others,
                // but sends them to DIS via a more targeted mechanism if needed (e.g. after CSNP processing).
                // Or, if it's our own LSP, non-DIS sends it to DIS.
                if (entry.own_lsp) {
                    // Get DIS MAC address from IsisInterfaceManager
                    // This is still tricky. For now, let's assume non-DIS also multicasts if it has to flood.
                    // Standard: Non-DIS sends LSPs to DIS. DIS floods them.
                    // This simple flood_lsp might be mostly for DIS or P2P.
                    // A non-DIS router would typically send its own LSP to the DIS.
                    // If this LSP is not its own, a non-DIS usually doesn't flood it further on that segment.
                    if (!entry.own_lsp) continue; // Non-DIS doesn't flood others' LSPs on LAN.
                    
                    // If own LSP, send to DIS. Need DIS MAC.
                    // For now, let non-DIS also multicast as a simplification.
                    dest_mac = (level_ == IsisLevel::L1) ? ALL_L1_ISS_MAC : ALL_L2_ISS_MAC;

                } else { // Not our LSP and we are not DIS
                    continue; 
                }
            }
        } else { // P2P
            // On P2P, flood to the neighbor.
            // The P2P link usually has only one active adjacency.
            // Destination MAC should be multicast or specific neighbor MAC if known.
            dest_mac = if_config_opt->p2p_destination_mac; // Use configured or default (L1/L2 ISs)
            if (level_ == IsisLevel::L1) dest_mac = ALL_L1_ISS_MAC;
            else if (level_ == IsisLevel::L2) dest_mac = ALL_L2_ISS_MAC;
            // If L1_L2, send based on some logic, or send two if PDU is level-specific.
            // Our LSDB is per-level, so the PDU is for that level.
        }
        
        // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Flooding LSP " << system_id_to_string(lsp_id.systemId) << "-" << (int)lsp_id.pseudonodeIdOrLspNumber
        //           << " on interface " << interface_id << " to " << dest_mac.to_string() << std::endl;
        send_pdu_callback_(interface_id, dest_mac, pdu_bytes);
    }
}


std::optional<LinkStatePdu> IsisLsdb::get_lsp(const LspId& lsp_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = lsdb_.find(lsp_id);
    if (it != lsdb_.end()) {
        return it->second.lsp;
    }
    return std::nullopt;
}

std::optional<LsdbEntry> IsisLsdb::get_lsdb_entry(const LspId& lsp_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = lsdb_.find(lsp_id);
    if (it != lsdb_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<LinkStatePdu> IsisLsdb::get_all_lsps() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LinkStatePdu> all_lsps;
    for (const auto& pair : lsdb_) {
        all_lsps.push_back(pair.second.lsp);
    }
    return all_lsps;
}

std::vector<LsdbEntry> IsisLsdb::get_all_lsdb_entries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LsdbEntry> all_entries;
    for (const auto& pair : lsdb_) {
        all_entries.push_back(pair.second);
    }
    return all_entries;
}


// --- SNP Handling (Simplified Stubs) ---
void IsisLsdb::handle_received_csnp(const CompleteSequenceNumbersPdu& csnp, uint32_t on_interface_id, const SystemID& from_neighbor_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isis_interface_manager_ || !send_pdu_callback_) return;
    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Received CSNP from " << system_id_to_string(from_neighbor_id) << " on interface " << on_interface_id << std::endl;

    std::vector<LspEntry> lsp_entries_to_request; // LSPs we need (neighbor has newer or we don't have)
    std::vector<LspEntry> lsp_entries_to_send;    // LSPs neighbor needs (we have newer or they don't have) - PSNP content for them
                                                 // Or, if neighbor is missing LSPs we have, we should send full LSPs.

    std::set<LspId> csnp_lsp_ids;

    // Iterate through TLVs in CSNP, assuming they are LSP Entry TLVs (Type 9, or similar concept)
    for (const auto& tlv : csnp.tlvs) {
        if (tlv.type == LSP_ENTRIES_TLV_TYPE) { // This constant needs to be well-defined for actual LSP entries
            BufferReader reader(tlv.value);
            while(reader.offset < reader.size) {
                LspEntry csnp_entry;
                // This parsing needs to be robust. Assuming direct LspEntry structures here.
                if (!parse_u16(reader, csnp_entry.lifetime)) break;
                if (!parse_lsp_id(reader, csnp_entry.lspId)) break;
                if (!parse_u32(reader, csnp_entry.sequenceNumber)) break;
                if (!parse_u16(reader, csnp_entry.checksum)) break;
                csnp_lsp_ids.insert(csnp_entry.lspId);

                auto local_it = lsdb_.find(csnp_entry.lspId);
                if (local_it == lsdb_.end()) { // We don't have this LSP
                    if (csnp_entry.lifetime > 0) { // And it's not a purged LSP
                        lsp_entries_to_request.push_back(csnp_entry);
                    }
                } else { // We have this LSP, compare versions
                    const LsdbEntry& local_entry = local_it->second;
                    uint32_t local_seq = ntohl(local_entry.lsp.sequenceNumber);
                    uint16_t local_lifetime = ntohs(local_entry.lsp.remainingLifetime);
                    // uint16_t local_checksum = ntohs(local_entry.lsp.checksum);

                    if (csnp_entry.lifetime == 0 && local_lifetime > 0) { // Neighbor has purged, we have live
                        lsp_entries_to_request.push_back(csnp_entry); // Request the purge
                    } else if (csnp_entry.lifetime > 0 && local_lifetime == 0) { // Neighbor has live, we have purged
                        // We should send our purge. This is complex. CSNP is a summary.
                        // For now, if they have it live and we have it purged, they need our purge.
                        // This would typically be handled by sending the full LSP.
                        // Add to lsp_entries_to_send.
                         lsp_entries_to_send.push_back({htons(local_lifetime), local_entry.lsp.lspId, htonl(local_seq), htons(local_entry.lsp.checksum)});

                    } else if (csnp_entry.sequenceNumber > local_seq) { // Neighbor has newer
                        lsp_entries_to_request.push_back(csnp_entry);
                    } else if (csnp_entry.sequenceNumber < local_seq) { // We have newer
                         lsp_entries_to_send.push_back({htons(local_lifetime), local_entry.lsp.lspId, htonl(local_seq), htons(local_entry.lsp.checksum)});
                    } else { // Same sequence number
                        if (csnp_entry.lifetime == 0 && local_lifetime > 0) { // They have purge, we don't
                            lsp_entries_to_request.push_back(csnp_entry);
                        } else if (local_lifetime == 0 && csnp_entry.lifetime > 0) { // We have purge, they don't
                             lsp_entries_to_send.push_back({htons(local_lifetime), local_entry.lsp.lspId, htonl(local_seq), htons(local_entry.lsp.checksum)});
                        }
                        // If checksums differ, also a point of contention. For now, primarily seq & lifetime.
                    }
                }
            }
        }
    }

    // Check for LSPs we have that were not in CSNP at all (neighbor is missing them)
    for (const auto& lsdb_pair : lsdb_) {
        if (csnp_lsp_ids.find(lsdb_pair.first) == csnp_lsp_ids.end()) {
            // We have this LSP, neighbor doesn't. Add to LSPs to send to neighbor.
            const LsdbEntry& local_entry = lsdb_pair.second;
             lsp_entries_to_send.push_back({htons(local_entry.lsp.remainingLifetime), 
                                           local_entry.lsp.lspId, 
                                           htonl(local_entry.lsp.sequenceNumber), 
                                           htons(local_entry.lsp.checksum)});
        }
    }
    
    MacAddress neighbor_mac; // Need to get neighbor's MAC address for sending PSNP or LSPs
    auto adj_list = isis_interface_manager_->get_adjacencies(on_interface_id);
    for(const auto& adj : adj_list) {
        if(adj.neighbor_system_id == from_neighbor_id && adj.state == AdjacencyState::UP) {
            neighbor_mac = adj.neighbor_mac_address;
            break;
        }
    }
    if(neighbor_mac.is_zero()) { /* std::cerr << "Cannot find MAC for neighbor " << system_id_to_string(from_neighbor_id) << std::endl;*/ return; }


    // Send PSNP for requested LSPs
    if (!lsp_entries_to_request.empty()) {
        // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Requesting " << lsp_entries_to_request.size() << " LSPs via PSNP to " << system_id_to_string(from_neighbor_id) << std::endl;
        send_psnp(on_interface_id, neighbor_mac, lsp_entries_to_request);
    }

    // Send full LSPs for entries neighbor needs (those we have newer or they are missing)
    // This part of CSNP/PSNP interaction is complex. Typically, if CSNP shows I have a newer LSP,
    // the other side might request it via PSNP. Or I might proactively send it.
    // For now, if CSNP processing indicates neighbor needs our LSP, send the full LSP.
    for (const auto& entry_summary : lsp_entries_to_send) {
        auto lsp_to_send_it = lsdb_.find(entry_summary.lspId);
        if (lsp_to_send_it != lsdb_.end()) {
            // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Sending full LSP " << system_id_to_string(entry_summary.lspId.systemId) << " to " << system_id_to_string(from_neighbor_id) << std::endl;
            std::vector<uint8_t> pdu_bytes = serialize_link_state_pdu(lsp_to_send_it->second.lsp);
            send_pdu_callback_(on_interface_id, neighbor_mac, pdu_bytes);
        }
    }
}

void IsisLsdb::handle_received_psnp(const PartialSequenceNumbersPdu& psnp, uint32_t on_interface_id, const SystemID& from_neighbor_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!send_pdu_callback_ || !isis_interface_manager_) return;
    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Received PSNP from " << system_id_to_string(from_neighbor_id) << " on interface " << on_interface_id << std::endl;

    MacAddress neighbor_mac; 
    auto adj_list = isis_interface_manager_->get_adjacencies(on_interface_id);
    for(const auto& adj : adj_list) {
        if(adj.neighbor_system_id == from_neighbor_id && adj.state == AdjacencyState::UP) {
            neighbor_mac = adj.neighbor_mac_address;
            break;
        }
    }
    if(neighbor_mac.is_zero()) { /*std::cerr << "Cannot find MAC for neighbor " << system_id_to_string(from_neighbor_id) << std::endl;*/ return; }


    // Iterate through TLVs in PSNP, assuming they are LSP Entry TLVs
    for (const auto& tlv : psnp.tlvs) {
        if (tlv.type == LSP_ENTRIES_TLV_TYPE) { // This constant needs to be well-defined
            BufferReader reader(tlv.value);
            while(reader.offset < reader.size) {
                LspEntry requested_entry_summary;
                // Parse LspEntry summary from TLV value
                if (!parse_u16(reader, requested_entry_summary.lifetime)) break;
                if (!parse_lsp_id(reader, requested_entry_summary.lspId)) break;
                // Seqnum and Checksum in PSNP are often ignored by receiver, only LSPID matters for request.
                // However, they might be used to describe the specific version being acked or requested.
                if (!parse_u32(reader, requested_entry_summary.sequenceNumber)) break;
                if (!parse_u16(reader, requested_entry_summary.checksum)) break;

                auto local_it = lsdb_.find(requested_entry_summary.lspId);
                if (local_it != lsdb_.end()) {
                    // Neighbor is requesting this LSP (or acknowledging it). Send our version.
                    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Neighbor " << system_id_to_string(from_neighbor_id) 
                    //           << " PSNP'd for LSP " << system_id_to_string(requested_entry_summary.lspId.systemId) << ". Sending it." << std::endl;
                    std::vector<uint8_t> pdu_bytes = serialize_link_state_pdu(local_it->second.lsp);
                    send_pdu_callback_(on_interface_id, neighbor_mac, pdu_bytes);
                } else {
                    // Neighbor PSNP'd for an LSP we don't have. This is unusual. Log or ignore.
                    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Neighbor " << system_id_to_string(from_neighbor_id) 
                    //           << " PSNP'd for LSP " << system_id_to_string(requested_entry_summary.lspId.systemId) << " which we don't have." << std::endl;
                }
            }
        }
    }
}


void IsisLsdb::send_csnp(uint32_t interface_id) {
    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Preparing to send CSNP on interface " << interface_id << std::endl;
    if (!send_pdu_callback_ || !isis_interface_manager_) return;
    
    auto if_config_opt = isis_interface_manager_->get_interface_config(interface_id);
    if (!if_config_opt || !if_config_opt->isis_enabled) return;

    CompleteSequenceNumbersPdu csnp;
    csnp.commonHeader.intradomainRoutingProtocolDiscriminator = 0x83;
    csnp.commonHeader.versionProtocolIdExtension = 1;
    csnp.commonHeader.version = 1;
    csnp.commonHeader.idLength = 0; // 6-byte SystemID
    csnp.commonHeader.pduType = (level_ == IsisLevel::L1) ? L1_CSNP_TYPE : L2_CSNP_TYPE;
    csnp.sourceId = local_system_id_; // Source is router ID. LAN CSNPs also include circuit ID (pseudonode ID part of LAN ID).
                                     // For now, just system ID. The actual source ID for LAN CSNP is SystemID+PseudonodeID of DIS.
    
    // Determine LAN ID if this interface is DIS for this level
    if (if_config_opt->circuit_type == CircuitType::BROADCAST) {
        if (isis_interface_manager_->is_elected_dis(interface_id)) {
             auto lan_id_opt = isis_interface_manager_->get_lan_id(interface_id);
             if (lan_id_opt) {
                 // CSNP source ID is the LAN ID (SystemID of DIS + pseudonode ID)
                 std::copy(lan_id_opt.value().begin(), lan_id_opt.value().begin() + 6, csnp.sourceId.begin());
                 // The LAN ID itself is not directly in CSNP sourceId field usually.
                 // SourceID of CSNP is SystemID of sender (+0 if P2P, +pseudonode if LAN DIS)
                 // Here, it should be local_system_id_ + our pseudonode ID for this interface if we are DIS.
                 // For simplicity, using local_system_id_ as sourceId. The LAN ID concept is more for LSP ID.
             }
        } else { // Not DIS, should not send periodic CSNPs
            return;
        }
    }


    // LSP Entries TLV
    TLV lsp_entries_tlv;
    lsp_entries_tlv.type = LSP_ENTRIES_TLV_TYPE; // Conceptual type
    
    std::vector<LsdbEntry> all_entries = get_all_lsdb_entries(); // Gets a copy under lock

    // Define Start and End LSP ID for CSNP (can be min/max or cover all)
    if (!all_entries.empty()) {
        // Sort by LSP ID to find min/max (LspId needs operator<)
        std::sort(all_entries.begin(), all_entries.end(), [](const LsdbEntry& a, const LsdbEntry& b){
            return a.lsp.lspId < b.lsp.lspId;
        });
        csnp.startLspId = all_entries.front().lsp.lspId;
        csnp.endLspId = all_entries.back().lsp.lspId;

        for (const auto& entry : all_entries) {
            // Serialize LspEntry into lsp_entries_tlv.value
            serialize_u16(lsp_entries_tlv.value, htons(entry.lsp.remainingLifetime)); // Or current remaining_lifetime_seconds
            serialize_lsp_id(lsp_entries_tlv.value, entry.lsp.lspId);
            serialize_u32(lsp_entries_tlv.value, htonl(entry.lsp.sequenceNumber));
            serialize_u16(lsp_entries_tlv.value, htons(entry.lsp.checksum));
        }
    } else { // Empty LSDB
        std::fill(csnp.startLspId.systemId.begin(), csnp.startLspId.systemId.end(), 0);
        csnp.startLspId.pseudonodeIdOrLspNumber = 0;
        std::fill(csnp.endLspId.systemId.begin(), csnp.endLspId.systemId.end(), 0);
        csnp.endLspId.pseudonodeIdOrLspNumber = 0xFF;
    }
    
    if (!lsp_entries_tlv.value.empty()) {
        lsp_entries_tlv.length = static_cast<uint8_t>(lsp_entries_tlv.value.size()); // Careful with >255 entries
        csnp.tlvs.push_back(lsp_entries_tlv);
    }

    std::vector<uint8_t> pdu_bytes = serialize_complete_sequence_numbers_pdu(csnp); // Assumed from isis_pdu.cpp
    
    MacAddress dest_mac = (level_ == IsisLevel::L1) ? ALL_L1_ISS_MAC : ALL_L2_ISS_MAC;
    send_pdu_callback_(interface_id, dest_mac, pdu_bytes);
    interface_last_csnp_time_[interface_id] = std::chrono::steady_clock::now();
}

void IsisLsdb::send_psnp(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<LspEntry>& lsp_entries_to_request_or_send) {
    if (!send_pdu_callback_ || lsp_entries_to_request_or_send.empty()) return;

    PartialSequenceNumbersPdu psnp;
    psnp.commonHeader.intradomainRoutingProtocolDiscriminator = 0x83;
    psnp.commonHeader.versionProtocolIdExtension = 1;
    psnp.commonHeader.version = 1;
    psnp.commonHeader.idLength = 0;
    psnp.commonHeader.pduType = (level_ == IsisLevel::L1) ? L1_PSNP_TYPE : L2_PSNP_TYPE;
    psnp.sourceId = local_system_id_; // Similar to CSNP, source is router ID.

    TLV lsp_entries_tlv;
    lsp_entries_tlv.type = LSP_ENTRIES_TLV_TYPE;
    for (const auto& entry_summary : lsp_entries_to_request_or_send) {
        // Serialize LspEntry summary into TLV (already in network byte order from CSNP handling)
        uint16_t lifetime_net = entry_summary.lifetime; // Already htons'd if from our CSNP logic
        uint32_t seq_net = entry_summary.sequenceNumber; // Already htonl'd
        uint16_t checksum_net = entry_summary.checksum; // Already htons'd

        serialize_u16(lsp_entries_tlv.value, lifetime_net); 
        serialize_lsp_id(lsp_entries_tlv.value, entry_summary.lspId); // Assumes SystemID part is fine
        serialize_u32(lsp_entries_tlv.value, seq_net);
        serialize_u16(lsp_entries_tlv.value, checksum_net);
    }
    if (!lsp_entries_tlv.value.empty()) {
        lsp_entries_tlv.length = static_cast<uint8_t>(lsp_entries_tlv.value.size());
        psnp.tlvs.push_back(lsp_entries_tlv);
    }
    
    std::vector<uint8_t> pdu_bytes = serialize_partial_sequence_numbers_pdu(psnp); // Assumed from isis_pdu.cpp
    send_pdu_callback_(interface_id, dest_mac, pdu_bytes);
}


// --- Periodic Tasks ---
void IsisLsdb::periodic_tasks() {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    std::vector<LspId> to_remove_from_lsdb; // LSPs that have been purged for long enough

    for (auto& pair : lsdb_) {
        LsdbEntry& entry = pair.second;
        
        // Age LSPs
        if (entry.remaining_lifetime_seconds > 0) {
            // Decrement based on time passed since arrival_time or last explicit update
            // This is simplified. Proper aging should decrement by 1 each second.
            // For simulation, if 'now' is 1s after 'arrival_time', decrement by 1.
            // A more robust way is to store arrival_time + initial_lifetime, then compute current remaining.
            // For now, simple decrement if 1s has passed since last check.
            // This periodic task should run every 1 second.
            if (entry.remaining_lifetime_seconds <=1 ) entry.remaining_lifetime_seconds = 0; // Prevent underflow if task runs slower than 1s
            else entry.remaining_lifetime_seconds--;
            
            entry.lsp.remainingLifetime = htons(entry.remaining_lifetime_seconds); // Update PDU
        }

        if (entry.remaining_lifetime_seconds == 0) {
            if (!entry.purge_initiated) {
                // std::cout << "LSDB (L" << static_cast<int>(level_) << "): LSP " << system_id_to_string(entry.lsp.lspId.systemId) << " lifetime expired. Initiating purge." << std::endl;
                // Initiate purge only if it's not our own LSP that just expired naturally
                // (own LSPs are refreshed or explicitly purged).
                // Or if it's an LSP we received that hit zero.
                if (!entry.own_lsp) {
                     originate_lsp_purge(entry.lsp.lspId); // This will re-add it with seq_num++ and lifetime 0
                     entry.purge_initiated = true; // Mark that we started the purge
                } else { // Own LSP expired
                    // Regenerate it. If it cannot be regenerated (e.g. component down), then purge it.
                    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Own LSP " << system_id_to_string(entry.lsp.lspId.systemId) << " lifetime expired. Attempting refresh." << std::endl;
                    if (!regenerate_own_lsp(entry.lsp.lspId.pseudonodeIdOrLspNumber)) {
                        originate_lsp_purge(entry.lsp.lspId); // Purge if refresh fails
                    }
                }
            } else { // Purge already initiated, check if it can be removed from LSDB
                if (std::chrono::duration_cast<std::chrono::seconds>(now - entry.arrival_time).count() > MAX_AGE_PURGE_DELAY_SECONDS) {
                    to_remove_from_lsdb.push_back(pair.first);
                }
            }
        } else if (entry.own_lsp) { // Own LSP, check for refresh
            if (std::chrono::duration_cast<std::chrono::seconds>(now - entry.last_refreshed_time).count() >= LSP_REFRESH_INTERVAL_SECONDS) {
                // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Refreshing own LSP " << system_id_to_string(entry.lsp.lspId.systemId) << std::endl;
                regenerate_own_lsp(entry.lsp.lspId.pseudonodeIdOrLspNumber);
            }
        }
    }

    for (const auto& lspid_to_remove : to_remove_from_lsdb) {
        // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Removing purged LSP " << system_id_to_string(lspid_to_remove.systemId) << " from DB." << std::endl;
        lsdb_.erase(lspid_to_remove);
    }

    // Trigger periodic CSNPs
    if (isis_interface_manager_) {
        auto interfaces = isis_interface_manager_->get_interface_ids_by_level(level_);
        for (uint32_t interface_id : interfaces) {
            auto if_config_opt = isis_interface_manager_->get_interface_config(interface_id);
            if (if_config_opt && if_config_opt->isis_enabled) {
                bool should_send_csnp = false;
                if (if_config_opt->circuit_type == CircuitType::BROADCAST) {
                    if (isis_interface_manager_->is_elected_dis(interface_id)) {
                        should_send_csnp = true; // DIS sends periodic CSNPs
                    }
                } else { // P2P
                    should_send_csnp = true; // P2P links send periodic CSNPs
                }

                if (should_send_csnp) {
                    auto last_sent_it = interface_last_csnp_time_.find(interface_id);
                    if (last_sent_it == interface_last_csnp_time_.end() ||
                        std::chrono::duration_cast<std::chrono::seconds>(now - last_sent_it->second).count() >= CSNP_INTERVAL_SECONDS) {
                        send_csnp(interface_id);
                        // interface_last_csnp_time_ updated in send_csnp
                    }
                }
            }
        }
    }
}

bool IsisLsdb::originate_lsp_purge(const LspId& lsp_id) {
    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Originate purge for LSP " << system_id_to_string(lsp_id.systemId) << "-" << (int)lsp_id.pseudonodeIdOrLspNumber << std::endl;
    std::optional<LsdbEntry> current_entry_opt;
    {
        std::lock_guard<std::mutex> lock(mutex_); // Lock for reading current entry
        auto it = lsdb_.find(lsp_id);
        if (it == lsdb_.end()) return false; // Not in DB
        current_entry_opt = it->second; // Copy
    }
    LsdbEntry& current_entry = current_entry_opt.value();


    LinkStatePdu purge_lsp = current_entry.lsp; // Copy existing LSP
    purge_lsp.remainingLifetime = htons(0);     // Set lifetime to 0
    purge_lsp.sequenceNumber = htonl(ntohl(purge_lsp.sequenceNumber) + 1); // Increment sequence number
    // TODO: Recompute checksum for purge_lsp
    // For now, assume checksum will be handled by serialization or is not strictly checked by others for purges.
    
    // Add this purge LSP to LSDB. is_own_lsp should be true if we are originating the purge for an LSP we "own"
    // or if we are taking responsibility for purging an expired one.
    // If it was already our own LSP, is_own_lsp remains true.
    // If it was someone else's LSP that expired, setting is_own_lsp=true for the purge
    // means we are now the source of this particular LSP version (the purge).
    // This is complex. A simpler model: if it's not our systemID, is_own_lsp is false even for purge.
    // But we still need to flood it.
    bool am_i_originator_of_this_lsp_id = (lsp_id.systemId == local_system_id_);
    return add_or_update_lsp(purge_lsp, 0, std::nullopt, am_i_originator_of_this_lsp_id);
}

bool IsisLsdb::regenerate_own_lsp(uint8_t lsp_number) {
    if (!generate_local_lsp_callback_) return false;

    LinkStatePdu new_own_lsp = generate_local_lsp_callback_(); // Callback provides the new LSP for this level/lsp_number
    
    // Ensure the LSP from callback has correct LSPID and level context if not already set by callback
    new_own_lsp.lspId = get_local_lsp_id(lsp_number);
    if (level_ == IsisLevel::L1) {
        new_own_lsp.pAttOlIsTypeBits &= 0xFB; // Clear L2 bit (bit 2), Set L1 bit (bit 1)
        new_own_lsp.pAttOlIsTypeBits |= 0x01;
    } else { // L2
        new_own_lsp.pAttOlIsTypeBits &= 0xFE; // Clear L1 bit, Set L2 bit
        new_own_lsp.pAttOlIsTypeBits |= 0x02;
    }
    new_own_lsp.commonHeader.pduType = (level_ == IsisLevel::L1) ? L1_LSP_TYPE : L2_LSP_TYPE;


    // Increment sequence number if we have a previous version
    std::optional<LsdbEntry> existing_entry_opt;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = lsdb_.find(new_own_lsp.lspId);
        if (it != lsdb_.end() && it->second.own_lsp) {
            existing_entry_opt = it->second;
        }
    }

    if(existing_entry_opt) {
        new_own_lsp.sequenceNumber = htonl(ntohl(existing_entry_opt.value().lsp.sequenceNumber) + 1);
    } else {
        new_own_lsp.sequenceNumber = htonl(1); // Initial sequence number
    }
    new_own_lsp.remainingLifetime = htons(LSP_MAX_AGE_SECONDS); // Give it full lifetime initially. Or configured default.
    // TODO: Recompute checksum for new_own_lsp

    // std::cout << "LSDB (L" << static_cast<int>(level_) << "): Regenerated own LSP "
    //           << system_id_to_string(new_own_lsp.lspId.systemId) << "-" << (int)new_own_lsp.lspId.pseudonodeIdOrLspNumber
    //           << " New Seq: " << ntohl(new_own_lsp.sequenceNumber) << std::endl;

    return add_or_update_lsp(new_own_lsp, 0, std::nullopt, true);
}


MacAddress IsisLsdb::get_destination_mac_for_level() const {
    if (level_ == IsisLevel::L1) return ALL_L1_ISS_MAC;
    if (level_ == IsisLevel::L2) return ALL_L2_ISS_MAC;
    // if (level_ == IsisLevel::L1_L2) {} // LSDB is per L1 or L2, not mixed L1_L2.
    return MacAddress{}; // Should not happen
}

// Helper functions (stubs for isis_pdu.cpp to provide, or implement locally if simple enough)
// These are used in CSNP/PSNP sending logic and need to write to a std::vector<uint8_t>
static void serialize_u16(std::vector<uint8_t>& buffer, uint16_t value) {
    // Assumes value is already in network byte order if coming from PDU struct fields
    // Or, if it's host order, do htons here.
    // For this file, assume it's PRE-ORDERED (network) if from existing PDU fields,
    // or needs ordering if it's a fresh value like a counter.
    // The LspEntry summaries are built from existing PDU fields, so they should be network order.
    buffer.push_back(static_cast<uint8_t>(value >> 8));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

static void serialize_u32(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>(value >> 24));
    buffer.push_back(static_cast<uint8_t>(value >> 16));
    buffer.push_back(static_cast<uint8_t>(value >> 8));
    buffer.push_back(static_cast<uint8_t>(value & 0xFF));
}

static void serialize_lsp_id(std::vector<uint8_t>& buffer, const LspId& id) {
    buffer.insert(buffer.end(), id.systemId.begin(), id.systemId.end());
    buffer.push_back(id.pseudonodeIdOrLspNumber);
}


} // namespace isis
} // namespace netflow

// Constants that might be needed by isis_pdu.cpp if it handles LSP_ENTRIES_TLV_TYPE
#ifndef LSP_ENTRIES_TLV_TYPE
#define LSP_ENTRIES_TLV_TYPE 9 // Standard type for "LSP Entries" in SNPs (though sometimes implemented directly)
#endif
