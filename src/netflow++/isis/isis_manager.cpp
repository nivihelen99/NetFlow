#include "netflow++/isis/isis_manager.hpp"
#include "netflow++/isis/isis_pdu_constants.hpp" // For TLV types, PDU types (should be in isis_common.hpp)
#include "netflow++/isis/isis_spf_calculator.hpp" // Needed for SPF calculation
#include "netflow++/byte_swap.hpp"             // For htons, htonl etc.

#include <iostream> // For debugging
#include <chrono>   // For sleep_for

// Assume PDU serialization functions from isis_pdu.cpp are available
// Assume PDU parsing functions for dispatching in receive_isis_pdu are available

namespace netflow {
namespace isis {

// Constructor updated to not take IsisConfig directly
IsisManager::IsisManager(netflow::InterfaceManager& underlying_if_mgr,
                         netflow::RoutingManager* routing_mgr)
    : underlying_interface_manager_(underlying_if_mgr),
      routing_manager_(routing_mgr),
      running_(false) {
    // config_ is default initialized. Actual values must be set via CLI/methods.
}

IsisManager::~IsisManager() {
    if (running_.load()) {
        stop();
    }
}

void IsisManager::register_send_frame_callback(std::function<void(uint32_t, const MacAddress&, uint16_t, const std::vector<uint8_t>&)> cb) {
    send_frame_callback_ = cb;
}

void IsisManager::send_isis_pdu_via_frame_callback(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<uint8_t>& pdu_payload) {
    if (send_frame_callback_) {
        send_frame_callback_(interface_id, dest_mac, ISIS_ETHERTYPE, pdu_payload);
    } else {
        // std::cerr << "IsisManager: send_frame_callback_ not registered. Cannot send PDU." << std::endl;
    }
}

bool IsisManager::is_globally_configured() const {
    // Basic check: System ID must be non-zero and at least one area address must be configured.
    bool sys_id_set = false;
    for(const auto& byte : config_.system_id) {
        if (byte != 0) {
            sys_id_set = true;
            break;
        }
    }
    return sys_id_set && !config_.area_addresses.empty();
}

bool IsisManager::start() {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) {
        return true; // Already running
    }

    if (!is_globally_configured()) {
        // std::cerr << "IsisManager: Cannot start. System ID or Area Address not configured." << std::endl;
        return false;
    }

    // Initialize InterfaceManager
    interface_manager_ = std::make_unique<IsisInterfaceManager>(underlying_interface_manager_, config_.system_id, config_.area_addresses);
    
    // Register internal callbacks with InterfaceManager
    interface_manager_->register_send_pdu_callback(
        [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
            this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
        });
    interface_manager_->register_adjacency_change_callback(
        [this](const IsisAdjacency& adj, bool is_up) {
            this->on_adjacency_change(adj, is_up);
        });

    // Initialize LSDBs based on enabled levels
    if (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2) {
        lsdb_map_[IsisLevel::L1] = std::make_unique<IsisLsdb>(IsisLevel::L1, config_.system_id, interface_manager_.get());
        lsdb_map_[IsisLevel::L1]->register_send_pdu_callback(
            [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
                this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
            });
        lsdb_map_[IsisLevel::L1]->register_generate_local_lsp_callback(
            [this]() { // Capture this
                return this->generate_lsp(IsisLevel::L1, config_.default_lsp_number);
            });
        // Initial LSP generation for L1
        lsdb_map_[IsisLevel::L1]->regenerate_own_lsp(config_.default_lsp_number);

    }
    if (config_.enabled_levels == IsisLevel::L2 || config_.enabled_levels == IsisLevel::L1_L2) {
        lsdb_map_[IsisLevel::L2] = std::make_unique<IsisLsdb>(IsisLevel::L2, config_.system_id, interface_manager_.get());
        lsdb_map_[IsisLevel::L2]->register_send_pdu_callback(
            [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
                this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
            });
        lsdb_map_[IsisLevel::L2]->register_generate_local_lsp_callback(
            [this]() { // Capture this
                return this->generate_lsp(IsisLevel::L2, config_.default_lsp_number);
            });
        // Initial LSP generation for L2
        lsdb_map_[IsisLevel::L2]->regenerate_own_lsp(config_.default_lsp_number);
    }
    
    running_ = true;
    periodic_task_thread_ = std::thread(&IsisManager::periodic_tasks_loop, this);
    // std::cout << "IsisManager started." << std::endl;
    // Initial SPF calculation after LSDBs are up and potentially first LSP generated
    if (running_.load()) { 
        for (const auto& pair : lsdb_map_) {
            trigger_spf_calculation(pair.first);
        }
    }
    return true;
}

void IsisManager::stop() {
    // std::cout << "IsisManager stopping..." << std::endl;
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) { // Ensure stop actions run only once
        if (periodic_task_thread_.joinable()) {
            periodic_task_thread_.join();
        }
        // Clear LSDBs and interface manager to reset state
        lsdb_map_.clear();
        interface_manager_.reset();
        // std::cout << "IsisManager stopped and reset." << std::endl;
    }
}

// --- Global Configuration Methods ---
void IsisManager::set_system_id(const SystemID& sys_id) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) {
        // std::cerr << "Cannot change System ID while IS-IS is running. Stop first." << std::endl;
        return;
    }
    config_.system_id = sys_id;
}

void IsisManager::add_area_address(const AreaAddress& area) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) {
        // std::cerr << "Cannot change Area Addresses while IS-IS is running. Stop first." << std::endl;
        return;
    }
    // Avoid duplicates
    if (std::find(config_.area_addresses.begin(), config_.area_addresses.end(), area) == config_.area_addresses.end()) {
        config_.area_addresses.push_back(area);
    }
}

void IsisManager::remove_area_address(const AreaAddress& area) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) {
        // std::cerr << "Cannot change Area Addresses while IS-IS is running. Stop first." << std::endl;
        return;
    }
    config_.area_addresses.erase(
        std::remove(config_.area_addresses.begin(), config_.area_addresses.end(), area),
        config_.area_addresses.end());
}

void IsisManager::set_enabled_levels(IsisLevel level) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) {
        // std::cerr << "Cannot change enabled levels while IS-IS is running. Stop first." << std::endl;
        return;
    }
    config_.enabled_levels = level;
}

// Renamed internal method
void IsisManager::internal_set_overload_bit(bool overload_status) {
    // This method assumes lock is already held or it's called from a context that ensures safety.
    if (config_.over_load_bit_set == overload_status) return;
    config_.over_load_bit_set = overload_status;
    // std::cout << "IsisManager: Overload bit set to " << overload_status << ". Triggering LSP regeneration." << std::endl;

    if (running_.load()) { // Only regenerate if running
        if (lsdb_map_.count(IsisLevel::L1)) {
            lsdb_map_[IsisLevel::L1]->regenerate_own_lsp(config_.default_lsp_number);
        }
        if (lsdb_map_.count(IsisLevel::L2)) {
            lsdb_map_[IsisLevel::L2]->regenerate_own_lsp(config_.default_lsp_number);
        }
    }
}


void IsisManager::set_overload_bit_cli(bool set_on) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    internal_set_overload_bit(set_on);
}


IsisConfig IsisManager::get_global_config() const {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    return config_;
}

void IsisManager::periodic_tasks_loop() {
    while (running_.load()) {
        try {
            if (interface_manager_) {
                interface_manager_->periodic_tasks();
            }
            // Lock manager_mutex_ before iterating lsdb_map_ in case it's modified by config changes.
            // However, periodic_tasks within LSDB already lock themselves.
            // The map itself might change if a level is dynamically enabled/disabled (not supported yet).
            // For reading the map, a shared_lock could be used if available and map is not modified.
            // For now, copy keys then call, or ensure map is stable during this loop.
            std::vector<IsisLevel> active_levels;
            { // Short lock to get active levels
                 std::lock_guard<std::mutex> lock(manager_mutex_);
                 for(const auto& pair : lsdb_map_) active_levels.push_back(pair.first);
            }

            for (IsisLevel level : active_levels) {
                std::unique_ptr<IsisLsdb>* lsdb_ptr = nullptr;
                { // Short lock to get pointer
                    std::lock_guard<std::mutex> lock(manager_mutex_);
                    auto it = lsdb_map_.find(level);
                    if (it != lsdb_map_.end()) {
                        lsdb_ptr = &it->second;
                    }
                }
                if (lsdb_ptr && lsdb_ptr->get()) {
                     (*lsdb_ptr)->periodic_tasks();
                }
            }
        } catch (const std::exception& e) {
            // std::cerr << "Exception in IsisManager periodic_tasks_loop: " << e.what() << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}


void IsisManager::receive_isis_pdu(uint32_t interface_id, const MacAddress& source_mac, const std::vector<uint8_t>& pdu_data) {
    if (pdu_data.empty()) return;

    CommonPduHeader common_header;
    BufferReader reader(pdu_data); // from isis_pdu.cpp (or similar)

    if (!parse_common_pdu_header(reader, common_header)) { // from isis_pdu.cpp
        // std::cerr << "IsisManager: Failed to parse common PDU header from " << source_mac.to_string() << " on if " << interface_id << std::endl;
        return;
    }

    // Determine IS-IS level from PDU type
    IsisLevel pdu_level = IsisLevel::NONE;
    switch (common_header.pduType) {
        case L1_LAN_IIH_TYPE:
        case L1_LSP_TYPE:
        case L1_CSNP_TYPE:
        case L1_PSNP_TYPE:
            pdu_level = IsisLevel::L1;
            break;
        case L2_LAN_IIH_TYPE:
        case L2_LSP_TYPE:
        case L2_CSNP_TYPE:
        case L2_PSNP_TYPE:
            pdu_level = IsisLevel::L2;
            break;
        case PTP_IIH_TYPE: // PTP IIH can be L1, L2, or L1/L2. Need to check interface config.
            {
                std::lock_guard<std::mutex> lock(manager_mutex_); // Lock for reading interface_manager_
                if (!interface_manager_) return;
                auto if_config = interface_manager_->get_interface_config(interface_id);
                if (if_config) {
                    pdu_level = if_config->level; // Use configured level of the interface.
                                                 // This is a simplification; PTP IIH itself contains circuit type.
            // A more robust way for PTP IIH: check its circuit type TLV.
            // For now, using interface's configured level for PTP context.
            // If interface is L1_L2, PTP IIH could be for L1 or L2 based on its content.
            // This simplistic model assumes PTP IIH is processed in the context of the interface's primary configured level.
            // A dual-level PTP interface might need to process PTP IIH against both L1 and L2 contexts if the PTP IIH indicates L1/L2.
             IsisLevel interface_configured_level = IsisLevel::NONE;
             auto if_config_opt = interface_manager_->get_interface_config(interface_id);
             if (if_config_opt) interface_configured_level = if_config_opt->level;

             if (interface_configured_level == IsisLevel::L1_L2) {
                // PTP IIH on an L1/L2 interface. The Hello's circuit type TLV (value 0x01, 0x02, 0x03)
                // indicates what level(s) the HELLO is for. We need to parse that from PTP PDU.
                // For now, assume we check if L1 is enabled and L2 is enabled and dispatch to both if PTP says L1/L2.
                // This is a complex part of PTP IIH handling.
                // Simplification: use the first level that matches.
                if (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2) pdu_level = IsisLevel::L1;
                else if (config_.enabled_levels == IsisLevel::L2) pdu_level = IsisLevel::L2;

             } else {
                 pdu_level = interface_configured_level;
             }

            } else return; // No config for this interface
            break;
        default:
            // std::cerr << "IsisManager: Unknown PDU type " << (int)common_header.pduType << std::endl;
            return;
    }
    
    // Check if this PDU's determined level is active on this router
    bool level_globally_active = false;
    if (pdu_level == IsisLevel::L1 && (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2)) level_globally_active = true;
    if (pdu_level == IsisLevel::L2 && (config_.enabled_levels == IsisLevel::L2 || config_.enabled_levels == IsisLevel::L1_L2)) level_globally_active = true;
    
    if (!level_globally_active && pdu_level != IsisLevel::NONE) {
         // std::cout << "IsisManager: PDU for globally disabled level " << static_cast<int>(pdu_level) << " received. Ignoring." << std::endl;
         return;
    }

    // Dispatch to InterfaceManager or LSDB
    // Ensure reader is reset or use a new one for specific PDU parsing
    BufferReader pdu_specific_reader(pdu_data); // Full PDU data

    std::lock_guard<std::mutex> lock(manager_mutex_); // Lock for accessing interface_manager_ and lsdb_map_
    if (!interface_manager_) return;

    switch (common_header.pduType) {
        case L1_LAN_IIH_TYPE:
        case L2_LAN_IIH_TYPE: {
            LanHelloPdu lan_hello;
            // parse_lan_hello_pdu needs the full buffer and will use common_header internally
            if (parse_lan_hello_pdu(pdu_data, common_header, lan_hello)) { // common_header is modified by parse_common_pdu_header
                interface_manager_->handle_received_hello(interface_id, source_mac, common_header, lan_hello);
            } else { /*std::cerr << "Failed to parse LAN Hello PDU" << std::endl; */ }
            break;
        }
        case PTP_IIH_TYPE: {
            PointToPointHelloPdu ptp_hello;
            if (parse_point_to_point_hello_pdu(pdu_data, common_header, ptp_hello)) {
                 interface_manager_->handle_received_hello(interface_id, source_mac, common_header, ptp_hello);
            } else { /*std::cerr << "Failed to parse PTP Hello PDU" << std::endl; */}
            break;
        }
        case L1_LSP_TYPE:
        case L2_LSP_TYPE: {
            LinkStatePdu lsp;
            // common_header is already parsed at the beginning of receive_isis_pdu.
            // parse_link_state_pdu will re-parse it internally if its first argument is the full pdu_data.
            // We need to ensure the common_header passed to add_or_update_lsp is the one from the start of this PDU.
            if (parse_link_state_pdu(pdu_data, common_header /* this is an in-out, will be re-populated */, lsp)) {
                if (lsdb_map_.count(pdu_level)) {
                    // Pass the original pdu_data, the common_header from the initial parse of this PDU, and the parsed lsp.
                    // The from_neighbor_id is simplified here as the LSP's own SystemID.
                    // In reality, it should be the SystemID of the neighbor that sent this PDU, if known from Hello.
                    bool changed = lsdb_map_[pdu_level]->add_or_update_lsp(pdu_data, common_header, lsp, interface_id, lsp.lspId.systemId, false);
                    if (changed) {
                        trigger_spf_calculation(pdu_level);
                    }
                }
            } else { /*std::cerr << "Failed to parse LSP PDU" << std::endl; */}
            break;
        }
        case L1_CSNP_TYPE:
        case L2_CSNP_TYPE: {
            CompleteSequenceNumbersPdu csnp;
            // Re-parse common_header as it might have been modified by previous calls if not careful
            BufferReader csnp_reader(pdu_data);
            CommonPduHeader csnp_common_header;
            parse_common_pdu_header(csnp_reader, csnp_common_header); 

            if (parse_complete_sequence_numbers_pdu(pdu_data, csnp_common_header, csnp)) {
                 if (lsdb_map_.count(pdu_level)) {
                    lsdb_map_[pdu_level]->handle_received_csnp(csnp, interface_id, csnp.sourceId);
                    // CSNP might trigger requests for LSPs, which in turn leads to add_or_update_lsp and then SPF.
                 }
            } else { /*std::cerr << "Failed to parse CSNP PDU" << std::endl; */}
            break;
        }
        case L1_PSNP_TYPE:
        case L2_PSNP_TYPE: {
            PartialSequenceNumbersPdu psnp;
            BufferReader psnp_reader(pdu_data);
            CommonPduHeader psnp_common_header;
            parse_common_pdu_header(psnp_reader, psnp_common_header);

            if (parse_partial_sequence_numbers_pdu(pdu_data, psnp_common_header, psnp)) {
                if (lsdb_map_.count(pdu_level)) {
                    lsdb_map_[pdu_level]->handle_received_psnp(psnp, interface_id, psnp.sourceId);
                    // PSNP processing (sending LSPs) doesn't directly change routes, but is part of sync.
                }
            } else { /*std::cerr << "Failed to parse PSNP PDU" << std::endl; */}
            break;
        }
    }
}

LinkStatePdu IsisManager::generate_lsp(IsisLevel level, uint8_t lsp_number) {
    std::lock_guard<std::mutex> lock(manager_mutex_); // Protects config_ and access to managers
    
    LinkStatePdu lsp;
    // Common PDU Header fields
    lsp.commonHeader.intradomainRoutingProtocolDiscriminator = 0x83;
    lsp.commonHeader.versionProtocolIdExtension = 1;
    lsp.commonHeader.version = 1;
    lsp.commonHeader.idLength = 0; // 6-byte SystemID
    lsp.commonHeader.pduType = (level == IsisLevel::L1) ? L1_LSP_TYPE : L2_LSP_TYPE;
    // lsp.commonHeader.lengthIndicator will be set by PDU serialization

    // LSP specific fields
    lsp.lspId.systemId = config_.system_id;
    lsp.lspId.pseudonodeIdOrLspNumber = lsp_number;
    lsp.remainingLifetime = htons(DEFAULT_LSP_MAX_LIFETIME); // Set initial lifetime
    lsp.sequenceNumber = htonl(1); // Initial: will be incremented by LSDB if existing found

    // P.ATT.OL.IS-Type bits
    lsp.pAttOlIsTypeBits = 0;
    if (config_.over_load_bit_set) {
        lsp.pAttOlIsTypeBits |= (1 << 2); // Overload bit (OL)
    }
    // TODO: Set Attached bit (ATT) if connected to another area (for L1 LSPs routing to L2).
    // This requires routing decision logic to determine if this router is an L1/L2 border router
    // and has reachability to other areas to advertise into L1.
    if (level == IsisLevel::L1) {
        lsp.pAttOlIsTypeBits |= 0x01; // IS-Type L1
    } else { // L2
        lsp.pAttOlIsTypeBits |= 0x03; // IS-Type L2 (some use 0x02, 0x03 means L1/L2 capable router, but this is L2 LSP)
                                      // Standard: L1 (01), L2 (11) for LSPs from L1/L2 router.
                                      // L1 only router: L1 (01). L2 only router: L2 (10).
                                      // Let's use 0x01 for L1 LSP, 0x02 for L2 LSP from L2-only context.
                                      // If router is L1/L2, L1 LSP type is 01, L2 LSP type is 11.
        if (config_.enabled_levels == IsisLevel::L1_L2) lsp.pAttOlIsTypeBits |= 0x03; // L1/L2 router generating L2 LSP
        else lsp.pAttOlIsTypeBits |= 0x02; // L2-only router generating L2 LSP
    }


    // --- TLVs ---
    // 1. Area Addresses TLV (Type 1) - Mandatory in L1 LSPs from L1/L2 routers.
    if (level == IsisLevel::L1 || (level == IsisLevel::L2 && !config_.area_addresses.empty())) { // L2 LSPs MAY contain it.
        TLV area_tlv;
        area_tlv.type = AREA_ADDRESSES_TLV_TYPE;
        AreaAddressesTlvValue area_val;
        area_val.areaAddresses = config_.area_addresses;
        area_tlv.value = serialize_area_addresses_tlv_value(area_val); // from isis_pdu.cpp
        area_tlv.length = static_cast<uint8_t>(area_tlv.value.size());
        if (area_tlv.length > 0) lsp.tlvs.push_back(area_tlv);
    }

    // 2. Protocols Supported TLV (Type 129)
    TLV protocols_tlv;
    protocols_tlv.type = PROTOCOLS_SUPPORTED_TLV_TYPE;
    protocols_tlv.value.push_back(0xCC); // NLPID for IPv4
    // protocols_tlv.value.push_back(0x8E); // NLPID for IPv6 if supported
    protocols_tlv.length = static_cast<uint8_t>(protocols_tlv.value.size());
    lsp.tlvs.push_back(protocols_tlv);

    // 3. IP Interface Addresses TLV (Type 132)
    TLV ip_intf_tlv;
    ip_intf_tlv.type = IP_INTERFACE_ADDRESS_TLV_TYPE;
    for (uint32_t if_id : underlying_interface_manager_.get_all_interface_ids()) {
        if (interface_manager_ && interface_manager_->is_interface_up_and_isis_enabled(if_id)) {
            auto if_details = underlying_interface_manager_.get_interface_details(if_id);
            if (if_details && if_details->ip_address.has_value()) {
                uint32_t ip_addr_net = htonl(if_details->ip_address.value().to_uint32());
                const uint8_t* ip_bytes_ptr = reinterpret_cast<const uint8_t*>(&ip_addr_net);
                ip_intf_tlv.value.insert(ip_intf_tlv.value.end(), ip_bytes_ptr, ip_bytes_ptr + 4);
            }
        }
    }
    if (!ip_intf_tlv.value.empty()) {
        ip_intf_tlv.length = static_cast<uint8_t>(ip_intf_tlv.value.size());
        lsp.tlvs.push_back(ip_intf_tlv);
    }
    
    // 4. IS Reachability TLV (Type 2 or 22 for Extended) - Adjacencies
    // Standard IS Reachability (Type 2) for L1 LSPs. Extended IS Reachability (Type 22) for L2 LSPs.
    TLV is_reach_tlv;
    if (level == IsisLevel::L1) {
        is_reach_tlv.type = IS_REACHABILITY_TLV_TYPE; // Standard IS Reachability (Type 2)
    } else { // L2
        is_reach_tlv.type = EXTENDED_IS_REACHABILITY_TLV_TYPE; // Extended IS Reachability (Type 22)
    }
    // Assuming the value structure (metric, neighbor ID) is compatible or handled by TLV processing.
    // Metric width can differ: Type 2 uses 6 bits (in a byte), Type 22 uses 3 bytes.
    // This simplified version uses a 1-byte metric placeholder for both.
    // A full implementation would require different serialization for Type 2 vs Type 22 values if metrics are handled strictly.

    if (interface_manager_) {
        auto all_adjs = interface_manager_->get_all_adjacencies_by_level(level);
        for (const auto& adj : all_adjs) {
            if (adj.state == AdjacencyState::UP) {
                // Default metric (1 byte), IS Neighbor ID (7 bytes: SystemID + 0)
                // This is simplified. Real IS Reach TLV has more fields.
                is_reach_tlv.value.push_back(10); // Default metric
                is_reach_tlv.value.insert(is_reach_tlv.value.end(), adj.neighbor_system_id.begin(), adj.neighbor_system_id.end());
                is_reach_tlv.value.push_back(0); // Pseudonode part of neighbor ID (0 for router)
            }
        }
    }
    if (!is_reach_tlv.value.empty()) {
        is_reach_tlv.length = static_cast<uint8_t>(is_reach_tlv.value.size());
        lsp.tlvs.push_back(is_reach_tlv);
    }


    // 5. Extended IP Reachability TLV (Type 135) - Prefixes
    TLV ext_ip_reach_tlv;
    ext_ip_reach_tlv.type = EXTENDED_IP_REACHABILITY_TLV_TYPE;
    // Add directly connected interface prefixes
    for (uint32_t if_id : underlying_interface_manager_.get_all_interface_ids()) {
         if (interface_manager_ && interface_manager_->is_interface_up_and_isis_enabled(if_id)) {
            auto if_details = underlying_interface_manager_.get_interface_details(if_id);
            if (if_details && if_details->ip_address.has_value() && if_details->subnet_mask.has_value()) {
                uint32_t metric = 10; // Default metric
                uint8_t prefix_len = if_details->subnet_mask.value().to_prefix_length(); // Assumes this method exists
                uint32_t ip_addr = if_details->ip_address.value().to_uint32();
                uint32_t network_addr = ip_addr & if_details->subnet_mask.value().to_uint32();

                // Serialize metric (4 bytes), prefix_len (1 byte), prefix
                uint32_t metric_be = htonl(metric);
                const uint8_t* metric_bytes = reinterpret_cast<const uint8_t*>(&metric_be);
                ext_ip_reach_tlv.value.insert(ext_ip_reach_tlv.value.end(), metric_bytes, metric_bytes + 4);
                ext_ip_reach_tlv.value.push_back(prefix_len);
                
                uint32_t network_addr_be = htonl(network_addr);
                int num_ip_bytes = (prefix_len + 7) / 8;
                const uint8_t* ip_prefix_bytes = reinterpret_cast<const uint8_t*>(&network_addr_be);
                ext_ip_reach_tlv.value.insert(ext_ip_reach_tlv.value.end(), ip_prefix_bytes, ip_prefix_bytes + num_ip_bytes);
            }
        }
    }
    // TODO: Add redistributed routes from routing_manager if any.
    if (!ext_ip_reach_tlv.value.empty()) {
        ext_ip_reach_tlv.length = static_cast<uint8_t>(ext_ip_reach_tlv.value.size());
        lsp.tlvs.push_back(ext_ip_reach_tlv);
    }

    // Calculate PDU Length (for lsp.pduLengthLsp field)
    // This is the length of the LSP starting from "Remaining Lifetime" field.
    // Common Header (8) + PDU Length (2) + Rem Lifetime (2) + LSPID (7) + Seq (4) + Checksum (2) + PATTOlIs (1) = 26 bytes fixed for LSP part.
    // This is wrong. pduLengthLsp is total length of PDU. -> This field is now pduLength.
    // The PDU serialization function should correctly set this.
    // For now, leave lsp.pduLength as 0; serialize_link_state_pdu will calculate it.
    lsp.pduLength = 0; // Placeholder, to be filled by serializer. Field name changed from pduLengthLsp.

    // --- Add Multicast TLVs ---
    // 6. Multicast Capability TLV (Type 230)
    TLV mcast_cap_tlv;
    mcast_cap_tlv.type = MULTICAST_CAPABILITY_TLV_TYPE;
    MulticastCapabilityTlvValue mcast_cap_val; // Empty struct
    mcast_cap_tlv.value = serialize_multicast_capability_tlv_value(mcast_cap_val); // from isis_pdu.cpp
    mcast_cap_tlv.length = static_cast<uint8_t>(mcast_cap_tlv.value.size()); // Should be 0
    lsp.tlvs.push_back(mcast_cap_tlv);

    // 7. Multicast Group Membership TLV (Type 231) - using static config for now
    if (!config_.local_multicast_groups_to_advertise.empty()) {
        TLV mcast_group_tlv;
        mcast_group_tlv.type = MULTICAST_GROUP_MEMBERSHIP_TLV_TYPE;
        MulticastGroupMembershipTlvValue mcast_group_val;
        mcast_group_val.groups = config_.local_multicast_groups_to_advertise;
        mcast_group_tlv.value = serialize_multicast_group_membership_tlv_value(mcast_group_val); // from isis_pdu.cpp
        mcast_group_tlv.length = static_cast<uint8_t>(mcast_group_tlv.value.size());
        if (mcast_group_tlv.length > 0) {
            lsp.tlvs.push_back(mcast_group_tlv);
        }
    }

    // Checksum: Placeholder. Proper Fletcher checksum needed.
    lsp.checksum = htons(0xFFFF); // Dummy checksum

    // std::cout << "IsisManager: Generated LSP for L" << static_cast<int>(level) << " Num:" << (int)lsp_number << std::endl;
    return lsp;
}


void IsisManager::on_adjacency_change(const IsisAdjacency& adj, bool is_up) {
    // std::cout << "IsisManager: Adjacency change event for neighbor " << system_id_to_string(adj.neighbor_system_id)
    //           << " on interface " << adj.interface_id << (is_up ? " UP" : " DOWN") << std::endl;
    
    std::lock_guard<std::mutex> lock(manager_mutex_); 

    IsisLevel adj_level_context = adj.level_established; // L1, L2, or L1_L2

    // Helper lambda to regenerate LSP and trigger SPF for a specific level
    auto regenerate_and_spf = [&](IsisLevel target_level) {
        if (lsdb_map_.count(target_level)) {
            // std::cout << "Triggering L" << static_cast<int>(target_level) << " LSP regeneration due to adjacency change." << std::endl;
            bool lsp_changed = lsdb_map_[target_level]->regenerate_own_lsp(config_.default_lsp_number);
            if (lsp_changed) { // regenerate_own_lsp should indicate if it indeed changed its own LSP
                trigger_spf_calculation(target_level);
            } else {
                 // Even if own LSP didn't change, the topology did, so SPF might be useful.
                 // However, if own LSP is the only thing reflecting the adj, then this is fine.
                 // More robust: trigger SPF if adj to DIS changes, or significant topology event.
                 // For now, linking it to own LSP change is one way.
                 // A simpler approach: always trigger SPF on adjacency UP/DOWN for relevant level.
                 trigger_spf_calculation(target_level);
            }
        }
    };

    if (adj_level_context == IsisLevel::L1 || adj_level_context == IsisLevel::L1_L2) {
        regenerate_and_spf(IsisLevel::L1);
    }
    if (adj_level_context == IsisLevel::L2 || adj_level_context == IsisLevel::L1_L2) {
        regenerate_and_spf(IsisLevel::L2);
    }
}

void IsisManager::trigger_spf_calculation(IsisLevel level) {
    if (!routing_manager_) {
        // std::cout << "IsisManager: RoutingManager not available, skipping SPF for L" << static_cast<int>(level) << std::endl;
        return;
    }
    if (!lsdb_map_.count(level)) {
        // std::cout << "IsisManager: LSDB for L" << static_cast<int>(level) << " not available, skipping SPF." << std::endl;
        return;
    }

    // std::cout << "IsisManager: Triggering SPF calculation for L" << static_cast<int>(level) << std::endl;
    IsisSpfCalculator spf_calculator(config_.system_id, level, lsdb_map_[level].get());
    std::vector<SpfRouteEntry> spf_results = spf_calculator.calculate_spf();

    std::vector<netflow::RouteEntry> routes_to_install;
    uint8_t admin_distance = (level == IsisLevel::L1) ? 110 : 115; // Example AD values
    RouteSource route_source = (level == IsisLevel::L1) ? RouteSource::ISIS_L1 : RouteSource::ISIS_L2;

    for (const auto& spf_entry : spf_results) {
        if (spf_entry.next_hop_ips.empty() && !(spf_entry.destination_prefix == IpAddress(0) && spf_entry.subnet_mask == IpAddress(0))) { // Skip default default route
             // This typically means a directly connected route from SPF perspective, or a route to self.
             // If it's truly connected, RoutingManager's add_connected_route handles it.
             // SPF might produce routes to own prefixes; these should be filtered or handled.
             // For now, if no next_hop_ips from SPF, and it's not the default route, skip.
             // A more robust check: if advertising_router_id is self, it's a local prefix.
            if (spf_entry.advertising_router_id == config_.system_id) {
                 // This is a prefix advertised by us. Typically, these are handled as "connected" routes
                 // already by InterfaceManager/RoutingManager or via generate_lsp advertising them.
                 // We generally don't install routes *from* SPF *to* our own advertised prefixes via ourselves.
                continue;
            }
        }

        // Handle ECMP: Create multiple RouteEntry if multiple next_hops/egress_interfaces
        // For simplicity, if multiple next_hops, create one RouteEntry per next_hop.
        // This assumes RoutingManager can handle multiple routes to the same prefix for ECMP.
        // If RoutingManager's update_dynamic_routes replaces all old routes for the source,
        // then we need to provide all ECMP paths at once.
        if (!spf_entry.next_hop_ips.empty()) {
            for (const auto& next_hop_ip : spf_entry.next_hop_ips) {
                 // Try to find a matching egress interface if multiple are listed.
                 // This part is simplified; a real ECMP setup needs careful interface mapping.
                uint32_t egress_if = 0;
                if (!spf_entry.egress_interface_ids.empty()) {
                    egress_if = *spf_entry.egress_interface_ids.begin(); // Take first one for simplicity
                }
                 routes_to_install.emplace_back(
                    spf_entry.destination_prefix,
                    spf_entry.subnet_mask,
                    next_hop_ip,
                    egress_if, 
                    static_cast<int>(spf_entry.metric),
                    route_source,
                    admin_distance);
            }
        } else if (spf_entry.advertising_router_id == config_.system_id && 
                   spf_entry.next_hop_ips.count(IpAddress("0.0.0.0")) > 0 ) { // Directly connected as per SPF result
            // This case should ideally be handled by connected routes added directly to RoutingManager.
            // However, if SPF explicitly flags them this way:
            routes_to_install.emplace_back(
                spf_entry.destination_prefix,
                spf_entry.subnet_mask,
                IpAddress("0.0.0.0"), // Indicates connected
                (spf_entry.egress_interface_ids.empty() ? 0 : *spf_entry.egress_interface_ids.begin()), // Egress if known
                static_cast<int>(spf_entry.metric), // Usually 0 for connected
                route_source, // Or RouteSource::CONNECTED if distinct
                admin_distance); 
        }
    }

    if (routing_manager_) {
        routing_manager_->update_dynamic_routes(routes_to_install, route_source);
        // std::cout << "IsisManager: Updated RoutingManager with " << routes_to_install.size() << " routes for L" << static_cast<int>(level) << std::endl;
    }
}


} // namespace isis
} // namespace netflow


// Define constants if not available from a common header (e.g. isis_pdu_constants.hpp or isis_common.hpp)
#ifndef AREA_ADDRESSES_TLV_TYPE
#define AREA_ADDRESSES_TLV_TYPE 1
#endif
#ifndef PROTOCOLS_SUPPORTED_TLV_TYPE
#define PROTOCOLS_SUPPORTED_TLV_TYPE 129
#endif
#ifndef IP_INTERFACE_ADDRESS_TLV_TYPE
#define IP_INTERFACE_ADDRESS_TLV_TYPE 132
#endif
#ifndef IS_REACHABILITY_TLV_TYPE // Standard IS Reachability
#define IS_REACHABILITY_TLV_TYPE 2
#endif
#ifndef EXTENDED_IS_REACHABILITY_TLV_TYPE
#define EXTENDED_IS_REACHABILITY_TLV_TYPE 22
#endif
#ifndef EXTENDED_IP_REACHABILITY_TLV_TYPE
#define EXTENDED_IP_REACHABILITY_TLV_TYPE 135
#endif

// PDU Types (already in isis_common.hpp, but as reminder)
// L1_LAN_IIH_TYPE, L2_LAN_IIH_TYPE, PTP_IIH_TYPE
// L1_LSP_TYPE, L2_LSP_TYPE
// L1_CSNP_TYPE, L2_CSNP_TYPE
// L1_PSNP_TYPE, L2_PSNP_TYPE

// Assumed PDU parsing functions (from isis_pdu.cpp or similar):
// parse_common_pdu_header(reader, header)
// parse_lan_hello_pdu(buffer, common_header_ref, out_pdu)
// parse_point_to_point_hello_pdu(buffer, common_header_ref, out_pdu)
// parse_link_state_pdu(buffer, common_header_ref, out_pdu)
// parse_complete_sequence_numbers_pdu(buffer, common_header_ref, out_pdu)
// parse_partial_sequence_numbers_pdu(buffer, common_header_ref, out_pdu)

// Assumed PDU serialization functions:
// serialize_area_addresses_tlv_value (for generate_lsp)
// serialize_link_state_pdu (for LSDB to use)
// etc.
```
