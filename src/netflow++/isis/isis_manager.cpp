#include "netflow++/isis/isis_manager.hpp"
#include "netflow++/isis/isis_common.hpp" // Includes PDU types and TLV constants via isis_pdu_constants.hpp
#include "netflow++/isis/isis_pdu_constants.hpp" // For TLV types, PDU types
#include "netflow++/isis/isis_spf_calculator.hpp"
#include "netflow++/byte_swap.hpp"
#include "netflow++/isis/isis_utils.hpp" // Include for BufferReader and basic parsers
#include "netflow++/isis/isis_pdu_parsing.hpp"
#include "netflow++/isis/isis_pdu_serialization.hpp"

#include <iostream>
#include <chrono>
#include <vector>
#include <algorithm> // For std::find, std::remove

namespace netflow {
namespace isis {

// NOTE: All local stubs for BufferReader, parse_xxx, serialize_xxx are REMOVED.
// They are now expected to be in isis_utils.hpp and isis_utils.cpp.

IsisManager::IsisManager(netflow::InterfaceManager& underlying_if_mgr,
                         netflow::RoutingManager* routing_mgr)
    : underlying_interface_manager_(underlying_if_mgr),
      routing_manager_(routing_mgr),
      running_(false) {}

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
    }
}

bool IsisManager::is_globally_configured() const {
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
    if (running_.load()) return true;
    if (!is_globally_configured()) return false;

    interface_manager_ = std::make_unique<IsisInterfaceManager>(underlying_interface_manager_, config_.system_id, config_.area_addresses);
    
    interface_manager_->register_send_pdu_callback(
        [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
            this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
        });
    interface_manager_->register_adjacency_change_callback(
        [this](const IsisAdjacency& adj, bool is_up) {
            this->on_adjacency_change(adj, is_up);
        });

    if (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2) {
        lsdb_map_[IsisLevel::L1] = std::make_unique<IsisLsdb>(IsisLevel::L1, config_.system_id, interface_manager_.get());
        lsdb_map_[IsisLevel::L1]->register_send_pdu_callback(
            [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
                this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
            });
        lsdb_map_[IsisLevel::L1]->register_generate_local_lsp_callback(
            [this]() { return this->generate_lsp(IsisLevel::L1, config_.default_lsp_number); });
        if(lsdb_map_[IsisLevel::L1]) lsdb_map_[IsisLevel::L1]->regenerate_own_lsp(config_.default_lsp_number);
    }
    if (config_.enabled_levels == IsisLevel::L2 || config_.enabled_levels == IsisLevel::L1_L2) {
        lsdb_map_[IsisLevel::L2] = std::make_unique<IsisLsdb>(IsisLevel::L2, config_.system_id, interface_manager_.get());
        lsdb_map_[IsisLevel::L2]->register_send_pdu_callback(
            [this](uint32_t if_id, const MacAddress& dm, const std::vector<uint8_t>& pp) {
                this->send_isis_pdu_via_frame_callback(if_id, dm, pp);
            });
        lsdb_map_[IsisLevel::L2]->register_generate_local_lsp_callback(
            [this]() { return this->generate_lsp(IsisLevel::L2, config_.default_lsp_number); });
        if(lsdb_map_[IsisLevel::L2]) lsdb_map_[IsisLevel::L2]->regenerate_own_lsp(config_.default_lsp_number);
    }
    
    running_ = true;
    periodic_task_thread_ = std::thread(&IsisManager::periodic_tasks_loop, this);
    if (running_.load()) { 
        for (const auto& pair : lsdb_map_) {
            trigger_spf_calculation(pair.first);
        }
    }
    return true;
}

void IsisManager::stop() {
    bool expected = true;
    if (running_.compare_exchange_strong(expected, false)) {
        if (periodic_task_thread_.joinable()) periodic_task_thread_.join();
        lsdb_map_.clear();
        interface_manager_.reset();
    }
}

void IsisManager::set_system_id(const SystemID& sys_id) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) return;
    config_.system_id = sys_id;
}

void IsisManager::add_area_address(const AreaAddress& area) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) return;
    if (std::find(config_.area_addresses.begin(), config_.area_addresses.end(), area) == config_.area_addresses.end()) {
        config_.area_addresses.push_back(area);
    }
}

void IsisManager::remove_area_address(const AreaAddress& area) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) return;
    config_.area_addresses.erase(
        std::remove(config_.area_addresses.begin(), config_.area_addresses.end(), area),
        config_.area_addresses.end());
}

void IsisManager::set_enabled_levels(IsisLevel level) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (running_.load()) return;
    config_.enabled_levels = level;
}

void IsisManager::internal_set_overload_bit(bool overload_status) {
    if (config_.over_load_bit_set == overload_status) return;
    config_.over_load_bit_set = overload_status;
    if (running_.load()) {
        if (lsdb_map_.count(IsisLevel::L1)) lsdb_map_[IsisLevel::L1]->regenerate_own_lsp(config_.default_lsp_number);
        if (lsdb_map_.count(IsisLevel::L2)) lsdb_map_[IsisLevel::L2]->regenerate_own_lsp(config_.default_lsp_number);
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
            if (interface_manager_) interface_manager_->periodic_tasks();
            std::vector<IsisLevel> active_levels;
            { std::lock_guard<std::mutex> lock(manager_mutex_); for(const auto& pair : lsdb_map_) active_levels.push_back(pair.first); }
            for (IsisLevel level : active_levels) {
                std::unique_ptr<IsisLsdb>* lsdb_ptr = nullptr;
                { std::lock_guard<std::mutex> lock(manager_mutex_); auto it = lsdb_map_.find(level); if (it != lsdb_map_.end()) lsdb_ptr = &it->second; }
                if (lsdb_ptr && lsdb_ptr->get()) (*lsdb_ptr)->periodic_tasks();
            }
        } catch (const std::exception&) {} // Basic catch, should log e.what()
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void IsisManager::receive_isis_pdu(uint32_t interface_id, const MacAddress& source_mac, const std::vector<uint8_t>& pdu_data) {
    if (pdu_data.empty()) return;
    CommonPduHeader common_header;
    BufferReader reader(pdu_data);
    if (!parse_common_pdu_header(reader, common_header)) return;

    IsisLevel pdu_level = IsisLevel::NONE;
    switch (common_header.pduType) {
        case L1_LAN_IIH_TYPE: case L1_LSP_TYPE: case L1_CSNP_TYPE: case L1_PSNP_TYPE: pdu_level = IsisLevel::L1; break;
        case L2_LAN_IIH_TYPE: case L2_LSP_TYPE: case L2_CSNP_TYPE: case L2_PSNP_TYPE: pdu_level = IsisLevel::L2; break;
        case PTP_IIH_TYPE: {
            std::lock_guard<std::mutex> lock(manager_mutex_);
            if (!interface_manager_) return;
            IsisLevel interface_configured_level = IsisLevel::NONE;
            auto if_config_opt = interface_manager_->get_interface_config(interface_id);
            if (if_config_opt) interface_configured_level = if_config_opt->level;
            else return; // No interface config, cannot determine PTP PDU level context

            if (interface_configured_level == IsisLevel::L1_L2) {
                // This part is complex: A PTP IIH on an L1/L2 interface could be for L1, L2, or both
                // based on its *own* circuit type field. For now, we'll use a simplification.
                // If router is L1/L2, assume PTP Hello could be for either and check global enabled levels.
                // This might need refinement based on PTP Hello PDU's actual content.
                if (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2) pdu_level = IsisLevel::L1; // Prefer L1 or process for both?
                else if (config_.enabled_levels == IsisLevel::L2) pdu_level = IsisLevel::L2;
                // If PTP PDU itself indicates L1/L2, might need to dispatch to both LSDBs if router is L1/L2.
            } else {
                 pdu_level = interface_configured_level;
            }
            break;
        }
        default: return;
    }
    
    bool level_globally_active = false;
    if (pdu_level == IsisLevel::L1 && (config_.enabled_levels == IsisLevel::L1 || config_.enabled_levels == IsisLevel::L1_L2)) level_globally_active = true;
    if (pdu_level == IsisLevel::L2 && (config_.enabled_levels == IsisLevel::L2 || config_.enabled_levels == IsisLevel::L1_L2)) level_globally_active = true;
    if (!level_globally_active && pdu_level != IsisLevel::NONE) return;

    // Declare PDU structs before the switch statement
    LanHelloPdu lan_hello;
    PointToPointHelloPdu ptp_hello;
    LinkStatePdu lsp;
    CompleteSequenceNumbersPdu csnp;
    PartialSequenceNumbersPdu psnp;
    // BufferReader for re-parsing common header for CSNP/PSNP needs to be distinct for each use if offset is modified.
    // Or reset the same reader.

    std::lock_guard<std::mutex> lock(manager_mutex_);
    if (!interface_manager_) return;

    switch (common_header.pduType) {
        case L1_LAN_IIH_TYPE:
        case L2_LAN_IIH_TYPE: {
            if (parse_lan_hello_pdu(pdu_data, common_header, lan_hello)) {
                interface_manager_->handle_received_hello(interface_id, source_mac, common_header, lan_hello);
            }
            break;
        }
        case PTP_IIH_TYPE: {
            if (parse_point_to_point_hello_pdu(pdu_data, common_header, ptp_hello)) {
                 interface_manager_->handle_received_hello(interface_id, source_mac, common_header, ptp_hello);
            }
            break;
        }
        case L1_LSP_TYPE:
        case L2_LSP_TYPE: {
            if (parse_link_state_pdu(pdu_data, common_header, lsp)) {
                if (lsdb_map_.count(pdu_level)) {
                    if (lsdb_map_[pdu_level]->add_or_update_lsp(pdu_data, common_header, lsp, interface_id, lsp.lspId.systemId, false))
                        trigger_spf_calculation(pdu_level);
                }
            }
            break;
        }
        case L1_CSNP_TYPE:
        case L2_CSNP_TYPE: {
            BufferReader csnp_specific_reader(pdu_data);
            CommonPduHeader csnp_common_header_local;
            if (parse_common_pdu_header(csnp_specific_reader, csnp_common_header_local)) {
                if (parse_complete_sequence_numbers_pdu(pdu_data, csnp_common_header_local, csnp)) {
                     if (lsdb_map_.count(pdu_level)) lsdb_map_[pdu_level]->handle_received_csnp(csnp, interface_id, csnp.sourceId);
                }
            }
            break;
        }
        case L1_PSNP_TYPE:
        case L2_PSNP_TYPE: {
            BufferReader psnp_specific_reader(pdu_data);
            CommonPduHeader psnp_common_header_local;
            if (parse_common_pdu_header(psnp_specific_reader, psnp_common_header_local)) {
                if (parse_partial_sequence_numbers_pdu(pdu_data, psnp_common_header_local, psnp)) {
                    if (lsdb_map_.count(pdu_level)) lsdb_map_[pdu_level]->handle_received_psnp(psnp, interface_id, psnp.sourceId);
                }
            }
            break;
        }
    }
}

LinkStatePdu IsisManager::generate_lsp(IsisLevel level, uint8_t lsp_number) {
    std::lock_guard<std::mutex> lock(manager_mutex_);
    LinkStatePdu lsp;
    lsp.commonHeader.intradomainRoutingProtocolDiscriminator = 0x83;
    lsp.commonHeader.versionProtocolIdExtension = 1; lsp.commonHeader.version = 1; lsp.commonHeader.idLength = 0;
    lsp.commonHeader.pduType = (level == IsisLevel::L1) ? L1_LSP_TYPE : L2_LSP_TYPE;
    lsp.lspId.systemId = config_.system_id; lsp.lspId.pseudonodeIdOrLspNumber = lsp_number;
    lsp.remainingLifetime = htons(DEFAULT_LSP_MAX_LIFETIME);

    // Increment sequence number logic
    uint32_t current_seq = 0;
    if(lsdb_map_.count(level)) {
        auto current_lsp_entry = lsdb_map_[level]->get_lsdb_entry(lsp.lspId);
        if(current_lsp_entry && current_lsp_entry->own_lsp) {
            current_seq = ntohl(current_lsp_entry->lsp.sequenceNumber);
        }
    }
    lsp.sequenceNumber = htonl(current_seq + 1);


    lsp.pAttOlIsTypeBits = 0;
    if (config_.over_load_bit_set) lsp.pAttOlIsTypeBits |= (1 << 2);
    if (level == IsisLevel::L1) lsp.pAttOlIsTypeBits |= 0x01;
    else { if (config_.enabled_levels == IsisLevel::L1_L2) lsp.pAttOlIsTypeBits |= 0x03; else lsp.pAttOlIsTypeBits |= 0x02; }

    if (level == IsisLevel::L1 || (level == IsisLevel::L2 && !config_.area_addresses.empty())) {
        TLV area_tlv; area_tlv.type = AREA_ADDRESSES_TLV_TYPE; AreaAddressesTlvValue area_val;
        area_val.areaAddresses = config_.area_addresses; area_tlv.value = serialize_area_addresses_tlv_value(area_val);
        area_tlv.length = static_cast<uint8_t>(area_tlv.value.size());
        if (area_tlv.length > 0) lsp.tlvs.push_back(area_tlv);
    }
    TLV protocols_tlv; protocols_tlv.type = PROTOCOLS_SUPPORTED_TLV_TYPE; protocols_tlv.value.push_back(0xCC); // ISIS NLPID for IP
    protocols_tlv.length = static_cast<uint8_t>(protocols_tlv.value.size()); lsp.tlvs.push_back(protocols_tlv);
    TLV ip_intf_tlv; ip_intf_tlv.type = IP_INTERNAL_REACH_TLV_TYPE; // Corrected from ISIS_TLV_IP_INTERFACE_ADDR
    for (uint32_t if_id : underlying_interface_manager_.get_all_interface_ids()) {
        if (interface_manager_ && interface_manager_->is_interface_up_and_isis_enabled(if_id)) {
            auto if_port_config_opt = underlying_interface_manager_.get_port_config(if_id);
            if (if_port_config_opt && !if_port_config_opt->ip_configurations.empty()) {
                IpAddress ip_addr = if_port_config_opt->ip_configurations[0].address;
                uint32_t ip_addr_net = htonl(ip_addr);
                const uint8_t* ip_bytes_ptr = reinterpret_cast<const uint8_t*>(&ip_addr_net);
                ip_intf_tlv.value.insert(ip_intf_tlv.value.end(), ip_bytes_ptr, ip_bytes_ptr + 4);
            }
        }
    }
    if (!ip_intf_tlv.value.empty()) { ip_intf_tlv.length = static_cast<uint8_t>(ip_intf_tlv.value.size()); lsp.tlvs.push_back(ip_intf_tlv); }
    TLV is_reach_tlv;
    if (level == IsisLevel::L1) is_reach_tlv.type = ISIS_TLV_IS_REACHABILITY; else is_reach_tlv.type = ISIS_TLV_EXTENDED_IS_REACHABILITY;
    if (interface_manager_) {
        auto all_adjs = interface_manager_->get_all_adjacencies_by_level(level);
        for (const auto& adj : all_adjs) { if (adj.state == AdjacencyState::UP) {
            is_reach_tlv.value.push_back(10);
            is_reach_tlv.value.insert(is_reach_tlv.value.end(), adj.neighbor_system_id.begin(), adj.neighbor_system_id.end());
            is_reach_tlv.value.push_back(0); } } }
    if (!is_reach_tlv.value.empty()) { is_reach_tlv.length = static_cast<uint8_t>(is_reach_tlv.value.size()); lsp.tlvs.push_back(is_reach_tlv); }
    TLV ext_ip_reach_tlv; ext_ip_reach_tlv.type = EXTENDED_IP_REACHABILITY_TLV_TYPE; // Corrected from ISIS_TLV_EXTENDED_IP_REACHABILITY
    for (uint32_t if_id : underlying_interface_manager_.get_all_interface_ids()) {
         if (interface_manager_ && interface_manager_->is_interface_up_and_isis_enabled(if_id)) {
            auto if_port_config_opt = underlying_interface_manager_.get_port_config(if_id);
            if (if_port_config_opt) {
                for(const auto& ip_config : if_port_config_opt->ip_configurations) {
                    uint32_t metric = 10;
                    uint8_t prefix_len = netflow::ip_mask_to_prefix_length(ip_config.subnet_mask);
                    uint32_t network_addr = ip_config.address & ip_config.subnet_mask;
                    uint32_t metric_be = htonl(metric);
                    const uint8_t* metric_bytes = reinterpret_cast<const uint8_t*>(&metric_be);
                    ext_ip_reach_tlv.value.insert(ext_ip_reach_tlv.value.end(), metric_bytes, metric_bytes + 4);
                    ext_ip_reach_tlv.value.push_back(prefix_len);
                    uint32_t network_addr_be = htonl(network_addr);
                    int num_ip_bytes = (prefix_len + 7) / 8;
                    const uint8_t* ip_prefix_bytes = reinterpret_cast<const uint8_t*>(&network_addr_be);
                    ext_ip_reach_tlv.value.insert(ext_ip_reach_tlv.value.end(), ip_prefix_bytes, ip_prefix_bytes + num_ip_bytes);
                }
            } } }
    if (!ext_ip_reach_tlv.value.empty()) { ext_ip_reach_tlv.length = static_cast<uint8_t>(ext_ip_reach_tlv.value.size()); lsp.tlvs.push_back(ext_ip_reach_tlv); }
    TLV mcast_cap_tlv; mcast_cap_tlv.type = MULTICAST_CAPABILITY_TLV_TYPE; MulticastCapabilityTlvValue mcast_cap_val; // Corrected
    mcast_cap_tlv.value = serialize_multicast_capability_tlv_value(mcast_cap_val);
    mcast_cap_tlv.length = static_cast<uint8_t>(mcast_cap_tlv.value.size()); lsp.tlvs.push_back(mcast_cap_tlv);
    if (!config_.local_multicast_groups_to_advertise.empty()) {
        TLV mcast_group_tlv; mcast_group_tlv.type = MULTICAST_GROUP_MEMBERSHIP_TLV_TYPE; MulticastGroupMembershipTlvValue mcast_group_val; // Corrected
        mcast_group_val.groups = config_.local_multicast_groups_to_advertise;
        mcast_group_tlv.value = serialize_multicast_group_membership_tlv_value(mcast_group_val);
        mcast_group_tlv.length = static_cast<uint8_t>(mcast_group_tlv.value.size());
        if (mcast_group_tlv.length > 0) lsp.tlvs.push_back(mcast_group_tlv);
    }
    lsp.pduLength = 0; lsp.checksum = htons(0xFFFF);
    return lsp;
}

void IsisManager::on_adjacency_change(const IsisAdjacency& adj, bool is_up) {
    std::lock_guard<std::mutex> lock(manager_mutex_); 
    IsisLevel adj_level_context = adj.level_established;
    auto regenerate_and_spf = [&](IsisLevel target_level) {
        if (lsdb_map_.count(target_level)) {
            if(lsdb_map_[target_level]) lsdb_map_[target_level]->regenerate_own_lsp(config_.default_lsp_number); // Check pointer
            trigger_spf_calculation(target_level); } };
    if (adj_level_context == IsisLevel::L1 || adj_level_context == IsisLevel::L1_L2) regenerate_and_spf(IsisLevel::L1);
    if (adj_level_context == IsisLevel::L2 || adj_level_context == IsisLevel::L1_L2) regenerate_and_spf(IsisLevel::L2);
}

void IsisManager::trigger_spf_calculation(IsisLevel level) {
    if (!routing_manager_ || !lsdb_map_.count(level) || !lsdb_map_.at(level)) return; // Check pointer
    IsisSpfCalculator spf_calculator(config_.system_id, level, lsdb_map_.at(level).get());
    std::vector<SpfRouteEntry> spf_results = spf_calculator.calculate_spf();
    std::vector<netflow::RouteEntry> routes_to_install;
    uint8_t admin_distance = (level == IsisLevel::L1) ? 110 : 115;
    RouteSource route_source = (level == IsisLevel::L1) ? RouteSource::ISIS_L1 : RouteSource::ISIS_L2;

    for (const auto& spf_entry : spf_results) {
        if (spf_entry.advertising_router_id == config_.system_id &&
            !(spf_entry.destination_prefix == 0 && spf_entry.subnet_mask == 0)) { // IpAddress is uint32_t
             bool is_connected_route = false;
             for(const auto& nh_ip : spf_entry.next_hop_ips) if(nh_ip == 0) is_connected_route = true; // IpAddress 0 for connected
             if (!is_connected_route) continue;
        }
        if (!spf_entry.next_hop_ips.empty()) {
            for (const auto& next_hop_ip : spf_entry.next_hop_ips) {
                uint32_t egress_if = (!spf_entry.egress_interface_ids.empty()) ? *spf_entry.egress_interface_ids.begin() : 0;
                 routes_to_install.emplace_back(spf_entry.destination_prefix, spf_entry.subnet_mask, next_hop_ip, egress_if,
                    static_cast<int>(spf_entry.metric), route_source, admin_distance);
            }
        } else if (spf_entry.advertising_router_id == config_.system_id && 
                   (spf_entry.next_hop_ips.empty() || spf_entry.next_hop_ips.count(0) > 0) ) { // IpAddress 0 for connected
            routes_to_install.emplace_back(spf_entry.destination_prefix, spf_entry.subnet_mask, IpAddress(0),
                (!spf_entry.egress_interface_ids.empty() ? *spf_entry.egress_interface_ids.begin() : 0),
                static_cast<int>(spf_entry.metric), route_source, admin_distance);
        }
    }
    // if (routing_manager_) routing_manager_->update_dynamic_routes(routes_to_install, route_source); // TODO: Implement in RoutingManager
}

} // namespace isis
} // namespace netflow
