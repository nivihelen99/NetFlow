#ifndef NETFLOW_ISIS_LSDB_HPP
#define NETFLOW_ISIS_LSDB_HPP

#include "netflow++/isis/isis_common.hpp" // Provides SystemID, MacAddress (via packet.hpp often)
#include "netflow++/isis/isis_pdu.hpp"     // Provides LspId, PDU structures
#include "netflow++/isis/isis_interface_manager.hpp" // Provides IsisLevel, IsisInterfaceManager type

#include <cstdint>    // For uintX_t types
#include <string>     // For std::string (general utility)
#include <vector>     // For std::vector
#include <map>        // For std::map
#include <mutex>      // For std::mutex
#include <chrono>     // For std::chrono
#include <functional> // For std::function
#include <set>        // For std::set (general utility)
#include <optional>   // For std::optional
// <array> is included via isis_common.hpp for SystemID

namespace netflow {
namespace isis {

// Custom comparator for LspId to be used in std::map keys.
// This should match the LspId structure in isis_pdu.hpp.
struct LspIdComparator {
    bool operator()(const LspId& lhs, const LspId& rhs) const {
        if (lhs.system_id < rhs.system_id) return true;
        if (rhs.system_id < lhs.system_id) return false;
        // system_ids are equal, compare pseudonode_id
        if (lhs.pseudonode_id < rhs.pseudonode_id) return true;
        if (rhs.pseudonode_id < lhs.pseudonode_id) return false;
        // pseudonode_ids are equal, compare lsp_number
        return lhs.lsp_number < rhs.lsp_number;
    }
};


struct LsdbEntry {
    Lsp lsp{}; // Changed from LinkStatePdu to Lsp to match isis_pdu.hpp
    std::chrono::steady_clock::time_point arrival_time{};
    std::chrono::steady_clock::time_point last_flooded_time{};
    std::chrono::steady_clock::time_point last_refreshed_time{};
    uint32_t received_on_interface_id = 0;
    std::optional<SystemID> received_from_neighbor_system_id{}; // Made optional
    bool own_lsp = false;
    bool purge_initiated = false;
    uint16_t remaining_lifetime_seconds = 0;
};

class IsisLsdb {
public:
    IsisLsdb(IsisLevel level, const SystemID& local_sys_id, IsisInterfaceManager* if_mgr);

    bool add_or_update_lsp(const Lsp& received_lsp, // Changed from LinkStatePdu
                           uint32_t on_interface_id,
                           std::optional<SystemID> from_neighbor_id,
                           bool is_own_lsp = false);

    void flood_lsp(const LspId& lsp_id, std::optional<uint32_t> received_on_interface_id_to_skip);

    std::optional<Lsp> get_lsp(const LspId& lsp_id) const; // Changed from LinkStatePdu
    std::optional<LsdbEntry> get_lsdb_entry(const LspId& lsp_id) const;
    std::vector<Lsp> get_all_lsps() const; // Changed from LinkStatePdu
    std::vector<LsdbEntry> get_all_lsdb_entries() const;

    void handle_received_csnp(const CsnPdu& csnp, // Changed from CompleteSequenceNumbersPdu
                              uint32_t on_interface_id,
                              const SystemID& from_neighbor_id);

    void handle_received_psnp(const PsnPdu& psnp, // Changed from PartialSequenceNumbersPdu
                              uint32_t on_interface_id,
                              const SystemID& from_neighbor_id);

    void send_csnp(uint32_t interface_id);
    void send_psnp(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<LspEntry>& lsp_entries_to_request_or_send);

    void periodic_tasks();

    void register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb);
    // Changed return type to Lsp
    void register_generate_local_lsp_callback(std::function<Lsp()> cb);

    bool originate_lsp_purge(const LspId& lsp_id);
    LspId get_local_lsp_id(uint8_t lsp_number = 0) const;
    bool regenerate_own_lsp(uint8_t lsp_number = 0);

private:
    bool validate_lsp_checksum(const Lsp& lsp) const; // Changed from LinkStatePdu
    void update_lsp_metadata(LsdbEntry& entry, const Lsp& lsp, uint32_t on_interface_id, std::optional<SystemID> from_neighbor_id, bool is_own); // Changed from LinkStatePdu
    MacAddress get_destination_mac_for_level() const;

    mutable std::mutex mutex_;
    std::map<LspId, LsdbEntry, LspIdComparator> lsdb_; // Added LspIdComparator
    IsisLevel level_;
    SystemID local_system_id_;
    IsisInterfaceManager* isis_interface_manager_;

    std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> send_pdu_callback_;
    std::function<Lsp()> generate_local_lsp_callback_; // Changed return type

    static constexpr uint16_t MAX_LSP_LIFETIME_SECONDS = 65535;
    static constexpr uint16_t ZERO_AGE_LSP_LIFETIME_SECONDS = 0;
    static constexpr uint16_t LSP_REFRESH_INTERVAL_SECONDS = 1800; 
    static constexpr uint16_t LSP_MAX_AGE_SECONDS = 3600; 
    static constexpr uint16_t CSNP_INTERVAL_SECONDS = 10;
    static constexpr uint16_t PSNP_INTERVAL_SECONDS = 2; 
    static constexpr uint16_t MAX_AGE_PURGE_DELAY_SECONDS = 60;

    std::map<uint32_t, std::chrono::steady_clock::time_point> interface_last_csnp_time_;

    const MacAddress ALL_L1_ISS_MAC = MacAddress("01:80:C2:00:00:14");
    const MacAddress ALL_L2_ISS_MAC = MacAddress("01:80:C2:00:00:15");
};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_LSDB_HPP
