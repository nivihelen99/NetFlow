#ifndef NETFLOW_ISIS_LSDB_HPP
#define NETFLOW_ISIS_LSDB_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp"
#include "netflow++/isis/isis_interface_manager.hpp" // Forward declare if possible to reduce coupling, but methods need types.

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <functional>
#include <set>
#include <optional>

namespace netflow {
namespace isis {

// For std::map key; LspId needs a less-than operator.
// Or convert LspId to a comparable string/tuple, or provide a custom comparator.
inline bool operator<(const LspId& lhs, const LspId& rhs) {
    if (lhs.systemId < rhs.systemId) return true;
    if (lhs.systemId > rhs.systemId) return false;
    return lhs.pseudonodeIdOrLspNumber < rhs.pseudonodeIdOrLspNumber;
}


struct LsdbEntry {
    LinkStatePdu lsp{};
    std::chrono::steady_clock::time_point arrival_time{};
    std::chrono::steady_clock::time_point last_flooded_time{};
    std::chrono::steady_clock::time_point last_refreshed_time{}; // For own LSPs
    uint32_t received_on_interface_id = 0; // Interface it was received on, 0 if self-originated initially
    SystemID received_from_neighbor_system_id{}; // Optional, if known
    bool own_lsp = false;
    bool purge_initiated = false; // True if we have started purging this LSP (sent our own zero-age version)
    uint16_t remaining_lifetime_seconds = 0; // Tracks the current lifetime, decremented by periodic tasks
};

class IsisLsdb {
public:
    IsisLsdb(IsisLevel level, const SystemID& local_sys_id, IsisInterfaceManager* if_mgr);

    // LSP Handling Methods
    // Changed to match the .cpp definition which includes raw PDU data for checksum validation
    bool add_or_update_lsp(const std::vector<uint8_t>& raw_pdu_data,
                           const CommonPduHeader& common_header,
                           const LinkStatePdu& received_lsp,
                           uint32_t on_interface_id,
                           std::optional<SystemID> from_neighbor_id,
                           bool is_own_lsp = false);
    
    void flood_lsp(const LspId& lsp_id, std::optional<uint32_t> received_on_interface_id_to_skip);
    
    std::optional<LinkStatePdu> get_lsp(const LspId& lsp_id) const;
    std::optional<LsdbEntry> get_lsdb_entry(const LspId& lsp_id) const;
    std::vector<LinkStatePdu> get_all_lsps() const;
    std::vector<LsdbEntry> get_all_lsdb_entries() const;

    // LSDB Synchronization (SNP Handling)
    void handle_received_csnp(const CompleteSequenceNumbersPdu& csnp, 
                              uint32_t on_interface_id, 
                              const SystemID& from_neighbor_id); // from_neighbor_id is const ref
    
    void handle_received_psnp(const PartialSequenceNumbersPdu& psnp, 
                              uint32_t on_interface_id, 
                              const SystemID& from_neighbor_id); // from_neighbor_id is const ref
    
    void send_csnp(uint32_t interface_id);
    void send_psnp(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<LspEntry>& lsp_entries_to_request_or_send);


    // Periodic Processing Method
    void periodic_tasks();

    // Callback Registration
    void register_send_pdu_callback(std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> cb);
    void register_generate_local_lsp_callback(std::function<LinkStatePdu()> cb);

    // LSP Origination
    bool originate_lsp_purge(const LspId& lsp_id);
    LspId get_local_lsp_id(uint8_t lsp_number = 0) const; // lsp_number for different LSPs from same system
    bool regenerate_own_lsp(uint8_t lsp_number = 0);


private:
    // Helper methods
    // Changed to match the .cpp definition
    bool validate_lsp_checksum(const std::vector<uint8_t>& raw_lsp_pdu_bytes,
                               const CommonPduHeader& common_header,
                               const LinkStatePdu& parsed_lsp) const;
    void update_lsp_metadata(LsdbEntry& entry, const LinkStatePdu& lsp, uint32_t on_interface_id, std::optional<SystemID> from_neighbor_id, bool is_own);
    MacAddress get_destination_mac_for_level() const;


    mutable std::mutex mutex_; // `mutable` for internal locking within const methods if necessary
    std::map<LspId, LsdbEntry> lsdb_;
    IsisLevel level_;
    SystemID local_system_id_;
    IsisInterfaceManager* isis_interface_manager_; // Non-owning

    std::function<void(uint32_t, const MacAddress&, const std::vector<uint8_t>&)> send_pdu_callback_;
    std::function<LinkStatePdu()> generate_local_lsp_callback_;

    // Constants
    static constexpr uint16_t MAX_LSP_LIFETIME_SECONDS = 65535; // Max age before implicit purge by others
    static constexpr uint16_t ZERO_AGE_LSP_LIFETIME_SECONDS = 0;
    static constexpr uint16_t LSP_REFRESH_INTERVAL_SECONDS = 1800; // 30 minutes (standard is ~20-25 min less than MaxLSPTransmitDelay)
                                                                  // MaxLSPTransmitDelay is 1200s. So refresh is MaxAge - 1200s.
                                                                  // A common value is 50 minutes (3000s) for refresh, if MaxAge is 60 min.
                                                                  // Let's use ~50 mins for refresh, MaxAge ~60 mins.
                                                                  // For now, using 30 mins for refresh.
    static constexpr uint16_t LSP_MAX_AGE_SECONDS = 3600; // 1 hour. LSPs older than this are invalid.
                                                          // This is different from remainingLifetime. This is absolute max.
    static constexpr uint16_t CSNP_INTERVAL_SECONDS = 10; 
    static constexpr uint16_t PSNP_INTERVAL_SECONDS = 2; // Or send PSNP as needed, not strictly periodic for sending.
    static constexpr uint16_t MAX_AGE_PURGE_DELAY_SECONDS = 60; // How long a zero-lifetime LSP stays before removal.

    std::chrono::steady_clock::time_point last_csnp_sent_time_on_interface_[256]; // Max 256 interfaces, hacky. Use map.
    std::map<uint32_t, std::chrono::steady_clock::time_point> interface_last_csnp_time_;

    // Constants for MAC addresses (already in IsisInterfaceManager, but good to have here too for clarity or if used differently)
    const MacAddress ALL_L1_ISS_MAC = MacAddress("01:80:C2:00:00:14");
    const MacAddress ALL_L2_ISS_MAC = MacAddress("01:80:C2:00:00:15");
};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_LSDB_HPP
