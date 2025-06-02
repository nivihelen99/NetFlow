#ifndef NETFLOW_ISIS_MANAGER_HPP
#define NETFLOW_ISIS_MANAGER_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp"
#include "netflow++/isis/isis_interface_manager.hpp"
#include "netflow++/isis/isis_lsdb.hpp"
#include "netflow++/interface_manager.hpp" // Passed to IsisInterfaceManager
#include "netflow++/packet.hpp"         // For MacAddress, IpAddress
#include "netflow++/routing_manager.hpp" // For future integration

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <optional>

namespace netflow {
namespace isis {

struct IsisConfig {
    SystemID system_id{};
    std::vector<AreaAddress> area_addresses{};
    IsisLevel enabled_levels = IsisLevel::L1_L2; // Which levels are active on this router
    bool over_load_bit_set = false;             // Router is overloaded
    uint8_t default_lsp_number = 0;             // For multi-part LSPs, typically 0 for the first/main
    // Timers and other global parameters can be added here
    std::vector<MulticastGroupAddressInfo> local_multicast_groups_to_advertise{}; // For testing mcast TLV
};

class IsisManager {
public:
    IsisManager(netflow::InterfaceManager& underlying_if_mgr,
                netflow::RoutingManager* routing_mgr); // Config will be applied via methods
    ~IsisManager();

    // Lifecycle Methods
    bool start(); // Return true if successfully started
    void stop();
    bool is_running() const { return running_.load(); }

    // Global Configuration Methods
    void set_system_id(const SystemID& sys_id);
    void add_area_address(const AreaAddress& area);
    void remove_area_address(const AreaAddress& area);
    void set_enabled_levels(IsisLevel level);
    void set_overload_bit_cli(bool set_on); // Renamed from set_overload_bit
    IsisConfig get_global_config() const;
    bool is_globally_configured() const; // Check if essential config (sysid, area) is present

    // Interface Configuration Methods (delegates to IsisInterfaceManager)
    void configure_interface(uint32_t interface_id, const IsisInterfaceConfig& if_config);
    void disable_isis_on_interface(uint32_t interface_id);
    std::optional<IsisInterfaceConfig> get_isis_interface_config(uint32_t interface_id) const;


    // PDU Reception Method (from lower layers)
    void receive_isis_pdu(uint32_t interface_id, const MacAddress& source_mac, const std::vector<uint8_t>& pdu_data);

    // Callback Registration (for sending frames)
    // The callback takes (interface_id, destination_mac, ethertype, payload)
    // For IS-IS, ethertype is usually handled by lower layers or known (e.g. 0x8870, or raw 802.3 LLC)
    // Here, we simplify: callback sends an IS-IS PDU payload, MAC is determined by manager/caller.
    void register_send_frame_callback(std::function<void(uint32_t, const MacAddress&, uint16_t, const std::vector<uint8_t>&)> cb);


private:
    void periodic_tasks_loop();
    LinkStatePdu generate_lsp(IsisLevel level, uint8_t lsp_number = 0);
    void on_adjacency_change(const IsisAdjacency& adj, bool is_up);
    
    // Callback wrapper for IsisInterfaceManager and IsisLsdb
    // They expect: void(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<uint8_t>& pdu_payload)
    void send_isis_pdu_via_frame_callback(uint32_t interface_id, const MacAddress& dest_mac, const std::vector<uint8_t>& pdu_payload);

    IsisConfig config_;
    std::unique_ptr<IsisInterfaceManager> interface_manager_;
    std::map<IsisLevel, std::unique_ptr<IsisLsdb>> lsdb_map_;
    
    netflow::InterfaceManager& underlying_interface_manager_; // Reference to existing manager
    netflow::RoutingManager* routing_manager_ = nullptr; // Non-owning pointer

    // Callback to send a fully formed L2 frame: (if_id, dest_mac, ethertype, payload)
    std::function<void(uint32_t, const MacAddress&, uint16_t, const std::vector<uint8_t>&)> send_frame_callback_;

    mutable std::mutex manager_mutex_; // `mutable` for const methods needing lock for internal state not exposed
    std::thread periodic_task_thread_;
    std::atomic<bool> running_{false};
    
    // Constants
    static constexpr uint16_t ISIS_ETHERTYPE = 0xFBFB; // Placeholder, actual EtherType for IS-IS can vary (e.g. 802.3 LLC, or specific like 0x8870)
                                                       // Often, IS-IS runs directly over Ethernet using LLC (DSAP/SSAP 0xFE)
                                                       // For simplicity, if an ethertype is used, this is a placeholder.
                                                       // The send_frame_callback might abstract this away.
    static constexpr uint16_t DEFAULT_LSP_MAX_LIFETIME = 3600; // seconds (1 hour)
    static constexpr uint16_t LSP_FRAGMENT_SIZE = 1400; // Max size of an LSP fragment (approx)

    const MacAddress ALL_L1_ISS_MAC = MacAddress("01:80:C2:00:00:14");
    const MacAddress ALL_L2_ISS_MAC = MacAddress("01:80:C2:00:00:15");
    const MacAddress ALL_ES_ISS_MAC = MacAddress("09:00:2B:00:00:04"); // End System anouncement
    const MacAddress ALL_IS_ISS_MAC = MacAddress("09:00:2B:00:00:05"); // IS announcement (deprecated by IEEE)

    // Private helper methods
    void trigger_spf_calculation(IsisLevel level);

};

} // namespace isis
} // namespace netflow

#endif // NETFLOW_ISIS_MANAGER_HPP
