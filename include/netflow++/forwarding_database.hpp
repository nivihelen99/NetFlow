#ifndef NETFLOW_FORWARDING_DATABASE_HPP
#define NETFLOW_FORWARDING_DATABASE_HPP

#include "packet.hpp" // For MacAddress and potentially VlanID definition/usage
#include <vector>
#include <chrono>
#include <optional>
#include <algorithm> // For std::remove_if, std::find_if
#include <map>       // As an alternative storage, or if MacAddress needs comparison for map keys
#include "logger.hpp" // For SwitchLogger

namespace netflow {

// Forwarding Database Entry
struct FdbEntry {
    MacAddress mac;
    uint32_t port;      // Switch port or interface ID
    uint16_t vlan_id;   // VLAN ID
    std::chrono::steady_clock::time_point timestamp; // For aging
    bool is_static;     // Static entries are not aged out

    FdbEntry(const MacAddress& m, uint32_t p, uint16_t v_id, bool stat = false)
        : mac(m), port(p), vlan_id(v_id), timestamp(std::chrono::steady_clock::now()), is_static(stat) {}
};

// Comparison operator for MacAddress, needed if used as a key in std::map
// Already defined in packet.hpp, but good to be mindful of.
// bool operator<(const MacAddress& lhs, const MacAddress& rhs) {
//    return std::memcmp(lhs.bytes, rhs.bytes, sizeof(lhs.bytes)) < 0;
//}


class ForwardingDatabase {
public:
    explicit ForwardingDatabase(size_t initial_capacity = 0);

    // Adds or updates a dynamic MAC entry. If the MAC+VLAN already exists, its port and timestamp are updated.
    // Returns true if a new entry was created, false otherwise.
    bool learn_mac(const MacAddress& mac, uint32_t port, uint16_t vlan_id);

    void set_logger(SwitchLogger* logger);

    // Adds or updates a static MAC entry. Static entries are not aged out.
    void add_static_entry(const MacAddress& mac, uint32_t port, uint16_t vlan_id);

    // Looks up the port for a given MAC address and VLAN ID.
    std::optional<uint32_t> lookup_port(const MacAddress& mac, uint16_t vlan_id) const;

    // Removes entries older than max_age, unless they are static.
    void age_entries(std::chrono::seconds max_age = std::chrono::seconds(300));

    // Removes all entries (static and dynamic) associated with a specific port.
    void flush_port(uint32_t port);

    // Removes all entries (static and dynamic) associated with a specific VLAN ID.
    void flush_vlan(uint16_t vlan_id);

    // Removes all entries (static and dynamic).
    void flush_all();

    // Statistics
    size_t entry_count() const;
    size_t capacity() const;
    double load_factor() const;

    // Get all entries (e.g. for display or debugging)
    const std::vector<FdbEntry>& get_all_entries() const;

private:
    std::vector<FdbEntry> entries_;
    // Alternative using std::map. The key could be a struct combining MAC and VLAN, or a pair.
    // struct FdbMapKey {
    //     MacAddress mac;
    //     uint16_t vlan_id;
    //     bool operator<(const FdbMapKey& other) const {
    //         if (mac < other.mac) return true;
    //         if (other.mac < mac) return false;
    //         return vlan_id < other.vlan_id;
    //     }
    // };
    // std::map<FdbMapKey, FdbEntryData> map_entries_; // Where FdbEntryData would not include mac and vlan_id

    SwitchLogger* logger_ = nullptr; // Pointer to a logger instance
};

} // namespace netflow

#endif // NETFLOW_FORWARDING_DATABASE_HPP
