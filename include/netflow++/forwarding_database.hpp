#ifndef NETFLOW_FORWARDING_DATABASE_HPP
#define NETFLOW_FORWARDING_DATABASE_HPP

#include "packet.hpp" // For MacAddress
#include "logger.hpp" // For SwitchLogger

#include <cstdint>   // For uint32_t, uint16_t
#include <vector>    // For std::vector
#include <chrono>    // For std::chrono types
#include <optional>  // For std::optional
#include <algorithm> // For std::remove_if, std::find_if (used in .cpp)
#include <map>       // For std::map (if alternative storage is used)
#include <cstddef>   // For std::size_t

// <cstring> for std::memcmp would be needed if the commented MacAddress operator< was used here

namespace netflow {

struct FdbEntry {
    MacAddress mac;
    uint32_t port;
    uint16_t vlan_id;
    std::chrono::steady_clock::time_point timestamp;
    bool is_static;

    FdbEntry(const MacAddress& m, uint32_t p, uint16_t v_id, bool stat = false)
        : mac(m), port(p), vlan_id(v_id), timestamp(std::chrono::steady_clock::now()), is_static(stat) {}
};

class ForwardingDatabase {
public:
    explicit ForwardingDatabase(std::size_t initial_capacity = 0);

    bool learn_mac(const MacAddress& mac, uint32_t port, uint16_t vlan_id);
    void set_logger(SwitchLogger* logger);
    void add_static_entry(const MacAddress& mac, uint32_t port, uint16_t vlan_id);
    std::optional<uint32_t> lookup_port(const MacAddress& mac, uint16_t vlan_id) const;
    void age_entries(std::chrono::seconds max_age = std::chrono::seconds(300));
    void flush_port(uint32_t port);
    void flush_vlan(uint16_t vlan_id);
    void flush_all();

    std::size_t entry_count() const;
    std::size_t capacity() const; // May relate to vector's capacity or a conceptual limit
    double load_factor() const;    // Typically for hash maps, but could be ratio of entries to capacity

    const std::vector<FdbEntry>& get_all_entries() const;
    bool remove_entry(const netflow::MacAddress& mac, uint16_t vlan_id);

private:
    std::vector<FdbEntry> entries_;
    SwitchLogger* logger_ = nullptr;
    std::size_t initial_capacity_hint_ = 0; // Store initial capacity if needed for reserve
};

} // namespace netflow

#endif // NETFLOW_FORWARDING_DATABASE_HPP
