#ifndef NETFLOW_PLUS_PLUS_SWITCHING_FDB_HPP
#define NETFLOW_PLUS_PLUS_SWITCHING_FDB_HPP

#include "netflow_plus_plus/core/types.hpp" // For MacAddress
#include <chrono>
#include <optional>
#include <unordered_map>
#include <vector> // Not strictly needed for FDB itself, but common for FDB interaction
#include <cstdint> // For uint32_t, uint16_t
#include <functional> // For std::hash

namespace netflow_plus_plus {
namespace switching {

struct FdbEntry {
    core::MacAddress mac;
    uint32_t port;
    uint16_t vlan_id;
    std::chrono::steady_clock::time_point timestamp;
    bool is_static;

    FdbEntry(const core::MacAddress& m, uint32_t p, uint16_t v, bool stat = false)
        : mac(m), port(p), vlan_id(v), timestamp(std::chrono::steady_clock::now()), is_static(stat) {}
};

// Key for the FDB unordered_map
struct FdbKey {
    core::MacAddress mac;
    uint16_t vlan_id;

    bool operator==(const FdbKey& other) const {
        return mac == other.mac && vlan_id == other.vlan_id;
    }
};

// Custom hash for FdbKey
struct FdbKeyHash {
    std::size_t operator()(const FdbKey& key) const {
        // A simple hash combination. Better hashing might be needed for performance.
        std::size_t h1 = std::hash<std::string>()(key.mac.toString()); // Assuming MacAddress has toString() or similar
        std::size_t h2 = std::hash<uint16_t>()(key.vlan_id);
        return h1 ^ (h2 << 1); // Combine hashes
    }
};


class ForwardingDatabase {
public:
    ForwardingDatabase();

    /**
     * @brief Learns or updates a MAC address on a specific port and VLAN.
     * If the entry is static, it won't be updated by dynamic learning.
     * @param mac The MAC address.
     * @param port The port number.
     * @param vlan_id The VLAN ID.
     * @return True if a new MAC was learned, false if an existing dynamic entry was updated or if a static entry already exists.
     */
    bool learn_mac(const core::MacAddress& mac, uint32_t port, uint16_t vlan_id);

    /**
     * @brief Looks up the egress port for a given MAC address and VLAN.
     * @param mac The MAC address to look up.
     * @param vlan_id The VLAN ID.
     * @return The port number if found, otherwise std::nullopt.
     */
    std::optional<uint32_t> lookup_port(const core::MacAddress& mac, uint16_t vlan_id) const;

    /**
     * @brief Removes entries older than max_age, unless they are static.
     * @param max_age The maximum age for dynamic entries.
     */
    void age_entries(std::chrono::seconds max_age = std::chrono::seconds(300));

    /**
     * @brief Removes all entries (static and dynamic) associated with a specific port.
     * @param port The port number to flush.
     */
    void flush_port(uint32_t port);

    /**
     * @brief Removes all entries (static and dynamic) associated with a specific VLAN.
     * @param vlan_id The VLAN ID to flush.
     */
    void flush_vlan(uint16_t vlan_id);

    /**
     * @brief Gets the total number of entries in the FDB.
     * @return The number of FDB entries.
     */
    size_t entry_count() const; // Already const, good.

    /**
     * @brief Adds a static FDB entry. Static entries are not aged out.
     * If an entry for the given MAC/VLAN already exists, it will be overwritten.
     * @param mac The MAC address.
     * @param port The port number.
     * @param vlan_id The VLAN ID.
     */
    void add_static_entry(const core::MacAddress& mac, uint32_t port, uint16_t vlan_id);

private:
    std::unordered_map<FdbKey, FdbEntry, FdbKeyHash> fdb_table_;
    // Mutex might be needed for concurrent access, but not for this phase.
    // std::mutex fdb_mutex_;
};

} // namespace switching
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_SWITCHING_FDB_HPP
