#ifndef NETFLOW_SWITCH_FORWARDINGDATABASE_H
#define NETFLOW_SWITCH_FORWARDINGDATABASE_H

#include <cstdint>
#include <array>
#include <unordered_map>
#include <mutex> // For thread safety
#include <chrono>  // For aging

// Define MACAddress type for clarity
using MACAddress = std::array<uint8_t, 6>;

// Hash functor for MACAddress to be used in unordered_map
namespace std {
    template<> struct hash<MACAddress> {
        size_t operator()(const MACAddress& mac) const noexcept {
            // A simple hash function for MAC addresses
            size_t h1 = std::hash<uint32_t>{}(*reinterpret_cast<const uint32_t*>(mac.data()));
            size_t h2 = std::hash<uint16_t>{}(*reinterpret_cast<const uint16_t*>(mac.data() + 4));
            return h1 ^ (h2 << 1);
        }
    };
} // namespace std

struct FdbEntry {
    uint16_t port_id;       // Output port for this MAC address
    uint16_t vlan_id;       // VLAN ID associated with this entry
    std::chrono::steady_clock::time_point last_seen; // For aging
    bool is_static;         // Static entries are not aged out

    FdbEntry(uint16_t port = 0, uint16_t vlan = 0, bool stat = false)
        : port_id(port), vlan_id(vlan), last_seen(std::chrono::steady_clock::now()), is_static(stat) {}
};

class ForwardingDatabase {
public:
    // Key for the FDB table: typically a combination of MAC and VLAN ID
    // For simplicity, we can use MACAddress as key if VLANs are handled by separate FDB instances
    // or use a pair<MACAddress, uint16_t> if one FDB handles multiple VLANs.
    // Let's use pair<MACAddress, uint16_t> for a more general approach.
    using FdbKey = std::pair<MACAddress, uint16_t>; // <MAC, VLAN_ID>

    // Hash functor for FdbKey
    struct FdbKeyHash {
        size_t operator()(const FdbKey& key) const {
            return std::hash<MACAddress>{}(key.first) ^ (std::hash<uint16_t>{}(key.second) << 1);
        }
    };

    // Constructor
    // aging_timeout_sec: time in seconds after which dynamic entries are considered for aging.
    explicit ForwardingDatabase(uint32_t aging_timeout_sec = 300);

    // Learn a MAC address on a specific port and VLAN.
    // If the entry already exists for this MAC/VLAN, its port and last_seen time are updated.
    void learn_mac(const MACAddress& mac, uint16_t vlan_id, uint16_t port_id);

    // Add a static MAC address entry. Static entries are not aged out.
    void add_static_mac(const MACAddress& mac, uint16_t vlan_id, uint16_t port_id);

    // Lookup the output port for a given MAC address and VLAN.
    // Returns 0 or a special value (e.g., FDB_PORT_NOT_FOUND) if not found.
    // Updates last_seen for dynamic entries.
    uint16_t lookup_port(const MACAddress& mac, uint16_t vlan_id);
    static const uint16_t FDB_PORT_NOT_FOUND = 0xFFFF; // Using a distinct value for not found

    // Age out old dynamic entries.
    // This method should be called periodically.
    void age_entries();

    // Flush all entries associated with a specific port.
    void flush_port(uint16_t port_id);

    // Flush all entries associated with a specific VLAN.
    void flush_vlan(uint16_t vlan_id);

    // Flush all dynamic entries in the FDB.
    void flush_all_dynamic();
    
    // Flush all entries (dynamic and static) in the FDB.
    void flush_all();

    // Get the number of entries in the FDB.
    size_t entry_count() const;

    // Get the current capacity (max number of entries it can hold, relevant if pre-allocated).
    // For std::unordered_map, this is less about a fixed capacity and more about bucket_count.
    size_t capacity() const;

    // Get the current load factor of the hash table.
    float load_factor() const;

    // Set the aging timeout for dynamic entries.
    void set_aging_timeout(uint32_t aging_timeout_sec);
    uint32_t get_aging_timeout_sec() const;


private:
    std::unordered_map<FdbKey, FdbEntry, FdbKeyHash> fdb_table_;
    mutable std::mutex fdb_mutex_; // To protect access to fdb_table_
    std::chrono::seconds aging_timeout_;
};

#endif // NETFLOW_SWITCH_FORWARDINGDATABASE_H
