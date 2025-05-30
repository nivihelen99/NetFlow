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
    ForwardingDatabase(size_t initial_capacity = 0) {
        if (initial_capacity > 0) {
            entries_.reserve(initial_capacity);
        }
        // For std::map, no need to reserve typically
    }

    // Adds or updates a dynamic MAC entry. If the MAC+VLAN already exists, its port and timestamp are updated.
    // Returns true if a new entry was created, false otherwise.
    bool learn_mac(const MacAddress& mac, uint32_t port, uint16_t vlan_id) {
        auto it = std::find_if(entries_.begin(), entries_.end(),
                               [&](const FdbEntry& entry) {
                                   return entry.mac == mac && entry.vlan_id == vlan_id;
                               });

        bool new_learn = false;
        bool port_changed = false;
        uint32_t old_port = 0;

        if (it != entries_.end()) {
            // Entry exists, update port and timestamp (if not static)
            if (!it->is_static) {
                if (it->port != port) {
                    port_changed = true;
                    old_port = it->port;
                }
                it->port = port;
                it->timestamp = std::chrono::steady_clock::now();
            }
        } else {
            // New entry
            entries_.emplace_back(mac, port, vlan_id);
            new_learn = true;
        }

        if (logger_) {
            if (new_learn) {
                logger_->log_mac_learning(mac, port, vlan_id);
            } else if (port_changed && !it->is_static) {
                // Need mac_to_string helper or similar. SwitchLogger has it private.
                // For now, construct a simpler message or enhance logger.
                // Let's assume a simpler log message for now, or that log_mac_learning can be adapted.
                // For this exercise, I'll use a debug log for moves.
                // To use logger_->mac_to_string, it needs to be public or FDB needs a way to format MACs.
                // Temporarily, let's make mac_to_string public in SwitchLogger for this.
                // (This is a design choice to be revisited - ideally, pass formatted strings or structured data to logger)
                // Assuming logger_->mac_to_string() is accessible (e.g., made public in SwitchLogger)
                logger_->debug("FDB", "MAC " + logger_->mac_to_string(mac) + " moved from port " + std::to_string(old_port) + " to " + std::to_string(port) + " on VLAN " + std::to_string(vlan_id));
            }
        }
        return new_learn;
    }

    void set_logger(SwitchLogger* logger) {
        logger_ = logger;
    }

    // Adds or updates a static MAC entry. Static entries are not aged out.
    void add_static_entry(const MacAddress& mac, uint32_t port, uint16_t vlan_id) {
        auto it = std::find_if(entries_.begin(), entries_.end(),
                               [&](const FdbEntry& entry) {
                                   return entry.mac == mac && entry.vlan_id == vlan_id;
                               });
        if (it != entries_.end()) {
            // Entry exists, update it and mark as static
            it->port = port;
            it->vlan_id = vlan_id; // ensure vlan is also updated if it changed for this static mac
            it->is_static = true;
            it->timestamp = std::chrono::steady_clock::now(); // Update timestamp for consistency
        } else {
            entries_.emplace_back(mac, port, vlan_id, true);
        }
    }


    // Looks up the port for a given MAC address and VLAN ID.
    std::optional<uint32_t> lookup_port(const MacAddress& mac, uint16_t vlan_id) const { // Added const
        auto it = std::find_if(entries_.begin(), entries_.end(),
                               [&](const FdbEntry& entry) {
                                   return entry.mac == mac && entry.vlan_id == vlan_id;
                               });

        if (it != entries_.end()) {
            // Optionally update timestamp on lookup (common in some FDBs, "refresh on hit")
            // if (!it->is_static) {
            //    it->timestamp = std::chrono::steady_clock::now();
            // }
            return it->port;
        }
        return std::nullopt;
    }

    // Removes entries older than max_age, unless they are static.
    void age_entries(std::chrono::seconds max_age = std::chrono::seconds(300)) {
        auto now = std::chrono::steady_clock::now();
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               if (entry.is_static) {
                                   return false; // Don't age out static entries
                               }
                               return (now - entry.timestamp) > max_age;
                           }),
            entries_.end());
    }

    // Removes all entries (static and dynamic) associated with a specific port.
    void flush_port(uint32_t port) {
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               return entry.port == port;
                           }),
            entries_.end());
    }

    // Removes all entries (static and dynamic) associated with a specific VLAN ID.
    void flush_vlan(uint16_t vlan_id) {
        entries_.erase(
            std::remove_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               return entry.vlan_id == vlan_id;
                           }),
            entries_.end());
    }

    // Removes all entries (static and dynamic).
    void flush_all() {
        entries_.clear();
    }

    // Statistics
    size_t entry_count() const {
        return entries_.size();
    }

    size_t capacity() const {
        return entries_.capacity(); // Specific to std::vector
        // For std::map, capacity is not as straightforward. Could return max_size() or a configured limit.
    }

    // Load factor: (number of entries / capacity). Only meaningful for std::vector.
    // For std::map, this concept is different (related to hash table load factor if unordered_map).
    // For std::vector, it tells how "full" the currently allocated memory is.
    double load_factor() const {
        if (capacity() == 0) {
            return 0.0; // Avoid division by zero
        }
        return static_cast<double>(entry_count()) / capacity();
    }

    // Get all entries (e.g. for display or debugging)
    const std::vector<FdbEntry>& get_all_entries() const {
        return entries_;
    }

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
