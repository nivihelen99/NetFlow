#include "netflow_plus_plus/switching/fdb.hpp"
#include <iostream> // For placeholder messages

namespace netflow_plus_plus {
namespace switching {

ForwardingDatabase::ForwardingDatabase() {
    // Constructor can be empty for now, or initialize any internal state if needed.
}

bool ForwardingDatabase::learn_mac(const core::MacAddress& mac, uint32_t port, uint16_t vlan_id) {
    FdbKey key{mac, vlan_id};
    auto it = fdb_table_.find(key);

    if (it != fdb_table_.end()) {
        // Entry exists
        if (it->second.is_static) {
            return false; // Static entry, do not update timestamp or port
        }
        // Update existing dynamic entry's port and timestamp
        it->second.port = port;
        it->second.timestamp = std::chrono::steady_clock::now();
        return false; // Updated existing entry
    } else {
        // New entry
        fdb_table_.emplace(key, FdbEntry(mac, port, vlan_id));
        return true; // New MAC learned
    }
}

std::optional<uint32_t> ForwardingDatabase::lookup_port(const core::MacAddress& mac, uint16_t vlan_id) const {
    FdbKey key{mac, vlan_id};
    auto it = fdb_table_.find(key);

    if (it != fdb_table_.end()) {
        // Optionally, check for aging here if strict aging is required on lookup
        // For now, we assume age_entries() handles expired entries periodically.
        // it->second.timestamp = std::chrono::steady_clock::now(); // Refresh timestamp on lookup (common behavior)
        return it->second.port;
    }
    return std::nullopt;
}

void ForwardingDatabase::age_entries(std::chrono::seconds max_age) {
    // Placeholder implementation
    // std::cout << "FDB: age_entries called. Max age: " << max_age.count() << "s. (Not yet fully implemented)" << std::endl;
    auto now = std::chrono::steady_clock::now();
    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); /* no increment here */) {
        if (!it->second.is_static && (now - it->second.timestamp > max_age)) {
            it = fdb_table_.erase(it); // Erase and get next iterator
        } else {
            ++it;
        }
    }
}

void ForwardingDatabase::flush_port(uint32_t port) {
    // Placeholder implementation
    // std::cout << "FDB: flush_port called for port " << port << ". (Not yet fully implemented)" << std::endl;
    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); /* no increment here */) {
        if (it->second.port == port) {
            it = fdb_table_.erase(it);
        } else {
            ++it;
        }
    }
}

void ForwardingDatabase::flush_vlan(uint16_t vlan_id) {
    // Placeholder implementation
    // std::cout << "FDB: flush_vlan called for VLAN " << vlan_id << ". (Not yet fully implemented)" << std::endl;
     for (auto it = fdb_table_.begin(); it != fdb_table_.end(); /* no increment here */) {
        if (it->second.vlan_id == vlan_id) {
            it = fdb_table_.erase(it);
        } else {
            ++it;
        }
    }
}

size_t ForwardingDatabase::entry_count() const {
    return fdb_table_.size();
}

void ForwardingDatabase::add_static_entry(const core::MacAddress& mac, uint32_t port, uint16_t vlan_id) {
    FdbKey key{mac, vlan_id};
    // Use insert_or_assign to avoid requiring a default constructor for FdbEntry
    fdb_table_.insert_or_assign(key, FdbEntry(mac, port, vlan_id, true));
}

} // namespace switching
} // namespace netflow_plus_plus
