#include "netflow/switch/ForwardingDatabase.h"
#include <iostream> // For potential debug/info messages

ForwardingDatabase::ForwardingDatabase(uint32_t aging_timeout_sec)
    : aging_timeout_(aging_timeout_sec) {
    // std::cout << "ForwardingDatabase initialized with aging timeout: " << aging_timeout_sec << "s" << std::endl;
}

void ForwardingDatabase::learn_mac(const MACAddress& mac, uint16_t vlan_id, uint16_t port_id) {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    FdbKey key = {mac, vlan_id};
    auto it = fdb_table_.find(key);

    if (it != fdb_table_.end()) {
        // Entry exists, update port and last_seen time
        it->second.port_id = port_id;
        it->second.last_seen = std::chrono::steady_clock::now();
        // If it was previously static and now learned dynamically, should it become dynamic?
        // Current logic: if learned, it's treated as dynamic for aging purposes unless explicitly static.
        // If an entry is learned, assume it's dynamic. A static entry should remain static.
        // So, if it->second.is_static is true, we might not want to update it here,
        // or only update last_seen if it's already matching the port.
        // For now, learn_mac makes it behave like a dynamic entry or updates existing dynamic.
        it->second.is_static = false; 
    } else {
        // New entry
        fdb_table_[key] = FdbEntry(port_id, vlan_id, false);
    }
    // std::cout << "FDB Learned: MAC=" << ... << " VLAN=" << vlan_id << " Port=" << port_id << std::endl;
}

void ForwardingDatabase::add_static_mac(const MACAddress& mac, uint16_t vlan_id, uint16_t port_id) {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    FdbKey key = {mac, vlan_id};
    fdb_table_[key] = FdbEntry(port_id, vlan_id, true); // Mark as static
    // std::cout << "FDB Static Added: MAC=" << ... << " VLAN=" << vlan_id << " Port=" << port_id << std::endl;
}

uint16_t ForwardingDatabase::lookup_port(const MACAddress& mac, uint16_t vlan_id) {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    FdbKey key = {mac, vlan_id};
    auto it = fdb_table_.find(key);

    if (it != fdb_table_.end()) {
        if (!it->second.is_static) {
            it->second.last_seen = std::chrono::steady_clock::now(); // Update for dynamic entries
        }
        return it->second.port_id;
    }
    return FDB_PORT_NOT_FOUND; // Not found
}

void ForwardingDatabase::age_entries() {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    auto now = std::chrono::steady_clock::now();
    // std::cout << "FDB Aging: Current time is " << now.time_since_epoch().count() << std::endl;
    // std::cout << "FDB Aging: Timeout is " << aging_timeout_.count() << "s" << std::endl;

    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); /* no increment here */) {
        if (!it->second.is_static) {
            auto elapsed_time = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen);
            // std::cout << "FDB Aging check: MAC=" << ... << " VLAN=" << it->first.second
            //           << " LastSeen=" << it->second.last_seen.time_since_epoch().count()
            //           << " Elapsed=" << elapsed_time.count() << "s" << std::endl;
            if (elapsed_time >= aging_timeout_) {
                // std::cout << "FDB Aged out: MAC=" << ... << " VLAN=" << it->first.second << std::endl;
                it = fdb_table_.erase(it); // Erase and get next valid iterator
            } else {
                ++it;
            }
        } else {
            ++it;
        }
    }
}

void ForwardingDatabase::flush_port(uint16_t port_id) {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); ) {
        if (it->second.port_id == port_id && !it->second.is_static) { // Only flush dynamic by port
            it = fdb_table_.erase(it);
        } else {
            ++it;
        }
    }
    // std::cout << "FDB Flushed port: " << port_id << std::endl;
}

void ForwardingDatabase::flush_vlan(uint16_t vlan_id) {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); ) {
        if (it->first.second == vlan_id && !it->second.is_static) { // Only flush dynamic by VLAN
            it = fdb_table_.erase(it);
        } else {
            ++it;
        }
    }
    // std::cout << "FDB Flushed VLAN: " << vlan_id << std::endl;
}

void ForwardingDatabase::flush_all_dynamic() {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    for (auto it = fdb_table_.begin(); it != fdb_table_.end(); ) {
        if (!it->second.is_static) {
            it = fdb_table_.erase(it);
        } else {
            ++it;
        }
    }
    // std::cout << "FDB Flushed all dynamic entries." << std::endl;
}

void ForwardingDatabase::flush_all() {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    fdb_table_.clear();
    // std::cout << "FDB Flushed all entries (dynamic and static)." << std::endl;
}


size_t ForwardingDatabase::entry_count() const {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    return fdb_table_.size();
}

size_t ForwardingDatabase::capacity() const {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    return fdb_table_.bucket_count(); // For unordered_map, bucket_count is a measure of capacity
}

float ForwardingDatabase::load_factor() const {
    std::lock_guard<std::mutex> lock(fdb_mutex_);
    return fdb_table_.load_factor();
}

void ForwardingDatabase::set_aging_timeout(uint32_t aging_timeout_sec) {
    std::lock_guard<std::mutex> lock(fdb_mutex_); // Lock if accessed concurrently, though often set at init
    aging_timeout_ = std::chrono::seconds(aging_timeout_sec);
    // std::cout << "FDB Aging timeout set to: " << aging_timeout_sec << "s" << std::endl;
}

uint32_t ForwardingDatabase::get_aging_timeout_sec() const {
    // No lock needed if std::chrono::seconds is atomic or reading it is safe.
    // For consistency, if set can be concurrent, get should be too.
    // However, aging_timeout_ is usually configured once.
    // std::lock_guard<std::mutex> lock(fdb_mutex_); // Uncomment if strict consistency is needed
    return static_cast<uint32_t>(aging_timeout_.count());
}
