#include "netflow++/forwarding_database.hpp"
#include <algorithm> // For std::find_if, std::remove_if
#include <chrono>    // For std::chrono::steady_clock, std::chrono::seconds
#include <vector>    // For std::vector
#include <optional>  // For std::optional, std::nullopt
#include <string>    // For std::to_string (used in logger call)

// SwitchLogger is forward-declared or included via forwarding_database.hpp
// MacAddress is included via forwarding_database.hpp -> packet.hpp

namespace netflow {

ForwardingDatabase::ForwardingDatabase(size_t initial_capacity) {
    if (initial_capacity > 0) {
        entries_.reserve(initial_capacity);
    }
}

bool ForwardingDatabase::learn_mac(const MacAddress& mac, uint32_t port, uint16_t vlan_id) {
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
            // Assuming logger_->mac_to_string() is accessible
            logger_->debug("FDB", "MAC " + logger_->mac_to_string(mac) + " moved from port " + std::to_string(old_port) + " to " + std::to_string(port) + " on VLAN " + std::to_string(vlan_id));
        }
    }
    return new_learn;
}

void ForwardingDatabase::set_logger(SwitchLogger* logger) {
    logger_ = logger;
}

void ForwardingDatabase::add_static_entry(const MacAddress& mac, uint32_t port, uint16_t vlan_id) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               return entry.mac == mac && entry.vlan_id == vlan_id;
                           });
    if (it != entries_.end()) {
        // Entry exists, update it and mark as static
        it->port = port;
        it->vlan_id = vlan_id; // Should be same, but update for completeness
        it->is_static = true;
        it->timestamp = std::chrono::steady_clock::now(); // Update timestamp for consistency, though not used for static
    } else {
        entries_.emplace_back(mac, port, vlan_id, true);
    }
}

bool ForwardingDatabase::remove_entry(const netflow::MacAddress& mac, uint16_t vlan_id) {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               return entry.mac == mac && entry.vlan_id == vlan_id;
                           });
    if (it != entries_.end()) {
        entries_.erase(it);
        return true;
    }
    return false;
}


std::optional<uint32_t> ForwardingDatabase::lookup_port(const MacAddress& mac, uint16_t vlan_id) const {
    auto it = std::find_if(entries_.begin(), entries_.end(),
                           [&](const FdbEntry& entry) {
                               return entry.mac == mac && entry.vlan_id == vlan_id;
                           });

    if (it != entries_.end()) {
        // Refresh on hit is not implemented here as per original header, can be added if needed.
        return it->port;
    }
    return std::nullopt;
}

void ForwardingDatabase::age_entries(std::chrono::seconds max_age) {
    auto now = std::chrono::steady_clock::now();
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const FdbEntry& entry) {
                           if (entry.is_static) {
                               return false;
                           }
                           return (now - entry.timestamp) > max_age;
                       }),
        entries_.end());
}

void ForwardingDatabase::flush_port(uint32_t port) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const FdbEntry& entry) {
                           return entry.port == port;
                       }),
        entries_.end());
}

void ForwardingDatabase::flush_vlan(uint16_t vlan_id) {
    entries_.erase(
        std::remove_if(entries_.begin(), entries_.end(),
                       [&](const FdbEntry& entry) {
                           return entry.vlan_id == vlan_id;
                       }),
        entries_.end());
}

void ForwardingDatabase::flush_all() {
    entries_.clear();
}

size_t ForwardingDatabase::entry_count() const {
    return entries_.size();
}

size_t ForwardingDatabase::capacity() const {
    return entries_.capacity();
}

double ForwardingDatabase::load_factor() const {
    if (capacity() == 0) {
        return 0.0;
    }
    return static_cast<double>(entry_count()) / capacity();
}

const std::vector<FdbEntry>& ForwardingDatabase::get_all_entries() const {
    return entries_;
}

} // namespace netflow
