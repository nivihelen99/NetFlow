#ifndef NETFLOW_ACL_MANAGER_HPP
#define NETFLOW_ACL_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <optional>   // For std::optional
#include <algorithm>  // For std::sort, std::remove_if
#include "packet.hpp" // For MacAddress, potentially other header structs if needed for matching

#include "netflow++/logger.hpp" // For SwitchLogger

// Forward declaration of FlowKey from PacketClassifier could be useful if we want to match against it directly.
// However, AclRule defines its own optional fields for flexibility.
// namespace netflow { class PacketClassifier; } // If we were to use PacketClassifier::FlowKey

namespace netflow {

// Forward declaration for logger
// class SwitchLogger;

enum class AclActionType {
    PERMIT,
    DENY,
    REDIRECT // Could also have LOG, MIRROR, etc.
};

struct AclRule {
    uint32_t rule_id = 0; // Unique identifier for the rule
    int priority = 0;     // Higher value means higher priority (evaluated first)

    // Match fields - using std::optional for flexibility.
    // If a field is std::nullopt, it's a wildcard (matches anything).
    // If it has a value, the packet's corresponding field must match.
    std::optional<MacAddress> src_mac;
    std::optional<MacAddress> dst_mac;
    std::optional<uint16_t> vlan_id;   // Host byte order
    std::optional<uint16_t> ethertype; // Host byte order (e.g., 0x0800 for IPv4)

    // For IP addresses, sticking to IPv4 (uint32_t in host byte order) for now.
    // A more generic solution might use a custom IpAddress struct/variant.
    std::optional<uint32_t> src_ip;    // Host byte order
    std::optional<uint32_t> dst_ip;    // Host byte order
    std::optional<uint8_t> protocol;   // IP protocol (e.g., 6 for TCP, 17 for UDP)
    std::optional<uint16_t> src_port;  // L4 source port (host byte order)
    std::optional<uint16_t> dst_port;  // L4 destination port (host byte order)

    // TODO: Add masks for IP addresses (e.g., std::optional<uint32_t> src_ip_mask)
    // For now, IP matching is exact if value is present.

    AclActionType action = AclActionType::DENY; // Default to DENY for safety
    std::optional<uint32_t> redirect_port_id; // Used if action is REDIRECT_PORT or similar

    // Default constructor
    AclRule() = default;

    // Custom constructor for convenience (example)
    AclRule(uint32_t id, int prio, AclActionType act)
        : rule_id(id), priority(prio), action(act) {}

    // Operator for sorting by priority. Higher priority value means it comes first.
    bool operator<(const AclRule& other) const {
        if (priority != other.priority) {
            return priority > other.priority; // Higher priority value first
        }
        // If priorities are equal, could sort by rule_id for stable ordering (optional)
        return rule_id < other.rule_id;
    }
};

class AclManager {
public:
    AclManager(SwitchLogger& logger); // Constructor that takes a logger
    ~AclManager();

    bool add_rule(const AclRule& rule);
    bool remove_rule(uint32_t rule_id_to_remove);
    std::optional<AclRule> get_rule(uint32_t rule_id) const; // New method
    const std::vector<AclRule>& get_all_rules() const; // Renamed from get_rules
    void clear_rules();
    AclActionType evaluate(const Packet& pkt, uint32_t& out_redirect_port_id) const; // Renamed from evaluate_packet
    void compile_rules();

private:
    SwitchLogger& logger_;
    std::vector<AclRule> acl_rules_;
    bool needs_compilation_ = true; // Flag to indicate if rules need recompilation (sorting)

    // Helper method for matching a packet against a rule.
    bool check_match(const Packet& pkt, const AclRule& rule) const;
};

} // namespace netflow

#endif // NETFLOW_ACL_MANAGER_HPP
