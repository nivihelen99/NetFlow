#ifndef NETFLOW_ACL_MANAGER_HPP
#define NETFLOW_ACL_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <optional>   // For std::optional
#include <algorithm>  // For std::sort, std::remove_if
#include "packet.hpp" // For MacAddress, potentially other header structs if needed for matching

// Forward declaration of FlowKey from PacketClassifier could be useful if we want to match against it directly.
// However, AclRule defines its own optional fields for flexibility.
// namespace netflow { class PacketClassifier; } // If we were to use PacketClassifier::FlowKey

namespace netflow {

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
    AclManager() = default;

    // Adds a rule to the ACL table.
    // Rules are kept sorted by priority.
    // Returns true if rule was added. False if rule_id already exists (for now, we just add).
    bool add_rule(const AclRule& rule) {
        // Optional: Check for duplicate rule_id and reject or replace
        // For now, we allow multiple rules with same ID, but remove_rule will remove first found or all.
        // A std::map<uint32_t, AclRule> might be better if rule_id must be unique key.
        // But vector allows multiple rules to share aspects if needed, and sorting handles priority.

        // Let's ensure rule_id is unique for simplicity of remove_rule by ID later
        auto it_existing = std::find_if(acl_rules_.begin(), acl_rules_.end(),
                                    [&rule](const AclRule& r){ return r.rule_id == rule.rule_id; });
        if (it_existing != acl_rules_.end()) {
            // Rule with this ID already exists. Replace it or return false.
            // For now, let's replace it.
            *it_existing = rule;
        } else {
            acl_rules_.push_back(rule);
        }

        // Sort rules by priority after adding/modifying. Higher priority value = evaluated first.
        std::sort(acl_rules_.begin(), acl_rules_.end());
        return true;
    }

    // Removes a rule by its unique ID.
    // Returns true if a rule was found and removed, false otherwise.
    bool remove_rule(uint32_t rule_id_to_remove) {
        auto it = std::remove_if(acl_rules_.begin(), acl_rules_.end(),
                                 [rule_id_to_remove](const AclRule& r){ return r.rule_id == rule_id_to_remove; });
        if (it != acl_rules_.end()) {
            acl_rules_.erase(it, acl_rules_.end());
            // No need to re-sort after removal if original order of other elements is preserved by remove_if/erase.
            return true;
        }
        return false;
    }

    // Retrieves all current ACL rules (e.g., for inspection or saving).
    const std::vector<AclRule>& get_rules() const {
        return acl_rules_;
    }

    // Clears all ACL rules.
    void clear_rules() {
        acl_rules_.clear();
    }

    AclActionType evaluate(const Packet& pkt, uint32_t& out_redirect_port_id) const {
        for (const auto& rule : acl_rules_) {
            if (check_match(pkt, rule)) {
                if (rule.action == AclActionType::REDIRECT) {
                    if (rule.redirect_port_id.has_value()) {
                        out_redirect_port_id = rule.redirect_port_id.value();
                    } else {
                        // Misconfigured rule: REDIRECT action without a redirect_port_id.
                        // Default to DENY or log an error. For now, treat as DENY.
                        // Or, if REDIRECT implies something else (e.g. to CPU if no port), handle that.
                        // For safety, let's assume DENY if redirect target is missing.
                        return AclActionType::DENY;
                    }
                }
                return rule.action;
            }
        }
        // Default action if no rules match.
        // Policy decision: default permit or default deny. Let's choose PERMIT.
        return AclActionType::PERMIT;
    }

    // Placeholder for matching logic (Part 2)
    // std::optional<AclAction> match_packet(const Packet& pkt) const;

    // Placeholder for rule compilation
    void compile_rules() {
        // In a production system, this method would be called after significant rule changes
        // to convert the acl_rules_ vector into an optimized format for faster lookups.
        // This could involve creating a decision tree, a TCAM-like structure,
        // or other hardware/software optimized lookup mechanisms.
        // For now, this is a placeholder.
        // std::cout << "AclManager::compile_rules() - Placeholder for rule optimization." << std::endl;
    }

private:
    std::vector<AclRule> acl_rules_; // Rules are stored sorted by priority

    // Placeholder for compiled/optimized rule representation if needed for performance
    // e.g., decision tree, TCAM-like structure.
    // void* compiled_rules_representation_ = nullptr;

private: // Helper methods
    bool check_match(const Packet& pkt, const AclRule& rule) const {
        // Packet accessor methods are const after previous updates.

        // L2 Matching
        if (rule.src_mac) {
            auto pkt_src_mac = pkt.src_mac();
            if (!pkt_src_mac || !(pkt_src_mac.value() == rule.src_mac.value())) return false;
        }
        if (rule.dst_mac) {
            auto pkt_dst_mac = pkt.dst_mac();
            if (!pkt_dst_mac || !(pkt_dst_mac.value() == rule.dst_mac.value())) return false;
        }
        if (rule.vlan_id) {
            auto pkt_vlan_id = pkt.vlan_id(); // This gets outermost VLAN ID
            if (!pkt_vlan_id || pkt_vlan_id.value() != rule.vlan_id.value()) return false;
        }

        // Determine effective EtherType (after VLAN tags if any) for L3 matching
        uint16_t effective_ethertype = 0;
        EthernetHeader* eth_hdr = pkt.ethernet(); // Returns EthernetHeader*
        if (!eth_hdr) {
            // If there's no Ethernet header, we can't match L2 specific fields above either.
            // This check might be redundant if src_mac/dst_mac checks imply eth_hdr exists.
            // However, if a rule *only* specifies ethertype, src_ip etc., this is important.
            if (rule.ethertype || rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port) {
                 return false; // Rule requires L2 type or L3/L4 info, but no Ethernet header.
            }
        } else { // Ethernet header exists
            if (pkt.has_vlan()) {
                VlanHeader* vlan_hdr = pkt.vlan();
                if (vlan_hdr) {
                    effective_ethertype = ntohs(vlan_hdr->ethertype);
                } else { // Should not happen if has_vlan() is true, but defensive
                    if (rule.ethertype || rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port)
                        return false;
                }
            } else {
                effective_ethertype = ntohs(eth_hdr->ethertype);
            }

            if (rule.ethertype && effective_ethertype != rule.ethertype.value()) {
                return false;
            }
        }


        // L3 Matching (IPv4)
        IPv4Header* ipv4_hdr = nullptr;
        bool needs_ip_header = rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port;

        if (needs_ip_header) {
            if (effective_ethertype == 0x0800) { // IPv4
                ipv4_hdr = pkt.ipv4();
                if (!ipv4_hdr) return false; // Rule needs IP, but packet has no IPv4 header
            } else {
                return false; // Rule needs IP, but packet is not IPv4
            }
        }

        if (ipv4_hdr) { // If we have an IPv4 header (either because rule needed it, or it was just present)
            if (rule.src_ip && ntohl(ipv4_hdr->src_ip) != rule.src_ip.value()) return false;
            if (rule.dst_ip && ntohl(ipv4_hdr->dst_ip) != rule.dst_ip.value()) return false;

            // Check protocol only if rule specifies it OR if L4 ports are specified
            if (rule.protocol) {
                 if (ipv4_hdr->protocol != rule.protocol.value()) return false;
            }

            // L4 Matching
            if (rule.src_port || rule.dst_port) {
                // To match L4 ports, the packet's protocol must match the rule's specified protocol (if any)
                // or the rule must specify a protocol for which L4 ports make sense.
                uint8_t packet_protocol = ipv4_hdr->protocol;
                if (rule.protocol.has_value() && rule.protocol.value() != packet_protocol) {
                    return false; // Packet protocol mismatch with rule's protocol, so port match is irrelevant.
                }

                if (packet_protocol == 6) { // TCP
                    TcpHeader* tcp_hdr = pkt.tcp();
                    if (!tcp_hdr) return false;
                    if (rule.src_port && ntohs(tcp_hdr->src_port) != rule.src_port.value()) return false;
                    if (rule.dst_port && ntohs(tcp_hdr->dst_port) != rule.dst_port.value()) return false;
                } else if (packet_protocol == 17) { // UDP
                    UdpHeader* udp_hdr = pkt.udp();
                    if (!udp_hdr) return false;
                    if (rule.src_port && ntohs(udp_hdr->src_port) != rule.src_port.value()) return false;
                    if (rule.dst_port && ntohs(udp_hdr->dst_port) != rule.dst_port.value()) return false;
                } else {
                    // Rule specifies L4 ports, but packet's protocol is not TCP or UDP
                    return false;
                }
            }
        } else if (needs_ip_header) {
            // This case should have been caught by "if (!ipv4_hdr) return false;" earlier if needs_ip_header was true.
            // Redundant check, but for clarity: if rule needed IP and we don't have ipv4_hdr, it's a mismatch.
            return false;
        }

        return true; // All specified fields in the rule matched
    }
};

} // namespace netflow

#endif // NETFLOW_ACL_MANAGER_HPP
