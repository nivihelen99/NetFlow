#ifndef NETFLOW_PACKET_CLASSIFIER_HPP
#define NETFLOW_PACKET_CLASSIFIER_HPP

#include "packet.hpp" // For Packet, MacAddress, header structs
#include <vector>
#include <algorithm> // For std::sort, std::equal
#include <cstdint>
#include <functional> // For std::hash for combining hashes (optional advanced hashing)
#include <array>      // For std::array (used for IPv6 addresses)

namespace netflow {

struct PacketClassifier {
public:
    struct FlowKey {
        MacAddress src_mac;
        MacAddress dst_mac;
        uint16_t vlan_id = 0;
        uint16_t ethertype = 0; // e.g., 0x0800 for IPv4, 0x86DD for IPv6

        bool is_ipv6 = false;
        // IPv4 fields
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        // IPv6 fields
        std::array<uint8_t, 16> src_ipv6{}; // Zero-initialized
        std::array<uint8_t, 16> dst_ipv6{}; // Zero-initialized

        uint8_t protocol = 0;   // e.g., 6 for TCP, 17 for UDP
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        FlowKey() = default; // Default constructor initializes above values

        // Comparison operator
        bool operator==(const FlowKey& other) const {
            if (is_ipv6 != other.is_ipv6) {
                return false;
            }
            bool ip_match = false;
            if (is_ipv6) {
                ip_match = (src_ipv6 == other.src_ipv6 && dst_ipv6 == other.dst_ipv6);
            } else {
                ip_match = (src_ip == other.src_ip && dst_ip == other.dst_ip);
            }

            return src_mac == other.src_mac &&
                   dst_mac == other.dst_mac &&
                   vlan_id == other.vlan_id &&
                   ethertype == other.ethertype &&
                   ip_match && // Covers both IPv4 and IPv6 based on is_ipv6 flag
                   protocol == other.protocol &&
                   src_port == other.src_port &&
                   dst_port == other.dst_port;
        }
    };

    struct ClassificationRule {
        FlowKey key_template; // The pattern to match
        FlowKey mask;         // Which fields in key_template to consider (1=match, 0=ignore)
        uint32_t action_id;   // Identifier for the action to take
        int priority;         // Higher value means higher priority

        // Default constructor
        ClassificationRule(const FlowKey& kt, const FlowKey& m, uint32_t aid, int prio)
            : key_template(kt), mask(m), action_id(aid), priority(prio) {}
    };

    // Extracts a FlowKey from a given packet.
    FlowKey extract_flow_key(const Packet& pkt) const;

    // Simple XOR sum hash for the FlowKey. Made static.
    static uint32_t hash_flow(const FlowKey& key);

    // Adds a rule to the classifier. Rules are sorted by priority after adding.
    void add_rule(const ClassificationRule& rule);

    // Classifies a packet based on the installed rules.
    // Returns action_id of the first matching rule, or 0 (default action) if no match.
    uint32_t classify(const Packet& pkt) const;

    const std::vector<ClassificationRule>& get_rules() const;

private:
    std::vector<ClassificationRule> rules_;

    // Helper function to match an extracted key against a rule template using a mask.
    bool match_key(const FlowKey& extracted, const FlowKey& templ, const FlowKey& mask) const;

    // Note: MASK_MATCH_ALL_MAC was removed as it was problematic and the logic in match_key
    // for MACs uses a zero_mac comparison for wildcarding, and integer fields use bitwise masks.
    // The specific interpretation of mask fields (e.g. all zeros for wildcard vs. specific bit patterns)
    // is crucial and should be consistently applied by users creating ClassificationRule objects.
};

// Helper to create a "match all" mask for integer types
template<typename T>
T make_match_all_mask() {
    if constexpr (std::is_integral_v<T>) {
        return static_cast<T>(~T(0)); // All bits set to 1
    }
    // For MacAddress, this would be trickier.
    // For now, users of ClassificationRule must set mask fields appropriately.
    return T{}; // Default constructor for others (e.g. MacAddress all zeros = wildcard)
}

} // namespace netflow

// Specialization of std::hash for netflow::PacketClassifier::FlowKey
namespace std {
template <>
struct hash<netflow::PacketClassifier::FlowKey> {
    std::size_t operator()(const netflow::PacketClassifier::FlowKey& key) const noexcept {
        // Use the static hash_flow method from PacketClassifier
        // Note: std::hash should return std::size_t. Our hash_flow returns uint32_t.
        // This is usually fine, but for full compliance, one might want to ensure wider distribution
        // if std::size_t is larger and many FlowKeys are used. For now, direct use is okay.
        return static_cast<std::size_t>(netflow::PacketClassifier::hash_flow(key));
    }
};
} // namespace std

#endif // NETFLOW_PACKET_CLASSIFIER_HPP
