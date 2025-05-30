#ifndef NETFLOW_PACKET_CLASSIFIER_HPP
#define NETFLOW_PACKET_CLASSIFIER_HPP

#include "packet.hpp" // For Packet, MacAddress, header structs
#include <vector>
#include <algorithm> // For std::sort, std::equal
#include <cstdint>
#include <functional> // For std::hash for combining hashes (optional advanced hashing)

namespace netflow {

struct PacketClassifier {
public:
    struct FlowKey {
        MacAddress src_mac;
        MacAddress dst_mac;
        uint16_t vlan_id = 0;
        uint16_t ethertype = 0; // e.g., 0x0800 for IPv4, 0x86DD for IPv6
        // IPv4 specific fields for now. For IPv6, this would need to be extended/unioned.
        uint32_t src_ip = 0;
        uint32_t dst_ip = 0;
        uint8_t protocol = 0;   // e.g., 6 for TCP, 17 for UDP
        uint16_t src_port = 0;
        uint16_t dst_port = 0;

        FlowKey() = default; // Default constructor initializes above values

        // Comparison operator
        bool operator==(const FlowKey& other) const {
            return src_mac == other.src_mac &&
                   dst_mac == other.dst_mac &&
                   vlan_id == other.vlan_id &&
                   ethertype == other.ethertype &&
                   src_ip == other.src_ip &&
                   dst_ip == other.dst_ip &&
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
    // This method itself doesn't need to be static as it operates on a Packet object.
    FlowKey extract_flow_key(const Packet& pkt) const {
        FlowKey key;
        key.vlan_id = 0; // Default to no VLAN or outermost VLAN if multiple

        EthernetHeader* eth = pkt.ethernet(); // Use const version if Packet class provides it
                                              // Assuming Packet::ethernet() etc. can be called on const Packet
                                              // If not, the Packet& pkt argument should not be const.
                                              // For now, let's assume Packet methods are const-correct or we cast if necessary.
                                              // But Packet class methods are not const. This is a design issue.
                                              // To fix this, Packet methods like ethernet() must be const.
                                              // These methods should now be const.

        // Packet& mutable_pkt = const_cast<Packet&>(pkt); // No longer needed

        if (pkt.ethernet()) {
            key.src_mac = pkt.src_mac().value_or(MacAddress());
            key.dst_mac = pkt.dst_mac().value_or(MacAddress());
            key.ethertype = ntohs(pkt.ethernet()->ethertype); // Store in host byte order

            if (pkt.has_vlan()) {
                key.vlan_id = pkt.vlan_id().value_or(0);
                // If there are multiple VLAN tags, this gets the outermost one.
                // The ethertype would be from the innermost VLAN tag if Packet::ethernet handles it,
                // or from the outer if not. Packet::ipv4() currently handles this logic.
                // For FlowKey, we want the ethertype that indicates L3 protocol.
                VlanHeader* vlan = pkt.vlan(); // Assuming this gets primary VLAN
                if (vlan) { // If VLAN is present, the L3 ethertype is after it
                    key.ethertype = ntohs(vlan->ethertype);
                }
            }
        }

        // Check for IPv4 based on determined ethertype
        if (key.ethertype == 0x0800) { // IPv4
            IPv4Header* ipv4_hdr = pkt.ipv4();
            if (ipv4_hdr) {
                key.src_ip = ntohl(ipv4_hdr->src_ip); // Store in host byte order
                key.dst_ip = ntohl(ipv4_hdr->dst_ip); // Store in host byte order
                key.protocol = ipv4_hdr->protocol;

                if (key.protocol == 6) { // TCP
                    TcpHeader* tcp_hdr = pkt.tcp();
                    if (tcp_hdr) {
                        key.src_port = ntohs(tcp_hdr->src_port); // Store in host byte order
                        key.dst_port = ntohs(tcp_hdr->dst_port); // Store in host byte order
                    }
                } else if (key.protocol == 17) { // UDP
                    UdpHeader* udp_hdr = pkt.udp();
                    if (udp_hdr) {
                        key.src_port = ntohs(udp_hdr->src_port); // Store in host byte order
                        key.dst_port = ntohs(udp_hdr->dst_port); // Store in host byte order
                    }
                }
            }
        }
        // TODO: Add IPv6 handling if key.ethertype == 0x86DD
        // This would involve populating IPv6 specific fields in FlowKey (if added)
        // or mapping IPv6 to the existing IPv4 fields in a defined way (less ideal).

        return key;
    }

    // Simple XOR sum hash for the FlowKey. Made static.
    static uint32_t hash_flow(const FlowKey& key) { // No longer const, as it's static
        uint32_t hash_val = 0;

        // Hash MAC addresses (example: XOR bytes)
        for (int i = 0; i < 6; ++i) {
            hash_val ^= static_cast<uint32_t>(key.src_mac.bytes[i]) << (i % 4 * 8);
            hash_val ^= static_cast<uint32_t>(key.dst_mac.bytes[i]) << (i % 4 * 8);
        }

        hash_val ^= static_cast<uint32_t>(key.vlan_id);
        hash_val ^= static_cast<uint32_t>(key.ethertype) << 16;
        hash_val ^= key.src_ip;
        hash_val ^= key.dst_ip; // Could use more sophisticated mixing here
        hash_val ^= static_cast<uint32_t>(key.protocol);
        hash_val ^= static_cast<uint32_t>(key.src_port) << 16;
        hash_val ^= static_cast<uint32_t>(key.dst_port);

        return hash_val;
    }

    // Adds a rule to the classifier. Rules are sorted by priority after adding.
    void add_rule(const ClassificationRule& rule) {
        rules_.push_back(rule);
        // Sort rules by priority (higher priority first)
        std::sort(rules_.begin(), rules_.end(), [](const ClassificationRule& a, const ClassificationRule& b) {
            return a.priority > b.priority;
        });
    }

    // Classifies a packet based on the installed rules.
    // Returns action_id of the first matching rule, or 0 (default action) if no match.
    uint32_t classify(const Packet& pkt) const {
        FlowKey extracted_key = extract_flow_key(pkt);

        for (const auto& rule : rules_) {
            if (match_key(extracted_key, rule.key_template, rule.mask)) {
                return rule.action_id; // Return action_id of the first match
            }
        }
        return 0; // Default action_id if no rule matches
    }

    const std::vector<ClassificationRule>& get_rules() const {
        return rules_;
    }

private:
    std::vector<ClassificationRule> rules_;

    // Helper function to match an extracted key against a rule template using a mask.
    bool match_key(const FlowKey& extracted, const FlowKey& templ, const FlowKey& mask) const {
        // For each field, check if the mask requires matching it.
        // If so, compare the field in extracted_key with key_template.
        // This is a bitwise AND logic: (extracted_field & mask_field) == (template_field & mask_field)
        // Or, more simply, if mask bit is set, then extracted must equal template.

        if (mask.src_mac == MASK_MATCH_ALL_MAC && !(extracted.src_mac == templ.src_mac)) return false;
        if (mask.dst_mac == MASK_MATCH_ALL_MAC && !(extracted.dst_mac == templ.dst_mac)) return false;
        // A more granular MAC mask would compare byte by byte if mask.src_mac.bytes[i] is 0xFF.
        // For simplicity, assume MASK_MATCH_ALL_MAC is a special MacAddress value (e.g. all FF)
        // or that if mask.field is non-zero, then exact match on that field is required.

        // Let's refine mask interpretation: if a field in mask is "active" (e.g., not default/zero),
        // then the corresponding fields in extracted and templ must match.

        // Simplified interpretation: if mask.field is non-zero/non-default, then match.
        // For IP/port, 0 can be a valid value. So mask needs to be explicit.
        // Typically, mask bits are 1 for "match this field", 0 for "don't care".
        // So, (extracted.field ^ templ.field) & mask.field should be 0.

        // Example for src_ip:
        if (((extracted.src_ip ^ templ.src_ip) & mask.src_ip) != 0) return false;
        if (((extracted.dst_ip ^ templ.dst_ip) & mask.dst_ip) != 0) return false;

        if (((extracted.vlan_id ^ templ.vlan_id) & mask.vlan_id) != 0) return false;
        if (((extracted.ethertype ^ templ.ethertype) & mask.ethertype) != 0) return false;

        if (((extracted.protocol ^ templ.protocol) & mask.protocol) != 0) return false;
        if (((extracted.src_port ^ templ.src_port) & mask.src_port) != 0) return false;
        if (((extracted.dst_port ^ templ.dst_port) & mask.dst_port) != 0) return false;

        // MAC address matching with mask is more complex if byte-level wildcards are needed.
        // For now, a simpler MAC mask: if mask.src_mac has any non-zero byte, it implies full match needed.
        // This is not a true bitmask for MACs yet.
        // Let's assume a convention for MAC mask: if mask.src_mac is not all zeros, then src_mac must match.
        // This can be done by initializing mask fields that are "don't care" to all zeros,
        // and fields to be matched to all ones (0xFFFF, 0xFFFFFFFF, etc.).
        // Then the logic becomes: if ( (extracted.field ^ templ.field) & mask.field ) != 0 then no match.

        // For MACs, a simple approach: if mask.src_mac is not "00:00:00:00:00:00", then compare.
        // This needs a defined "any" MAC or a proper per-byte mask.
        // Let's assume mask.src_mac being non-zero means "match src_mac".
        MacAddress zero_mac; // All zeros by default
        if (!(mask.src_mac == zero_mac) && !(extracted.src_mac == templ.src_mac)) return false;
        if (!(mask.dst_mac == zero_mac) && !(extracted.dst_mac == templ.dst_mac)) return false;

        return true;
    }

    // Special MacAddress to indicate full match required for MACs in mask.
    // This is a simplification. A real mask might be per-byte.
    const MacAddress MASK_MATCH_ALL_MAC = MacAddress(reinterpret_cast<const uint8_t*>("\xFF\xFF\xFF\xFF\xFF\xFF"));
    // This MASK_MATCH_ALL_MAC is problematic for direct comparison in mask.field == MASK_MATCH_ALL_MAC.
    // The bitwise XOR approach for integer fields is more standard for masks.
    // For MACs in FlowKey, the mask should also be a MacAddress.
    // If mask.src_mac.bytes[i] is 0xFF, then extracted.src_mac.bytes[i] must equal templ.src_mac.bytes[i].
    // If mask.src_mac.bytes[i] is 0x00, then it's a wildcard for that byte.
    // This requires a loop for MACs.
    // Let's refine match_key for MACs:
    // Re-evaluating match_key for MACs based on typical mask usage:
    // For MAC addresses, a bitwise mask is also possible if we treat them as 48-bit integers,
    // but that's often not how it's done. Usually, it's full match or wildcard.
    // The (extracted ^ template) & mask == 0 is good for integer fields.
    // For MACs, if we want to use this, the FlowKey.mask.src_mac should be all 0xFFs for a match.
    // Let's assume FlowKey.mask.src_mac = MacAddress({FF,FF,FF,FF,FF,FF}) means match src_mac.
    // And FlowKey.mask.src_mac = MacAddress({00,00,00,00,00,00}) means wildcard.
    // Then the logic `if (!(mask.src_mac == zero_mac) && !(extracted.src_mac == templ.src_mac)) return false;` is okay.
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
