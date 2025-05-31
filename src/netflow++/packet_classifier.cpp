#include "netflow++/packet_classifier.hpp"
#include "netflow++/packet.hpp" // Required for Packet, header structs
#include <vector>
#include <algorithm> // For std::sort, std::copy, std::begin, std::end
#include <array>     // For std::array

// std::hash specialization is in the header.

namespace netflow {

// Extracts a FlowKey from a given packet.
PacketClassifier::FlowKey PacketClassifier::extract_flow_key(const Packet& pkt) const {
    FlowKey key;
    // key.is_ipv6 is already false by default
    // IPv6 arrays are already zero-initialized by default
    key.vlan_id = 0; // Default to no VLAN or outermost VLAN if multiple

    if (pkt.ethernet()) {
        key.src_mac = pkt.src_mac().value_or(MacAddress());
        key.dst_mac = pkt.dst_mac().value_or(MacAddress());
        key.ethertype = ntohs(pkt.ethernet()->ethertype); // Store in host byte order

        if (pkt.has_vlan()) {
            key.vlan_id = pkt.vlan_id().value_or(0);
            VlanHeader* vlan = pkt.vlan();
            if (vlan) {
                key.ethertype = ntohs(vlan->ethertype);
            }
        }
    }

    // Check for IPv4 based on determined ethertype
    if (key.ethertype == 0x0800) { // IPv4
        key.is_ipv6 = false;
        IPv4Header* ipv4_hdr = pkt.ipv4();
        if (ipv4_hdr) {
            key.src_ip = ntohl(ipv4_hdr->src_ip);
            key.dst_ip = ntohl(ipv4_hdr->dst_ip);
            key.protocol = ipv4_hdr->protocol;

            if (key.protocol == 6) { // TCP
                TcpHeader* tcp_hdr = pkt.tcp();
                if (tcp_hdr) {
                    key.src_port = ntohs(tcp_hdr->src_port);
                    key.dst_port = ntohs(tcp_hdr->dst_port);
                }
            } else if (key.protocol == 17) { // UDP
                UdpHeader* udp_hdr = pkt.udp();
                if (udp_hdr) {
                    key.src_port = ntohs(udp_hdr->src_port);
                    key.dst_port = ntohs(udp_hdr->dst_port);
                }
            }
        }
    } else if (key.ethertype == 0x86DD) { // IPv6
        key.is_ipv6 = true;
        IPv6Header* ipv6_hdr = pkt.ipv6();
        if (ipv6_hdr) {
            std::copy(std::begin(ipv6_hdr->src_ip), std::end(ipv6_hdr->src_ip), key.src_ipv6.begin());
            std::copy(std::begin(ipv6_hdr->dst_ip), std::end(ipv6_hdr->dst_ip), key.dst_ipv6.begin());
            key.protocol = ipv6_hdr->next_header;

            if (key.protocol == 6) { // TCP
                TcpHeader* tcp_hdr = pkt.tcp();
                if (tcp_hdr) {
                    key.src_port = ntohs(tcp_hdr->src_port);
                    key.dst_port = ntohs(tcp_hdr->dst_port);
                }
            } else if (key.protocol == 17) { // UDP
                UdpHeader* udp_hdr = pkt.udp();
                if (udp_hdr) {
                    key.src_port = ntohs(udp_hdr->src_port);
                    key.dst_port = ntohs(udp_hdr->dst_port);
                }
            }
        }
    }
    return key;
}

// Simple XOR sum hash for the FlowKey. Made static.
uint32_t PacketClassifier::hash_flow(const FlowKey& key) {
    uint32_t hash_val = 0;

    for (int i = 0; i < 6; ++i) {
        hash_val ^= static_cast<uint32_t>(key.src_mac.bytes[i]) << (i % 4 * 8);
        hash_val ^= static_cast<uint32_t>(key.dst_mac.bytes[i]) << (i % 4 * 8);
    }

    hash_val ^= static_cast<uint32_t>(key.vlan_id);
    hash_val ^= static_cast<uint32_t>(key.ethertype) << 16;

    if (key.is_ipv6) {
        for (size_t i = 0; i < 16; ++i) {
            hash_val ^= static_cast<uint32_t>(key.src_ipv6[i]) << ((i % 4) * 8);
            hash_val ^= static_cast<uint32_t>(key.dst_ipv6[i]) << ((i % 4) * 8);
        }
    } else {
        hash_val ^= key.src_ip;
        hash_val ^= key.dst_ip;
    }

    hash_val ^= static_cast<uint32_t>(key.protocol);
    hash_val ^= static_cast<uint32_t>(key.src_port) << 16;
    hash_val ^= static_cast<uint32_t>(key.dst_port);

    return hash_val;
}

void PacketClassifier::add_rule(const ClassificationRule& rule) {
    rules_.push_back(rule);
    std::sort(rules_.begin(), rules_.end(), [](const ClassificationRule& a, const ClassificationRule& b) {
        return a.priority > b.priority;
    });
}

uint32_t PacketClassifier::classify(const Packet& pkt) const {
    FlowKey extracted_key = extract_flow_key(pkt);

    for (const auto& rule : rules_) {
        if (match_key(extracted_key, rule.key_template, rule.mask)) {
            return rule.action_id;
        }
    }
    return 0;
}

const std::vector<PacketClassifier::ClassificationRule>& PacketClassifier::get_rules() const {
    return rules_;
}

// Helper function to match an extracted key against a rule template using a mask.
bool PacketClassifier::match_key(const FlowKey& extracted, const FlowKey& templ, const FlowKey& mask) const {
    // Common non-IP fields first
    if (((extracted.vlan_id ^ templ.vlan_id) & mask.vlan_id) != 0) return false;
    if (((extracted.ethertype ^ templ.ethertype) & mask.ethertype) != 0) return false;

    MacAddress zero_mac{};
    if (!(mask.src_mac == zero_mac) && !(extracted.src_mac == templ.src_mac)) return false;
    if (!(mask.dst_mac == zero_mac) && !(extracted.dst_mac == templ.dst_mac)) return false;

    // IP Version matching (if mask.is_ipv6 is true, it means this rule cares about IP version)
    if (mask.is_ipv6) {
        if (extracted.is_ipv6 != templ.is_ipv6) return false;
    }

    // IP address specific matching
    if (extracted.is_ipv6) {
        std::array<uint8_t, 16> zero_ipv6{};
        if (!(mask.src_ipv6 == zero_ipv6) && !(extracted.src_ipv6 == templ.src_ipv6)) return false;
        if (!(mask.dst_ipv6 == zero_ipv6) && !(extracted.dst_ipv6 == templ.dst_ipv6)) return false;
        // Assuming rule consistency: if it's an IPv6 rule (templ.is_ipv6=true), then IPv4 mask fields (mask.src_ip, etc.) should be 0.
    } else {
        // IPv4 matching
        if (((extracted.src_ip ^ templ.src_ip) & mask.src_ip) != 0) return false;
        if (((extracted.dst_ip ^ templ.dst_ip) & mask.dst_ip) != 0) return false;
        // Assuming rule consistency: if it's an IPv4 rule, IPv6 mask fields should be zero.
    }

    // Protocol and Port matching (common to IPv4 and IPv6 if IP fields matched)
    if (((extracted.protocol ^ templ.protocol) & mask.protocol) != 0) return false;
    if (((extracted.src_port ^ templ.src_port) & mask.src_port) != 0) return false;
    if (((extracted.dst_port ^ templ.dst_port) & mask.dst_port) != 0) return false;

    return true;
}

} // namespace netflow
