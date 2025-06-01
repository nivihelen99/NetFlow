#include "netflow++/acl_manager.hpp"
#include "netflow++/packet.hpp" // Required for Packet and its header accessors
#include "netflow++/logger.hpp" // For SwitchLogger
#include <algorithm> // For std::sort, std::remove_if, std::find_if

// For ntohs, ntohl if used (e.g. in check_match)
#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif


namespace netflow {

AclManager::AclManager(SwitchLogger& logger) : logger_(logger) {
    logger_.log(LogLevel::DEBUG, "AclManager", "AclManager initialized.");
    // TODO: Implement constructor if more setup is needed
}

AclManager::~AclManager() {
    logger_.log(LogLevel::DEBUG, "AclManager", "AclManager destroyed.");
    // TODO: Implement destructor if cleanup is needed
}

bool AclManager::add_rule(const AclRule& rule) {
    // TODO: Implement
    // Based on previous header implementation:
    auto it_existing = std::find_if(acl_rules_.begin(), acl_rules_.end(),
                                [&](const AclRule& r){ return r.rule_id == rule.rule_id; });
    if (it_existing != acl_rules_.end()) {
        *it_existing = rule; // Replace existing rule with the same ID
        logger_.log(LogLevel::INFO, "AclManager", "Replaced ACL rule with ID: " + std::to_string(rule.rule_id));
    } else {
        acl_rules_.push_back(rule);
        logger_.log(LogLevel::INFO, "AclManager", "Added new ACL rule with ID: " + std::to_string(rule.rule_id));
    }
    // std::sort(acl_rules_.begin(), acl_rules_.end()); // Sorting moved to compile_rules
    needs_compilation_ = true;
    return true;
}

bool AclManager::remove_rule(uint32_t rule_id_to_remove) {
    // TODO: Implement
    // Based on previous header implementation:
    auto it = std::remove_if(acl_rules_.begin(), acl_rules_.end(),
                             [rule_id_to_remove](const AclRule& r){ return r.rule_id == rule_id_to_remove; });
    if (it != acl_rules_.end()) {
        acl_rules_.erase(it, acl_rules_.end());
        logger_.log(LogLevel::INFO, "AclManager", "Removed ACL rule with ID: " + std::to_string(rule_id_to_remove));
        return true;
    }
    logger_.log(LogLevel::WARNING, "AclManager", "Failed to remove ACL rule ID: " + std::to_string(rule_id_to_remove) + ", not found.");
    return false;
}

std::optional<AclRule> AclManager::get_rule(uint32_t rule_id) const {
    // TODO: Implement
    auto it = std::find_if(acl_rules_.begin(), acl_rules_.end(),
                           [rule_id](const AclRule& r){ return r.rule_id == rule_id; });
    if (it != acl_rules_.end()) {
        return *it;
    }
    return std::nullopt;
}

const std::vector<AclRule>& AclManager::get_all_rules() const {
    // TODO: Implement (or confirm if simple return is fine)
    // Based on previous header implementation:
    return acl_rules_;
}

void AclManager::clear_rules() {
    // TODO: Implement
    // Based on previous header implementation:
    acl_rules_.clear();
    logger_.log(LogLevel::INFO, "AclManager", "All ACL rules cleared.");
}

void AclManager::compile_rules() {
    // TODO: Implement
    // Placeholder for future optimization. For now, rules are evaluated sequentially.
    logger_.log(LogLevel::INFO, "AclManager", "Compiling ACL rules (sorting by priority)...");
    std::sort(acl_rules_.begin(), acl_rules_.end()); // Higher priority value first, then by ID for stability
    needs_compilation_ = false;
    logger_.log(LogLevel::INFO, "AclManager", "ACL rules compiled.");
}

AclActionType AclManager::evaluate(const Packet& pkt, uint32_t& out_redirect_port_id) const {
    if (needs_compilation_) {
        logger_.log(LogLevel::WARNING, "AclManager", "Evaluating ACLs with uncompiled rule set. Performance may be affected. Consider calling compile_rules().");
        // Depending on policy, could force compilation or return an error/default.
        // For now, proceed with current (potentially unsorted) list, but sort would be safer.
        // To be safe for evaluation logic that expects sorted rules:
        // const_cast<AclManager*>(this)->compile_rules(); // Not ideal to const_cast
        // Or, make evaluate non-const if it can trigger compilation.
        // For now, just a warning and proceed. The current sort in add_rule makes this less critical,
        // but if add_rule stops sorting, this warning is important.
        // With sorting removed from add_rule, this warning is very relevant.
    }

    // Based on previous header implementation:
    for (const auto& rule : acl_rules_) { // acl_rules_ should be sorted by compile_rules()
        if (check_match(pkt, rule)) {
            logger_.log(LogLevel::DEBUG, "AclManager", "Packet matched ACL rule ID: " + std::to_string(rule.rule_id) +
                                                     ", Priority: " + std::to_string(rule.priority) +
                                                     ", Action: " + std::to_string(static_cast<int>(rule.action)));
            if (rule.action == AclActionType::REDIRECT) {
                if (rule.redirect_port_id.has_value()) {
                    out_redirect_port_id = rule.redirect_port_id.value();
                } else {
                    logger_.log(LogLevel::ERROR, "AclManager", "Rule ID " + std::to_string(rule.rule_id) +
                                                              " has REDIRECT action but no redirect_port_id. Defaulting to DENY.");
                    return AclActionType::DENY;
                }
            }
            return rule.action;
        }
    }
    logger_.log(LogLevel::DEBUG, "AclManager", "Packet did not match any ACL rules. Default action: PERMIT.");
    return AclActionType::PERMIT; // Default action if no rules match
}


// Private helper method implementation
bool AclManager::check_match(const Packet& pkt, const AclRule& rule) const {
    // TODO: Implement
    // Based on previous header implementation:
    if (rule.src_mac) {
        auto pkt_src_mac = pkt.src_mac();
        if (!pkt_src_mac || !(pkt_src_mac.value() == rule.src_mac.value())) return false;
    }
    if (rule.dst_mac) {
        auto pkt_dst_mac = pkt.dst_mac();
        if (!pkt_dst_mac || !(pkt_dst_mac.value() == rule.dst_mac.value())) return false;
    }
    if (rule.vlan_id) {
        auto pkt_vlan_id = pkt.vlan_id();
        if (!pkt_vlan_id || pkt_vlan_id.value() != rule.vlan_id.value()) return false;
    }

    uint16_t effective_ethertype = 0;
    EthernetHeader* eth_hdr = pkt.ethernet();
    if (!eth_hdr) {
        if (rule.ethertype || rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port) {
             return false;
        }
    } else {
        if (pkt.has_vlan()) {
            VlanHeader* vlan_hdr = pkt.vlan();
            if (vlan_hdr) {
                effective_ethertype = ntohs(vlan_hdr->ethertype);
            } else {
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

    IPv4Header* ipv4_hdr = nullptr;
    bool needs_ip_header = rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port;

    if (needs_ip_header) {
        if (effective_ethertype == ETHERTYPE_IPV4) {
            ipv4_hdr = pkt.ipv4();
            if (!ipv4_hdr) return false;
        } else {
            return false;
        }
    }

    if (ipv4_hdr) {
        if (rule.src_ip && ntohl(ipv4_hdr->src_ip) != rule.src_ip.value()) return false;
        if (rule.dst_ip && ntohl(ipv4_hdr->dst_ip) != rule.dst_ip.value()) return false;
        if (rule.protocol) {
             if (ipv4_hdr->protocol != rule.protocol.value()) return false;
        }

        if (rule.src_port || rule.dst_port) {
            uint8_t packet_protocol = ipv4_hdr->protocol;
            if (rule.protocol.has_value() && rule.protocol.value() != packet_protocol) {
                return false;
            }
            if (packet_protocol == IPPROTO_TCP) {
                TcpHeader* tcp_hdr = pkt.tcp();
                if (!tcp_hdr) return false;
                if (rule.src_port && ntohs(tcp_hdr->src_port) != rule.src_port.value()) return false;
                if (rule.dst_port && ntohs(tcp_hdr->dst_port) != rule.dst_port.value()) return false;
            } else if (packet_protocol == IPPROTO_UDP) {
                UdpHeader* udp_hdr = pkt.udp();
                if (!udp_hdr) return false;
                if (rule.src_port && ntohs(udp_hdr->src_port) != rule.src_port.value()) return false;
                if (rule.dst_port && ntohs(udp_hdr->dst_port) != rule.dst_port.value()) return false;
            } else {
                return false;
            }
        }
    } else if (needs_ip_header) {
        return false;
    }
    return true;
}

} // namespace netflow
