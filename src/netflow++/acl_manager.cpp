#include "netflow++/acl_manager.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <algorithm>

#if __has_include(<arpa/inet.h>)
#include <arpa/inet.h>
#elif __has_include(<winsock2.h>)
#include <winsock2.h>
#endif


namespace netflow {

AclManager::AclManager(SwitchLogger& logger) : logger_(logger) {
    logger_.log(LogLevel::DEBUG, "AclManager", "AclManager initialized for named ACLs.");
}

AclManager::~AclManager() {
    logger_.log(LogLevel::DEBUG, "AclManager", "AclManager destroyed.");
}

// Named ACL management
bool AclManager::create_acl(const std::string& acl_name) {
    if (acl_name.empty()) {
        logger_.log(LogLevel::ERROR, "AclManager", "ACL name cannot be empty.");
        return false;
    }
    auto it = named_acl_rules_.find(acl_name);
    if (it != named_acl_rules_.end()) {
        logger_.log(LogLevel::WARNING, "AclManager", "ACL with name '" + acl_name + "' already exists.");
        return false; // Or true, if existing is fine
    }
    named_acl_rules_[acl_name] = std::vector<AclRule>();
    named_acl_needs_compilation_[acl_name] = true; // New ACL, technically empty but mark for consistency
    logger_.log(LogLevel::INFO, "AclManager", "Created new ACL: '" + acl_name + "'.");
    return true;
}

bool AclManager::delete_acl(const std::string& acl_name) {
    if (named_acl_rules_.erase(acl_name) > 0) {
        named_acl_needs_compilation_.erase(acl_name);
        logger_.log(LogLevel::INFO, "AclManager", "Deleted ACL: '" + acl_name + "'.");
        return true;
    }
    logger_.log(LogLevel::WARNING, "AclManager", "Failed to delete ACL: '" + acl_name + "', not found.");
    return false;
}

std::vector<std::string> AclManager::get_acl_names() const {
    std::vector<std::string> names;
    for (const auto& pair : named_acl_rules_) {
        names.push_back(pair.first);
    }
    return names;
}

std::map<std::string, std::vector<AclRule>> AclManager::get_all_named_acls() const {
    // Ensure all ACLs are compiled (sorted) before returning for inspection if needed
    // For now, just returns current state. Caller might want to call compile_rules on each.
    return named_acl_rules_;
}

void AclManager::clear_all_acls() {
    named_acl_rules_.clear();
    named_acl_needs_compilation_.clear();
    logger_.log(LogLevel::INFO, "AclManager", "All ACLs and their rules cleared.");
}


// Rule management within a named ACL
bool AclManager::add_rule(const std::string& acl_name, const AclRule& rule) {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl == named_acl_rules_.end()) {
        logger_.log(LogLevel::ERROR, "AclManager", "Cannot add rule to non-existent ACL: '" + acl_name + "'.");
        return false;
    }
    std::vector<AclRule>& rules = it_acl->second;
    auto it_existing_rule = std::find_if(rules.begin(), rules.end(),
                                        [&](const AclRule& r){ return r.rule_id == rule.rule_id; });
    if (it_existing_rule != rules.end()) {
        *it_existing_rule = rule;
        logger_.log(LogLevel::INFO, "AclManager", "Replaced rule ID " + std::to_string(rule.rule_id) + " in ACL '" + acl_name + "'.");
    } else {
        rules.push_back(rule);
        logger_.log(LogLevel::INFO, "AclManager", "Added new rule ID " + std::to_string(rule.rule_id) + " to ACL '" + acl_name + "'.");
    }
    named_acl_needs_compilation_[acl_name] = true;
    return true;
}

bool AclManager::remove_rule(const std::string& acl_name, uint32_t rule_id_to_remove) {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl == named_acl_rules_.end()) {
        logger_.log(LogLevel::ERROR, "AclManager", "Cannot remove rule from non-existent ACL: '" + acl_name + "'.");
        return false;
    }
    std::vector<AclRule>& rules = it_acl->second;
    auto it = std::remove_if(rules.begin(), rules.end(),
                             [rule_id_to_remove](const AclRule& r){ return r.rule_id == rule_id_to_remove; });
    if (it != rules.end()) {
        rules.erase(it, rules.end());
        named_acl_needs_compilation_[acl_name] = true;
        logger_.log(LogLevel::INFO, "AclManager", "Removed rule ID " + std::to_string(rule_id_to_remove) + " from ACL '" + acl_name + "'.");
        return true;
    }
    logger_.log(LogLevel::WARNING, "AclManager", "Rule ID " + std::to_string(rule_id_to_remove) + " not found in ACL '" + acl_name + "'.");
    return false;
}

std::optional<AclRule> AclManager::get_rule(const std::string& acl_name, uint32_t rule_id) const {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl == named_acl_rules_.end()) {
        logger_.log(LogLevel::DEBUG, "AclManager", "ACL '" + acl_name + "' not found for get_rule.");
        return std::nullopt;
    }
    const std::vector<AclRule>& rules = it_acl->second;
    auto it = std::find_if(rules.begin(), rules.end(),
                           [rule_id](const AclRule& r){ return r.rule_id == rule_id; });
    if (it != rules.end()) {
        return *it;
    }
    return std::nullopt;
}

std::vector<AclRule> AclManager::get_all_rules(const std::string& acl_name) const {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl != named_acl_rules_.end()) {
        // Consider if this should return a copy of compiled (sorted) rules
        // For now, returns current state which might be uncompiled.
        return it_acl->second;
    }
    logger_.log(LogLevel::WARNING, "AclManager", "ACL '" + acl_name + "' not found for get_all_rules.");
    return {}; // Return empty vector
}

void AclManager::clear_rules(const std::string& acl_name) {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl != named_acl_rules_.end()) {
        it_acl->second.clear();
        named_acl_needs_compilation_[acl_name] = true; // Mark as needing compilation (though it's empty)
        logger_.log(LogLevel::INFO, "AclManager", "Cleared all rules from ACL '" + acl_name + "'.");
    } else {
        logger_.log(LogLevel::WARNING, "AclManager", "Cannot clear rules, ACL '" + acl_name + "' not found.");
    }
}

void AclManager::compile_rules(const std::string& acl_name) {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl == named_acl_rules_.end()) {
        logger_.log(LogLevel::ERROR, "AclManager", "Cannot compile rules for non-existent ACL: '" + acl_name + "'.");
        return;
    }
    std::vector<AclRule>& rules = it_acl->second;
    logger_.log(LogLevel::INFO, "AclManager", "Compiling ACL '" + acl_name + "' (sorting " + std::to_string(rules.size()) + " rules by priority)...");
    std::sort(rules.begin(), rules.end()); // Higher priority value first, then by ID for stability
    named_acl_needs_compilation_[acl_name] = false;
    logger_.log(LogLevel::INFO, "AclManager", "ACL '" + acl_name + "' compiled.");
}

AclActionType AclManager::evaluate(const std::string& acl_name, const Packet& pkt, uint32_t& out_redirect_port_id) const {
    auto it_acl = named_acl_rules_.find(acl_name);
    if (it_acl == named_acl_rules_.end()) {
        logger_.log(LogLevel::WARNING, "AclManager", "ACL '" + acl_name + "' not found for evaluation. Defaulting to PERMIT.");
        return AclActionType::PERMIT; // Default action if ACL name doesn't exist
    }

    auto it_needs_compile = named_acl_needs_compilation_.find(acl_name);
    if (it_needs_compile != named_acl_needs_compilation_.end() && it_needs_compile->second) {
        logger_.log(LogLevel::WARNING, "AclManager", "Evaluating ACL '" + acl_name +
                                     "' with uncompiled rule set. Performance may be affected. Consider calling compile_rules().");
    }

    const std::vector<AclRule>& rules = it_acl->second;
    for (const auto& rule : rules) { // acl_rules_ should be sorted by compile_rules()
        if (check_match(pkt, rule)) {
            logger_.log(LogLevel::DEBUG, "AclManager", "Packet matched ACL '" + acl_name + "' rule ID: " + std::to_string(rule.rule_id) +
                                                     ", Priority: " + std::to_string(rule.priority) +
                                                     ", Action: " + std::to_string(static_cast<int>(rule.action)));
            if (rule.action == AclActionType::REDIRECT) {
                if (rule.redirect_port_id.has_value()) {
                    out_redirect_port_id = rule.redirect_port_id.value();
                } else {
                    logger_.log(LogLevel::ERROR, "AclManager", "Rule ID " + std::to_string(rule.rule_id) + " in ACL '" + acl_name +
                                                              "' has REDIRECT action but no redirect_port_id. Defaulting to DENY.");
                    return AclActionType::DENY;
                }
            }
            return rule.action;
        }
    }
    logger_.log(LogLevel::DEBUG, "AclManager", "Packet did not match any rules in ACL '" + acl_name + "'. Default action: PERMIT.");
    return AclActionType::PERMIT;
}


// Private helper method implementation (remains largely the same logic)
bool AclManager::check_match(const Packet& pkt, const AclRule& rule) const {
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
    if (!eth_hdr) { // No Ethernet header, cannot match L2+ fields
        if (rule.ethertype || rule.src_ip || rule.dst_ip || rule.protocol || rule.src_port || rule.dst_port) {
             return false;
        }
    } else {
        if (pkt.has_vlan()) {
            VlanHeader* vlan_hdr = pkt.vlan();
            if (vlan_hdr) {
                effective_ethertype = ntohs(vlan_hdr->ethertype);
            } else { // Should not happen if has_vlan() is true
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
        } else { // Rule needs IP info, but packet is not IPv4 (or no eth header to determine type)
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
            } else { // Rule specifies L4 ports, but packet is not TCP or UDP
                return false;
            }
        }
    } else if (needs_ip_header) {
        // This means the rule required IP fields, but the packet either wasn't IPv4 or didn't have an IP header.
        return false;
    }
    return true;
}

} // namespace netflow
