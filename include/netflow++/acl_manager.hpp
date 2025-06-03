#ifndef NETFLOW_ACL_MANAGER_HPP
#define NETFLOW_ACL_MANAGER_HPP

#include "packet.hpp" // For MacAddress, netflow::Packet, and potentially other header structs
#include "netflow++/logger.hpp" // For SwitchLogger

#include <cstdint>   // For uint32_t, uint16_t, uint8_t
#include <vector>    // For std::vector
#include <optional>  // For std::optional
#include <algorithm> // For std::sort, std::remove_if (used in .cpp)
#include <map>       // For std::map
#include <string>    // For std::string

namespace netflow {

enum class AclActionType {
    PERMIT,
    DENY,
    REDIRECT
};

struct AclRule {
    uint32_t rule_id = 0;
    int priority = 0;

    std::optional<MacAddress> src_mac;
    std::optional<MacAddress> dst_mac;
    std::optional<uint16_t> vlan_id;
    std::optional<uint16_t> ethertype;
    std::optional<uint32_t> src_ip;
    std::optional<uint32_t> dst_ip;
    std::optional<uint8_t> protocol;
    std::optional<uint16_t> src_port;
    std::optional<uint16_t> dst_port;

    AclActionType action = AclActionType::DENY;
    std::optional<uint32_t> redirect_port_id;

    AclRule() = default;
    AclRule(uint32_t id, int prio, AclActionType act)
        : rule_id(id), priority(prio), action(act) {}

    bool operator<(const AclRule& other) const {
        if (priority != other.priority) {
            return priority > other.priority;
        }
        return rule_id < other.rule_id;
    }
};

class AclManager {
public:
    AclManager(SwitchLogger& logger);
    ~AclManager(); // Default is fine if no manual resource management

    bool create_acl(const std::string& acl_name);
    bool delete_acl(const std::string& acl_name);
    std::vector<std::string> get_acl_names() const;
    std::map<std::string, std::vector<AclRule>> get_all_named_acls() const;
    void clear_all_acls();

    bool add_rule(const std::string& acl_name, const AclRule& rule);
    bool remove_rule(const std::string& acl_name, uint32_t rule_id_to_remove);
    std::optional<AclRule> get_rule(const std::string& acl_name, uint32_t rule_id) const;
    std::vector<AclRule> get_all_rules(const std::string& acl_name) const;
    void clear_rules(const std::string& acl_name);

    AclActionType evaluate(const std::string& acl_name, const Packet& pkt, uint32_t& out_redirect_port_id) const;
    void compile_rules(const std::string& acl_name); // Sorts rules by priority

private:
    SwitchLogger& logger_;
    std::map<std::string, std::vector<AclRule>> named_acl_rules_;
    // Potentially a map for compiled/optimized rules if needed:
    // std::map<std::string, CompiledAcl> compiled_acls_;
    std::map<std::string, bool> named_acl_needs_compilation_; // True if rules changed since last compile

    bool check_match(const Packet& pkt, const AclRule& rule) const;
};

} // namespace netflow

#endif // NETFLOW_ACL_MANAGER_HPP
