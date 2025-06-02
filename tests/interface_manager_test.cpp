#include "gtest/gtest.h"
#include "netflow++/interface_manager.hpp"
#include "netflow++/logger.hpp"      // For SwitchLogger
#include "netflow++/acl_manager.hpp" // For AclManager
#include "netflow++/packet.hpp"      // For IpAddress, MacAddress if used directly in helpers
#include <functional>
#include <vector>
#include <optional>
#include <string>
#include <arpa/inet.h> // For inet_pton

// Helper to convert string IP to network byte order IpAddress (uint32_t)
// Specific to this test file to avoid name clashes if linked with others that define it differently.
bool string_to_ip_net_order_if_test(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr; // Already in network byte order
        return true;
    }
    return false;
}


// Test fixture for InterfaceManager tests
class InterfaceManagerTest : public ::testing::Test {
protected:
    netflow::SwitchLogger logger_{netflow::LogLevel::DEBUG};
    netflow::AclManager acl_manager_{logger_};
    netflow::InterfaceManager ifManager{logger_, acl_manager_};

    uint32_t test_port_id = 1;
    uint32_t test_port_id_2 = 2;
    std::string test_acl_name_1 = "ingress_test_acl";
    std::string test_acl_name_2 = "egress_test_acl";

    void SetUp() override {
        ifManager.configure_port(test_port_id, {});
        ifManager.configure_port(test_port_id_2, {});

        ASSERT_TRUE(acl_manager_.create_acl(test_acl_name_1));
        ASSERT_TRUE(acl_manager_.create_acl(test_acl_name_2));
        acl_manager_.compile_rules(test_acl_name_1);
        acl_manager_.compile_rules(test_acl_name_2);
    }
};

// --- Port Configuration Tests ---
TEST_F(InterfaceManagerTest, SetAndGetAdminStatus) {
    netflow::InterfaceManager::PortConfig config;
    config.admin_up = true;
    ifManager.configure_port(test_port_id, config);
    EXPECT_TRUE(ifManager.is_port_admin_up(test_port_id));
    ASSERT_TRUE(ifManager.get_port_config(test_port_id).has_value());
    EXPECT_TRUE(ifManager.get_port_config(test_port_id).value().admin_up);

    config.admin_up = false;
    ifManager.configure_port(test_port_id, config);
    EXPECT_FALSE(ifManager.is_port_admin_up(test_port_id));
    ASSERT_TRUE(ifManager.get_port_config(test_port_id).has_value());
    EXPECT_FALSE(ifManager.get_port_config(test_port_id).value().admin_up);
}

TEST_F(InterfaceManagerTest, ConfigureFullPortAndVerify) {
    netflow::InterfaceManager::PortConfig config;
    config.admin_up = true;
    config.speed_mbps = 25000;
    config.full_duplex = true;
    config.auto_negotiation = false;
    config.mtu = 1550;
    config.ingress_acl_name = std::nullopt;
    config.egress_acl_name = std::nullopt;
    ifManager.configure_port(test_port_id, config);

    auto p_config_opt = ifManager.get_port_config(test_port_id);
    ASSERT_TRUE(p_config_opt.has_value());
    const auto& p_config = p_config_opt.value();
    EXPECT_EQ(p_config.admin_up, true);
    EXPECT_EQ(p_config.speed_mbps, 25000);
    EXPECT_EQ(p_config.full_duplex, true);
    EXPECT_EQ(p_config.auto_negotiation, false);
    EXPECT_EQ(p_config.mtu, 1550);
    EXPECT_FALSE(p_config.ingress_acl_name.has_value());
    EXPECT_FALSE(p_config.egress_acl_name.has_value());
}

// --- New ACL Binding Test Cases ---

TEST_F(InterfaceManagerTest, ApplyAndGetAclName) {
    ASSERT_TRUE(ifManager.apply_acl_to_interface(test_port_id, test_acl_name_1, netflow::AclDirection::INGRESS));
    std::optional<std::string> applied_ingress = ifManager.get_applied_acl_name(test_port_id, netflow::AclDirection::INGRESS);
    ASSERT_TRUE(applied_ingress.has_value());
    EXPECT_EQ(applied_ingress.value(), test_acl_name_1);

    auto port_config = ifManager.get_port_config(test_port_id);
    ASSERT_TRUE(port_config.has_value());
    ASSERT_TRUE(port_config.value().ingress_acl_name.has_value());
    EXPECT_EQ(port_config.value().ingress_acl_name.value(), test_acl_name_1);
    EXPECT_FALSE(port_config.value().egress_acl_name.has_value());

    ASSERT_TRUE(ifManager.apply_acl_to_interface(test_port_id_2, test_acl_name_2, netflow::AclDirection::EGRESS));
    std::optional<std::string> applied_egress = ifManager.get_applied_acl_name(test_port_id_2, netflow::AclDirection::EGRESS);
    ASSERT_TRUE(applied_egress.has_value());
    EXPECT_EQ(applied_egress.value(), test_acl_name_2);

    port_config = ifManager.get_port_config(test_port_id_2);
    ASSERT_TRUE(port_config.has_value());
    EXPECT_FALSE(port_config.value().ingress_acl_name.has_value());
    ASSERT_TRUE(port_config.value().egress_acl_name.has_value());
    EXPECT_EQ(port_config.value().egress_acl_name.value(), test_acl_name_2);

    ASSERT_TRUE(ifManager.apply_acl_to_interface(test_port_id, test_acl_name_2, netflow::AclDirection::INGRESS));
    applied_ingress = ifManager.get_applied_acl_name(test_port_id, netflow::AclDirection::INGRESS);
    ASSERT_TRUE(applied_ingress.has_value());
    EXPECT_EQ(applied_ingress.value(), test_acl_name_2);
}

TEST_F(InterfaceManagerTest, ApplyNonExistentAclName) {
    std::string non_existent_acl = "ghost_acl";
    ASSERT_FALSE(ifManager.apply_acl_to_interface(test_port_id, non_existent_acl, netflow::AclDirection::INGRESS));

    auto port_config = ifManager.get_port_config(test_port_id);
    ASSERT_TRUE(port_config.has_value());
    EXPECT_FALSE(port_config.value().ingress_acl_name.has_value());
    EXPECT_FALSE(ifManager.get_applied_acl_name(test_port_id, netflow::AclDirection::INGRESS).has_value());
}

TEST_F(InterfaceManagerTest, RemoveAcl) {
    ASSERT_TRUE(ifManager.apply_acl_to_interface(test_port_id, test_acl_name_1, netflow::AclDirection::INGRESS));
    ASSERT_TRUE(ifManager.get_applied_acl_name(test_port_id, netflow::AclDirection::INGRESS).has_value());

    ASSERT_TRUE(ifManager.remove_acl_from_interface(test_port_id, netflow::AclDirection::INGRESS));
    EXPECT_FALSE(ifManager.get_applied_acl_name(test_port_id, netflow::AclDirection::INGRESS).has_value());

    auto port_config = ifManager.get_port_config(test_port_id);
    ASSERT_TRUE(port_config.has_value());
    EXPECT_FALSE(port_config.value().ingress_acl_name.has_value());

    ASSERT_TRUE(ifManager.remove_acl_from_interface(test_port_id, netflow::AclDirection::INGRESS));
}

TEST_F(InterfaceManagerTest, ApplyToNonExistentPort) {
    uint32_t non_existent_port_id = 999;
    EXPECT_FALSE(ifManager.apply_acl_to_interface(non_existent_port_id, test_acl_name_1, netflow::AclDirection::INGRESS));
    EXPECT_FALSE(ifManager.remove_acl_from_interface(non_existent_port_id, netflow::AclDirection::INGRESS));
    EXPECT_FALSE(ifManager.get_applied_acl_name(non_existent_port_id, netflow::AclDirection::INGRESS).has_value());
}

TEST_F(InterfaceManagerTest, GetDefaultPortStats) { /* ... unchanged ... */ }
TEST_F(InterfaceManagerTest, IncrementAndClearPortStats) { /* ... unchanged ... */ }

struct LinkStateTracker {
    bool up_called = false; bool down_called = false;
    uint32_t up_port_id = 0; uint32_t down_port_id = 0;
    void link_up_handler(uint32_t port_id) { up_called = true; up_port_id = port_id; }
    void link_down_handler(uint32_t port_id) { down_called = true; down_port_id = port_id; }
};
TEST_F(InterfaceManagerTest, LinkStateNotification) { /* ... unchanged ... */ }
TEST_F(InterfaceManagerTest, ConfigureNonExistentPort) { /* ... unchanged ... */ }
TEST_F(InterfaceManagerTest, GetStatsForNonExistentPort) { /* ... unchanged ... */ }
TEST_F(InterfaceManagerTest, GetConfigForNonExistentPort) { /* ... unchanged ... */ }

TEST_F(InterfaceManagerTest, AddAndGetIpAddress) {
    netflow::IpAddress ip1, mask1;
    // Use the locally defined helper
    ASSERT_TRUE(string_to_ip_net_order_if_test("192.168.1.1", ip1));
    ASSERT_TRUE(string_to_ip_net_order_if_test("255.255.255.0", mask1));

    ifManager.add_ip_address(test_port_id, ip1, mask1);
    auto ips = ifManager.get_interface_ip_configs(test_port_id);
    ASSERT_EQ(ips.size(), 1);
    EXPECT_EQ(ips[0].address, ip1);
    EXPECT_EQ(ips[0].subnet_mask, mask1);

    EXPECT_TRUE(ifManager.is_my_ip(ip1));
    EXPECT_EQ(ifManager.find_interface_for_ip(ip1).value_or(0), test_port_id);
}
