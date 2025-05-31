#include "gtest/gtest.h"
#include "netflow++/interface_manager.hpp"
#include <functional>
#include <vector>
#include <optional>

// Test fixture for InterfaceManager tests
class InterfaceManagerTest : public ::testing::Test {
protected:
    netflow::InterfaceManager ifManager;
    uint32_t test_port_id = 1;
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

TEST_F(InterfaceManagerTest, SetAndGetPortSpeed) {
    netflow::InterfaceManager::PortConfig config;
    config.speed_mbps = 10000; // 10 Gbps
    ifManager.configure_port(test_port_id, config);
    ASSERT_TRUE(ifManager.get_port_config(test_port_id).has_value());
    EXPECT_EQ(ifManager.get_port_config(test_port_id).value().speed_mbps, 10000);
}

TEST_F(InterfaceManagerTest, SetAndGetMTU) {
    netflow::InterfaceManager::PortConfig config;
    config.mtu = 9000;
    ifManager.configure_port(test_port_id, config);
    ASSERT_TRUE(ifManager.get_port_config(test_port_id).has_value());
    EXPECT_EQ(ifManager.get_port_config(test_port_id).value().mtu, 9000);
}

TEST_F(InterfaceManagerTest, ConfigureFullPortAndVerify) {
    netflow::InterfaceManager::PortConfig config;
    config.admin_up = true;
    config.speed_mbps = 25000; // 25 Gbps
    config.full_duplex = true;
    config.auto_negotiation = false;
    config.mtu = 1550;
    ifManager.configure_port(test_port_id, config);

    auto p_config_opt = ifManager.get_port_config(test_port_id);
    ASSERT_TRUE(p_config_opt.has_value());
    const auto& p_config = p_config_opt.value();
    EXPECT_EQ(p_config.admin_up, true);
    EXPECT_EQ(p_config.speed_mbps, 25000);
    EXPECT_EQ(p_config.full_duplex, true);
    EXPECT_EQ(p_config.auto_negotiation, false);
    EXPECT_EQ(p_config.mtu, 1550);
}

// --- Port Statistics Tests ---
TEST_F(InterfaceManagerTest, GetDefaultPortStats) {
    // Port might not be configured yet, get_port_stats should return default (zeroed) stats
    netflow::InterfaceManager::PortStats stats = ifManager.get_port_stats(test_port_id);
    EXPECT_EQ(stats.rx_packets, 0);
    EXPECT_EQ(stats.tx_packets, 0);
    EXPECT_EQ(stats.rx_bytes, 0);
    EXPECT_EQ(stats.tx_bytes, 0);
    EXPECT_EQ(stats.rx_errors, 0);
    EXPECT_EQ(stats.tx_errors, 0);
    EXPECT_EQ(stats.rx_drops, 0);
    EXPECT_EQ(stats.tx_drops, 0);

    // Configure the port to ensure it exists, then get stats again
    netflow::InterfaceManager::PortConfig config;
    ifManager.configure_port(test_port_id, config);
    stats = ifManager.get_port_stats(test_port_id);
    EXPECT_EQ(stats.rx_packets, 0); // Should still be zero
}

TEST_F(InterfaceManagerTest, IncrementAndClearPortStats) {
    netflow::InterfaceManager::PortConfig config; // Ensure port exists
    ifManager.configure_port(test_port_id, config);

    // Use public helper methods to increment stats
    ifManager._increment_rx_stats(test_port_id, 100, true, false); // 1 packet, 100 bytes, 1 error
    ifManager._increment_tx_stats(test_port_id, 200, false, true); // 1 packet, 200 bytes, 1 drop

    netflow::InterfaceManager::PortStats stats = ifManager.get_port_stats(test_port_id);
    EXPECT_EQ(stats.rx_packets, 1);
    EXPECT_EQ(stats.rx_bytes, 100);
    EXPECT_EQ(stats.rx_errors, 1);
    EXPECT_EQ(stats.rx_drops, 0);
    EXPECT_EQ(stats.tx_packets, 1);
    EXPECT_EQ(stats.tx_bytes, 200);
    EXPECT_EQ(stats.tx_errors, 0);
    EXPECT_EQ(stats.tx_drops, 1);

    ifManager.clear_port_stats(test_port_id);
    stats = ifManager.get_port_stats(test_port_id);
    EXPECT_EQ(stats.rx_packets, 0);
    EXPECT_EQ(stats.tx_packets, 0);
    EXPECT_EQ(stats.rx_bytes, 0);
    EXPECT_EQ(stats.tx_bytes, 0);
    EXPECT_EQ(stats.rx_errors, 0);
    EXPECT_EQ(stats.tx_errors, 0);
    EXPECT_EQ(stats.rx_drops, 0);
    EXPECT_EQ(stats.tx_drops, 0);
}

// --- Link State Notification Tests ---
struct LinkStateTracker {
    bool up_called = false;
    bool down_called = false;
    uint32_t up_port_id = 0;
    uint32_t down_port_id = 0;

    void link_up_handler(uint32_t port_id) {
        up_called = true;
        up_port_id = port_id;
    }
    void link_down_handler(uint32_t port_id) {
        down_called = true;
        down_port_id = port_id;
    }
};

TEST_F(InterfaceManagerTest, LinkStateNotification) {
    LinkStateTracker tracker;

    ifManager.on_link_up(std::bind(&LinkStateTracker::link_up_handler, &tracker, std::placeholders::_1));
    ifManager.on_link_down(std::bind(&LinkStateTracker::link_down_handler, &tracker, std::placeholders::_1));

    // Simulate link up
    ifManager.simulate_port_link_up(test_port_id);
    EXPECT_TRUE(tracker.up_called);
    EXPECT_EQ(tracker.up_port_id, test_port_id);
    EXPECT_TRUE(ifManager.is_port_link_up(test_port_id));
    tracker.up_called = false; // Reset for next check

    // Simulate link down
    ifManager.simulate_port_link_down(test_port_id);
    EXPECT_TRUE(tracker.down_called);
    EXPECT_EQ(tracker.down_port_id, test_port_id);
    EXPECT_FALSE(ifManager.is_port_link_up(test_port_id));
}

// --- Error Handling/Boundary Condition Tests ---
TEST_F(InterfaceManagerTest, ConfigureNonExistentPort) {
    uint32_t non_existent_port = 999;
    netflow::InterfaceManager::PortConfig config;
    // configure_port creates the port if it doesn't exist, so this is normal operation.
    // We can check if it's actually created.
    ASSERT_FALSE(ifManager.get_port_config(non_existent_port).has_value());
    ifManager.configure_port(non_existent_port, config);
    ASSERT_TRUE(ifManager.get_port_config(non_existent_port).has_value());
}

TEST_F(InterfaceManagerTest, GetStatsForNonExistentPort) {
    uint32_t non_existent_port = 998;
    // get_port_stats returns default (zeroed) stats if port not found.
    netflow::InterfaceManager::PortStats stats = ifManager.get_port_stats(non_existent_port);
    EXPECT_EQ(stats.rx_packets, 0);
    EXPECT_EQ(stats.tx_bytes, 0);
}

TEST_F(InterfaceManagerTest, GetConfigForNonExistentPort) {
    uint32_t non_existent_port = 997;
    EXPECT_FALSE(ifManager.get_port_config(non_existent_port).has_value());
}
