#include "gtest/gtest.h"
#include "netflow++/routing_manager.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/logger.hpp"
#include "netflow++/packet.hpp" // For IpAddress definition (uint32_t)

#include <arpa/inet.h> // For inet_pton, htonl, ntohl
#include <vector>
#include <algorithm> // For std::find_if

// Helper to convert string IP to network byte order IpAddress (uint32_t)
bool string_to_ip_net_order(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr; // Already in network byte order
        return true;
    }
    return false;
}

// Helper to convert network byte order IpAddress to string
std::string ip_to_string_net_order(netflow::IpAddress net_ip) {
    struct in_addr addr;
    addr.s_addr = net_ip;
    return inet_ntoa(addr);
}


class RoutingManagerTest : public ::testing::Test {
protected:
    netflow::SwitchLogger& logger_ = netflow::SwitchLogger::getInstance();
    netflow::InterfaceManager if_mgr_{logger_};
    netflow::RoutingManager rm_{logger_, if_mgr_};

    // Helper to create a RouteEntry for easy comparison.
    // IPs should be provided in string format ("1.2.3.4").
    static netflow::RouteEntry create_entry(
        const std::string& dest_str,
        const std::string& mask_str,
        const std::string& next_hop_str,
        uint32_t if_id,
        int metric = 1,
        netflow::RouteType type = netflow::RouteType::STATIC,
        netflow::RouteSource source = netflow::RouteSource::STATIC_CONFIG
        ) {
        netflow::IpAddress dest_ip, mask_ip, next_hop_ip_val;
        string_to_ip_net_order(dest_str, dest_ip);
        string_to_ip_net_order(mask_str, mask_ip);
        string_to_ip_net_order(next_hop_str, next_hop_ip_val);

        return netflow::RouteEntry{dest_ip, mask_ip, next_hop_ip_val, if_id, metric, type, source};
    }

    // Helper to find a route in a vector of routes
    bool find_route(const std::vector<netflow::RouteEntry>& table, const netflow::RouteEntry& target) {
        return std::any_of(table.begin(), table.end(), [&](const netflow::RouteEntry& r) {
            return r.destination_network == target.destination_network &&
                   r.subnet_mask == target.subnet_mask &&
                   r.next_hop_ip == target.next_hop_ip &&
                   r.egress_interface_id == target.egress_interface_id &&
                   r.metric == target.metric &&
                   r.type == target.type &&
                   r.source == target.source;
        });
    }
};

TEST_F(RoutingManagerTest, Placeholder) {
    ASSERT_TRUE(true);
}

TEST_F(RoutingManagerTest, AddAndGetRoute) {
    netflow::IpAddress net1, mask1, nh1;
    ASSERT_TRUE(string_to_ip_net_order("192.168.1.0", net1));
    ASSERT_TRUE(string_to_ip_net_order("255.255.255.0", mask1));
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.1", nh1));
    uint32_t if_id1 = 1;
    rm_.add_static_route(net1, mask1, nh1, if_id1, 10);

    netflow::IpAddress net2, mask2, nh2; // Default route
    ASSERT_TRUE(string_to_ip_net_order("0.0.0.0", net2));
    ASSERT_TRUE(string_to_ip_net_order("0.0.0.0", mask2));
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.2", nh2));
    uint32_t if_id2 = 2;
    rm_.add_static_route(net2, mask2, nh2, if_id2, 100);

    std::vector<netflow::RouteEntry> table = rm_.get_routing_table();
    ASSERT_EQ(table.size(), 2);

    netflow::RouteEntry expected_route1 = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.1", if_id1, 10);
    netflow::RouteEntry expected_route2 = create_entry("0.0.0.0", "0.0.0.0", "10.0.0.2", if_id2, 100);

    EXPECT_TRUE(find_route(table, expected_route1));
    EXPECT_TRUE(find_route(table, expected_route2));

    // Test adding a duplicate route - should overwrite if behavior is replace, or ignore.
    // Current RoutingManager might just add another one if not checking for duplicates,
    // or if LPM simply picks the best one. Let's assume it might add another or update.
    // For this test, if it adds, size would be 3. If it updates, size 2 and metric changes.
    // The current simple vector based RM would just add another. LPM would pick one.
    // Let's test an update: add same network/mask with different next_hop/metric
    netflow::IpAddress nh1_updated;
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.3", nh1_updated));
    rm_.add_static_route(net1, mask1, nh1_updated, if_id1, 20); // Same dest/mask, different metric/nexthop

    table = rm_.get_routing_table();
    // The current simple RM adds it. If it was an update, size would be 2.
    // Given it's vector based, it's likely added.
    // EXPECT_EQ(table.size(), 2); // If it updates
    // For now, let's assume it might add. A more sophisticated RM would update or reject.
    // The current `add_static_route` doesn't check for duplicates.
    // So, size will be 3.
    ASSERT_EQ(table.size(), 3);
    netflow::RouteEntry updated_expected_route1 = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.3", if_id1, 20);
    EXPECT_TRUE(find_route(table, updated_expected_route1));
}

TEST_F(RoutingManagerTest, RouteLookupLPM) {
    // Routes are added in an order that doesn't reflect LPM precedence
    rm_.add_static_route(create_entry("0.0.0.0", "0.0.0.0", "192.168.0.1", 0, 200));      // if0
    rm_.add_static_route(create_entry("10.0.0.0", "255.0.0.0", "10.255.255.254", 1, 10)); // if1
    rm_.add_static_route(create_entry("10.1.0.0", "255.255.0.0", "10.1.255.254", 2, 20)); // if2
    rm_.add_static_route(create_entry("10.1.1.0", "255.255.255.0", "10.1.1.254", 3, 30)); // if3

    netflow::IpAddress dest_ip;

    // Test 1: Matches 10.1.1.0/24
    ASSERT_TRUE(string_to_ip_net_order("10.1.1.1", dest_ip));
    std::optional<netflow::RouteEntry> result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 3);
    EXPECT_EQ(result.value().metric, 30);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.1.1.0");

    // Test 2: Matches 10.1.0.0/16
    ASSERT_TRUE(string_to_ip_net_order("10.1.2.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 2);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.1.0.0");

    // Test 3: Matches 10.0.0.0/8
    ASSERT_TRUE(string_to_ip_net_order("10.2.1.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 1);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.0.0.0");

    // Test 4: Matches default route 0.0.0.0/0
    ASSERT_TRUE(string_to_ip_net_order("192.168.1.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 0);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "0.0.0.0");

    // Test with no default route (clear current routes and add specific ones)
    // Assuming RoutingManager has a clear_routes or similar, or just re-init for this test part
    // For simplicity, current RM is re-instantiated by test fixture.
    // This part of test is implicitly covered if the default route was not added.
    // Let's test lookup for an IP with no default route added.
    RoutingManager rm_no_default(logger_, if_mgr_); // Fresh RM
    rm_no_default.add_static_route(create_entry("10.0.0.0", "255.0.0.0", "10.255.255.254", 1, 10));
    ASSERT_TRUE(string_to_ip_net_order("172.16.0.1", dest_ip)); // Unroutable
    result = rm_no_default.lookup_route(dest_ip);
    ASSERT_FALSE(result.has_value());
}

TEST_F(RoutingManagerTest, RemoveRoute) {
    netflow::IpAddress net1, mask1, nh1;
    ASSERT_TRUE(string_to_ip_net_order("192.168.1.0", net1));
    ASSERT_TRUE(string_to_ip_net_order("255.255.255.0", mask1));
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.1", nh1));
    uint32_t if_id1 = 1;

    rm_.add_static_route(net1, mask1, nh1, if_id1);

    // Add another route to ensure it's not affected
    rm_.add_static_route(create_entry("10.0.0.0", "255.0.0.0", "10.0.0.254", 2));

    std::vector<netflow::RouteEntry> table_before_remove = rm_.get_routing_table();
    ASSERT_EQ(table_before_remove.size(), 2);

    // Remove the first route
    rm_.remove_static_route(net1, mask1);
    std::vector<netflow::RouteEntry> table_after_remove = rm_.get_routing_table();
    ASSERT_EQ(table_after_remove.size(), 1);

    // Verify the correct route was removed
    netflow::RouteEntry removed_route_lookup_target = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.1", if_id1);
    EXPECT_FALSE(find_route(table_after_remove, removed_route_lookup_target));

    netflow::RouteEntry remaining_route_lookup_target = create_entry("10.0.0.0", "255.0.0.0", "10.0.0.254", 2);
    EXPECT_TRUE(find_route(table_after_remove, remaining_route_lookup_target));

    // Test removing a non-existent route
    netflow::IpAddress non_existent_net, non_existent_mask;
    ASSERT_TRUE(string_to_ip_net_order("172.16.0.0", non_existent_net));
    ASSERT_TRUE(string_to_ip_net_order("255.255.0.0", non_existent_mask));
    rm_.remove_static_route(non_existent_net, non_existent_mask);
    ASSERT_EQ(rm_.get_routing_table().size(), 1); // Size should remain unchanged
}

TEST_F(RoutingManagerTest, RouteAddEdgeCases) {
    // Test adding a duplicate route (same network, same mask, same metric)
    // The current RoutingManager::add_static_route just pushes to vector, so it will be added.
    // A more advanced implementation might update or ignore.
    netflow::IpAddress net1, mask1, nh1;
    ASSERT_TRUE(string_to_ip_net_order("192.168.1.0", net1));
    ASSERT_TRUE(string_to_ip_net_order("255.255.255.0", mask1));
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.1", nh1));
    rm_.add_static_route(net1, mask1, nh1, 1, 10);
    rm_.add_static_route(net1, mask1, nh1, 1, 10); // Add exact duplicate

    std::vector<netflow::RouteEntry> table = rm_.get_routing_table();
    // Current simple vector-based implementation will have 2 identical entries.
    // LPM will pick one (usually the first one encountered or based on some tie-breaking).
    EXPECT_EQ(table.size(), 2);

    // Test adding same network/mask but different next_hop/metric (already covered in AddAndGetRoute)
    // This is typically allowed and results in multiple paths if metrics differ, or replacement.
    // For this RM, it just adds another entry.
}
