#include "gtest/gtest.h"
#include "netflow++/routing_manager.hpp"
#include "netflow++/logger.hpp"
#include "netflow++/packet.hpp"

#include <arpa/inet.h>
#include <vector>
#include <algorithm>

// Helper to convert string IP to network byte order IpAddress (uint32_t)
bool string_to_ip_net_order(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
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
    netflow::RoutingManager rm_{};

    static netflow::RouteEntry create_entry(
        const std::string& dest_str,
        const std::string& mask_str,
        const std::string& next_hop_str,
        uint32_t if_id,
        int metric = 1
        ) {
        netflow::IpAddress dest_ip, mask_ip, next_hop_ip_val;
        string_to_ip_net_order(dest_str, dest_ip);
        string_to_ip_net_order(mask_str, mask_ip);
        string_to_ip_net_order(next_hop_str, next_hop_ip_val);

        return netflow::RouteEntry{dest_ip, mask_ip, next_hop_ip_val, if_id, metric};
    }

    bool find_route(const std::vector<netflow::RouteEntry>& table, const netflow::RouteEntry& target) {
        return std::any_of(table.begin(), table.end(), [&](const netflow::RouteEntry& r) {
            return r.destination_network == target.destination_network &&
                   r.subnet_mask == target.subnet_mask &&
                   r.next_hop_ip == target.next_hop_ip &&
                   r.egress_interface_id == target.egress_interface_id &&
                   r.metric == target.metric;
        });
    }

    // Helper to add route using strings for convenience in tests
    void add_route_str(const std::string& dest_str, const std::string& mask_str,
                       const std::string& next_hop_str, uint32_t if_id, int metric = 1) {
        netflow::IpAddress dest_ip, mask_ip, next_hop_ip_val;
        ASSERT_TRUE(string_to_ip_net_order(dest_str, dest_ip));
        ASSERT_TRUE(string_to_ip_net_order(mask_str, mask_ip));
        ASSERT_TRUE(string_to_ip_net_order(next_hop_str, next_hop_ip_val));
        rm_.add_static_route(dest_ip, mask_ip, next_hop_ip_val, if_id, metric);
    }
};

TEST_F(RoutingManagerTest, Placeholder) {
    ASSERT_TRUE(true);
}

TEST_F(RoutingManagerTest, AddAndGetRoute) {
    add_route_str("192.168.1.0", "255.255.255.0", "10.0.0.1", 1, 10);
    add_route_str("0.0.0.0", "0.0.0.0", "10.0.0.2", 2, 100);

    std::vector<netflow::RouteEntry> table = rm_.get_routing_table();
    ASSERT_EQ(table.size(), 2);

    netflow::RouteEntry expected_route1 = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.1", 1, 10);
    netflow::RouteEntry expected_route2 = create_entry("0.0.0.0", "0.0.0.0", "10.0.0.2", 2, 100);

    EXPECT_TRUE(find_route(table, expected_route1));
    EXPECT_TRUE(find_route(table, expected_route2));

    add_route_str("192.168.1.0", "255.255.255.0", "10.0.0.3", 1, 20);

    table = rm_.get_routing_table();
    ASSERT_EQ(table.size(), 3);
    netflow::RouteEntry updated_expected_route1 = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.3", 1, 20);
    EXPECT_TRUE(find_route(table, updated_expected_route1));
}

TEST_F(RoutingManagerTest, RouteLookupLPM) {
    add_route_str("0.0.0.0", "0.0.0.0", "192.168.0.1", 0, 200);
    add_route_str("10.0.0.0", "255.0.0.0", "10.255.255.254", 1, 10);
    add_route_str("10.1.0.0", "255.255.0.0", "10.1.255.254", 2, 20);
    add_route_str("10.1.1.0", "255.255.255.0", "10.1.1.254", 3, 30);

    netflow::IpAddress dest_ip;

    ASSERT_TRUE(string_to_ip_net_order("10.1.1.1", dest_ip));
    std::optional<netflow::RouteEntry> result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 3);
    EXPECT_EQ(result.value().metric, 30);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.1.1.0");

    ASSERT_TRUE(string_to_ip_net_order("10.1.2.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 2);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.1.0.0");

    ASSERT_TRUE(string_to_ip_net_order("10.2.1.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 1);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "10.0.0.0");

    ASSERT_TRUE(string_to_ip_net_order("192.168.1.1", dest_ip));
    result = rm_.lookup_route(dest_ip);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().egress_interface_id, 0);
    EXPECT_EQ(ip_to_string_net_order(result.value().destination_network), "0.0.0.0");

    netflow::RoutingManager rm_no_default;
    netflow::IpAddress net_10, mask_10, nh_10;
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.0", net_10));
    ASSERT_TRUE(string_to_ip_net_order("255.0.0.0", mask_10));
    ASSERT_TRUE(string_to_ip_net_order("10.255.255.254", nh_10));
    rm_no_default.add_static_route(net_10, mask_10, nh_10, 1, 10);

    ASSERT_TRUE(string_to_ip_net_order("172.16.0.1", dest_ip));
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
    add_route_str("10.0.0.0", "255.0.0.0", "10.0.0.254", 2);

    std::vector<netflow::RouteEntry> table_before_remove = rm_.get_routing_table();
    ASSERT_EQ(table_before_remove.size(), 2);

    rm_.remove_static_route(net1, mask1);
    std::vector<netflow::RouteEntry> table_after_remove = rm_.get_routing_table();
    ASSERT_EQ(table_after_remove.size(), 1);

    netflow::RouteEntry removed_route_lookup_target = create_entry("192.168.1.0", "255.255.255.0", "10.0.0.1", if_id1);
    EXPECT_FALSE(find_route(table_after_remove, removed_route_lookup_target));

    netflow::RouteEntry remaining_route_lookup_target = create_entry("10.0.0.0", "255.0.0.0", "10.0.0.254", 2);
    EXPECT_TRUE(find_route(table_after_remove, remaining_route_lookup_target));

    netflow::IpAddress non_existent_net, non_existent_mask;
    ASSERT_TRUE(string_to_ip_net_order("172.16.0.0", non_existent_net));
    ASSERT_TRUE(string_to_ip_net_order("255.255.0.0", non_existent_mask));
    rm_.remove_static_route(non_existent_net, non_existent_mask);
    ASSERT_EQ(rm_.get_routing_table().size(), 1);
}

TEST_F(RoutingManagerTest, RouteAddEdgeCases) {
    netflow::IpAddress net1, mask1, nh1;
    ASSERT_TRUE(string_to_ip_net_order("192.168.1.0", net1));
    ASSERT_TRUE(string_to_ip_net_order("255.255.255.0", mask1));
    ASSERT_TRUE(string_to_ip_net_order("10.0.0.1", nh1));
    rm_.add_static_route(net1, mask1, nh1, 1, 10);
    rm_.add_static_route(net1, mask1, nh1, 1, 10);

    std::vector<netflow::RouteEntry> table = rm_.get_routing_table();
    EXPECT_EQ(table.size(), 1);
}
