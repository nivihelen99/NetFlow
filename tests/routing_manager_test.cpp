#include "gtest/gtest.h"
#include "netflow++/routing_manager.hpp"
#include "netflow++/packet.hpp" // For IpAddress
#include <memory> // For std::unique_ptr

using namespace netflow;

class RoutingManagerTest : public ::testing::Test {
protected:
    std::unique_ptr<RoutingManager> rm;
    IpAddress network1_addr;
    IpAddress network1_mask;
    IpAddress network1_next_hop;
    uint32_t network1_if_id;

    IpAddress network2_addr; // More specific route
    IpAddress network2_mask;
    IpAddress network2_next_hop;
    uint32_t network2_if_id;

    IpAddress default_route_addr;
    IpAddress default_route_mask;
    IpAddress default_route_next_hop;
    uint32_t default_route_if_id;


    void SetUp() override {
        rm = std::make_unique<RoutingManager>(); // Ensure clean state for each test

        network1_addr = stringToIpAddress("192.168.1.0");
        network1_mask = stringToIpAddress("255.255.255.0"); // /24
        network1_next_hop = stringToIpAddress("10.0.0.1");
        network1_if_id = 1;

        network2_addr = stringToIpAddress("192.168.1.128");
        network2_mask = stringToIpAddress("255.255.255.128"); // /25
        network2_next_hop = stringToIpAddress("10.0.0.2");
        network2_if_id = 2;

        default_route_addr = stringToIpAddress("0.0.0.0");
        default_route_mask = stringToIpAddress("0.0.0.0"); // /0
        default_route_next_hop = stringToIpAddress("10.0.0.3");
        default_route_if_id = 3;
    }
};

TEST_F(RoutingManagerTest, AddAndLookupRoute) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id);
    auto route = rm->lookup_route(stringToIpAddress("192.168.1.10"));
    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(route->next_hop_ip, network1_next_hop);
    EXPECT_EQ(route->egress_interface_id, network1_if_id);
}

TEST_F(RoutingManagerTest, LookupNonExistentRoute) {
    auto route = rm->lookup_route(stringToIpAddress("172.16.0.1"));
    EXPECT_FALSE(route.has_value());
}

TEST_F(RoutingManagerTest, AddMultipleRoutesAndLookup) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id);
    rm->add_static_route(default_route_addr, default_route_mask, default_route_next_hop, default_route_if_id);

    // Test lookup for network1
    auto route1 = rm->lookup_route(stringToIpAddress("192.168.1.10"));
    ASSERT_TRUE(route1.has_value());
    EXPECT_EQ(route1->next_hop_ip, network1_next_hop);
    EXPECT_EQ(route1->egress_interface_id, network1_if_id);

    // Test lookup for an address covered by default route
    auto route_default = rm->lookup_route(stringToIpAddress("100.100.100.1"));
    ASSERT_TRUE(route_default.has_value());
    EXPECT_EQ(route_default->next_hop_ip, default_route_next_hop);
    EXPECT_EQ(route_default->egress_interface_id, default_route_if_id);
}

TEST_F(RoutingManagerTest, LongestPrefixMatch) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id); // /24
    rm->add_static_route(network2_addr, network2_mask, network2_next_hop, network2_if_id); // /25 (more specific)

    // Lookup an IP that falls into network2 (more specific)
    auto route_specific = rm->lookup_route(stringToIpAddress("192.168.1.130"));
    ASSERT_TRUE(route_specific.has_value());
    EXPECT_EQ(route_specific->next_hop_ip, network2_next_hop);
    EXPECT_EQ(route_specific->egress_interface_id, network2_if_id);
    EXPECT_EQ(route_specific->destination_network, network2_addr);
    EXPECT_EQ(route_specific->subnet_mask, network2_mask);


    // Lookup an IP in network1 but not network2
    auto route_general = rm->lookup_route(stringToIpAddress("192.168.1.10"));
    ASSERT_TRUE(route_general.has_value());
    EXPECT_EQ(route_general->next_hop_ip, network1_next_hop);
    EXPECT_EQ(route_general->egress_interface_id, network1_if_id);
    EXPECT_EQ(route_general->destination_network, network1_addr);
    EXPECT_EQ(route_general->subnet_mask, network1_mask);
}

TEST_F(RoutingManagerTest, RemoveRoute) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id);
    auto route_before_remove = rm->lookup_route(stringToIpAddress("192.168.1.10"));
    ASSERT_TRUE(route_before_remove.has_value());

    rm->remove_static_route(network1_addr, network1_mask);
    auto route_after_remove = rm->lookup_route(stringToIpAddress("192.168.1.10"));
    EXPECT_FALSE(route_after_remove.has_value());
}

TEST_F(RoutingManagerTest, AddRouteWithZeroNextHop) {
    IpAddress directly_connected_network = stringToIpAddress("192.168.5.0");
    IpAddress directly_connected_mask = stringToIpAddress("255.255.255.0");
    IpAddress zero_next_hop = stringToIpAddress("0.0.0.0");
    uint32_t if_id = 5;

    rm->add_static_route(directly_connected_network, directly_connected_mask, zero_next_hop, if_id);
    auto route = rm->lookup_route(stringToIpAddress("192.168.5.50"));
    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(route->next_hop_ip, zero_next_hop);
    EXPECT_EQ(route->destination_network, directly_connected_network);
    EXPECT_EQ(route->subnet_mask, directly_connected_mask);
    EXPECT_EQ(route->egress_interface_id, if_id);
}

TEST_F(RoutingManagerTest, GetRoutingTable) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id, 10);
    rm->add_static_route(network2_addr, network2_mask, network2_next_hop, network2_if_id, 5); // More specific, better metric
    rm->add_static_route(default_route_addr, default_route_mask, default_route_next_hop, default_route_if_id, 100);

    auto table = rm->get_routing_table();
    ASSERT_EQ(table.size(), 3);

    // RoutingManager sorts by longest prefix match, then metric, then destination IP.
    // Expected order:
    // 1. network2 (/25, metric 5)
    // 2. network1 (/24, metric 10)
    // 3. default_route (/0, metric 100)

    EXPECT_EQ(table[0].destination_network, network2_addr);
    EXPECT_EQ(table[0].subnet_mask, network2_mask);
    EXPECT_EQ(table[0].next_hop_ip, network2_next_hop);
    EXPECT_EQ(table[0].egress_interface_id, network2_if_id);
    EXPECT_EQ(table[0].metric, 5);

    EXPECT_EQ(table[1].destination_network, network1_addr);
    EXPECT_EQ(table[1].subnet_mask, network1_mask);
    EXPECT_EQ(table[1].next_hop_ip, network1_next_hop);
    EXPECT_EQ(table[1].egress_interface_id, network1_if_id);
    EXPECT_EQ(table[1].metric, 10);

    EXPECT_EQ(table[2].destination_network, default_route_addr);
    EXPECT_EQ(table[2].subnet_mask, default_route_mask);
    EXPECT_EQ(table[2].next_hop_ip, default_route_next_hop);
    EXPECT_EQ(table[2].egress_interface_id, default_route_if_id);
    EXPECT_EQ(table[2].metric, 100);
}

TEST_F(RoutingManagerTest, RemoveNonExistentRoute) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id);
    // Try to remove a route that doesn't exist
    rm->remove_static_route(stringToIpAddress("10.10.10.0"), stringToIpAddress("255.255.255.0"));

    auto table = rm->get_routing_table();
    ASSERT_EQ(table.size(), 1); // Should still have network1
    EXPECT_EQ(table[0].destination_network, network1_addr);
}

TEST_F(RoutingManagerTest, AddDuplicateRoute) {
    rm->add_static_route(network1_addr, network1_mask, network1_next_hop, network1_if_id, 10);
    // Add the same route again, possibly with a different metric or next hop
    // The current implementation should overwrite based on destination and mask.
    // If metric/next_hop is different, it's an update. If identical, no change in size.
    rm->add_static_route(network1_addr, network1_mask, stringToIpAddress("10.0.0.100"), network1_if_id + 1, 5);

    auto table = rm->get_routing_table();
    ASSERT_EQ(table.size(), 1);
    EXPECT_EQ(table[0].next_hop_ip, stringToIpAddress("10.0.0.100"));
    EXPECT_EQ(table[0].egress_interface_id, network1_if_id + 1);
    EXPECT_EQ(table[0].metric, 5);
}

TEST_F(RoutingManagerTest, RouteLookupOrderWithSamePrefixLength) {
    // Routes with same prefix length, different metrics
    IpAddress routeA_addr = stringToIpAddress("192.168.3.0");
    IpAddress routeA_mask = stringToIpAddress("255.255.255.0"); // /24
    IpAddress routeA_next_hop = stringToIpAddress("10.0.3.1");
    uint32_t routeA_if_id = 13;

    IpAddress routeB_addr = stringToIpAddress("192.168.3.0"); // Same dest/mask as A
    IpAddress routeB_mask = stringToIpAddress("255.255.255.0"); // /24
    IpAddress routeB_next_hop = stringToIpAddress("10.0.3.2");
    uint32_t routeB_if_id = 14;

    rm->add_static_route(routeA_addr, routeA_mask, routeA_next_hop, routeA_if_id, 20);
    // Adding B should update A because dest/mask are identical.
    // Let's test adding a different route but with same prefix length and metric, see if dest IP sorts it

    IpAddress routeC_addr = stringToIpAddress("192.168.4.0");
    IpAddress routeC_mask = stringToIpAddress("255.255.255.0"); // /24
    IpAddress routeC_next_hop = stringToIpAddress("10.0.4.1");
    uint32_t routeC_if_id = 15;
    rm->add_static_route(routeC_addr, routeC_mask, routeC_next_hop, routeC_if_id, 10);


    // Add routeA again but with a better metric, should update
    rm->add_static_route(routeA_addr, routeA_mask, routeA_next_hop, routeA_if_id, 10);


    auto table = rm->get_routing_table();
    ASSERT_EQ(table.size(), 2); // routeA (updated) and routeC

    // Expected: routeA (192.168.3.0/24 metric 10), then routeC (192.168.4.0/24 metric 10)
    // Sorted by prefix (same), then metric (same), then destination IP
    EXPECT_EQ(table[0].destination_network, routeA_addr);
    EXPECT_EQ(table[0].metric, 10);

    EXPECT_EQ(table[1].destination_network, routeC_addr);
    EXPECT_EQ(table[1].metric, 10);

    // Check lookup picks the one with metric 10 for 192.168.3.x
    auto lookup = rm->lookup_route(stringToIpAddress("192.168.3.100"));
    ASSERT_TRUE(lookup.has_value());
    EXPECT_EQ(lookup->metric, 10);
    EXPECT_EQ(lookup->next_hop_ip, routeA_next_hop);
}
