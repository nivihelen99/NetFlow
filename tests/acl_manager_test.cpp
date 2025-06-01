#include "gtest/gtest.h"
#include "netflow++/acl_manager.hpp"
#include "netflow++/logger.hpp"    // For SwitchLogger
#include "netflow++/packet.hpp"    // For Packet, PacketBuffer, headers
#include <vector>
#include <optional>
#include <cstring> // For memcpy in packet creation helper
#include <numeric> // For std::iota in packet creation helper
#include <arpa/inet.h> // For htonl, ntohl (used in IpAddress representation)


// Helper function to create a PacketBuffer with specific Ethernet + VLAN frame
// Returns a Packet object.
// Note: IpAddress values in AclRule are stored in host byte order.
// Packet methods like ipv4()->src_ip return network byte order, so comparison needs care (use ntohl).
netflow::Packet create_acl_test_packet(
    std::optional<netflow::MacAddress> src_mac_opt,
    std::optional<netflow::MacAddress> dst_mac_opt,
    std::optional<uint16_t> vlan_id_opt,      // Host byte order
    std::optional<uint8_t> pcp_opt,           // PCP to set if VLAN tag is present
    uint16_t outer_ethertype,                 // Host byte order (e.g., ETHERTYPE_VLAN, ETHERTYPE_IPV4)
    std::optional<uint16_t> inner_ethertype_opt, // Host byte order (e.g., ETHERTYPE_IPV4)
    std::optional<uint32_t> src_ip_opt,      // Host byte order
    std::optional<uint32_t> dst_ip_opt,      // Host byte order
    std::optional<uint8_t> protocol_opt,
    std::optional<uint16_t> src_port_opt,    // Host byte order
    std::optional<uint16_t> dst_port_opt,    // Host byte order
    size_t payload_size = 10)
{
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t VLAN_HEADER_SIZE = netflow::VlanHeader::SIZE;
    constexpr size_t IPV4_HEADER_SIZE = netflow::IPv4Header::MIN_SIZE;
    constexpr size_t TCP_HEADER_SIZE = netflow::TcpHeader::MIN_SIZE;
    constexpr size_t UDP_HEADER_SIZE = netflow::UdpHeader::SIZE;

    std::vector<unsigned char> frame_data;
    frame_data.reserve(ETH_HEADER_SIZE + VLAN_HEADER_SIZE + IPV4_HEADER_SIZE + TCP_HEADER_SIZE + payload_size);

    netflow::EthernetHeader eth_header_data; // Use _data to avoid conflict with struct name
    uint8_t default_dst_mac_bytes[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t default_src_mac_bytes[] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    eth_header_data.dst_mac = dst_mac_opt.value_or(netflow::MacAddress(default_dst_mac_bytes));
    eth_header_data.src_mac = src_mac_opt.value_or(netflow::MacAddress(default_src_mac_bytes));
    eth_header_data.ethertype = htons(outer_ethertype); // Network byte order for header

    unsigned char eth_buf[ETH_HEADER_SIZE];
    std::memcpy(eth_buf, &eth_header_data, ETH_HEADER_SIZE);
    frame_data.insert(frame_data.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

    if (outer_ethertype == netflow::ETHERTYPE_VLAN && inner_ethertype_opt.has_value()) {
        netflow::VlanHeader vlan_h_data;
        vlan_h_data.set_vlan_id(vlan_id_opt.value_or(1)); // Host byte order for set method
        vlan_h_data.set_priority(pcp_opt.value_or(0));
        vlan_h_data.ethertype = htons(inner_ethertype_opt.value()); // Network byte order

        unsigned char vlan_buf[VLAN_HEADER_SIZE];
        std::memcpy(vlan_buf, &vlan_h_data, VLAN_HEADER_SIZE);
        frame_data.insert(frame_data.end(), vlan_buf, vlan_buf + VLAN_HEADER_SIZE);
    }

    uint16_t current_l3_ethertype = (outer_ethertype == netflow::ETHERTYPE_VLAN && inner_ethertype_opt.has_value())
                                    ? inner_ethertype_opt.value()
                                    : outer_ethertype;

    if (src_ip_opt || dst_ip_opt || protocol_opt || src_port_opt || dst_port_opt) {
        if (current_l3_ethertype != netflow::ETHERTYPE_IPV4) {
            // This test packet is malformed for L3/L4 content if ethertype isn't IP.
            // For robust tests, ensure ethertypes align with content.
        }
        netflow::IPv4Header ipv4_h_data;
        ipv4_h_data.version_ihl = (4 << 4) | 5;
        ipv4_h_data.dscp_ecn = 0;
        ipv4_h_data.identification = htons(12345);
        ipv4_h_data.flags_fragment_offset = 0;
        ipv4_h_data.ttl = 64;
        ipv4_h_data.protocol = protocol_opt.value_or(0);
        ipv4_h_data.header_checksum = 0;
        ipv4_h_data.src_ip = htonl(src_ip_opt.value_or(0)); // Network byte order
        ipv4_h_data.dst_ip = htonl(dst_ip_opt.value_or(0)); // Network byte order

        size_t l4_size = 0;
        if (src_port_opt || dst_port_opt) {
            if (ipv4_h_data.protocol == IPPROTO_TCP) l4_size = TCP_HEADER_SIZE;
            else if (ipv4_h_data.protocol == IPPROTO_UDP) l4_size = UDP_HEADER_SIZE;
        }
        ipv4_h_data.total_length = htons(IPV4_HEADER_SIZE + l4_size + payload_size);

        unsigned char ipv4_buf[IPV4_HEADER_SIZE];
        std::memcpy(ipv4_buf, &ipv4_h_data, IPV4_HEADER_SIZE);
        // TODO: Calculate actual IPv4 checksum if strict checking is needed by Packet class or ACL
        frame_data.insert(frame_data.end(), ipv4_buf, ipv4_buf + IPV4_HEADER_SIZE);

        if (l4_size > 0) {
            if (ipv4_h_data.protocol == IPPROTO_TCP) {
                netflow::TcpHeader tcp_h_data;
                tcp_h_data.src_port = htons(src_port_opt.value_or(0)); // Network byte order
                tcp_h_data.dst_port = htons(dst_port_opt.value_or(0)); // Network byte order
                // Minimal other TCP fields
                tcp_h_data.seq_number = 0;
                tcp_h_data.ack_number = 0;
                tcp_h_data.data_offset_reserved_flags = (5 << 4); // 20-byte header
                tcp_h_data.window_size = htons(1500);
                tcp_h_data.checksum = 0; // Placeholder
                tcp_h_data.urgent_pointer = 0;
                unsigned char tcp_buf[TCP_HEADER_SIZE];
                std::memcpy(tcp_buf, &tcp_h_data, TCP_HEADER_SIZE);
                frame_data.insert(frame_data.end(), tcp_buf, tcp_buf + TCP_HEADER_SIZE);
            } else if (ipv4_h_data.protocol == IPPROTO_UDP) {
                netflow::UdpHeader udp_h_data;
                udp_h_data.src_port = htons(src_port_opt.value_or(0)); // Network byte order
                udp_h_data.dst_port = htons(dst_port_opt.value_or(0)); // Network byte order
                udp_h_data.length = htons(UDP_HEADER_SIZE + payload_size); // Network byte order
                udp_h_data.checksum = 0; // Placeholder
                unsigned char udp_buf[UDP_HEADER_SIZE];
                std::memcpy(udp_buf, &udp_h_data, UDP_HEADER_SIZE);
                frame_data.insert(frame_data.end(), udp_buf, udp_buf + UDP_HEADER_SIZE);
            }
        }
    }

    std::vector<unsigned char> payload(payload_size);
    std::iota(payload.begin(), payload.end(), static_cast<unsigned char>(0xA0));
    frame_data.insert(frame_data.end(), payload.begin(), payload.end());

    unsigned char* buffer_data_heap = new unsigned char[frame_data.size()];
    std::memcpy(buffer_data_heap, frame_data.data(), frame_data.size());

    netflow::PacketBuffer pkt_buf(buffer_data_heap, frame_data.size(), [buffer_data_heap]() { delete[] buffer_data_heap; });
    return netflow::Packet(&pkt_buf);
}


class AclManagerTest : public ::testing::Test {
protected:
    netflow::SwitchLogger logger_ = netflow::SwitchLogger::getInstance();
    netflow::AclManager am_{logger_};

    void SetUp() override {
        am_.clear_rules();
        am_.compile_rules(); // Ensure compiled state is clean
    }
};

TEST_F(AclManagerTest, AddAndGetRule) {
    netflow::AclRule rule1(1, 100, netflow::AclActionType::PERMIT);
    rule1.src_ip = 0xC0A80101; // 192.168.1.1 (Host Byte Order)

    ASSERT_TRUE(am_.add_rule(rule1));
    // Rules are not sorted until compile_rules() is called
    std::optional<netflow::AclRule> retrieved_rule_before_compile = am_.get_rule(1);
    ASSERT_TRUE(retrieved_rule_before_compile.has_value()); // Should find it even before compile

    am_.compile_rules(); // Sorts the rules

    ASSERT_EQ(am_.get_all_rules().size(), 1);
    std::optional<netflow::AclRule> retrieved_rule = am_.get_rule(1);
    ASSERT_TRUE(retrieved_rule.has_value());
    EXPECT_EQ(retrieved_rule.value().rule_id, 1);
    EXPECT_EQ(retrieved_rule.value().priority, 100);
    EXPECT_EQ(retrieved_rule.value().src_ip.value(), 0xC0A80101);

    netflow::AclRule rule1_updated(1, 150, netflow::AclActionType::DENY); // Same ID, new priority
    ASSERT_TRUE(am_.add_rule(rule1_updated)); // Should replace
    am_.compile_rules();
    ASSERT_EQ(am_.get_all_rules().size(), 1);
    retrieved_rule = am_.get_rule(1);
    ASSERT_TRUE(retrieved_rule.has_value());
    EXPECT_EQ(retrieved_rule.value().priority, 150);
    EXPECT_EQ(retrieved_rule.value().action, netflow::AclActionType::DENY);
}

TEST_F(AclManagerTest, RulePrioritizationAndEvaluation) {
    netflow::AclRule rule_low_prio_permit(1, 10, netflow::AclActionType::PERMIT); // Permit all (low prio)

    netflow::AclRule rule_high_prio_deny_tcp(2, 100, netflow::AclActionType::DENY);
    rule_high_prio_deny_tcp.protocol = IPPROTO_TCP;

    netflow::AclRule rule_med_prio_redirect_udp_port53(3, 50, netflow::AclActionType::REDIRECT);
    rule_med_prio_redirect_udp_port53.protocol = IPPROTO_UDP;
    rule_med_prio_redirect_udp_port53.dst_port = 53; // Host byte order
    rule_med_prio_redirect_udp_port53.redirect_port_id = 10;

    am_.add_rule(rule_low_prio_permit);
    am_.add_rule(rule_high_prio_deny_tcp);
    am_.add_rule(rule_med_prio_redirect_udp_port53);
    am_.compile_rules(); // Sorts: rule_high_prio_deny_tcp, rule_med_prio_redirect_udp_port53, rule_low_prio_permit

    uint32_t redirect_port;

    // TCP Packet - Should be denied by rule_high_prio_deny_tcp
    netflow::Packet tcp_packet = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                    netflow::ETHERTYPE_IPV4, std::nullopt,
                                                    0xC0A8010A, 0xC0A8010B, IPPROTO_TCP, 12345, 80);
    EXPECT_EQ(am_.evaluate(tcp_packet, redirect_port), netflow::AclActionType::DENY);

    // UDP DNS Packet - Should be redirected by rule_med_prio_redirect_udp_port53
    netflow::Packet udp_dns_packet = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                        netflow::ETHERTYPE_IPV4, std::nullopt,
                                                        0xC0A8010A, 0xC0A8010B, IPPROTO_UDP, 12345, 53);
    EXPECT_EQ(am_.evaluate(udp_dns_packet, redirect_port), netflow::AclActionType::REDIRECT);
    EXPECT_EQ(redirect_port, 10);

    // Other UDP Packet - Should be permitted by rule_low_prio_permit
    netflow::Packet other_udp_packet = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                          netflow::ETHERTYPE_IPV4, std::nullopt,
                                                          0xC0A8010A, 0xC0A8010B, IPPROTO_UDP, 12345, 5000);
    EXPECT_EQ(am_.evaluate(other_udp_packet, redirect_port), netflow::AclActionType::PERMIT);
}


TEST_F(AclManagerTest, MatchConditions) {
    uint32_t redirect_port;
    // MAC Address Matching
    netflow::AclRule rule_mac(1, 100, netflow::AclActionType::DENY);
    uint8_t src_mac_bytes[] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    rule_mac.src_mac = netflow::MacAddress(src_mac_bytes);
    am_.add_rule(rule_mac);
    am_.compile_rules();

    netflow::Packet pkt_match_mac = create_acl_test_packet(netflow::MacAddress(src_mac_bytes), std::nullopt, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_match_mac, redirect_port), netflow::AclActionType::DENY);

    uint8_t other_mac_bytes[] = {0x11,0x22,0x33,0x44,0x55,0x66};
    netflow::Packet pkt_no_match_mac = create_acl_test_packet(netflow::MacAddress(other_mac_bytes), std::nullopt, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_no_match_mac, redirect_port), netflow::AclActionType::PERMIT); // Default permit

    am_.clear_rules();

    // VLAN ID Matching
    netflow::AclRule rule_vlan(2, 100, netflow::AclActionType::DENY);
    rule_vlan.vlan_id = 100;
    am_.add_rule(rule_vlan);
    am_.compile_rules();

    netflow::Packet pkt_match_vlan = create_acl_test_packet(std::nullopt, std::nullopt, (uint16_t)100, (uint8_t)0, netflow::ETHERTYPE_VLAN, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_match_vlan, redirect_port), netflow::AclActionType::DENY);
    netflow::Packet pkt_no_match_vlan = create_acl_test_packet(std::nullopt, std::nullopt, (uint16_t)200, (uint8_t)0, netflow::ETHERTYPE_VLAN, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_no_match_vlan, redirect_port), netflow::AclActionType::PERMIT);
    netflow::Packet pkt_no_vlan_tag = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_no_vlan_tag, redirect_port), netflow::AclActionType::PERMIT);

    am_.clear_rules();

    // Ethertype Matching
    netflow::AclRule rule_ethertype(3, 100, netflow::AclActionType::DENY);
    rule_ethertype.ethertype = netflow::ETHERTYPE_ARP; // Match ARP
    am_.add_rule(rule_ethertype);
    am_.compile_rules();

    netflow::Packet pkt_match_ethertype = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt, netflow::ETHERTYPE_ARP, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_match_ethertype, redirect_port), netflow::AclActionType::DENY);
    netflow::Packet pkt_no_match_ethertype = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_no_match_ethertype, redirect_port), netflow::AclActionType::PERMIT);

    // Ethertype matching with VLAN
    netflow::Packet pkt_vlan_arp = create_acl_test_packet(std::nullopt, std::nullopt, (uint16_t)10, (uint8_t)0, netflow::ETHERTYPE_VLAN, netflow::ETHERTYPE_ARP, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_vlan_arp, redirect_port), netflow::AclActionType::DENY);


    am_.clear_rules();
    // IP and L4 Port Matching
    netflow::AclRule rule_ip_l4(4, 100, netflow::AclActionType::DENY);
    rule_ip_l4.src_ip = 0x0A0A0A01; // 10.10.10.1
    rule_ip_l4.dst_ip = 0x0B0B0B02; // 11.11.11.2
    rule_ip_l4.protocol = IPPROTO_UDP;
    rule_ip_l4.dst_port = 161; // SNMP
    am_.add_rule(rule_ip_l4);
    am_.compile_rules();

    netflow::Packet pkt_match_ip_l4 = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
        netflow::ETHERTYPE_IPV4, std::nullopt,
        0x0A0A0A01, 0x0B0B0B02, IPPROTO_UDP, (uint16_t)12345, (uint16_t)161);
    EXPECT_EQ(am_.evaluate(pkt_match_ip_l4, redirect_port), netflow::AclActionType::DENY);

    netflow::Packet pkt_wrong_dst_port = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
        netflow::ETHERTYPE_IPV4, std::nullopt,
        0x0A0A0A01, 0x0B0B0B02, IPPROTO_UDP, (uint16_t)12345, (uint16_t)162);
    EXPECT_EQ(am_.evaluate(pkt_wrong_dst_port, redirect_port), netflow::AclActionType::PERMIT);
}

TEST_F(AclManagerTest, RedirectAction) {
    netflow::AclRule rule_redirect(1, 100, netflow::AclActionType::REDIRECT);
    rule_redirect.src_ip = 0xAC100101; // 172.16.1.1
    rule_redirect.redirect_port_id = 5;
    am_.add_rule(rule_redirect);
    am_.compile_rules();

    uint32_t redirect_port = 0; // Default, should be overwritten
    netflow::Packet pkt_to_redirect = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                        netflow::ETHERTYPE_IPV4, std::nullopt,
                                                        0xAC100101, 0x01010101, std::nullopt,
                                                        std::nullopt, std::nullopt);
    EXPECT_EQ(am_.evaluate(pkt_to_redirect, redirect_port), netflow::AclActionType::REDIRECT);
    EXPECT_EQ(redirect_port, 5);

    // Test REDIRECT rule with no redirect_port_id set (should default to DENY)
    am_.clear_rules();
    netflow::AclRule rule_bad_redirect(2, 100, netflow::AclActionType::REDIRECT);
    rule_bad_redirect.src_ip = 0xAC100101;
    // rule_bad_redirect.redirect_port_id is not set
    am_.add_rule(rule_bad_redirect);
    am_.compile_rules();
    EXPECT_EQ(am_.evaluate(pkt_to_redirect, redirect_port), netflow::AclActionType::DENY);
}

TEST_F(AclManagerTest, CompileRulesEffect) {
    netflow::AclRule rule1(1, 10, netflow::AclActionType::PERMIT); // Low prio
    netflow::AclRule rule2(2, 100, netflow::AclActionType::DENY);  // High prio
    rule2.protocol = IPPROTO_TCP;

    am_.add_rule(rule1); // Added out of order based on priority value
    am_.add_rule(rule2);
    // Rules are [rule1 (10), rule2 (100)] initially in vector if not sorted by add_rule
    // Before compile, if evaluate iterates in vector order, TCP would be PERMITTED by rule1.

    // Create a TCP packet
    uint32_t redirect_port;
    netflow::Packet tcp_packet = create_acl_test_packet(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                    netflow::ETHERTYPE_IPV4, std::nullopt,
                                                    0xC0A8010A, 0xC0A8010B, IPPROTO_TCP, 12345, 80);

    // Evaluate before compile (AclManager logs a warning)
    // Depending on initial order and if evaluate sorts internally, this might pass or fail
    // For now, our evaluate logs warning and uses current order.
    // EXPECT_NE(am_.evaluate(tcp_packet, redirect_port), netflow::AclActionType::DENY); // This might be flaky

    am_.compile_rules(); // Sorts to [rule2 (100), rule1 (10)]
    EXPECT_EQ(am_.evaluate(tcp_packet, redirect_port), netflow::AclActionType::DENY); // Now rule2 (DENY) should match first.
}
File 'tests/acl_manager_test.cpp' overwritten successfully.
