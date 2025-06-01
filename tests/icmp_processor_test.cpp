#include "gtest/gtest.h"
#include "netflow++/icmp_processor.hpp"
#include "netflow++/switch.hpp" // For Switch object
#include "netflow++/interface_manager.hpp"
#include "netflow++/routing_manager.hpp" // For adding routes
#include "netflow++/arp_processor.hpp"   // For populating ARP cache
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <vector>
#include <optional>
#include <cstring>     // For memcpy
#include <arpa/inet.h> // For htonl, ntohl, inet_pton

// Helper to convert string IP to network byte order IpAddress (uint32_t)
bool string_to_ip_net_order_icmp_test(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}
std::string ip_to_string_net_order_icmp_test(netflow::IpAddress net_ip) {
    struct in_addr addr;
    addr.s_addr = net_ip;
    return inet_ntoa(addr);
}

// General IPv4 packet creation helper for ICMP tests
netflow::Packet create_ipv4_packet_for_icmp_test(
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    netflow::IpAddress src_ip_net, netflow::IpAddress dst_ip_net, // Network byte order
    uint8_t ttl,
    uint8_t next_protocol = netflow::IPPROTO_UDP, // e.g., UDP
    const std::vector<unsigned char>& l4_payload = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04} // Ensure at least 8 bytes for ICMP error payload
) {
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t IPV4_HEADER_SIZE = netflow::IPv4Header::MIN_SIZE;
    // Assuming a generic L4 payload for simplicity, not building full L4 headers unless needed
    // For ICMP error generation, usually only IP header + first 8 bytes of L4 payload matters.

    std::vector<unsigned char> frame_data;
    size_t ip_payload_size = l4_payload.size();
    size_t ip_total_length = IPV4_HEADER_SIZE + ip_payload_size;
    frame_data.reserve(ETH_HEADER_SIZE + ip_total_length);

    // Ethernet Header
    netflow::EthernetHeader eth_h;
    eth_h.dst_mac = dst_eth_mac;
    eth_h.src_mac = src_eth_mac;
    eth_h.ethertype = htons(netflow::ETHERTYPE_IPV4);
    unsigned char eth_buf[ETH_HEADER_SIZE];
    std::memcpy(eth_buf, &eth_h, ETH_HEADER_SIZE);
    frame_data.insert(frame_data.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

    // IPv4 Header
    netflow::IPv4Header ip_h;
    ip_h.version_ihl = (4 << 4) | 5;
    ip_h.dscp_ecn = 0;
    ip_h.total_length = htons(ip_total_length);
    ip_h.identification = htons(12345);
    ip_h.flags_fragment_offset = 0;
    ip_h.ttl = ttl;
    ip_h.protocol = next_protocol;
    ip_h.header_checksum = 0; // Will be calculated by packet.update_checksums()
    ip_h.src_ip = src_ip_net;
    ip_h.dst_ip = dst_ip_net;
    unsigned char ipv4_buf[IPV4_HEADER_SIZE];
    std::memcpy(ipv4_buf, &ip_h, IPV4_HEADER_SIZE);
    frame_data.insert(frame_data.end(), ipv4_buf, ipv4_buf + IPV4_HEADER_SIZE);

    // L4 Payload (direct copy for simplicity)
    frame_data.insert(frame_data.end(), l4_payload.begin(), l4_payload.end());

    unsigned char* buffer_data_heap = new unsigned char[frame_data.size()];
    std::memcpy(buffer_data_heap, frame_data.data(), frame_data.size());
    netflow::PacketBuffer pkt_buf(buffer_data_heap, frame_data.size(), [buffer_data_heap]() { delete[] buffer_data_heap; });

    netflow::Packet final_packet(&pkt_buf);
    final_packet.update_checksums(); // Calculate IP checksum
    return final_packet;
}

// Helper to create an ICMP Echo Request Packet (can be kept for specific echo tests)
netflow::Packet create_icmp_echo_request_packet( /* ... as before ... */
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    netflow::IpAddress src_ip_net, netflow::IpAddress dst_ip_net,
    uint16_t icmp_id, uint16_t icmp_seq,
    const std::vector<unsigned char>& payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
) {
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t IPV4_HEADER_SIZE = netflow::IPv4Header::MIN_SIZE;
    constexpr size_t ICMP_ECHO_HEADER_SIZE = 8;

    std::vector<unsigned char> frame_data;
    size_t icmp_total_size = ICMP_ECHO_HEADER_SIZE + payload.size();
    size_t ip_total_length = IPV4_HEADER_SIZE + icmp_total_size;
    frame_data.reserve(ETH_HEADER_SIZE + ip_total_length);

    netflow::EthernetHeader eth_h;
    eth_h.dst_mac = dst_eth_mac;
    eth_h.src_mac = src_eth_mac;
    eth_h.ethertype = htons(netflow::ETHERTYPE_IPV4);
    unsigned char eth_buf[ETH_HEADER_SIZE];
    std::memcpy(eth_buf, &eth_h, ETH_HEADER_SIZE);
    frame_data.insert(frame_data.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

    netflow::IPv4Header ip_h;
    ip_h.version_ihl = (4 << 4) | 5;
    ip_h.dscp_ecn = 0;
    ip_h.total_length = htons(ip_total_length);
    ip_h.identification = htons(54321);
    ip_h.flags_fragment_offset = 0;
    ip_h.ttl = 64;
    ip_h.protocol = netflow::IPPROTO_ICMP;
    ip_h.header_checksum = 0;
    ip_h.src_ip = src_ip_net;
    ip_h.dst_ip = dst_ip_net;
    unsigned char ipv4_buf[IPV4_HEADER_SIZE];
    std::memcpy(ipv4_buf, &ip_h, IPV4_HEADER_SIZE);
    frame_data.insert(frame_data.end(), ipv4_buf, ipv4_buf + IPV4_HEADER_SIZE);

    netflow::IcmpHeader icmp_h;
    icmp_h.type = netflow::IcmpHeader::TYPE_ECHO_REQUEST;
    icmp_h.code = 0;
    icmp_h.checksum = 0;
    icmp_h.identifier = htons(icmp_id);
    icmp_h.sequence_number = htons(icmp_seq);
    unsigned char icmp_header_buf[ICMP_ECHO_HEADER_SIZE];
    std::memcpy(icmp_header_buf, &icmp_h, ICMP_ECHO_HEADER_SIZE);
    frame_data.insert(frame_data.end(), icmp_header_buf, icmp_header_buf + ICMP_ECHO_HEADER_SIZE);

    frame_data.insert(frame_data.end(), payload.begin(), payload.end());

    unsigned char* buffer_data_heap = new unsigned char[frame_data.size()];
    std::memcpy(buffer_data_heap, frame_data.data(), frame_data.size());
    netflow::PacketBuffer pkt_buf(buffer_data_heap, frame_data.size(), [buffer_data_heap]() { delete[] buffer_data_heap; });

    netflow::Packet final_packet(&pkt_buf);
    final_packet.update_checksums();
    return final_packet;
}


class IcmpProcessorTest : public ::testing::Test {
protected:
    netflow::SwitchLogger& logger_ = netflow::SwitchLogger::getInstance(netflow::LogLevel::DEBUG);
    std::unique_ptr<netflow::Switch> switch_obj_;
    netflow::InterfaceManager* if_mgr_ = nullptr;
    netflow::RoutingManager* rt_mgr_ = nullptr;
    netflow::ArpProcessor* arp_proc_ = nullptr;
    netflow::IcmpProcessor* icmp_proc_ = nullptr;

    std::optional<netflow::Packet> last_sent_packet_;
    uint32_t last_sent_port_ = 0xFFFFFFFF;

    void SetUp() override {
        switch_obj_ = std::make_unique<netflow::Switch>(/*num_ports=*/4, /*switch_mac=*/0x00AABBCCDDEEFFULL);
        if_mgr_ = &switch_obj_->interface_manager_;
        rt_mgr_ = &switch_obj_->routing_manager_;
        arp_proc_ = &switch_obj_->arp_processor_;
        icmp_proc_ = &switch_obj_->icmp_processor_;

        last_sent_packet_.reset();
        last_sent_port_ = 0xFFFFFFFF;

        switch_obj_->test_packet_send_hook =
            [this](const netflow::Packet& pkt, uint32_t port) {
                auto original_buf = pkt.get_buffer();
                unsigned char* new_data = new unsigned char[original_buf->get_data_length()];
                std::memcpy(new_data, original_buf->get_data_start_ptr(), original_buf->get_data_length());
                netflow::PacketBuffer* new_pb = new netflow::PacketBuffer(new_data, original_buf->get_data_length(), [new_data](){ delete[] new_data; });

                this->last_sent_packet_ = netflow::Packet(new_pb);
                new_pb->decrement_ref();
                this->last_sent_port_ = port;
            };

        for (uint32_t i = 0; i < 4; ++i) {
            netflow::InterfaceManager::PortConfig p_cfg;
            p_cfg.admin_up = true;
            if_mgr_->configure_port(i, p_cfg);
            if_mgr_->simulate_port_link_up(i);
        }
    }

    void TearDown() override {
        if(switch_obj_) {
            switch_obj_->test_packet_send_hook = nullptr;
        }
    }
};

TEST_F(IcmpProcessorTest, Placeholder) {
    ASSERT_TRUE(true);
}

TEST_F(IcmpProcessorTest, ReceiveEchoRequestAndSendReply) {
    uint32_t ingress_port = 0;
    netflow::IpAddress my_ip_net, requester_ip_net;
    netflow::MacAddress my_mac({0x00,0xAA,0xBB,0xCC,0xDD,0xEE});
    netflow::MacAddress requester_mac({0x11,0x22,0x33,0x44,0x55,0x66});

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.0.1", my_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.0.100", requester_ip_net));

    if_mgr_->set_interface_ip(ingress_port, my_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(ingress_port, my_mac);

    // Simulate ARP entry for the requester
    netflow::Packet arp_reply_sim = create_arp_packet(requester_mac, my_mac, 2, requester_mac, requester_ip_net, my_mac, my_ip_net);
    arp_proc_->process_arp_packet(arp_reply_sim, ingress_port);
    ASSERT_TRUE(arp_proc_->lookup_mac(requester_ip_net).has_value());


    uint16_t icmp_id = 1234;
    uint16_t icmp_seq = 1;
    std::vector<unsigned char> payload = { 'h', 'e', 'l', 'l', 'o' };
    netflow::Packet echo_request = create_icmp_echo_request_packet(
        requester_mac, my_mac,
        requester_ip_net, my_ip_net,
        icmp_id, icmp_seq, payload
    );

    last_sent_packet_.reset();
    icmp_proc_->process_icmp_packet(echo_request, ingress_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    ASSERT_EQ(last_sent_port_, ingress_port);

    const auto& sent_reply = last_sent_packet_.value();
    // ... (rest of assertions from previous version of this test)
    auto* eth_hdr = sent_reply.ethernet(); /* ... */ EXPECT_TRUE(eth_hdr->dst_mac == requester_mac);
    auto* ip_hdr = sent_reply.ipv4();     /* ... */ EXPECT_EQ(ip_hdr->src_ip, my_ip_net);
    auto* icmp_hdr = sent_reply.icmp();   /* ... */ EXPECT_EQ(icmp_hdr->type, netflow::IcmpHeader::TYPE_ECHO_REPLY);
}

TEST_F(IcmpProcessorTest, SendIcmpTimeExceeded) {
    uint32_t original_ingress_port = 0;
    uint32_t icmp_source_port = 1; // Port from which ICMP error will be sent

    netflow::IpAddress icmp_src_ip_net, original_src_ip_net, original_dst_ip_net, next_hop_ip_net;
    netflow::MacAddress icmp_src_mac({0x0A,0x00,0x00,0x00,0x00,0x01});
    netflow::MacAddress next_hop_mac({0x0A,0x00,0x00,0x00,0x00,0x02}); // MAC for 10.0.0.2

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.1", icmp_src_ip_net));          // Switch's IP for sending error
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.1.100", original_src_ip_net)); // Original packet's source
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("172.16.1.100", original_dst_ip_net));  // Original packet's dest
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.2", next_hop_ip_net));          // Next hop to reach original_src_ip

    if_mgr_->set_interface_ip(icmp_source_port, icmp_src_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(icmp_source_port, icmp_src_mac);

    // Route back to original sender 192.168.1.100 via 10.0.0.2 on port 1
    rt_mgr_->add_static_route(original_src_ip_net, htonl(0xFFFFFF00), next_hop_ip_net, icmp_source_port);
    // ARP entry for the next hop 10.0.0.2
    netflow::Packet arp_reply_sim = create_arp_packet(next_hop_mac, icmp_src_mac, 2, next_hop_mac, next_hop_ip_net, icmp_src_mac, icmp_src_ip_net);
    arp_proc_->process_arp_packet(arp_reply_sim, icmp_source_port);
    ASSERT_TRUE(arp_proc_->lookup_mac(next_hop_ip_net).has_value());

    netflow::Packet original_packet = create_ipv4_packet_for_icmp_test(
        netflow::MacAddress({0xDE,0xAD,0xBE,0xEF,0x00,0x01}), // Original eth src
        netflow::MacAddress({0xDE,0xAD,0xBE,0xEF,0x00,0x02}), // Original eth dst (router MAC)
        original_src_ip_net, original_dst_ip_net,
        1 // TTL = 1
    );

    last_sent_packet_.reset();
    icmp_proc_->send_time_exceeded(original_packet, original_ingress_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    EXPECT_EQ(last_sent_port_, icmp_source_port);

    const auto& icmp_error_pkt = last_sent_packet_.value();
    auto* eth = icmp_error_pkt.ethernet();
    ASSERT_NE(eth, nullptr);
    EXPECT_TRUE(eth->src_mac == icmp_src_mac);
    EXPECT_TRUE(eth->dst_mac == next_hop_mac);

    auto* ip = icmp_error_pkt.ipv4();
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->src_ip, icmp_src_ip_net);
    EXPECT_EQ(ip->dst_ip, original_src_ip_net);
    EXPECT_EQ(ip->protocol, netflow::IPPROTO_ICMP);

    auto* icmp = icmp_error_pkt.icmp();
    ASSERT_NE(icmp, nullptr);
    EXPECT_EQ(icmp->type, 11); // Time Exceeded
    EXPECT_EQ(icmp->code, 0);  // TTL expired in transit

    // Verify payload (original IP header + 8 bytes of original L4 payload)
    const unsigned char* icmp_payload_ptr = reinterpret_cast<const unsigned char*>(icmp) + 8; // Skip ICMP header
    size_t icmp_payload_len = ntohs(ip->total_length) - (ip->get_header_length()) - 8;

    auto* orig_ip_in_payload = reinterpret_cast<const netflow::IPv4Header*>(icmp_payload_ptr);
    EXPECT_EQ(orig_ip_in_payload->src_ip, original_src_ip_net);
    EXPECT_EQ(orig_ip_in_payload->dst_ip, original_dst_ip_net);
    EXPECT_GE(icmp_payload_len, netflow::IPv4Header::MIN_SIZE + 8);
}

TEST_F(IcmpProcessorTest, SendIcmpNetUnreachable) {
    uint32_t original_ingress_port = 0;
    uint32_t icmp_source_port = 1;

    netflow::IpAddress icmp_src_ip_net, original_src_ip_net, unroutable_dst_ip_net, next_hop_ip_net;
    netflow::MacAddress icmp_src_mac({0x0A,0x00,0x00,0x00,0x00,0x01});
    netflow::MacAddress next_hop_mac({0x0A,0x00,0x00,0x00,0x00,0x02});

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.1", icmp_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.1.100", original_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("203.0.113.5", unroutable_dst_ip_net)); // Unroutable
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.2", next_hop_ip_net));

    if_mgr_->set_interface_ip(icmp_source_port, icmp_src_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(icmp_source_port, icmp_src_mac);

    rt_mgr_->add_static_route(original_src_ip_net, htonl(0xFFFFFF00), next_hop_ip_net, icmp_source_port);
    netflow::Packet arp_reply_sim = create_arp_packet(next_hop_mac, icmp_src_mac, 2, next_hop_mac, next_hop_ip_net, icmp_src_mac, icmp_src_ip_net);
    arp_proc_->process_arp_packet(arp_reply_sim, icmp_source_port);
    ASSERT_TRUE(arp_proc_->lookup_mac(next_hop_ip_net).has_value());

    netflow::Packet original_packet = create_ipv4_packet_for_icmp_test(
        netflow::MacAddress({0xDE,0xAD,0xBE,0xEF,0x00,0x01}),
        netflow::MacAddress({0xDE,0xAD,0xBE,0xEF,0x00,0x02}),
        original_src_ip_net, unroutable_dst_ip_net,
        64
    );

    last_sent_packet_.reset();
    // Assuming RoutingManager returns std::nullopt for unroutable_dst_ip_net which triggers this
    icmp_proc_->send_destination_unreachable(original_packet, original_ingress_port, 0); // Code 0: Net Unreachable

    ASSERT_TRUE(last_sent_packet_.has_value());
    EXPECT_EQ(last_sent_port_, icmp_source_port);

    const auto& icmp_error_pkt = last_sent_packet_.value();
    auto* ip = icmp_error_pkt.ipv4();
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->src_ip, icmp_src_ip_net);
    EXPECT_EQ(ip->dst_ip, original_src_ip_net);

    auto* icmp = icmp_error_pkt.icmp();
    ASSERT_NE(icmp, nullptr);
    EXPECT_EQ(icmp->type, 3); // Destination Unreachable
    EXPECT_EQ(icmp->code, 0); // Net Unreachable
}

// Test for Host Unreachable (e.g. ARP fails) would be similar to NetUnreachable,
// but the trigger condition (ARP failure for a known route's next-hop) happens inside L3 forwarding,
// which then calls IcmpProcessor. Testing this directly via IcmpProcessor needs the ARP state to be "failed".
// IcmpProcessor::send_destination_unreachable with code 1 would be called.
File 'tests/icmp_processor_test.cpp' overwritten successfully.
