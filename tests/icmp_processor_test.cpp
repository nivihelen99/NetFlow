#include "gtest/gtest.h"
#include "netflow++/icmp_processor.hpp"
#include "netflow++/switch.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/routing_manager.hpp"
#include "netflow++/arp_processor.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>
#include <numeric>

bool string_to_ip_net_order_icmp_test(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}

// Helper (from arp_processor_test, ensure it's available or duplicated if needed)
// For ICMP tests, we might need to simulate ARP replies to populate cache.
netflow::Packet create_arp_packet_for_icmp_test(
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    uint16_t arp_opcode,
    netflow::MacAddress arp_sender_mac, netflow::IpAddress arp_sender_ip,
    netflow::MacAddress arp_target_mac, netflow::IpAddress arp_target_ip,
    std::optional<uint16_t> vlan_id = std::nullopt, uint8_t pcp = 0)
{
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t VLAN_HEADER_SIZE = netflow::VlanHeader::SIZE;
    constexpr size_t ARP_PAYLOAD_SIZE = 28;

    std::vector<unsigned char> frame_data_vec;
    frame_data_vec.reserve(ETH_HEADER_SIZE + (vlan_id ? VLAN_HEADER_SIZE : 0) + ARP_PAYLOAD_SIZE);

    netflow::EthernetHeader eth_header_data;
    eth_header_data.dst_mac = dst_eth_mac;
    eth_header_data.src_mac = src_eth_mac;
    unsigned char eth_buf[ETH_HEADER_SIZE];

    if (vlan_id) {
        eth_header_data.ethertype = htons(netflow::ETHERTYPE_VLAN);
        std::memcpy(eth_buf, &eth_header_data, ETH_HEADER_SIZE);
        frame_data_vec.insert(frame_data_vec.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

        netflow::VlanHeader vlan_h_data;
        vlan_h_data.set_vlan_id(vlan_id.value());
        vlan_h_data.set_priority(pcp);
        vlan_h_data.ethertype = htons(netflow::ETHERTYPE_ARP); // Inner type is ARP
        unsigned char vlan_buf[VLAN_HEADER_SIZE];
        std::memcpy(vlan_buf, &vlan_h_data, VLAN_HEADER_SIZE);
        frame_data_vec.insert(frame_data_vec.end(), vlan_buf, vlan_buf + VLAN_HEADER_SIZE);
    } else {
        eth_header_data.ethertype = htons(netflow::ETHERTYPE_ARP);
        std::memcpy(eth_buf, &eth_header_data, ETH_HEADER_SIZE);
        frame_data_vec.insert(frame_data_vec.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);
    }

    netflow::ArpHeader arp_header_data;
    arp_header_data.hardware_type = htons(1);
    arp_header_data.protocol_type = htons(netflow::ETHERTYPE_IPV4);
    arp_header_data.hardware_addr_len = 6;
    arp_header_data.protocol_addr_len = 4;
    arp_header_data.opcode = htons(arp_opcode);
    arp_header_data.sender_mac = arp_sender_mac;
    arp_header_data.sender_ip = arp_sender_ip;
    arp_header_data.target_mac = arp_target_mac;
    arp_header_data.target_ip = arp_target_ip;

    unsigned char arp_buf[ARP_PAYLOAD_SIZE];
    std::memcpy(arp_buf, &arp_header_data, ARP_PAYLOAD_SIZE);
    frame_data_vec.insert(frame_data_vec.end(), arp_buf, arp_buf + ARP_PAYLOAD_SIZE);

    netflow::PacketBuffer* pb = new netflow::PacketBuffer(frame_data_vec.size());
    std::memcpy(pb->get_data_start_ptr(), frame_data_vec.data(), frame_data_vec.size());
    pb->set_data_len(frame_data_vec.size());

    netflow::Packet pkt(pb);
    pb->decrement_ref();
    return pkt;
}


netflow::Packet create_ipv4_packet_for_icmp_test(
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    netflow::IpAddress src_ip_net, netflow::IpAddress dst_ip_net,
    uint8_t ttl,
    uint8_t next_protocol = netflow::IPPROTO_UDP,
    const std::vector<unsigned char>& l4_payload = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
) {
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t IPV4_HEADER_SIZE = netflow::IPv4Header::MIN_SIZE;

    std::vector<unsigned char> frame_data_vec;
    size_t ip_payload_size = l4_payload.size();
    size_t ip_total_length = IPV4_HEADER_SIZE + ip_payload_size;
    frame_data_vec.reserve(ETH_HEADER_SIZE + ip_total_length);

    netflow::EthernetHeader eth_h;
    eth_h.dst_mac = dst_eth_mac;
    eth_h.src_mac = src_eth_mac;
    eth_h.ethertype = htons(netflow::ETHERTYPE_IPV4);
    unsigned char eth_buf[ETH_HEADER_SIZE];
    std::memcpy(eth_buf, &eth_h, ETH_HEADER_SIZE);
    frame_data_vec.insert(frame_data_vec.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

    netflow::IPv4Header ip_h;
    ip_h.version_ihl = (4 << 4) | 5;
    ip_h.dscp_ecn = 0;
    ip_h.total_length = htons(ip_total_length);
    ip_h.identification = htons(12345);
    ip_h.flags_fragment_offset = 0;
    ip_h.ttl = ttl;
    ip_h.protocol = next_protocol;
    ip_h.header_checksum = 0;
    ip_h.src_ip = src_ip_net;
    ip_h.dst_ip = dst_ip_net;
    unsigned char ipv4_buf[IPV4_HEADER_SIZE];
    std::memcpy(ipv4_buf, &ip_h, IPV4_HEADER_SIZE);
    frame_data_vec.insert(frame_data_vec.end(), ipv4_buf, ipv4_buf + IPV4_HEADER_SIZE);

    frame_data_vec.insert(frame_data_vec.end(), l4_payload.begin(), l4_payload.end());

    netflow::PacketBuffer* pb = new netflow::PacketBuffer(frame_data_vec.size());
    std::memcpy(pb->get_data_start_ptr(), frame_data_vec.data(), frame_data_vec.size());
    pb->set_data_len(frame_data_vec.size());

    netflow::Packet final_packet(pb);
    final_packet.update_checksums();
    pb->decrement_ref();
    return final_packet;
}

netflow::Packet create_icmp_echo_request_packet(
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    netflow::IpAddress src_ip_net, netflow::IpAddress dst_ip_net,
    uint16_t icmp_id, uint16_t icmp_seq,
    const std::vector<unsigned char>& payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
) {
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t IPV4_HEADER_SIZE = netflow::IPv4Header::MIN_SIZE;
    constexpr size_t ICMP_ECHO_HEADER_SIZE = 8;

    std::vector<unsigned char> frame_data_vec;
    size_t icmp_total_size = ICMP_ECHO_HEADER_SIZE + payload.size();
    size_t ip_total_length = IPV4_HEADER_SIZE + icmp_total_size;
    frame_data_vec.reserve(ETH_HEADER_SIZE + ip_total_length);

    netflow::EthernetHeader eth_h;
    eth_h.dst_mac = dst_eth_mac;
    eth_h.src_mac = src_eth_mac;
    eth_h.ethertype = htons(netflow::ETHERTYPE_IPV4);
    unsigned char eth_buf[ETH_HEADER_SIZE];
    std::memcpy(eth_buf, &eth_h, ETH_HEADER_SIZE);
    frame_data_vec.insert(frame_data_vec.end(), eth_buf, eth_buf + ETH_HEADER_SIZE);

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
    frame_data_vec.insert(frame_data_vec.end(), ipv4_buf, ipv4_buf + IPV4_HEADER_SIZE);

    netflow::IcmpHeader icmp_h_data; // Renamed to avoid conflict
    icmp_h_data.type = netflow::IcmpHeader::TYPE_ECHO_REQUEST;
    icmp_h_data.code = 0;
    icmp_h_data.checksum = 0;
    icmp_h_data.identifier = htons(icmp_id);
    icmp_h_data.sequence_number = htons(icmp_seq);
    unsigned char icmp_header_buf[ICMP_ECHO_HEADER_SIZE];
    std::memcpy(icmp_header_buf, &icmp_h_data, ICMP_ECHO_HEADER_SIZE);
    frame_data_vec.insert(frame_data_vec.end(), icmp_header_buf, icmp_header_buf + ICMP_ECHO_HEADER_SIZE);

    frame_data_vec.insert(frame_data_vec.end(), payload.begin(), payload.end());

    netflow::PacketBuffer* pb = new netflow::PacketBuffer(frame_data_vec.size());
    std::memcpy(pb->get_data_start_ptr(), frame_data_vec.data(), frame_data_vec.size());
    pb->set_data_len(frame_data_vec.size());

    netflow::Packet final_packet(pb);
    final_packet.update_checksums();
    pb->decrement_ref();
    return final_packet;
}

// Helper to create MacAddress from initializer list
netflow::MacAddress make_mac_icmp_test(std::initializer_list<uint8_t> bytes) {
    if (bytes.size() != 6) throw std::length_error("MacAddress initializer list must contain 6 bytes");
    return netflow::MacAddress(std::data(bytes));
}


class IcmpProcessorTest : public ::testing::Test {
protected:
    // Switch owns all managers, including logger
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

        // Set logger level on the switch's logger for more verbose test output if needed
        switch_obj_->logger_.set_min_log_level(netflow::LogLevel::DEBUG);


        last_sent_packet_.reset();
        last_sent_port_ = 0xFFFFFFFF;

        switch_obj_->test_packet_send_hook =
            [this](const netflow::Packet& pkt, uint32_t port) {
                auto original_buf = pkt.get_buffer();
                netflow::PacketBuffer* new_pb = new netflow::PacketBuffer(original_buf->get_data_length());
                std::memcpy(new_pb->get_data_start_ptr(), original_buf->get_data_start_ptr(), original_buf->get_data_length());
                new_pb->set_data_len(original_buf->get_data_length());

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

    void set_interface_details_icmp(uint32_t port_id, const std::string& ip_str, const std::string& mac_str, const std::string& mask_str = "255.255.255.0") {
        netflow::IpAddress ip_addr_net, subnet_mask_net;
        uint8_t mac_bytes_arr[6];
        sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_bytes_arr[0], &mac_bytes_arr[1], &mac_bytes_arr[2], &mac_bytes_arr[3], &mac_bytes_arr[4], &mac_bytes_arr[5]);
        netflow::MacAddress mac(mac_bytes_arr);

        ASSERT_TRUE(string_to_ip_net_order_icmp_test(ip_str, ip_addr_net));
        ASSERT_TRUE(string_to_ip_net_order_icmp_test(mask_str, subnet_mask_net));

        netflow::InterfaceManager::PortConfig current_config = if_mgr_->get_port_config(port_id).value_or(netflow::InterfaceManager::PortConfig());
        current_config.mac_address = mac;
        if_mgr_->configure_port(port_id, current_config);
        if_mgr_->add_ip_address(port_id, ip_addr_net, subnet_mask_net);
    }
};

TEST_F(IcmpProcessorTest, Placeholder) {
    ASSERT_TRUE(true);
}

TEST_F(IcmpProcessorTest, ReceiveEchoRequestAndSendReply) {
    uint32_t ingress_port = 0;
    netflow::IpAddress my_ip_net, requester_ip_net;
    netflow::MacAddress my_mac = make_mac_icmp_test({0x00,0xAA,0xBB,0xCC,0xDD,0xEE});
    netflow::MacAddress requester_mac = make_mac_icmp_test({0x11,0x22,0x33,0x44,0x55,0x66});

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.0.1", my_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.0.100", requester_ip_net));

    set_interface_details_icmp(ingress_port, "192.168.0.1", "00:AA:BB:CC:DD:EE");

    netflow::Packet arp_reply_sim = create_arp_packet_for_icmp_test(
        requester_mac, my_mac, 2,
        requester_mac, requester_ip_net,
        my_mac, my_ip_net
    );
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
    auto* eth_hdr = sent_reply.ethernet();
    ASSERT_NE(eth_hdr, nullptr);
    EXPECT_TRUE(eth_hdr->dst_mac == requester_mac);
    EXPECT_TRUE(eth_hdr->src_mac == my_mac);
    EXPECT_EQ(ntohs(eth_hdr->ethertype), netflow::ETHERTYPE_IPV4);

    auto* ip_hdr = sent_reply.ipv4();
    ASSERT_NE(ip_hdr, nullptr);
    EXPECT_EQ(ip_hdr->src_ip, my_ip_net);
    EXPECT_EQ(ip_hdr->dst_ip, requester_ip_net);
    EXPECT_EQ(ip_hdr->protocol, netflow::IPPROTO_ICMP);

    auto* icmp_hdr = sent_reply.icmp();
    ASSERT_NE(icmp_hdr, nullptr);
    EXPECT_EQ(icmp_hdr->type, netflow::IcmpHeader::TYPE_ECHO_REPLY);
    EXPECT_EQ(icmp_hdr->code, 0);
    EXPECT_EQ(ntohs(icmp_hdr->identifier), icmp_id);
    EXPECT_EQ(ntohs(icmp_hdr->sequence_number), icmp_seq);

    size_t reply_icmp_header_offset = netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE;
    size_t reply_payload_offset = reply_icmp_header_offset + 8;
    ASSERT_GE(sent_reply.get_buffer()->get_data_length(), reply_payload_offset + payload.size());
    const unsigned char* reply_payload_ptr = sent_reply.get_buffer()->get_data_start_ptr() + reply_payload_offset;
    for(size_t i=0; i < payload.size(); ++i) {
        EXPECT_EQ(reply_payload_ptr[i], payload[i]);
    }
}

TEST_F(IcmpProcessorTest, SendIcmpTimeExceeded) {
    uint32_t original_ingress_port = 0;
    uint32_t icmp_source_port = 1;

    netflow::IpAddress icmp_src_ip_net, original_src_ip_net, original_dst_ip_net, next_hop_ip_net;
    netflow::MacAddress icmp_src_mac = make_mac_icmp_test({0x0A,0x00,0x00,0x00,0x00,0x01});
    netflow::MacAddress next_hop_mac = make_mac_icmp_test({0x0A,0x00,0x00,0x00,0x00,0x02});

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.1", icmp_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.1.100", original_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("172.16.1.100", original_dst_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.2", next_hop_ip_net));

    set_interface_details_icmp(icmp_source_port, "10.0.0.1", "0A:00:00:00:00:01");

    rt_mgr_->add_static_route(original_src_ip_net, htonl(0xFFFFFF00), next_hop_ip_net, icmp_source_port);
    netflow::Packet arp_reply_sim = create_arp_packet_for_icmp_test(next_hop_mac, icmp_src_mac, 2, next_hop_mac, next_hop_ip_net, icmp_src_mac, icmp_src_ip_net);
    arp_proc_->process_arp_packet(arp_reply_sim, icmp_source_port);
    ASSERT_TRUE(arp_proc_->lookup_mac(next_hop_ip_net).has_value());

    netflow::Packet original_packet = create_ipv4_packet_for_icmp_test(
        make_mac_icmp_test({0xDE,0xAD,0xBE,0xEF,0x00,0x01}),
        make_mac_icmp_test({0xDE,0xAD,0xBE,0xEF,0x00,0x02}),
        original_src_ip_net, original_dst_ip_net,
        1
    );

    last_sent_packet_.reset();
    icmp_proc_->send_time_exceeded(original_packet, original_ingress_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    // ... (rest of assertions)
}

TEST_F(IcmpProcessorTest, SendIcmpNetUnreachable) {
    uint32_t original_ingress_port = 0;
    uint32_t icmp_source_port = 1;

    netflow::IpAddress icmp_src_ip_net, original_src_ip_net, unroutable_dst_ip_net, next_hop_ip_net;
    netflow::MacAddress icmp_src_mac = make_mac_icmp_test({0x0A,0x00,0x00,0x00,0x00,0x01});
    netflow::MacAddress next_hop_mac = make_mac_icmp_test({0x0A,0x00,0x00,0x00,0x00,0x02});

    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.1", icmp_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("192.168.1.100", original_src_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("203.0.113.5", unroutable_dst_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_icmp_test("10.0.0.2", next_hop_ip_net));

    set_interface_details_icmp(icmp_source_port, "10.0.0.1", "0A:00:00:00:00:01");

    rt_mgr_->add_static_route(original_src_ip_net, htonl(0xFFFFFF00), next_hop_ip_net, icmp_source_port);
    netflow::Packet arp_reply_sim = create_arp_packet_for_icmp_test(next_hop_mac, icmp_src_mac, 2, next_hop_mac, next_hop_ip_net, icmp_src_mac, icmp_src_ip_net);
    arp_proc_->process_arp_packet(arp_reply_sim, icmp_source_port);
    ASSERT_TRUE(arp_proc_->lookup_mac(next_hop_ip_net).has_value());

    netflow::Packet original_packet = create_ipv4_packet_for_icmp_test(
        make_mac_icmp_test({0xDE,0xAD,0xBE,0xEF,0x00,0x01}),
        make_mac_icmp_test({0xDE,0xAD,0xBE,0xEF,0x00,0x02}),
        original_src_ip_net, unroutable_dst_ip_net,
        64
    );

    last_sent_packet_.reset();
    icmp_proc_->send_destination_unreachable(original_packet, original_ingress_port, 0);

    ASSERT_TRUE(last_sent_packet_.has_value());
    // ... (rest of assertions)
}
