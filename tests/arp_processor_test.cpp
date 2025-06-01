#include "gtest/gtest.h"
#include "netflow++/arp_processor.hpp"
#include "netflow++/switch.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>
#include <iomanip> // For std::setw, std::setfill, std::hex
#include <sstream> // For std::ostringstream

// Helper to convert string IP to network byte order IpAddress (uint32_t)
bool string_to_ip_net_order_arp_test(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}

// Helper function to convert MacAddress to string
std::string mac_to_string_arp_test(const netflow::MacAddress& mac) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        oss << std::setw(2) << static_cast<int>(mac.bytes[i]);
        if (i < 5) oss << ":";
    }
    return oss.str();
}


netflow::Packet create_arp_packet_arp_test(
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
        vlan_h_data.ethertype = htons(netflow::ETHERTYPE_ARP);
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


class ArpProcessorTest : public ::testing::Test {
protected:
    netflow::SwitchLogger logger_{netflow::LogLevel::DEBUG};
    std::unique_ptr<netflow::Switch> switch_obj_;
    netflow::InterfaceManager* if_mgr_ = nullptr;
    netflow::ForwardingDatabase* fdb_ = nullptr;
    netflow::ArpProcessor* arp_proc_ = nullptr;

    std::optional<netflow::Packet> last_sent_packet_;
    uint32_t last_sent_port_ = 0xFFFFFFFF;

    static netflow::MacAddress make_mac(std::initializer_list<uint8_t> bytes) {
        if (bytes.size() != 6) throw std::length_error("MacAddress initializer list must contain 6 bytes");
        return netflow::MacAddress(std::data(bytes));
    }

    void SetUp() override {
        switch_obj_ = std::make_unique<netflow::Switch>(/*num_ports=*/4, /*switch_mac=*/0x001122334455ULL);
        if_mgr_ = &switch_obj_->interface_manager_;
        fdb_ = &switch_obj_->fdb;
        arp_proc_ = &switch_obj_->arp_processor_;
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

    void set_interface_details(uint32_t port_id, const std::string& ip_str, const std::string& mac_str, const std::string& mask_str = "255.255.255.0") {
        netflow::IpAddress ip_addr_net, subnet_mask_net;
        uint8_t mac_bytes_arr[6];
        // Using sscanf to parse MAC string
        int r = sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac_bytes_arr[0], &mac_bytes_arr[1], &mac_bytes_arr[2],
               &mac_bytes_arr[3], &mac_bytes_arr[4], &mac_bytes_arr[5]);
        if (r != 6) {
            throw std::runtime_error("Invalid MAC string format in test: " + mac_str);
        }
        netflow::MacAddress mac(mac_bytes_arr);

        ASSERT_TRUE(string_to_ip_net_order_arp_test(ip_str, ip_addr_net));
        ASSERT_TRUE(string_to_ip_net_order_arp_test(mask_str, subnet_mask_net));

        netflow::InterfaceManager::PortConfig current_config = if_mgr_->get_port_config(port_id).value_or(netflow::InterfaceManager::PortConfig());
        current_config.mac_address = mac;
        current_config.admin_up = true; // Ensure admin up
        if_mgr_->configure_port(port_id, current_config);
        if_mgr_->add_ip_address(port_id, ip_addr_net, subnet_mask_net);
        if_mgr_->simulate_port_link_up(port_id); // Ensure link is up
    }
};

TEST_F(ArpProcessorTest, SendArpRequest) {
    uint32_t test_port = 1;
    netflow::IpAddress target_ip_to_request_net;
    std::string interface_ip_str = "192.168.1.1";
    std::string interface_mac_str = "00:01:02:03:04:05";
    netflow::MacAddress interface_mac = make_mac({0x00,0x01,0x02,0x03,0x04,0x05});

    set_interface_details(test_port, interface_ip_str, interface_mac_str);
    ASSERT_TRUE(string_to_ip_net_order_arp_test("192.168.1.100", target_ip_to_request_net));

    netflow::IpAddress interface_ip_net_check;
    ASSERT_TRUE(string_to_ip_net_order_arp_test(interface_ip_str, interface_ip_net_check));

    arp_proc_->send_arp_request(target_ip_to_request_net, test_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    ASSERT_EQ(last_sent_port_, test_port);

    const auto& sent_pkt = last_sent_packet_.value();
    auto* eth_hdr = sent_pkt.ethernet();
    ASSERT_NE(eth_hdr, nullptr);
    EXPECT_TRUE(eth_hdr->dst_mac == make_mac({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}));
    EXPECT_TRUE(eth_hdr->src_mac == interface_mac);
    EXPECT_EQ(ntohs(eth_hdr->ethertype), netflow::ETHERTYPE_ARP);

    auto* arp_hdr = sent_pkt.arp();
    ASSERT_NE(arp_hdr, nullptr);
    EXPECT_EQ(ntohs(arp_hdr->opcode), 1);
    EXPECT_TRUE(arp_hdr->sender_mac == interface_mac);
    EXPECT_EQ(arp_hdr->sender_ip, interface_ip_net_check);
    EXPECT_TRUE(arp_hdr->target_mac == make_mac({0x00,0x00,0x00,0x00,0x00,0x00}));
    EXPECT_EQ(arp_hdr->target_ip, target_ip_to_request_net);
}

TEST_F(ArpProcessorTest, ReceiveArpReplyAndCache) {
    uint32_t test_port = 1;
    std::string interface_ip_str = "192.168.1.1";
    std::string interface_mac_str = "00:01:02:03:04:05";
    netflow::MacAddress interface_mac = make_mac({0x00,0x01,0x02,0x03,0x04,0x05});

    std::string reply_sender_ip_str = "192.168.1.50";
    netflow::MacAddress reply_sender_mac = make_mac({0xAA,0xBB,0xCC,0xDD,0xEE,0xFF});

    set_interface_details(test_port, interface_ip_str, interface_mac_str);

    netflow::IpAddress interface_ip_net, reply_sender_ip_net;
    ASSERT_TRUE(string_to_ip_net_order_arp_test(interface_ip_str, interface_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_arp_test(reply_sender_ip_str, reply_sender_ip_net));

    netflow::Packet arp_reply = create_arp_packet_arp_test(
        reply_sender_mac, interface_mac,
        2,
        reply_sender_mac, reply_sender_ip_net,
        interface_mac, interface_ip_net
    );

    arp_proc_->process_arp_packet(arp_reply, test_port);

    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(reply_sender_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == reply_sender_mac);
}

TEST_F(ArpProcessorTest, ReceiveArpRequestAndSendReply) {
    uint32_t test_port = 1;
    std::string my_ip_str = "172.16.0.10";
    std::string my_mac_str = "00:DE:AD:BE:EF:01";
    netflow::MacAddress my_mac = make_mac({0x00,0xDE,0xAD,0xBE,0xEF,0x01});

    std::string requester_ip_str = "172.16.0.20";
    netflow::MacAddress requester_mac = make_mac({0x11,0x22,0x33,0x44,0x55,0x66});

    set_interface_details(test_port, my_ip_str, my_mac_str);

    netflow::IpAddress my_ip_net, requester_ip_net;
    ASSERT_TRUE(string_to_ip_net_order_arp_test(my_ip_str, my_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_arp_test(requester_ip_str, requester_ip_net));

    netflow::Packet arp_request = create_arp_packet_arp_test(
        requester_mac, make_mac({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        1,
        requester_mac, requester_ip_net,
        make_mac({0x00,0x00,0x00,0x00,0x00,0x00}), my_ip_net
    );

    last_sent_packet_.reset();
    arp_proc_->process_arp_packet(arp_request, test_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    // ... (rest of assertions from previous version)
    const auto& sent_reply = last_sent_packet_.value();
    auto* eth_hdr = sent_reply.ethernet();
    ASSERT_NE(eth_hdr, nullptr);
    EXPECT_TRUE(eth_hdr->dst_mac == requester_mac);
    EXPECT_TRUE(eth_hdr->src_mac == my_mac);

    auto* arp_hdr = sent_reply.arp();
    ASSERT_NE(arp_hdr, nullptr);
    EXPECT_EQ(ntohs(arp_hdr->opcode), 2);
    EXPECT_TRUE(arp_hdr->sender_mac == my_mac);
    EXPECT_EQ(arp_hdr->sender_ip, my_ip_net);
    EXPECT_TRUE(arp_hdr->target_mac == requester_mac);
    EXPECT_EQ(arp_hdr->target_ip, requester_ip_net);

    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(requester_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == requester_mac);
}

TEST_F(ArpProcessorTest, LookupMacNotInCache) {
    netflow::IpAddress unknown_ip;
    ASSERT_TRUE(string_to_ip_net_order_arp_test("10.254.254.1", unknown_ip));
    EXPECT_FALSE(arp_proc_->lookup_mac(unknown_ip).has_value());
}

TEST_F(ArpProcessorTest, ReceiveGratuitousArpRequest) {
    uint32_t test_port = 2;
    netflow::IpAddress gratuitous_ip_net;
    netflow::MacAddress gratuitous_mac = make_mac({0x12,0x34,0x56,0x78,0x9A,0xBC});

    ASSERT_TRUE(string_to_ip_net_order_arp_test("192.168.2.10", gratuitous_ip_net));

    netflow::Packet garp_request = create_arp_packet_arp_test(
        gratuitous_mac, make_mac({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        1,
        gratuitous_mac, gratuitous_ip_net,
        make_mac({0x00,0x00,0x00,0x00,0x00,0x00}), gratuitous_ip_net
    );

    last_sent_packet_.reset();
    arp_proc_->process_arp_packet(garp_request, test_port);

    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(gratuitous_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == gratuitous_mac);
    EXPECT_FALSE(last_sent_packet_.has_value());
}
TEST_F(ArpProcessorTest, ReceiveGratuitousArpReply) {
    uint32_t test_port = 3;
    netflow::IpAddress gratuitous_ip_net;
    netflow::MacAddress gratuitous_mac = make_mac({0xAB,0xCD,0xEF,0x12,0x34,0x56});

    ASSERT_TRUE(string_to_ip_net_order_arp_test("192.168.3.20", gratuitous_ip_net));

    netflow::Packet garp_reply = create_arp_packet_arp_test(
        gratuitous_mac, make_mac({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        2,
        gratuitous_mac, gratuitous_ip_net,
        gratuitous_mac, gratuitous_ip_net
    );

    last_sent_packet_.reset();
    arp_proc_->process_arp_packet(garp_reply, test_port);

    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(gratuitous_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == gratuitous_mac);
    EXPECT_FALSE(last_sent_packet_.has_value());
}
