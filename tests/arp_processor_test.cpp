#include "gtest/gtest.h"
#include "netflow++/arp_processor.hpp"
#include "netflow++/switch.hpp" // For Switch object, which owns ArpProcessor and others
#include "netflow++/interface_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <vector>
#include <optional>
#include <cstring> // For memcpy
#include <arpa/inet.h> // For htonl, ntohl, inet_pton

// Helper to convert string IP to network byte order IpAddress (uint32_t)
bool string_to_ip_net_order_test(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr; // Already in network byte order
        return true;
    }
    return false;
}

// Helper to create an ARP Packet object for testing
netflow::Packet create_arp_packet(
    netflow::MacAddress src_eth_mac, netflow::MacAddress dst_eth_mac,
    uint16_t arp_opcode,
    netflow::MacAddress arp_sender_mac, netflow::IpAddress arp_sender_ip, // IPs in network byte order
    netflow::MacAddress arp_target_mac, netflow::IpAddress arp_target_ip,
    std::optional<uint16_t> vlan_id = std::nullopt, uint8_t pcp = 0)
{
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t VLAN_HEADER_SIZE = netflow::VlanHeader::SIZE;
    // From ArpHeader struct in packet.hpp:
    // static constexpr size_t SIZE = 2 * sizeof(uint16_t) + 2 * sizeof(uint8_t) + sizeof(uint16_t) + 2 * sizeof(MacAddress) + 2 * sizeof(IpAddress);
    // This is 2+2+2+2 + 2 + 12 + 8 = 28 bytes.
    constexpr size_t ARP_PAYLOAD_SIZE = 28;


    std::vector<unsigned char> frame_data;
    frame_data.reserve(ETH_HEADER_SIZE + (vlan_id ? VLAN_HEADER_SIZE : 0) + ARP_PAYLOAD_SIZE);

    netflow::EthernetHeader eth_header_data;
    eth_header_data.dst_mac = dst_eth_mac;
    eth_header_data.src_mac = src_eth_mac;

    unsigned char header_buf[ETH_HEADER_SIZE + VLAN_HEADER_SIZE];

    if (vlan_id) {
        eth_header_data.ethertype = htons(netflow::ETHERTYPE_VLAN);
        std::memcpy(header_buf, &eth_header_data, ETH_HEADER_SIZE);
        frame_data.insert(frame_data.end(), header_buf, header_buf + ETH_HEADER_SIZE);

        netflow::VlanHeader vlan_h_data;
        vlan_h_data.set_vlan_id(vlan_id.value());
        vlan_h_data.set_priority(pcp);
        vlan_h_data.ethertype = htons(netflow::ETHERTYPE_ARP);
        std::memcpy(header_buf, &vlan_h_data, VLAN_HEADER_SIZE);
        frame_data.insert(frame_data.end(), header_buf, header_buf + VLAN_HEADER_SIZE);
    } else {
        eth_header_data.ethertype = htons(netflow::ETHERTYPE_ARP);
        std::memcpy(header_buf, &eth_header_data, ETH_HEADER_SIZE);
        frame_data.insert(frame_data.end(), header_buf, header_buf + ETH_HEADER_SIZE);
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
    frame_data.insert(frame_data.end(), arp_buf, arp_buf + ARP_PAYLOAD_SIZE);

    unsigned char* buffer_data_heap = new unsigned char[frame_data.size()];
    std::memcpy(buffer_data_heap, frame_data.data(), frame_data.size());

    netflow::PacketBuffer pkt_buf(buffer_data_heap, frame_data.size(), [buffer_data_heap]() { delete[] buffer_data_heap; });
    return netflow::Packet(&pkt_buf);
}


class ArpProcessorTest : public ::testing::Test {
protected:
    // Logger can be a static instance or obtained differently if your project requires
    netflow::SwitchLogger& logger_ = netflow::SwitchLogger::getInstance(netflow::LogLevel::DEBUG);
    std::unique_ptr<netflow::Switch> switch_obj_;
    netflow::InterfaceManager* if_mgr_ = nullptr;
    netflow::ForwardingDatabase* fdb_ = nullptr;
    netflow::ArpProcessor* arp_proc_ = nullptr;

    std::optional<netflow::Packet> last_sent_packet_;
    uint32_t last_sent_port_ = 0xFFFFFFFF;

    void SetUp() override {
        // Switch constructor in switch.hpp is:
        // Switch(uint32_t num_ports, uint64_t switch_mac_address,
        //        uint16_t stp_default_priority = 32768, uint16_t lacp_default_priority = 32768)
        // It initializes its own logger_ member.
        // The ArpProcessor gets the Switch reference, and can use switch_obj_->logger_ if needed.
        switch_obj_ = std::make_unique<netflow::Switch>(/*num_ports=*/4, /*switch_mac=*/0x001122334455ULL);
        if_mgr_ = &switch_obj_->interface_manager_;
        fdb_ = &switch_obj_->fdb;
        arp_proc_ = &switch_obj_->arp_processor_;

        last_sent_packet_.reset();
        last_sent_port_ = 0xFFFFFFFF;

        switch_obj_->test_packet_send_hook =
            [this](const netflow::Packet& pkt, uint32_t port) {
                // Create a new PacketBuffer by copying data from pkt's buffer
                // This ensures lifetime independence for the captured packet.
                auto original_buf = pkt.get_buffer();
                unsigned char* new_data = new unsigned char[original_buf->get_data_length()];
                std::memcpy(new_data, original_buf->get_data_start_ptr(), original_buf->get_data_length());
                netflow::PacketBuffer* new_pb = new netflow::PacketBuffer(new_data, original_buf->get_data_length(), [new_data](){ delete[] new_data; });

                this->last_sent_packet_ = netflow::Packet(new_pb);
                // Decrement ref for new_pb as Packet constructor increments it.
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

TEST_F(ArpProcessorTest, SendArpRequest) {
    uint32_t test_port = 1;
    netflow::IpAddress interface_ip_net; // Network byte order
    netflow::IpAddress target_ip_to_request_net; // Network byte order
    netflow::MacAddress interface_mac({0x00,0x01,0x02,0x03,0x04,0x05});

    ASSERT_TRUE(string_to_ip_net_order_test("192.168.1.1", interface_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_test("192.168.1.100", target_ip_to_request_net));

    if_mgr_->set_interface_ip(test_port, interface_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(test_port, interface_mac);

    arp_proc_->send_arp_request(target_ip_to_request_net, test_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    ASSERT_EQ(last_sent_port_, test_port);

    const auto& sent_pkt = last_sent_packet_.value();
    auto* eth_hdr = sent_pkt.ethernet();
    ASSERT_NE(eth_hdr, nullptr);
    EXPECT_TRUE(eth_hdr->dst_mac == netflow::MacAddress({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}));
    EXPECT_TRUE(eth_hdr->src_mac == interface_mac);
    EXPECT_EQ(ntohs(eth_hdr->ethertype), netflow::ETHERTYPE_ARP);

    auto* arp_hdr = sent_pkt.arp();
    ASSERT_NE(arp_hdr, nullptr);
    EXPECT_EQ(ntohs(arp_hdr->opcode), 1);
    EXPECT_TRUE(arp_hdr->sender_mac == interface_mac);
    EXPECT_EQ(arp_hdr->sender_ip, interface_ip_net);
    EXPECT_TRUE(arp_hdr->target_mac == netflow::MacAddress({0x00,0x00,0x00,0x00,0x00,0x00}));
    EXPECT_EQ(arp_hdr->target_ip, target_ip_to_request_net);
}

TEST_F(ArpProcessorTest, ReceiveArpReplyAndCache) {
    uint32_t test_port = 1;
    netflow::IpAddress interface_ip_net, reply_sender_ip_net;
    netflow::MacAddress interface_mac({0x00,0x01,0x02,0x03,0x04,0x05});
    netflow::MacAddress reply_sender_mac({0xAA,0xBB,0xCC,0xDD,0xEE,0xFF});

    ASSERT_TRUE(string_to_ip_net_order_test("192.168.1.1", interface_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_test("192.168.1.50", reply_sender_ip_net));

    if_mgr_->set_interface_ip(test_port, interface_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(test_port, interface_mac);

    netflow::Packet arp_reply = create_arp_packet(
        reply_sender_mac, interface_mac,
        2, // ARP Opcode: Reply
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
    netflow::IpAddress my_ip_net, requester_ip_net;
    netflow::MacAddress my_mac({0x00,0xDE,0xAD,0xBE,0xEF,0x01});
    netflow::MacAddress requester_mac({0x11,0x22,0x33,0x44,0x55,0x66});

    ASSERT_TRUE(string_to_ip_net_order_test("172.16.0.10", my_ip_net));
    ASSERT_TRUE(string_to_ip_net_order_test("172.16.0.20", requester_ip_net));

    if_mgr_->set_interface_ip(test_port, my_ip_net, htonl(0xFFFFFF00));
    if_mgr_->set_interface_mac(test_port, my_mac);

    netflow::Packet arp_request = create_arp_packet(
        requester_mac, netflow::MacAddress({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        1, // ARP Opcode: Request
        requester_mac, requester_ip_net,
        netflow::MacAddress({0x00,0x00,0x00,0x00,0x00,0x00}), my_ip_net
    );

    last_sent_packet_.reset();
    arp_proc_->process_arp_packet(arp_request, test_port);

    ASSERT_TRUE(last_sent_packet_.has_value());
    ASSERT_EQ(last_sent_port_, test_port);

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
    ASSERT_TRUE(string_to_ip_net_order_test("10.254.254.1", unknown_ip));
    EXPECT_FALSE(arp_proc_->lookup_mac(unknown_ip).has_value());
}

// Gratuitous ARP: ARP Request with Sender IP == Target IP
TEST_F(ArpProcessorTest, ReceiveGratuitousArpRequest) {
    uint32_t test_port = 2;
    netflow::IpAddress gratuitous_ip_net;
    netflow::MacAddress gratuitous_mac({0x12,0x34,0x56,0x78,0x9A,0xBC});

    ASSERT_TRUE(string_to_ip_net_order_test("192.168.2.10", gratuitous_ip_net));

    // Gratuitous ARP can be a request or reply. Test request first.
    // Target MAC in Ethernet header is often broadcast for GARP request.
    netflow::Packet garp_request = create_arp_packet(
        gratuitous_mac, netflow::MacAddress({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        1, // ARP Opcode: Request
        gratuitous_mac, gratuitous_ip_net, // Sender IP and MAC
        netflow::MacAddress({0x00,0x00,0x00,0x00,0x00,0x00}), gratuitous_ip_net // Target IP is same as sender, Target MAC is often zero
    );

    last_sent_packet_.reset(); // Ensure no reply is expected for this type of GARP
    arp_proc_->process_arp_packet(garp_request, test_port);

    // Check cache
    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(gratuitous_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == gratuitous_mac);
    EXPECT_FALSE(last_sent_packet_.has_value()); // Should not send a reply to a GARP request for itself
}

// Gratuitous ARP: ARP Reply (often with broadcast MAC in Ethernet header)
TEST_F(ArpProcessorTest, ReceiveGratuitousArpReply) {
    uint32_t test_port = 3;
    netflow::IpAddress gratuitous_ip_net;
    netflow::MacAddress gratuitous_mac({0xAB,0xCD,0xEF,0x12,0x34,0x56});

    ASSERT_TRUE(string_to_ip_net_order_test("192.168.3.20", gratuitous_ip_net));

    netflow::Packet garp_reply = create_arp_packet(
        gratuitous_mac, netflow::MacAddress({0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}),
        2, // ARP Opcode: Reply
        gratuitous_mac, gratuitous_ip_net, // Sender IP and MAC
        gratuitous_mac, gratuitous_ip_net  // Target IP/MAC can be same as sender for GARP reply
    );

    last_sent_packet_.reset();
    arp_proc_->process_arp_packet(garp_reply, test_port);

    std::optional<netflow::MacAddress> cached_mac = arp_proc_->lookup_mac(gratuitous_ip_net);
    ASSERT_TRUE(cached_mac.has_value());
    EXPECT_TRUE(cached_mac.value() == gratuitous_mac);
    EXPECT_FALSE(last_sent_packet_.has_value());
}

// Note: ARP Cache Aging test is more complex due to time dependency.
// It would typically require a way to mock or advance the steady_clock.
// For now, testing add/lookup covers basic cache functionality.

File 'tests/arp_processor_test.cpp' overwritten successfully.
