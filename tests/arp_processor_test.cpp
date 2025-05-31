#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "netflow++/arp_processor.hpp"
#include "netflow++/interface_manager.hpp" // Real header for types
#include "netflow++/switch.hpp"         // Real header for types
#include "netflow++/packet.hpp"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/buffer_pool.hpp"
#include <chrono>
#include <memory> // For std::make_shared
#include <vector> // For std::vector

using namespace netflow;
using namespace std::chrono_literals;
using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::An; // For An<Type>()
using ::testing::NiceMock;
using ::testing::Invoke;

// Mock InterfaceManager
// Using NiceMock to suppress warnings about uninteresting calls for default setup
class MockArpInterfaceManager : public InterfaceManager {
public:
    // Constructor needed if base InterfaceManager has a specific constructor.
    // Assuming InterfaceManager() or InterfaceManager(Switch&) or similar.
    // For this test, we don't need a real Switch reference in the mock.
    MockArpInterfaceManager() : InterfaceManager() {} // Adjust if base constructor is different

    MOCK_METHOD(std::optional<MacAddress>, get_interface_mac, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::vector<InterfaceIpConfig>, get_interface_ip_configs, (uint32_t port_id), (const, override));
    MOCK_METHOD(bool, is_my_ip, (const IpAddress& ip), (const, override));
    MOCK_METHOD(std::optional<uint32_t>, get_port_id_for_ip_subnet, (const IpAddress& ip), (const, override));
    MOCK_METHOD(std::optional<MacAddress>, get_mac_for_ip, (const IpAddress& ip), (const, override));
    MOCK_METHOD(bool, is_port_l3, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::optional<InterfaceIpConfig>, get_primary_ip_config, (uint32_t port_id), (const, override));

};

// Mock Switch
// Using NiceMock to suppress warnings about uninteresting calls
class MockArpSwitch : public Switch {
public:
    MockArpSwitch(uint32_t num_ports = 1, uint64_t switch_mac_val = 0x112233445566ULL)
        : Switch(num_ports, switch_mac_val) {} // Call base constructor

    MOCK_METHOD(void, send_control_plane_frame_raw, (uint32_t egress_port_id, const uint8_t* frame_data, size_t frame_length), (override));

    // Override the version that takes payload vector to redirect to raw version for easier mocking.
    void send_control_plane_frame(uint32_t egress_port_id, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype, const std::vector<uint8_t>& payload) override {
        // Construct the full frame to pass to the raw method
        size_t header_size = sizeof(EthernetHeader);
        size_t total_size = header_size + payload.size();
        std::vector<uint8_t> frame_data(total_size);

        EthernetHeader* eth_hdr = reinterpret_cast<EthernetHeader*>(frame_data.data());
        eth_hdr->dst_mac = dst_mac;
        eth_hdr->src_mac = src_mac;
        eth_hdr->ethertype = htons(ethertype);
        std::copy(payload.begin(), payload.end(), frame_data.data() + header_size);

        send_control_plane_frame_raw(egress_port_id, frame_data.data(), frame_data.size());
    }
};

class ArpProcessorTest : public ::testing::Test {
protected:
    std::shared_ptr<NiceMock<MockArpInterfaceManager>> mock_if_mgr;
    std::shared_ptr<NiceMock<MockArpSwitch>> mock_switch;
    std::unique_ptr<ArpProcessor> arp_processor;

    BufferPool test_pool{10, sizeof(EthernetHeader) + sizeof(ArpPacket) + 64}; // Ensure enough space

    IpAddress local_ip1{"192.168.1.1"};
    MacAddress local_mac1{{0x00,0x00,0x00,0x01,0x01,0x01}};
    uint32_t port1_id = 1;

    IpAddress remote_ip1{"192.168.1.100"};
    MacAddress remote_mac1{{0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}};

    IpAddress remote_ip2{"192.168.1.101"}; // For pending requests

    void SetUp() override {
        mock_if_mgr = std::make_shared<NiceMock<MockArpInterfaceManager>>();
        mock_switch = std::make_shared<NiceMock<MockArpSwitch>>();
        arp_processor = std::make_unique<ArpProcessor>(*mock_switch, *mock_if_mgr);
        arp_processor->set_entry_timeout(1s); // Short timeout for testing
        arp_processor->set_pending_request_timeout(1s);
        arp_processor->set_max_pending_requests(5);


        // Default actions for InterfaceManager
        ON_CALL(*mock_if_mgr, get_interface_mac(port1_id)).WillByDefault(Return(local_mac1));
        ON_CALL(*mock_if_mgr, get_interface_ip_configs(port1_id)).WillByDefault(Return(std::vector<InterfaceIpConfig>{{local_ip1, IpAddress("255.255.255.0")}}));
        ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));
        ON_CALL(*mock_if_mgr, is_my_ip(local_ip1)).WillByDefault(Return(true));
        ON_CALL(*mock_if_mgr, get_mac_for_ip(local_ip1)).WillByDefault(Return(local_mac1)); // For requests originating from us
        ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(remote_ip1)).WillByDefault(Return(port1_id));
        ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(remote_ip2)).WillByDefault(Return(port1_id));
        ON_CALL(*mock_if_mgr, is_port_l3(port1_id)).WillByDefault(Return(true));

    }

    // Helper to create an ARP Packet
    Packet create_arp_packet(uint16_t opcode,
                             const MacAddress& sender_mac, const IpAddress& sender_ip,
                             const MacAddress& target_mac, const IpAddress& target_ip,
                             uint32_t ingress_port = 0) { // ingress_port for the packet itself
        PacketBuffer* pb = test_pool.allocate();
        if (!pb) throw std::runtime_error("Failed to allocate packet buffer in test");

        size_t arp_payload_size = sizeof(ArpPacket);
        pb->set_data_length(sizeof(EthernetHeader) + arp_payload_size);

        Packet pkt(pb);
        pkt.set_ingress_port(ingress_port);


        EthernetHeader* eth = pkt.ethernet();
        eth->dst_mac = (opcode == ARP_OPCODE_REQUEST) ? MAC_BROADCAST : target_mac; // Simplified target for reply
        eth->src_mac = sender_mac;
        eth->ethertype = htons(ETHERTYPE_ARP);

        ArpPacket* arp_hdr = reinterpret_cast<ArpPacket*>(pkt.get_payload_data_writeable());
        arp_hdr->htype = htons(ARP_HTYPE_ETHERNET);
        arp_hdr->ptype = htons(ETHERTYPE_IPV4);
        arp_hdr->hlen = 6;
        arp_hdr->plen = 4;
        arp_hdr->oper = htons(opcode);
        arp_hdr->sha = sender_mac;
        arp_hdr->spa = sender_ip;
        arp_hdr->tha = target_mac; // For request, this is often 00s, for reply, it's us
        arp_hdr->tpa = target_ip;

        pb->decrement_ref();
        return pkt;
    }
};

TEST_F(ArpProcessorTest, ProcessArpRequestForLocalIp) {
    Packet arp_request = create_arp_packet(ARP_OPCODE_REQUEST, remote_mac1, remote_ip1, MacAddress::ZERO, local_ip1, port1_id);

    const uint8_t* sent_frame_data = nullptr;
    size_t sent_frame_length = 0;
    std::vector<uint8_t> captured_frame_data;

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(port1_id, _, _))
        .WillOnce(Invoke([&](uint32_t, const uint8_t* data, size_t length) {
            captured_frame_data.assign(data, data + length);
        }));

    ON_CALL(*mock_if_mgr, get_interface_mac(port1_id)).WillByDefault(Return(local_mac1));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));


    arp_processor->process_arp_packet(arp_request);

    ASSERT_FALSE(captured_frame_data.empty());
    EthernetHeader* reply_eth = reinterpret_cast<EthernetHeader*>(captured_frame_data.data());
    ArpPacket* reply_arp = reinterpret_cast<ArpPacket*>(captured_frame_data.data() + sizeof(EthernetHeader));

    EXPECT_EQ(reply_eth->dst_mac, remote_mac1);
    EXPECT_EQ(reply_eth->src_mac, local_mac1);
    EXPECT_EQ(ntohs(reply_eth->ethertype), ETHERTYPE_ARP);
    EXPECT_EQ(ntohs(reply_arp->oper), ARP_OPCODE_REPLY);
    EXPECT_EQ(reply_arp->sha, local_mac1);
    EXPECT_EQ(reply_arp->spa, local_ip1);
    EXPECT_EQ(reply_arp->tha, remote_mac1);
    EXPECT_EQ(reply_arp->tpa, remote_ip1);

    // Also check if the requester's MAC was learned
    auto learned_mac = arp_processor->lookup_mac(remote_ip1);
    ASSERT_TRUE(learned_mac.has_value());
    EXPECT_EQ(learned_mac.value(), remote_mac1);
}

TEST_F(ArpProcessorTest, ProcessArpRequestForNonLocalIp) {
    IpAddress some_other_ip("10.10.10.10");
    ON_CALL(*mock_if_mgr, is_my_ip(some_other_ip)).WillByDefault(Return(false));
    // Ensure get_primary_ip_config for the ingress port returns an IP that doesn't match some_other_ip
    ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));


    Packet arp_request = create_arp_packet(ARP_OPCODE_REQUEST, remote_mac1, remote_ip1, MacAddress::ZERO, some_other_ip, port1_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);
    arp_processor->process_arp_packet(arp_request);
}

TEST_F(ArpProcessorTest, ProcessArpReply) {
    Packet arp_reply = create_arp_packet(ARP_OPCODE_REPLY, remote_mac1, remote_ip1, local_mac1, local_ip1, port1_id);

    // Simulate that we were waiting for this reply
    arp_processor->resolve_mac(remote_ip1, port1_id); // This should put it in pending

    arp_processor->process_arp_packet(arp_reply);

    auto resolved_mac = arp_processor->lookup_mac(remote_ip1);
    ASSERT_TRUE(resolved_mac.has_value());
    EXPECT_EQ(resolved_mac.value(), remote_mac1);
}

TEST_F(ArpProcessorTest, LookupMacNotInCacheNoRequestSent) {
    IpAddress unknown_ip("1.2.3.4");
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);
    auto mac = arp_processor->lookup_mac(unknown_ip);
    EXPECT_FALSE(mac.has_value());
}

TEST_F(ArpProcessorTest, SendArpRequestAndCachePending) {
    ON_CALL(*mock_if_mgr, get_interface_mac(port1_id)).WillByDefault(Return(local_mac1));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));
    ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(remote_ip2)).WillByDefault(Return(port1_id));


    const uint8_t* sent_frame_data = nullptr;
    size_t sent_frame_length = 0;
    std::vector<uint8_t> captured_frame_data;

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(port1_id, _, _))
        .WillOnce(Invoke([&](uint32_t, const uint8_t* data, size_t length) {
            captured_frame_data.assign(data, data + length);
        }));

    arp_processor->resolve_mac(remote_ip2, port1_id); // This IP is not in cache

    ASSERT_FALSE(captured_frame_data.empty());
    EthernetHeader* req_eth = reinterpret_cast<EthernetHeader*>(captured_frame_data.data());
    ArpPacket* req_arp = reinterpret_cast<ArpPacket*>(captured_frame_data.data() + sizeof(EthernetHeader));

    EXPECT_EQ(req_eth->dst_mac, MAC_BROADCAST);
    EXPECT_EQ(req_eth->src_mac, local_mac1);
    EXPECT_EQ(ntohs(req_arp->oper), ARP_OPCODE_REQUEST);
    EXPECT_EQ(req_arp->sha, local_mac1);
    EXPECT_EQ(req_arp->spa, local_ip1); // Sender is our interface IP
    EXPECT_EQ(req_arp->tha, MacAddress::ZERO);
    EXPECT_EQ(req_arp->tpa, remote_ip2); // Target is the IP we want to resolve

    // Check if it's in pending state (implementation specific, lookup might return nullopt)
    auto mac_after_req = arp_processor->lookup_mac(remote_ip2);
    EXPECT_FALSE(mac_after_req.has_value()); // Should be pending, not resolved yet
}


TEST_F(ArpProcessorTest, ArpCacheTimeout) {
    // Process a reply to populate the cache
    Packet arp_reply = create_arp_packet(ARP_OPCODE_REPLY, remote_mac1, remote_ip1, local_mac1, local_ip1, port1_id);
    arp_processor->process_arp_packet(arp_reply);

    auto mac_before_timeout = arp_processor->lookup_mac(remote_ip1);
    ASSERT_TRUE(mac_before_timeout.has_value());
    EXPECT_EQ(mac_before_timeout.value(), remote_mac1);

    // Wait for longer than the timeout (1s set in SetUp)
    std::this_thread::sleep_for(1100ms);
    arp_processor->cleanup_expired_entries();

    auto mac_after_timeout = arp_processor->lookup_mac(remote_ip1);
    EXPECT_FALSE(mac_after_timeout.has_value());
}

TEST_F(ArpProcessorTest, GratuitousArpProcessing) {
    // Gratuitous ARP: sender_ip == target_ip, target_mac is often zero in request, or sender mac in reply
    // Using a common GARP format (ARP Request with SHA=Real MAC, SPA=Our IP, THA=Zeroes, TPA=Our IP)
    MacAddress new_sender_mac{{0x12,0x34,0x56,0x78,0x9A,0xBC}};
    IpAddress new_sender_ip("192.168.1.200");

    Packet garp_packet = create_arp_packet(ARP_OPCODE_REQUEST, new_sender_mac, new_sender_ip, MacAddress::ZERO, new_sender_ip, port1_id);

    // No ARP reply should be sent for a GARP
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);

    arp_processor->process_arp_packet(garp_packet);

    auto learned_mac = arp_processor->lookup_mac(new_sender_ip);
    ASSERT_TRUE(learned_mac.has_value());
    EXPECT_EQ(learned_mac.value(), new_sender_mac);
}

TEST_F(ArpProcessorTest, PendingRequestTimeout) {
    ON_CALL(*mock_if_mgr, get_interface_mac(port1_id)).WillByDefault(Return(local_mac1));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));

    // Expect initial ARP request
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(port1_id, _, _)).Times(1);
    arp_processor->resolve_mac(remote_ip2, port1_id);

    // Wait for pending request to time out
    std::this_thread::sleep_for(1100ms); // timeout is 1s
    arp_processor->cleanup_expired_entries(); // This should remove the pending request

    // Try to resolve again, it should send a new request if the old one timed out
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(port1_id, _, _)).Times(1);
    arp_processor->resolve_mac(remote_ip2, port1_id);
}

TEST_F(ArpProcessorTest, MaxPendingRequests) {
    ON_CALL(*mock_if_mgr, get_interface_mac(port1_id)).WillByDefault(Return(local_mac1));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(port1_id)).WillByDefault(Return(InterfaceIpConfig{local_ip1, IpAddress("255.255.255.0")}));

    int max_req = 3;
    arp_processor->set_max_pending_requests(max_req);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(port1_id, _, _)).Times(max_req);

    for(int i=0; i < max_req; ++i) {
        arp_processor->resolve_mac(IpAddress("192.168.1.20" + std::to_string(i)), port1_id);
    }

    // This one should exceed max pending requests
    bool result = arp_processor->resolve_mac(IpAddress("192.168.1.299"), port1_id);
    EXPECT_FALSE(result); // Should fail to send because pending queue is full
}

TEST_F(ArpProcessorTest, ProcessArpRequestToL3PortWithoutIpConfig) {
    uint32_t l3_port_no_ip_id = 2;
    ON_CALL(*mock_if_mgr, is_port_l3(l3_port_no_ip_id)).WillByDefault(Return(true));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(l3_port_no_ip_id)).WillByDefault(Return(std::nullopt)); // Port is L3 but no IP

    // ARP Request for some IP, arriving on port 2
    Packet arp_request = create_arp_packet(ARP_OPCODE_REQUEST, remote_mac1, remote_ip1, MacAddress::ZERO, IpAddress("192.168.1.50"), l3_port_no_ip_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);
    arp_processor->process_arp_packet(arp_request);
}

TEST_F(ArpProcessorTest, ProcessArpRequestToNonL3Port) {
    uint32_t l2_port_id = 3;
    ON_CALL(*mock_if_mgr, is_port_l3(l2_port_id)).WillByDefault(Return(false)); // Not an L3 port

    Packet arp_request = create_arp_packet(ARP_OPCODE_REQUEST, remote_mac1, remote_ip1, MacAddress::ZERO, local_ip1, l2_port_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);
    arp_processor->process_arp_packet(arp_request);
}

TEST_F(ArpProcessorTest, ResolveMacForIpOnNonL3PortOrNoRoute) {
    uint32_t target_port_id = 4; // Some port
    IpAddress target_ip_no_route("172.16.50.1");

    // Case 1: Port for subnet is not L3
    ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(target_ip_no_route)).WillByDefault(Return(target_port_id));
    ON_CALL(*mock_if_mgr, is_port_l3(target_port_id)).WillByDefault(Return(false));
    EXPECT_FALSE(arp_processor->resolve_mac(target_ip_no_route, target_port_id));
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);

    // Case 2: No route/port for subnet
    ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(target_ip_no_route)).WillByDefault(Return(std::nullopt));
    EXPECT_FALSE(arp_processor->resolve_mac(target_ip_no_route, target_port_id)); // target_port_id here is just for consistency, not used if no route
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);

    // Case 3: Port is L3, but no primary IP config on that port (cannot source ARP request)
    ON_CALL(*mock_if_mgr, get_port_id_for_ip_subnet(target_ip_no_route)).WillByDefault(Return(target_port_id));
    ON_CALL(*mock_if_mgr, is_port_l3(target_port_id)).WillByDefault(Return(true));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(target_port_id)).WillByDefault(Return(std::nullopt));
    EXPECT_FALSE(arp_processor->resolve_mac(target_ip_no_route, target_port_id));
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_)).Times(0);

}

TEST_F(ArpProcessorTest, UpdateExistingEntryWithNewMac) {
    // Initial ARP reply to populate the cache
    Packet arp_reply1 = create_arp_packet(ARP_OPCODE_REPLY, remote_mac1, remote_ip1, local_mac1, local_ip1, port1_id);
    arp_processor->process_arp_packet(arp_reply1);
    auto mac1 = arp_processor->lookup_mac(remote_ip1);
    ASSERT_TRUE(mac1.has_value());
    EXPECT_EQ(mac1.value(), remote_mac1);

    // Another ARP reply for the same IP but different MAC (e.g. device changed NIC)
    MacAddress new_remote_mac{{0xDE,0xAD,0xBE,0xEF,0x00,0x11}};
    Packet arp_reply2 = create_arp_packet(ARP_OPCODE_REPLY, new_remote_mac, remote_ip1, local_mac1, local_ip1, port1_id);
    arp_processor->process_arp_packet(arp_reply2);

    auto mac2 = arp_processor->lookup_mac(remote_ip1);
    ASSERT_TRUE(mac2.has_value());
    EXPECT_EQ(mac2.value(), new_remote_mac); // MAC should be updated
}

TEST_F(ArpProcessorTest, StaticArpEntry) {
    IpAddress static_ip("192.168.1.250");
    MacAddress static_mac{{0x01,0x02,0x03,0x04,0x05,0x06}};
    uint32_t static_port = port1_id;

    arp_processor->add_static_entry(static_ip, static_mac, static_port);

    auto mac = arp_processor->lookup_mac(static_ip);
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac.value(), static_mac);

    // Try to "learn" a different MAC for this IP via dynamic ARP - it should be ignored
    Packet arp_reply_dynamic = create_arp_packet(ARP_OPCODE_REPLY, remote_mac1, static_ip, local_mac1, local_ip1, port1_id);
    arp_processor->process_arp_packet(arp_reply_dynamic);
    mac = arp_processor->lookup_mac(static_ip);
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(mac.value(), static_mac); // Should still be the static MAC

    // Test timeout - static entry should not time out
    std::this_thread::sleep_for(1100ms); // Timeout is 1s
    arp_processor->cleanup_expired_entries();
    mac = arp_processor->lookup_mac(static_ip);
    ASSERT_TRUE(mac.has_value()); // Still there
    EXPECT_EQ(mac.value(), static_mac);

    // Remove static entry
    arp_processor->remove_static_entry(static_ip);
    mac = arp_processor->lookup_mac(static_ip);
    EXPECT_FALSE(mac.has_value()); // Should be gone
}
