#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "netflow++/icmp_processor.hpp"
#include "netflow++/interface_manager.hpp" // Real header for types
#include "netflow++/routing_manager.hpp"   // Real header for types
#include "netflow++/arp_processor.hpp"     // Real header for types
#include "netflow++/switch.hpp"           // Real header for types
#include "netflow++/packet.hpp"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/buffer_pool.hpp"
#include <memory> // For std::make_shared
#include <vector>

using namespace netflow;
using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::NotNull;
using ::testing::NiceMock;
using ::testing::Invoke;
using ::testing::SaveArgs;


// Mocks
class MockIcmpInterfaceManager : public InterfaceManager {
public:
    MockIcmpInterfaceManager() : InterfaceManager() {}
    MOCK_METHOD(bool, is_my_ip, (const IpAddress& ip), (const, override));
    MOCK_METHOD(std::optional<MacAddress>, get_interface_mac, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::vector<InterfaceIpConfig>, get_interface_ip_configs, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::optional<InterfaceIpConfig>, get_primary_ip_config_for_subnet, (const IpAddress& ip), (const, override));
    MOCK_METHOD(std::optional<uint32_t>, get_port_id_for_ip_subnet, (const IpAddress& ip), (const, override));
    MOCK_METHOD(std::optional<InterfaceIpConfig>, get_primary_ip_config, (uint32_t port_id), (const, override));

};

class MockIcmpRoutingManager : public RoutingManager {
public:
     MockIcmpRoutingManager() : RoutingManager() {}
    MOCK_METHOD(std::optional<RouteEntry>, lookup_route, (const IpAddress& destination_ip), (const, override));
};

class MockIcmpArpProcessor : public ArpProcessor {
public:
    MockIcmpArpProcessor(Switch& sw, InterfaceManager& if_mgr) : ArpProcessor(sw, if_mgr) {}
    MOCK_METHOD(std::optional<MacAddress>, lookup_mac, (const IpAddress& ip), (override));
    MOCK_METHOD(void, resolve_mac, (const IpAddress& target_ip, uint32_t egress_port_id, const Packet* original_packet), (override));
};

class MockIcmpSwitch : public Switch {
public:
    MockIcmpSwitch(uint32_t num_ports = 1, uint64_t mac = 0x010203040506ULL) : Switch(num_ports, mac) {}
    // Capture all arguments for send_control_plane_frame_raw
    MOCK_METHOD(void, send_control_plane_frame_raw, (uint32_t egress_port_id, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype, const uint8_t* payload_data, size_t payload_len), (override));

};


class IcmpProcessorTest : public ::testing::Test {
protected:
    std::shared_ptr<NiceMock<MockIcmpInterfaceManager>> mock_if_mgr;
    std::shared_ptr<NiceMock<MockIcmpRoutingManager>> mock_rt_mgr;
    std::shared_ptr<NiceMock<MockIcmpArpProcessor>> mock_arp_processor;
    std::shared_ptr<NiceMock<MockIcmpSwitch>> mock_switch;
    std::unique_ptr<IcmpProcessor> icmp_processor;

    BufferPool test_pool{10, 1500}; // Pool for creating packets

    IpAddress local_ip{"192.168.1.1"};
    MacAddress local_mac{{0x01,0x01,0x01,0x01,0x01,0x01}};
    uint32_t ingress_port_id = 1;
    uint32_t egress_port_id_for_remote = 2;


    IpAddress remote_ip{"192.168.1.100"};
    MacAddress remote_mac{{0xAA,0xBB,0xCC,0xDD,0xEE,0x01}};

    IpAddress another_remote_ip{"10.10.10.10"}; // For testing ICMP errors going to a different network
    MacAddress another_remote_mac{{0xAA,0xBB,0xCC,0xDD,0xEE,0x02}};
    IpAddress next_hop_for_another_remote_ip{"192.168.1.254"};
    MacAddress mac_for_next_hop_another_remote_ip{{0x00,0x01,0x02,0x03,0x04,0x05}};


    void SetUp() override {
        mock_if_mgr = std::make_shared<NiceMock<MockIcmpInterfaceManager>>();
        mock_rt_mgr = std::make_shared<NiceMock<MockIcmpRoutingManager>>();
        mock_switch = std::make_shared<NiceMock<MockIcmpSwitch>>();
        mock_arp_processor = std::make_shared<NiceMock<MockIcmpArpProcessor>>(*mock_switch, *mock_if_mgr);

        icmp_processor = std::make_unique<IcmpProcessor>(*mock_switch, *mock_if_mgr, *mock_rt_mgr, *mock_arp_processor);

        // Common ON_CALL setups
        ON_CALL(*mock_if_mgr, is_my_ip(local_ip)).WillByDefault(Return(true));
        ON_CALL(*mock_if_mgr, is_my_ip(remote_ip)).WillByDefault(Return(false));
        ON_CALL(*mock_if_mgr, is_my_ip(another_remote_ip)).WillByDefault(Return(false));

        ON_CALL(*mock_if_mgr, get_interface_mac(ingress_port_id)).WillByDefault(Return(local_mac));
        ON_CALL(*mock_if_mgr, get_interface_mac(egress_port_id_for_remote)).WillByDefault(Return(local_mac)); // Assuming egress uses same MAC for now

        // Used when local_ip is the source of an ICMP error message
        ON_CALL(*mock_if_mgr, get_primary_ip_config_for_subnet(local_ip))
            .WillByDefault(Return(InterfaceIpConfig{local_ip, IpAddress("255.255.255.0")}));
        ON_CALL(*mock_if_mgr, get_primary_ip_config(ingress_port_id))
            .WillByDefault(Return(InterfaceIpConfig{local_ip, IpAddress("255.255.255.0")}));


        // For routing ICMP replies back to remote_ip
        RouteEntry route_to_remote;
        route_to_remote.destination_network = IpAddress("192.168.1.0");
        route_to_remote.subnet_mask = IpAddress("255.255.255.0");
        route_to_remote.next_hop_ip = remote_ip; // Directly connected for simplicity in echo reply
        route_to_remote.egress_interface_id = ingress_port_id; // Replies go out same interface it came in
        ON_CALL(*mock_rt_mgr, lookup_route(remote_ip)).WillByDefault(Return(route_to_remote));
        ON_CALL(*mock_arp_processor, lookup_mac(remote_ip)).WillByDefault(Return(remote_mac));


        // For routing ICMP error messages to another_remote_ip
        RouteEntry route_to_another_remote;
        route_to_another_remote.destination_network = IpAddress("10.10.10.0");
        route_to_another_remote.subnet_mask = IpAddress("255.255.255.0");
        route_to_another_remote.next_hop_ip = next_hop_for_another_remote_ip;
        route_to_another_remote.egress_interface_id = egress_port_id_for_remote;
        ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(route_to_another_remote));
        ON_CALL(*mock_arp_processor, lookup_mac(next_hop_for_another_remote_ip)).WillByDefault(Return(mac_for_next_hop_another_remote_ip));
        ON_CALL(*mock_if_mgr, get_interface_mac(egress_port_id_for_remote)).WillByDefault(Return(local_mac)); // Source MAC for error messages
         ON_CALL(*mock_if_mgr, get_primary_ip_config(egress_port_id_for_remote))
            .WillByDefault(Return(InterfaceIpConfig{IpAddress("192.168.2.1"), IpAddress("255.255.255.0")})); // Source IP for error messages from this port
    }

    Packet create_packet_with_payload(const IpAddress& src_ip, const MacAddress& src_mac_addr,
                                      const IpAddress& dst_ip, const MacAddress& dst_mac_addr,
                                      uint8_t protocol, const std::vector<uint8_t>& payload,
                                      uint32_t specific_ingress_port_id) {
        size_t total_len = sizeof(EthernetHeader) + sizeof(IPv4Header) + payload.size();
        PacketBuffer* pb = test_pool.allocate(total_len);
        if (!pb) throw std::runtime_error("Failed to allocate packet buffer in test");
        pb->set_data_length(total_len);
        Packet pkt(pb);
        pkt.set_ingress_port(specific_ingress_port_id);


        EthernetHeader* eth = pkt.ethernet();
        eth->dst_mac = dst_mac_addr;
        eth->src_mac = src_mac_addr;
        eth->ethertype = htons(ETHERTYPE_IPV4);

        IPv4Header* ip_hdr = pkt.ipv4();
        ip_hdr->version_ihl = 0x45;
        ip_hdr->dscp_ecn = 0;
        ip_hdr->total_length = htons(sizeof(IPv4Header) + payload.size());
        ip_hdr->identification = htons(54321);
        ip_hdr->flags_fragment_offset = 0;
        ip_hdr->ttl = 64;
        ip_hdr->protocol = protocol;
        ip_hdr->header_checksum = 0;
        ip_hdr->src_ip = src_ip;
        ip_hdr->dst_ip = dst_ip;
        ip_hdr->header_checksum = ip_hdr->calculate_checksum();

        uint8_t* ip_payload_data = reinterpret_cast<uint8_t*>(ip_hdr) + sizeof(IPv4Header);
        memcpy(ip_payload_data, payload.data(), payload.size());

        pb->decrement_ref();
        return pkt;
    }

    Packet create_icmp_echo_request(const IpAddress& src_ip, const MacAddress& src_mac_addr,
                                    const IpAddress& dst_ip, const MacAddress& dst_mac_addr,
                                    uint16_t id, uint16_t seq, const std::string& payload_str,
                                    uint32_t specific_ingress_port_id) {

        std::vector<uint8_t> icmp_payload;
        icmp_payload.resize(sizeof(IcmpHeader) + payload_str.length());
        IcmpHeader* icmp_hdr_build = reinterpret_cast<IcmpHeader*>(icmp_payload.data());
        icmp_hdr_build->type = ICMP_TYPE_ECHO_REQUEST;
        icmp_hdr_build->code = 0;
        icmp_hdr_build->checksum = 0;
        icmp_hdr_build->identifier = htons(id);
        icmp_hdr_build->sequence_number = htons(seq);
        memcpy(icmp_payload.data() + sizeof(IcmpHeader), payload_str.data(), payload_str.length());

        // Calculate checksum over ICMP header and payload
        uint16_t calculated_checksum = IcmpProcessor::calculate_icmp_checksum_raw(
            reinterpret_cast<const uint8_t*>(icmp_payload.data()),
            icmp_payload.size(),
            src_ip, dst_ip); // Need pseudo header for checksum
        icmp_hdr_build->checksum = calculated_checksum;

        return create_packet_with_payload(src_ip, src_mac_addr, dst_ip, dst_mac_addr, IP_PROTOCOL_ICMP, icmp_payload, specific_ingress_port_id);
    }
};


TEST_F(IcmpProcessorTest, ProcessEchoRequestToLocalIp) {
    std::string payload = "Hello, ICMP!";
    Packet echo_request = create_icmp_echo_request(remote_ip, remote_mac, local_ip, local_mac, 123, 456, payload, ingress_port_id);

    MacAddress actual_dst_mac, actual_src_mac;
    uint16_t actual_ethertype = 0;
    const uint8_t* actual_payload_data = nullptr;
    size_t actual_payload_len = 0;

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(ingress_port_id, _, _, _, _, _))
        .WillOnce(Invoke([&](uint32_t, const MacAddress& dst, const MacAddress& src, uint16_t etype, const uint8_t* pdata, size_t plen) {
            actual_dst_mac = dst;
            actual_src_mac = src;
            actual_ethertype = etype;
            // Need to copy payload data as it might be a temporary buffer
            uint8_t* data_copy = new uint8_t[plen];
            memcpy(data_copy, pdata, plen);
            actual_payload_data = data_copy;
            actual_payload_len = plen;
        }));

    icmp_processor->process_icmp_packet(echo_request);

    ASSERT_NE(actual_payload_data, nullptr);
    EXPECT_EQ(actual_dst_mac, remote_mac);
    EXPECT_EQ(actual_src_mac, local_mac);
    EXPECT_EQ(ntohs(actual_ethertype), ETHERTYPE_IPV4);

    IPv4Header* reply_ip_hdr = reinterpret_cast<IPv4Header*>(const_cast<uint8_t*>(actual_payload_data));
    EXPECT_EQ(reply_ip_hdr->src_ip, local_ip);
    EXPECT_EQ(reply_ip_hdr->dst_ip, remote_ip);
    EXPECT_EQ(reply_ip_hdr->protocol, IP_PROTOCOL_ICMP);

    IcmpHeader* reply_icmp_hdr = reinterpret_cast<IcmpHeader*>(const_cast<uint8_t*>(actual_payload_data) + reply_ip_hdr->ihl() * 4);
    EXPECT_EQ(reply_icmp_hdr->type, ICMP_TYPE_ECHO_REPLY);
    EXPECT_EQ(reply_icmp_hdr->code, 0);
    EXPECT_EQ(ntohs(reply_icmp_hdr->identifier), 123);
    EXPECT_EQ(ntohs(reply_icmp_hdr->sequence_number), 456);

    std::string reply_payload_str(reinterpret_cast<char*>(reply_icmp_hdr) + sizeof(IcmpHeader), actual_payload_len - (reply_ip_hdr->ihl() * 4) - sizeof(IcmpHeader));
    EXPECT_EQ(reply_payload_str, payload);

    delete[] actual_payload_data; // Clean up copied data
}

TEST_F(IcmpProcessorTest, ProcessEchoRequestToNonLocalIp) {
    IpAddress non_local_dest_ip("1.2.3.4");
    ON_CALL(*mock_if_mgr, is_my_ip(non_local_dest_ip)).WillByDefault(Return(false));
    Packet echo_request = create_icmp_echo_request(remote_ip, remote_mac, non_local_dest_ip, local_mac, 1, 1, "test", ingress_port_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->process_icmp_packet(echo_request);
}

TEST_F(IcmpProcessorTest, SendDestinationUnreachableNet) {
    // Original packet that triggers the error
    std::vector<uint8_t> original_udp_payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    Packet original_packet = create_packet_with_payload(another_remote_ip, another_remote_mac, IpAddress("172.16.10.20"), MacAddress::BROADCAST, IP_PROTOCOL_UDP, original_udp_payload, ingress_port_id);
    original_packet.set_ingress_port(ingress_port_id);


    // Setup mocks for sending the ICMP error message
    // Route lookup for the source of the original packet (another_remote_ip)
    ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(RouteEntry{IpAddress("10.10.10.0"), IpAddress("255.255.255.0"), next_hop_for_another_remote_ip, egress_port_id_for_remote}));
    ON_CALL(*mock_arp_processor, lookup_mac(next_hop_for_another_remote_ip)).WillByDefault(Return(mac_for_next_hop_another_remote_ip));
    ON_CALL(*mock_if_mgr, get_interface_mac(egress_port_id_for_remote)).WillByDefault(Return(local_mac)); // Our MAC for the egress port
    ON_CALL(*mock_if_mgr, get_primary_ip_config(egress_port_id_for_remote)).WillByDefault(Return(InterfaceIpConfig{IpAddress("192.168.2.1"), IpAddress("255.255.255.0")})); // Our IP for the egress port


    const uint8_t* actual_payload_data = nullptr;
    size_t actual_payload_len = 0;
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(egress_port_id_for_remote, mac_for_next_hop_another_remote_ip, local_mac, _, _, _))
         .WillOnce(Invoke([&](uint32_t, const MacAddress&, const MacAddress&, uint16_t, const uint8_t* pdata, size_t plen) {
            uint8_t* data_copy = new uint8_t[plen];
            memcpy(data_copy, pdata, plen);
            actual_payload_data = data_copy;
            actual_payload_len = plen;
        }));

    icmp_processor->send_destination_unreachable(original_packet, ICMP_CODE_DEST_NET_UNREACHABLE);

    ASSERT_NE(actual_payload_data, nullptr);
    IPv4Header* error_ip_hdr = reinterpret_cast<IPv4Header*>(const_cast<uint8_t*>(actual_payload_data));
    EXPECT_EQ(error_ip_hdr->src_ip, IpAddress("192.168.2.1")); // IP of egress_port_id_for_remote
    EXPECT_EQ(error_ip_hdr->dst_ip, another_remote_ip); // Sent back to original sender
    EXPECT_EQ(error_ip_hdr->protocol, IP_PROTOCOL_ICMP);

    IcmpHeader* error_icmp_hdr = reinterpret_cast<IcmpHeader*>(const_cast<uint8_t*>(actual_payload_data) + error_ip_hdr->ihl() * 4);
    EXPECT_EQ(error_icmp_hdr->type, ICMP_TYPE_DEST_UNREACHABLE);
    EXPECT_EQ(error_icmp_hdr->code, ICMP_CODE_DEST_NET_UNREACHABLE);

    // Check embedded original packet data
    uint8_t* embedded_data = reinterpret_cast<uint8_t*>(error_icmp_hdr) + sizeof(IcmpHeader) + 4; // +4 for unused part of ICMP error header
    IPv4Header* embedded_ip_hdr = reinterpret_cast<IPv4Header*>(embedded_data);
    EXPECT_EQ(embedded_ip_hdr->src_ip, original_packet.ipv4()->src_ip);
    EXPECT_EQ(embedded_ip_hdr->dst_ip, original_packet.ipv4()->dst_ip);
    EXPECT_EQ(embedded_ip_hdr->protocol, original_packet.ipv4()->protocol);

    size_t expected_original_data_len = original_packet.ipv4()->ihl() * 4 + 8; // Original IP header + 8 bytes of payload
    size_t actual_icmp_payload_len = actual_payload_len - (error_ip_hdr->ihl() * 4) - sizeof(IcmpHeader) - 4; // -4 for unused
    EXPECT_EQ(actual_icmp_payload_len, expected_original_data_len);

    delete[] actual_payload_data;
}


TEST_F(IcmpProcessorTest, SendTimeExceeded) {
    std::vector<uint8_t> original_tcp_payload = {0x11, 0x22, 0x33, 0x44, 0x11, 0x22, 0x33, 0x44, 0x11, 0x22}; // 10 bytes
    Packet original_packet = create_packet_with_payload(another_remote_ip, another_remote_mac, IpAddress("172.16.10.20"), MacAddress::BROADCAST, IP_PROTOCOL_TCP, original_tcp_payload, ingress_port_id);
    original_packet.set_ingress_port(ingress_port_id);


    ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(RouteEntry{IpAddress("10.10.10.0"), IpAddress("255.255.255.0"), next_hop_for_another_remote_ip, egress_port_id_for_remote}));
    ON_CALL(*mock_arp_processor, lookup_mac(next_hop_for_another_remote_ip)).WillByDefault(Return(mac_for_next_hop_another_remote_ip));
    ON_CALL(*mock_if_mgr, get_interface_mac(egress_port_id_for_remote)).WillByDefault(Return(local_mac));
    ON_CALL(*mock_if_mgr, get_primary_ip_config(egress_port_id_for_remote)).WillByDefault(Return(InterfaceIpConfig{IpAddress("192.168.2.1"), IpAddress("255.255.255.0")}));


    const uint8_t* actual_payload_data = nullptr;
    size_t actual_payload_len = 0;
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(egress_port_id_for_remote, mac_for_next_hop_another_remote_ip, local_mac, _, _, _))
        .WillOnce(Invoke([&](uint32_t, const MacAddress&, const MacAddress&, uint16_t, const uint8_t* pdata, size_t plen) {
            uint8_t* data_copy = new uint8_t[plen];
            memcpy(data_copy, pdata, plen);
            actual_payload_data = data_copy;
            actual_payload_len = plen;
        }));

    icmp_processor->send_time_exceeded(original_packet, ICMP_CODE_TTL_EXPIRED);

    ASSERT_NE(actual_payload_data, nullptr);
    IPv4Header* error_ip_hdr = reinterpret_cast<IPv4Header*>(const_cast<uint8_t*>(actual_payload_data));
    EXPECT_EQ(error_ip_hdr->src_ip, IpAddress("192.168.2.1"));
    EXPECT_EQ(error_ip_hdr->dst_ip, another_remote_ip);
    EXPECT_EQ(error_ip_hdr->protocol, IP_PROTOCOL_ICMP);

    IcmpHeader* error_icmp_hdr = reinterpret_cast<IcmpHeader*>(const_cast<uint8_t*>(actual_payload_data) + error_ip_hdr->ihl() * 4);
    EXPECT_EQ(error_icmp_hdr->type, ICMP_TYPE_TIME_EXCEEDED);
    EXPECT_EQ(error_icmp_hdr->code, ICMP_CODE_TTL_EXPIRED);

    delete[] actual_payload_data;
}

TEST_F(IcmpProcessorTest, HandleMalformedIcmpPacketTooShort) {
    // Create a packet that's too short to contain a full ICMP header
    std::vector<uint8_t> short_payload = {ICMP_TYPE_ECHO_REQUEST, 0, 0, 0}; // Only 4 bytes, IcmpHeader is 8
    Packet malformed_packet = create_packet_with_payload(remote_ip, remote_mac, local_ip, local_mac, IP_PROTOCOL_ICMP, short_payload, ingress_port_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->process_icmp_packet(malformed_packet);
}

TEST_F(IcmpProcessorTest, DontSendErrorIfOriginalIsIcmpError) {
    // Create a dummy ICMP error packet (e.g., Dest Unreachable)
    std::vector<uint8_t> icmp_error_payload;
    icmp_error_payload.resize(sizeof(IcmpHeader) + 4 + sizeof(IPv4Header) + 8); // type, code, checksum, unused + original IP + 8 bytes
    IcmpHeader* icmp_hdr_build = reinterpret_cast<IcmpHeader*>(icmp_error_payload.data());
    icmp_hdr_build->type = ICMP_TYPE_DEST_UNREACHABLE; // This is an ICMP error type
    icmp_hdr_build->code = ICMP_CODE_DEST_HOST_UNREACHABLE;
    // ... (fill other fields if necessary for it to be "valid enough" for processing)

    Packet original_icmp_error_packet = create_packet_with_payload(
        another_remote_ip, another_remote_mac,
        local_ip, // doesn't matter for this test where it's going
        local_mac, IP_PROTOCOL_ICMP, icmp_error_payload, ingress_port_id);
    original_icmp_error_packet.set_ingress_port(ingress_port_id);

    // Attempt to generate a TimeExceeded for this ICMP error packet
    // No ICMP error should be generated in response to an ICMP error.
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->send_time_exceeded(original_icmp_error_packet, ICMP_CODE_TTL_EXPIRED);
}

TEST_F(IcmpProcessorTest, DontSendErrorIfNoRouteToOriginalSender) {
    std::vector<uint8_t> original_udp_payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Packet original_packet = create_packet_with_payload(another_remote_ip, another_remote_mac, IpAddress("172.16.10.20"), MacAddress::BROADCAST, IP_PROTOCOL_UDP, original_udp_payload, ingress_port_id);
    original_packet.set_ingress_port(ingress_port_id);

    // Simulate no route back to the original sender (another_remote_ip)
    ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(std::nullopt));

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->send_destination_unreachable(original_packet, ICMP_CODE_DEST_NET_UNREACHABLE);
}

TEST_F(IcmpProcessorTest, DontSendErrorIfArpResolutionFails) {
    std::vector<uint8_t> original_udp_payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Packet original_packet = create_packet_with_payload(another_remote_ip, another_remote_mac, IpAddress("172.16.10.20"), MacAddress::BROADCAST, IP_PROTOCOL_UDP, original_udp_payload, ingress_port_id);
    original_packet.set_ingress_port(ingress_port_id);

    // Route found, but ARP lookup for next hop fails
    ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(RouteEntry{IpAddress("10.10.10.0"), IpAddress("255.255.255.0"), next_hop_for_another_remote_ip, egress_port_id_for_remote}));
    ON_CALL(*mock_arp_processor, lookup_mac(next_hop_for_another_remote_ip)).WillByDefault(Return(std::nullopt));
    // And resolve_mac will be called
    EXPECT_CALL(*mock_arp_processor, resolve_mac(next_hop_for_another_remote_ip, egress_port_id_for_remote, NotNull())).Times(1);


    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0); // Should not send if ARP fails
    icmp_processor->send_destination_unreachable(original_packet, ICMP_CODE_DEST_NET_UNREACHABLE);
}

TEST_F(IcmpProcessorTest, SourceIpForErrorMessageNotAvailable) {
    std::vector<uint8_t> original_udp_payload = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Packet original_packet = create_packet_with_payload(another_remote_ip, another_remote_mac, IpAddress("172.16.10.20"), MacAddress::BROADCAST, IP_PROTOCOL_UDP, original_udp_payload, ingress_port_id);
    original_packet.set_ingress_port(ingress_port_id);

    ON_CALL(*mock_rt_mgr, lookup_route(another_remote_ip)).WillByDefault(Return(RouteEntry{IpAddress("10.10.10.0"), IpAddress("255.255.255.0"), next_hop_for_another_remote_ip, egress_port_id_for_remote}));
    ON_CALL(*mock_arp_processor, lookup_mac(next_hop_for_another_remote_ip)).WillByDefault(Return(mac_for_next_hop_another_remote_ip));
    // Simulate that the egress interface for the error message has NO IP configured
    ON_CALL(*mock_if_mgr, get_primary_ip_config(egress_port_id_for_remote)).WillByDefault(Return(std::nullopt));


    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->send_destination_unreachable(original_packet, ICMP_CODE_DEST_NET_UNREACHABLE);
}

TEST_F(IcmpProcessorTest, InvalidIcmpChecksumInRequest) {
    std::string payload = "ChecksumTest";
    Packet echo_request = create_icmp_echo_request(remote_ip, remote_mac, local_ip, local_mac, 789, 101, payload, ingress_port_id);

    // Intentionally corrupt the checksum
    IcmpHeader* icmp_hdr = echo_request.icmp();
    ASSERT_NE(icmp_hdr, nullptr);
    icmp_hdr->checksum = htons(ntohs(icmp_hdr->checksum) + 1); // Corrupt checksum

    EXPECT_CALL(*mock_if_mgr, is_my_ip(local_ip)).WillByDefault(Return(true)); // Still my IP
    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0); // Should not reply due to bad checksum

    icmp_processor->process_icmp_packet(echo_request);
}

TEST_F(IcmpProcessorTest, ProcessIcmpPacketNotForUs) {
    // This test is similar to ProcessEchoRequestToNonLocalIp but more generic
    std::vector<uint8_t> icmp_payload; // Some generic ICMP payload
    icmp_payload.resize(sizeof(IcmpHeader));
    IcmpHeader* icmp_hdr_build = reinterpret_cast<IcmpHeader*>(icmp_payload.data());
    icmp_hdr_build->type = ICMP_TYPE_ECHO_REQUEST; // Could be any type
    icmp_hdr_build->code = 0;
    icmp_hdr_build->checksum = 0; // Assume checksum is fine for this test focus

    IpAddress other_dest_ip("192.168.100.200");
    ON_CALL(*mock_if_mgr, is_my_ip(other_dest_ip)).WillByDefault(Return(false));

    Packet icmp_packet = create_packet_with_payload(
        remote_ip, remote_mac,
        other_dest_ip, local_mac, // Destined elsewhere, MAC is ours (router)
        IP_PROTOCOL_ICMP, icmp_payload, ingress_port_id);

    EXPECT_CALL(*mock_switch, send_control_plane_frame_raw(_,_,_,_,_,_)).Times(0);
    icmp_processor->process_icmp_packet(icmp_packet);
}
