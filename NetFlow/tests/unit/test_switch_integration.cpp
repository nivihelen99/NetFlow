#include "gtest/gtest.h"

#include "NetFlow/include/netflow/switch/Switch.h"
#include "NetFlow/include/netflow/packet/Packet.h"
// InterfaceInfo is in Switch.h
#include "NetFlow/include/netflow/switch/ForwardingDatabase.h"
#include "NetFlow/include/netflow/switch/VlanManager.h"
#include "NetFlow/include/netflow/switch/StpManager.h"
#include "NetFlow/include/netflow/protocols/arp.h"
#include "NetFlow/include/netflow/protocols/icmp.h"
#include "NetFlow/include/netflow/core/flow.h"       // For netflow::core::Flow
#include "NetFlow/include/netflow/core/flow_table.h" // For netflow::core::FlowTable (used by Switch)
#include "NetFlow/include/netflow/packet/ethernet.h"
#include "NetFlow/include/netflow/packet/ip.h"
#include "NetFlow/include/netflow/core/PacketBuffer.h"


#include <vector>
#include <map>
#include <functional>
#include <array>
#include <cstring>     // For memcpy
#include <arpa/inet.h> // For htons, ntohs, htonl, ntohl, inet_pton
#include <algorithm>   // For std::fill

// Type alias for convenience
using MACAddress = std::array<uint8_t, 6>;
using IPAddress = uint32_t; // Host byte order

// --- Helper Functions ---

// Convert string MAC "XX:XX:XX:XX:XX:XX" to MACAddress
MACAddress str_to_mac(const std::string& mac_str) {
    MACAddress mac;
    if(sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
        return mac;
    }
    throw std::runtime_error("Invalid MAC string format: " + mac_str);
}

// Convert string IP "a.b.c.d" to IPAddress (uint32_t in host byte order)
IPAddress str_to_ip(const std::string& ip_str) {
    struct in_addr sa; // Use in_addr for inet_pton with AF_INET
    if (inet_pton(AF_INET, ip_str.c_str(), &sa) == 1) {
        return ntohl(sa.s_addr); // Convert from network to host byte order for storage/use
    }
    throw std::runtime_error("Invalid IP string format: " + ip_str);
}


// Create a raw Ethernet frame (vector of bytes)
std::vector<uint8_t> create_raw_ethernet_frame(
    const MACAddress& dst_mac,
    const MACAddress& src_mac,
    uint16_t ethertype_host_order,
    const std::vector<uint8_t>& payload,
    uint16_t vlan_id_host_order = 0, // 0 means no VLAN tag
    uint8_t vlan_pcp = 0) 
{
    std::vector<uint8_t> frame_data;
    frame_data.resize(sizeof(netflow::packet::EthernetHeader) + 
                      (vlan_id_host_order != 0 ? sizeof(netflow::packet::VlanTag) : 0) + 
                      payload.size());

    unsigned char* current_ptr = frame_data.data();

    netflow::packet::EthernetHeader* eth_h = reinterpret_cast<netflow::packet::EthernetHeader*>(current_ptr);
    eth_h->dest_mac = dst_mac;
    eth_h->src_mac = src_mac;
    
    if (vlan_id_host_order != 0) {
        eth_h->type = htons(netflow::packet::VLAN_TPID); // Outer type is VLAN
        current_ptr += sizeof(netflow::packet::EthernetHeader); // Advance past eth_h

        netflow::packet::VlanTag* vlan_h = reinterpret_cast<netflow::packet::VlanTag*>(current_ptr);
        uint16_t tci = (static_cast<uint16_t>(vlan_pcp & 0x7) << 13) | (vlan_id_host_order & 0xFFF);
        vlan_h->tci = htons(tci);
        vlan_h->ethertype = htons(ethertype_host_order); // Inner type
        current_ptr += sizeof(netflow::packet::VlanTag); // Advance past vlan_h
    } else {
        eth_h->type = htons(ethertype_host_order);
        current_ptr += sizeof(netflow::packet::EthernetHeader); // Advance past eth_h
    }

    if (!payload.empty()) {
        std::memcpy(current_ptr, payload.data(), payload.size());
    }
    return frame_data;
}

// Create ARP Packet Payload (not the full Ethernet frame)
std::vector<uint8_t> create_arp_payload(
    uint16_t opcode_host_order, // 1 for request, 2 for reply
    const MACAddress& sender_mac, IPAddress sender_ip_host_order,
    const MACAddress& target_mac, IPAddress target_ip_host_order)
{
    netflow::protocols::arp::ArpHeader arp_h;
    arp_h.hrd_type = htons(netflow::protocols::arp::ARP_HRD_ETHERNET);
    arp_h.pro_type = htons(netflow::packet::ETHERTYPE_IP); // ARP_PRO_IPV4
    arp_h.hrd_len = 6;
    arp_h.pro_len = 4;
    arp_h.opcode = htons(opcode_host_order);
    arp_h.sender_mac = sender_mac;
    arp_h.sender_ip = htonl(sender_ip_host_order);
    arp_h.target_mac = target_mac;
    arp_h.target_ip = htonl(target_ip_host_order);

    std::vector<uint8_t> payload(sizeof(arp_h));
    std::memcpy(payload.data(), &arp_h, sizeof(arp_h));
    return payload;
}

// Create IP Packet Payload (L3, not full Ethernet frame)
std::vector<uint8_t> create_ip_payload(
    IPAddress src_ip_host, IPAddress dst_ip_host,
    uint8_t protocol, uint8_t ttl, uint16_t id_host,
    const std::vector<uint8_t>& l4_payload)
{
    netflow::packet::IpHeader ip_h;
    ip_h.version = 4;
    ip_h.ihl = 5; // No options
    ip_h.tos = 0;
    ip_h.tot_len = htons(sizeof(netflow::packet::IpHeader) + l4_payload.size());
    ip_h.id = htons(id_host);
    ip_h.frag_off = 0;
    ip_h.ttl = ttl;
    ip_h.protocol = protocol;
    ip_h.saddr = htonl(src_ip_host);
    ip_h.daddr = htonl(dst_ip_host);
    ip_h.check = 0; 
    ip_h.check = netflow::packet::calculate_ip_header_checksum(&ip_h);

    std::vector<uint8_t> ip_packet_data(sizeof(ip_h));
    std::memcpy(ip_packet_data.data(), &ip_h, sizeof(ip_h));
    ip_packet_data.insert(ip_packet_data.end(), l4_payload.begin(), l4_payload.end());
    return ip_packet_data;
}

// Create ICMP Echo Request Payload (L4, not full IP packet)
std::vector<uint8_t> create_icmp_echo_request_payload(
    uint16_t id_host, uint16_t seq_host, const std::vector<uint8_t>& data)
{
    // Size of ICMP header (8 bytes for type, code, checksum, id, seq)
    size_t icmp_header_size = 8; 
    std::vector<uint8_t> icmp_payload(icmp_header_size + data.size());
    
    unsigned char* icmp_ptr = icmp_payload.data();
    icmp_ptr[0] = netflow::protocols::icmp::ICMP_TYPE_ECHO_REQUEST;
    icmp_ptr[1] = 0; // Code
    icmp_ptr[2] = 0; icmp_ptr[3] = 0; // Checksum placeholder
    uint16_t id_net = htons(id_host);
    uint16_t seq_net = htons(seq_host);
    std::memcpy(&icmp_ptr[4], &id_net, sizeof(id_net));
    std::memcpy(&icmp_ptr[6], &seq_net, sizeof(seq_net));

    if (!data.empty()) {
        std::memcpy(icmp_ptr + icmp_header_size, data.data(), data.size());
    }
    
    uint16_t checksum = netflow::protocols::icmp::calculate_icmp_checksum(icmp_payload.data(), icmp_payload.size());
    std::memcpy(&icmp_ptr[2], &checksum, sizeof(checksum)); 

    return icmp_payload;
}


// --- Test Fixture ---
class SwitchIntegrationTest : public ::testing::Test {
protected:
    netflow::switch_logic::Switch sw;
    std::map<uint32_t, std::vector<std::vector<uint8_t>>> captured_packets_;

    MACAddress mac_p1 = str_to_mac("0A:00:00:00:01:01"); 
    MACAddress mac_p2 = str_to_mac("0A:00:00:00:02:01"); 
    MACAddress mac_p3 = str_to_mac("0A:00:00:00:03:01"); 

    IPAddress ip_p1_host = str_to_ip("192.168.1.1");
    IPAddress ip_p2_host = str_to_ip("192.168.2.1");
    IPAddress ip_p3_host = str_to_ip("192.168.3.1"); 

    MACAddress mac_host_a = str_to_mac("0C:00:00:0A:00:01"); 
    MACAddress mac_host_b = str_to_mac("0C:00:00:0B:00:01"); 
    MACAddress mac_host_c = str_to_mac("0C:00:00:0C:00:01"); 

    IPAddress ip_host_a_net1 = str_to_ip("192.168.1.100");
    IPAddress ip_host_b_net2 = str_to_ip("192.168.2.100");


    SwitchIntegrationTest() : sw(4) {} 

    void SetUp() override {
        captured_packets_.clear();
        sw.set_send_packet_callback([this](int interface_id, const std::vector<uint8_t>& packet_data) {
            captured_packets_[static_cast<uint32_t>(interface_id)].push_back(packet_data);
        });

        sw.add_interface(1, "eth1", ip_p1_host, mac_p1);
        sw.add_interface(2, "eth2", ip_p2_host, mac_p2);
        sw.add_interface(3, "eth3", 0, mac_p3); 
    }

    void clear_captured_packets() {
        captured_packets_.clear();
    }

    const std::vector<std::vector<uint8_t>>& get_captured_on_port(uint32_t port_id) {
        static const std::vector<std::vector<uint8_t>> empty_vector;
        auto it = captured_packets_.find(port_id);
        if (it == captured_packets_.end()) {
            return empty_vector;
        }
        return it->second;
    }

    void send_packet_to_switch(uint32_t ingress_port, const std::vector<uint8_t>& raw_packet_data) {
        sw.handle_raw_frame(static_cast<int>(ingress_port), raw_packet_data.data(), raw_packet_data.size());
    }
};


// --- Test Suites ---

// 1. L2Forwarding Test Suite
class L2Forwarding : public SwitchIntegrationTest {};

TEST_F(L2Forwarding, KnownMacUnicast) {
    sw.fdb().learn_mac(mac_host_b, DEFAULT_VLAN_ID, 2);
    std::vector<uint8_t> payload(100, 0xAA); 
    std::vector<uint8_t> frame = create_raw_ethernet_frame(mac_host_b, mac_host_a, netflow::packet::ETHERTYPE_IP, payload);
    
    send_packet_to_switch(1, frame); 

    EXPECT_EQ(get_captured_on_port(1).size(), 0); 
    EXPECT_EQ(get_captured_on_port(2).size(), 1); 
    EXPECT_EQ(get_captured_on_port(3).size(), 0); 
    EXPECT_EQ(get_captured_on_port(0).size(), 0); 

    if (get_captured_on_port(2).size() == 1) {
        const auto& out_frame = get_captured_on_port(2)[0];
        EXPECT_EQ(out_frame.size(), frame.size());
        Packet out_pkt(out_frame.data(), out_frame.size());
        EXPECT_EQ(out_pkt.dst_mac(), mac_host_b);
        EXPECT_EQ(out_pkt.src_mac(), mac_host_a);
    }
}

TEST_F(L2Forwarding, UnknownMacFlood) {
    std::vector<uint8_t> payload(64, 0xBB);
    std::vector<uint8_t> frame = create_raw_ethernet_frame(mac_host_c, mac_host_a, netflow::packet::ETHERTYPE_IP, payload);

    send_packet_to_switch(1, frame); 

    EXPECT_EQ(get_captured_on_port(1).size(), 0);
    EXPECT_EQ(get_captured_on_port(2).size(), 1); 
    EXPECT_EQ(get_captured_on_port(3).size(), 1); 
    EXPECT_EQ(get_captured_on_port(0).size(), 0);

    if (get_captured_on_port(2).size() == 1) {
        Packet out_pkt(get_captured_on_port(2)[0].data(), get_captured_on_port(2)[0].size());
        EXPECT_EQ(out_pkt.dst_mac(), mac_host_c);
        EXPECT_EQ(out_pkt.src_mac(), mac_host_a);
    }
}

TEST_F(L2Forwarding, VlanSeparation) {
    sw.vlan_manager().configure_port(1, VlanManager::PortType::ACCESS, 10);
    sw.vlan_manager().configure_port(2, VlanManager::PortType::ACCESS, 20);
    VlanManager::PortConfig trunk_config;
    trunk_config.type = VlanManager::PortType::TRUNK;
    trunk_config.native_vlan_id = 99; 
    trunk_config.allowed_vlans = {10, 20};
    sw.vlan_manager().configure_port(3, trunk_config);

    MACAddress mac_target_vlan10 = str_to_mac("DE:AD:00:00:10:01");
    MACAddress mac_target_vlan20 = str_to_mac("DE:AD:00:00:20:01");
    MACAddress mac_source_generic = str_to_mac("BE:EF:00:00:00:01");

    sw.fdb().learn_mac(mac_target_vlan10, 10, 1); 
    sw.fdb().learn_mac(mac_target_vlan20, 20, 2); 
    
    clear_captured_packets();

    std::vector<uint8_t> payload(20,0x11);
    std::vector<uint8_t> frame_to_vlan10 = create_raw_ethernet_frame(mac_target_vlan10, mac_source_generic, 
                                                            netflow::packet::ETHERTYPE_IP, payload, 10); 
    send_packet_to_switch(3, frame_to_vlan10); 
    EXPECT_EQ(get_captured_on_port(1).size(), 1); 
    EXPECT_EQ(get_captured_on_port(2).size(), 0);
    EXPECT_EQ(get_captured_on_port(3).size(), 0);
    if (get_captured_on_port(1).size() == 1) {
        Packet out_pkt(get_captured_on_port(1)[0].data(), get_captured_on_port(1)[0].size());
        EXPECT_FALSE(out_pkt.has_vlan());
    }
    clear_captured_packets();

    std::vector<uint8_t> frame_to_vlan20 = create_raw_ethernet_frame(mac_target_vlan20, mac_source_generic, 
                                                            netflow::packet::ETHERTYPE_IP, payload, 20);
    send_packet_to_switch(3, frame_to_vlan20);
    EXPECT_EQ(get_captured_on_port(1).size(), 0);
    EXPECT_EQ(get_captured_on_port(2).size(), 1); 
    EXPECT_EQ(get_captured_on_port(3).size(), 0);
     if (get_captured_on_port(2).size() == 1) {
        Packet out_pkt(get_captured_on_port(2)[0].data(), get_captured_on_port(2)[0].size());
        EXPECT_FALSE(out_pkt.has_vlan());
    }
    clear_captured_packets();

    MACAddress unknown_mac_vlan10 = str_to_mac("DE:AD:BE:EF:10:FF");
    std::vector<uint8_t> frame_untagged_vlan10 = create_raw_ethernet_frame(unknown_mac_vlan10, mac_source_generic,
                                                                        netflow::packet::ETHERTYPE_IP, payload);
    send_packet_to_switch(1, frame_untagged_vlan10);
    EXPECT_EQ(get_captured_on_port(1).size(), 0);
    EXPECT_EQ(get_captured_on_port(2).size(), 0); 
    EXPECT_EQ(get_captured_on_port(3).size(), 1); 
    if (get_captured_on_port(3).size() == 1) {
        Packet out_pkt(get_captured_on_port(3)[0].data(), get_captured_on_port(3)[0].size());
        EXPECT_TRUE(out_pkt.has_vlan());
        EXPECT_EQ(out_pkt.vlan_id(), 10);
    }
}

TEST_F(L2Forwarding, StpBlocking) {
    sw.fdb().learn_mac(mac_host_b, DEFAULT_VLAN_ID, 2);
    sw.stp_manager().set_port_state_admin(2, false); 
    ASSERT_EQ(sw.stp_manager().get_port_state(2), StpManager::StpPortState::DISABLED);
    ASSERT_FALSE(sw.stp_manager().should_forward(2));

    std::vector<uint8_t> payload(100, 0xCC);
    std::vector<uint8_t> frame = create_raw_ethernet_frame(mac_host_b, mac_host_a, netflow::packet::ETHERTYPE_IP, payload);
    
    send_packet_to_switch(1, frame);

    EXPECT_EQ(get_captured_on_port(1).size(), 0);
    EXPECT_EQ(get_captured_on_port(2).size(), 0); 
    EXPECT_EQ(get_captured_on_port(3).size(), 1); 
}

// 2. L3SwitchProcessing Test Suite
class L3SwitchProcessing : public SwitchIntegrationTest {
protected:
    void SetUp() override {
        SwitchIntegrationTest::SetUp(); // Call base fixture's SetUp
        sw.clear_flow_table_for_test();
        sw.clear_arp_cache_for_test();
    }
};


TEST_F(L3SwitchProcessing, ArpRequestToSwitchIp) {
    std::vector<uint8_t> arp_req_payload = create_arp_payload(1, mac_host_a, ip_host_a_net1, 
                                                              MACAddress{0}, ip_p1_host); 
    std::vector<uint8_t> arp_frame = create_raw_ethernet_frame(str_to_mac("FF:FF:FF:FF:FF:FF"), mac_host_a, 
                                                               netflow::packet::ETHERTYPE_ARP, arp_req_payload);
    send_packet_to_switch(1, arp_frame);

    EXPECT_EQ(get_captured_on_port(1).size(), 1); 
    if (get_captured_on_port(1).size() == 1) {
        Packet reply_pkt(get_captured_on_port(1)[0].data(), get_captured_on_port(1)[0].size());
        EXPECT_EQ(reply_pkt.dst_mac(), mac_host_a);
        EXPECT_EQ(reply_pkt.src_mac(), mac_p1);
        ASSERT_EQ(reply_pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_ARP);
        
        ASSERT_NE(reply_pkt.l3_offset(), -1);
        auto arp_reply = reply_pkt.get_header<netflow::protocols::arp::ArpHeader>(reply_pkt.l3_offset());
        ASSERT_NE(arp_reply, nullptr);

        EXPECT_EQ(ntohs(arp_reply->opcode), 2); 
        EXPECT_EQ(arp_reply->sender_mac, mac_p1);
        EXPECT_EQ(ntohl(arp_reply->sender_ip), ip_p1_host);
        EXPECT_EQ(arp_reply->target_mac, mac_host_a);
        EXPECT_EQ(ntohl(arp_reply->target_ip), ip_host_a_net1);
    }
}

TEST_F(L3SwitchProcessing, IcmpEchoToSwitchIp) {
    std::vector<uint8_t> icmp_data = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> icmp_payload = create_icmp_echo_request_payload(0x1234, 0x5678, icmp_data);
    std::vector<uint8_t> ip_payload = create_ip_payload(ip_host_a_net1, ip_p1_host, netflow::packet::IPPROTO_ICMP, 64, 0xABCD, icmp_payload);
    std::vector<uint8_t> eth_frame = create_raw_ethernet_frame(mac_p1, mac_host_a, netflow::packet::ETHERTYPE_IP, ip_payload);

    send_packet_to_switch(1, eth_frame);

    EXPECT_EQ(get_captured_on_port(1).size(), 1); 
    if (get_captured_on_port(1).size() == 1) {
        Packet reply_pkt(get_captured_on_port(1)[0].data(), get_captured_on_port(1)[0].size());
        EXPECT_EQ(reply_pkt.dst_mac(), mac_host_a);
        EXPECT_EQ(reply_pkt.src_mac(), mac_p1);
        ASSERT_EQ(reply_pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP);

        auto ip_hdr = reply_pkt.ipv4();
        ASSERT_NE(ip_hdr, nullptr);
        EXPECT_EQ(ntohl(ip_hdr->saddr), ip_p1_host);
        EXPECT_EQ(ntohl(ip_hdr->daddr), ip_host_a_net1);
        EXPECT_EQ(ip_hdr->protocol, netflow::packet::IPPROTO_ICMP);
        
        ASSERT_NE(reply_pkt.l4_offset(), -1);
        auto icmp_reply = reply_pkt.get_header<netflow::protocols::icmp::IcmpHeader>(reply_pkt.l4_offset());
        ASSERT_NE(icmp_reply, nullptr);
        EXPECT_EQ(icmp_reply->type, netflow::protocols::icmp::ICMP_TYPE_ECHO_REPLY);
        EXPECT_EQ(icmp_reply->code, 0);
        // Verify ID and Seq
        uint16_t reply_id = ntohs(*reinterpret_cast<const uint16_t*>(&icmp_reply->rest_of_header));
        uint16_t reply_seq = ntohs(*(reinterpret_cast<const uint16_t*>(&icmp_reply->rest_of_header) + 1));
        EXPECT_EQ(reply_id, 0x1234);
        EXPECT_EQ(reply_seq, 0x5678);
    }
}

// 3. L3Routing Test Suite
class L3Routing : public SwitchIntegrationTest {
protected:
    void SetUp() override {
        SwitchIntegrationTest::SetUp(); // Call base fixture's SetUp
        sw.clear_flow_table_for_test();
        sw.clear_arp_cache_for_test();
    }
};

TEST_F(L3Routing, BasicIpRoute) {
    const uint32_t P1 = 1, P2 = 2;
    // mac_p1, mac_p2 are already defined in fixture.
    
    // Source is external to switch's directly connected networks for this test.
    IPAddress src_ip_ext_client_host = str_to_ip("10.0.0.5"); 
    MACAddress mac_ext_client = str_to_mac("0B:00:00:00:00:05");

    // Target device on Port 2's segment (192.168.2.0/24)
    IPAddress target_ip_on_p2_net_host = str_to_ip("192.168.2.10");
    MACAddress target_mac_on_p2_net = str_to_mac("0C:00:00:00:02:10");

    // 1. Add flow entry: Route packets for target_ip_on_p2_net_host out of Port 2
    // Flow constructor expects host order IPs.
    netflow::core::Flow flow_to_target(src_ip_ext_client_host, target_ip_on_p2_net_host, 
                                       12345, 80, netflow::packet::IPPROTO_UDP);
    sw.add_flow_entry_for_test(flow_to_target, P2);

    // 2. Add ARP entry for target_ip_on_p2_net_host (next hop resolved to its MAC)
    // add_arp_entry_for_test expects host order IP.
    sw.add_arp_entry_for_test(target_ip_on_p2_net_host, target_mac_on_p2_net);

    // 3. Create the IP packet from external client to target
    // create_ip_payload expects host order IPs.
    std::vector<uint8_t> udp_payload = {0xDE, 0xAD, 0xBE, 0xEF};
    std::vector<uint8_t> ip_payload = create_ip_payload(
        src_ip_ext_client_host, target_ip_on_p2_net_host, 
        netflow::packet::IPPROTO_UDP, 64, 0xBBBB, udp_payload);
    
    // Packet arrives on Port 1, addressed to Port 1's MAC (mac_p1)
    std::vector<uint8_t> raw_pkt = create_raw_ethernet_frame(
        mac_p1, mac_ext_client, netflow::packet::ETHERTYPE_IP, ip_payload);

    // 4. Send packet to Switch's Port 1
    send_packet_to_switch(P1, raw_pkt);

    // 5. Verification
    auto& p2_pkts = get_captured_on_port(P2);
    ASSERT_EQ(p2_pkts.size(), 1) << "Packet should be routed to Port 2";

    netflow::packet::Packet out_pkt(p2_pkts[0].data(), p2_pkts[0].size());
    ASSERT_NE(out_pkt.ethernet(), nullptr);
    EXPECT_EQ(out_pkt.ethernet()->src_mac, mac_p2); // MAC of outgoing interface P2
    EXPECT_EQ(out_pkt.ethernet()->dest_mac, target_mac_on_p2_net); // MAC of final target
    ASSERT_EQ(out_pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP);

    auto out_ip_hdr = out_pkt.ipv4();
    ASSERT_NE(out_ip_hdr, nullptr);
    EXPECT_EQ(ntohl(out_ip_hdr->saddr), src_ip_ext_client_host); // Original Source IP
    EXPECT_EQ(ntohl(out_ip_hdr->daddr), target_ip_on_p2_net_host); // Original Dest IP
    EXPECT_EQ(out_ip_hdr->ttl, 63); // TTL decremented

    // Verify checksum
    uint16_t received_checksum = out_ip_hdr->check;
    netflow::packet::IpHeader mutable_ip_header_copy = *out_ip_hdr; // Make a copy to zero out checksum for recalc
    mutable_ip_header_copy.check = 0;
    uint16_t expected_checksum = netflow::packet::calculate_ip_header_checksum(&mutable_ip_header_copy);
    EXPECT_EQ(received_checksum, expected_checksum) << "IP checksum incorrect after routing";

    EXPECT_EQ(get_captured_on_port(P1).size(), 0);
    uint32_t P3 = 3; 
    // Check if port 3 is configured (it is by default in SetUp)
    const netflow::switch_logic::InterfaceInfo* p3_info = sw.get_interface_info(P3); // Assuming such getter exists or it's fine
    if (p3_info) { // A more robust check would be to see if port 3 is part of the same VLAN and STP forwarding.
         EXPECT_EQ(get_captured_on_port(P3).size(), 0);
    }
}


// --- End of test_switch_integration.cpp ---
