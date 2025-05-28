#include "gtest/gtest.h"
#include "netflow/packet/Packet.h"
#include "netflow/core/PacketBuffer.h"
#include "netflow/packet/ethernet.h"
#include "netflow/packet/ip.h"
#include "netflow/packet/Packet.h" // For TcpHeader, UdpHeader, VlanTag (defined in Packet.h)
#include "netflow/protocols/arp.h"  // For ArpHeader
#include "netflow/protocols/icmp.h" // For IcmpHeader

#include <arpa/inet.h> // For ntohs, ntohl, htons, htonl
#include <vector>
#include <array>

// --- Test Data ---

// Basic Ethernet + IPv4 + TCP Packet
// Dst MAC: 00:01:02:03:04:05, Src MAC: 0A:0B:0C:0D:0E:0F, EtherType: IP (0x0800)
// IP: Version 4, IHL 5, ToS 0, Total Length 40 (20 IP + 20 TCP)
//     ID 0x1234, Flags/FragOffset 0
//     TTL 64, Protocol TCP (6), Checksum 0xABCD (placeholder, will be recalculated in tests)
//     Src IP 192.168.1.1 (0xC0A80101), Dst IP 192.168.1.2 (0xC0A80102)
// TCP: Src Port 49153 (0xC001), Dst Port 80 (0x0050)
//      Seq 1, Ack 2, DataOffset 5 (20 bytes), Flags SYN (0x02)
//      Window 8192 (0x2000), Checksum 0, UrgentPtr 0
const unsigned char sample_eth_ip_tcp_packet_data[] = {
    // Ethernet
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Dst MAC
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, // Src MAC
    0x08, 0x00,                         // Ethertype IP
    // IP
    0x45, 0x00, 0x00, 0x28,             // Version, IHL, ToS, Total Length (40 bytes)
    0x12, 0x34, 0x00, 0x00,             // ID, Flags, Frag Offset
    0x40, 0x06, 0xAB, 0xCD,             // TTL (64), Protocol (TCP), Header Checksum (placeholder)
    0xC0, 0xA8, 0x01, 0x01,             // Src IP (192.168.1.1)
    0xC0, 0xA8, 0x01, 0x02,             // Dst IP (192.168.1.2)
    // TCP
    0xC0, 0x01, 0x00, 0x50,             // Src Port (49153), Dst Port (80)
    0x00, 0x00, 0x00, 0x01,             // Seq Number
    0x00, 0x00, 0x00, 0x02,             // Ack Number
    0x50, 0x02, 0x20, 0x00,             // Data Offset (5*4=20 bytes), Reserved, Flags (SYN)
    0xFE, 0xDC, 0x00, 0x00              // Checksum (placeholder), Urgent Pointer
};

// Ethernet + VLAN + IPv4 + UDP Packet
// Dst MAC: 00:01:02:03:04:06, Src MAC: 0A:0B:0C:0D:0E:AA, EtherType: VLAN (0x8100)
// VLAN: TCI: Prio 3, VID 100 (0x064 -> 0x6064 with prio 3 (011)) -> 0110 0000 0110 0100 -> 0x6064
//       Inner EtherType: IP (0x0800)
// IP: Version 4, IHL 5, ToS 0, Total Length 32 (20 IP + 8 UDP + 4 data)
//     ID 0x5678, Flags/FragOffset 0
//     TTL 128, Protocol UDP (17), Checksum (placeholder)
//     Src IP 10.0.0.1 (0x0A000001), Dst IP 10.0.0.2 (0x0A000002)
// UDP: Src Port 12345 (0x3039), Dst Port 54321 (0xD431)
//      Length 12 (8 UDP + 4 data), Checksum (placeholder)
// Data: DE AD BE EF
const unsigned char sample_eth_vlan_ip_udp_packet_data[] = {
    // Ethernet
    0x00, 0x01, 0x02, 0x03, 0x04, 0x06, // Dst MAC
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xAA, // Src MAC
    0x81, 0x00,                         // Ethertype VLAN
    // VLAN Tag
    0x60, 0x64,                         // TCI (Prio 3, VID 100)
    0x08, 0x00,                         // Inner Ethertype IP
    // IP
    0x45, 0x00, 0x00, 0x20,             // Version, IHL, ToS, Total Length (32 bytes)
    0x56, 0x78, 0x00, 0x00,             // ID, Flags, Frag Offset
    0x80, 0x11, 0xAB, 0xCD,             // TTL (128), Protocol (UDP), Header Checksum (placeholder)
    0x0A, 0x00, 0x00, 0x01,             // Src IP (10.0.0.1)
    0x0A, 0x00, 0x00, 0x02,             // Dst IP (10.0.0.2)
    // UDP
    0x30, 0x39, 0xD4, 0x31,             // Src Port (12345), Dst Port (54321)
    0x00, 0x0C, 0x12, 0x34,             // Length (12), Checksum (placeholder)
    // Payload
    0xDE, 0xAD, 0xBE, 0xEF
};

// Ethernet + ARP Packet
// Dst MAC: FF:FF:FF:FF:FF:FF (Broadcast), Src MAC: 0A:0B:0C:0D:0E:BB, EtherType: ARP (0x0806)
// ARP: HTYPE Ethernet (1), PTYPE IPv4 (0x0800), HLEN 6, PLEN 4
//      OPER Request (1)
//      Sender MAC 0A:0B:0C:0D:0E:BB, Sender IP 192.168.1.10 (0xC0A8010A)
//      Target MAC 00:00:00:00:00:00, Target IP 192.168.1.20 (0xC0A80114)
const unsigned char sample_eth_arp_packet_data[] = {
    // Ethernet
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Dst MAC
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xBB, // Src MAC
    0x08, 0x06,                         // Ethertype ARP
    // ARP
    0x00, 0x01,                         // HTYPE (Ethernet)
    0x08, 0x00,                         // PTYPE (IPv4)
    0x06,                               // HLEN (6)
    0x04,                               // PLEN (4)
    0x00, 0x01,                         // OPER (Request)
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xBB, // Sender MAC
    0xC0, 0xA8, 0x01, 0x0A,             // Sender IP (192.168.1.10)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Target MAC (unasnwered for request)
    0xC0, 0xA8, 0x01, 0x14              // Target IP (192.168.1.20)
};

// Ethernet + IPv4 + ICMP Echo Request
// Dst MAC: 00:01:02:03:04:07, Src MAC: 0A:0B:0C:0D:0E:CC, EtherType: IP (0x0800)
// IP: Total Length 32 (20 IP + 8 ICMP + 4 data)
//     Protocol ICMP (1), Src IP 172.16.0.1, Dst IP 172.16.0.2
// ICMP: Type Echo Request (8), Code 0, Checksum (placeholder)
//       Identifier 0xABCD, Sequence 0x1234
// Data: CA FE BA BE
const unsigned char sample_eth_ip_icmp_packet_data[] = {
    // Ethernet
    0x00, 0x01, 0x02, 0x03, 0x04, 0x07, // Dst MAC
    0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xCC, // Src MAC
    0x08, 0x00,                         // Ethertype IP
    // IP
    0x45, 0x00, 0x00, 0x24,             // Version, IHL, ToS, Total Length (36 bytes = 20 IP + 8 ICMP + 8 data)
    0x78, 0x9A, 0x00, 0x00,             // ID, Flags, Frag Offset
    0x40, 0x01, 0xAB, 0xCD,             // TTL (64), Protocol (ICMP), Header Checksum (placeholder)
    0xAC, 0x10, 0x00, 0x01,             // Src IP (172.16.0.1)
    0xAC, 0x10, 0x00, 0x02,             // Dst IP (172.16.0.2)
    // ICMP
    0x08, 0x00, 0x12, 0x34,             // Type (8), Code (0), Checksum (placeholder)
    0xAB, 0xCD, 0x12, 0x34,             // Identifier, Sequence Number
    // Payload (example data)
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF
};


// --- Helper for MAC address comparison ---
void ExpectMacEq(const std::array<uint8_t, 6>& mac1, const std::array<uint8_t, 6>& mac2) {
    for (size_t i = 0; i < 6; ++i) {
        EXPECT_EQ(mac1[i], mac2[i]) << "at index " << i;
    }
}

// --- Test Suites ---

// 1. PacketConstruction Test Suite
TEST(PacketConstruction, TestFromRawData) {
    Packet pkt(sample_eth_ip_tcp_packet_data, sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_NE(pkt.head(), nullptr);
    ASSERT_EQ(pkt.length(), sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_TRUE(pkt.get_buffer() != nullptr);
    EXPECT_TRUE(pkt.get_buffer()->is_owner()); // Packet created from raw data owns its buffer
}

TEST(PacketConstruction, TestFromPacketBuffer) {
    PacketBuffer* pb = new PacketBuffer(sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_NE(pb, nullptr);
    ASSERT_NE(pb->data(), nullptr);
    std::memcpy(pb->data(), sample_eth_ip_tcp_packet_data, sizeof(sample_eth_ip_tcp_packet_data));
    pb->set_data_len(sizeof(sample_eth_ip_tcp_packet_data));

    Packet pkt(pb);
    ASSERT_NE(pkt.head(), nullptr);
    ASSERT_EQ(pkt.length(), sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_EQ(pkt.get_buffer(), pb);
    EXPECT_FALSE(pkt.get_buffer()->is_owner()); // Packet constructed with existing buffer does not own it

    // Test that modifications to PacketBuffer's data length are reflected if Packet is re-parsed or its length is set.
    size_t new_length = sizeof(sample_eth_ip_tcp_packet_data) - 10;
    // pb->set_data_len(new_length); // Modifying PB directly
    // pkt.parse_packet(); // Packet doesn't have a public parse_packet method. set_length calls parse_packet.
    pkt.set_length(new_length);
    ASSERT_EQ(pkt.length(), new_length);

    // Packet destructor will be called, should not delete pb because it doesn't own it.
    // We need to delete pb manually.
    delete pb; 
}


// 2. EthernetParsing Test Suite
TEST(EthernetParsing, ParseBasicFrame) {
    Packet pkt(sample_eth_ip_tcp_packet_data, sizeof(sample_eth_ip_tcp_packet_data));
    
    std::array<uint8_t, 6> expected_dst_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    std::array<uint8_t, 6> expected_src_mac = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    
    ExpectMacEq(pkt.dst_mac(), expected_dst_mac);
    ExpectMacEq(pkt.src_mac(), expected_src_mac);
    EXPECT_EQ(pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP);
    EXPECT_FALSE(pkt.has_vlan());
}

TEST(EthernetParsing, ParseWithVlan) {
    Packet pkt(sample_eth_vlan_ip_udp_packet_data, sizeof(sample_eth_vlan_ip_udp_packet_data));

    std::array<uint8_t, 6> expected_dst_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x06};
    std::array<uint8_t, 6> expected_src_mac = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xAA};

    ExpectMacEq(pkt.dst_mac(), expected_dst_mac);
    ExpectMacEq(pkt.src_mac(), expected_src_mac);
    
    ASSERT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pkt.vlan_id(), 100);
    EXPECT_EQ(pkt.vlan_priority(), 3); // Prio 3 (011)
    EXPECT_EQ(pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP); // Inner EtherType
}

// 3. IpParsing Test Suite (for IPv4)
TEST(IpParsing, ParseBasicIpPacket) {
    Packet pkt(sample_eth_ip_tcp_packet_data, sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_EQ(pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP);
    
    auto ip_hdr = pkt.ipv4();
    ASSERT_NE(ip_hdr, nullptr);

    EXPECT_EQ(ip_hdr->version, 4);
    EXPECT_EQ(ip_hdr->ihl, 5);
    EXPECT_EQ(ntohs(ip_hdr->tot_len), 40); // 20 IP + 20 TCP
    EXPECT_EQ(ip_hdr->ttl, 64);
    EXPECT_EQ(ip_hdr->protocol, netflow::packet::IPPROTO_TCP);
    
    EXPECT_EQ(pkt.get_src_ip(), 0xC0A80101); // 192.168.1.1
    EXPECT_EQ(pkt.get_dst_ip(), 0xC0A80102); // 192.168.1.2
    EXPECT_EQ(pkt.get_ip_protocol(), netflow::packet::IPPROTO_TCP);
}

TEST(IpParsing, ParseIpOverVlan) {
    Packet pkt(sample_eth_vlan_ip_udp_packet_data, sizeof(sample_eth_vlan_ip_udp_packet_data));
    ASSERT_TRUE(pkt.has_vlan());
    ASSERT_EQ(pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_IP);

    auto ip_hdr = pkt.ipv4();
    ASSERT_NE(ip_hdr, nullptr);

    EXPECT_EQ(ip_hdr->version, 4);
    EXPECT_EQ(ip_hdr->ihl, 5);
    EXPECT_EQ(ntohs(ip_hdr->tot_len), 32); // 20 IP + 8 UDP + 4 data
    EXPECT_EQ(ip_hdr->ttl, 128);
    EXPECT_EQ(ip_hdr->protocol, netflow::packet::IPPROTO_UDP);

    EXPECT_EQ(pkt.get_src_ip(), 0x0A000001); // 10.0.0.1
    EXPECT_EQ(pkt.get_dst_ip(), 0x0A000002); // 10.0.0.2
    EXPECT_EQ(pkt.get_ip_protocol(), netflow::packet::IPPROTO_UDP);
}

// 4. L4Parsing Test Suite
TEST(L4Parsing, ParseTcpPacket) {
    Packet pkt(sample_eth_ip_tcp_packet_data, sizeof(sample_eth_ip_tcp_packet_data));
    ASSERT_EQ(pkt.get_ip_protocol(), netflow::packet::IPPROTO_TCP);

    auto tcp_hdr = pkt.tcp();
    ASSERT_NE(tcp_hdr, nullptr);

    EXPECT_EQ(ntohs(tcp_hdr->src_port), 49153);
    EXPECT_EQ(ntohs(tcp_hdr->dst_port), 80);
    EXPECT_EQ(ntohl(tcp_hdr->seq_number), 1);
    EXPECT_EQ(ntohl(tcp_hdr->ack_number), 2);
    EXPECT_EQ(tcp_hdr->get_data_offset_bytes(), 20); // 5 * 4
    EXPECT_EQ(tcp_hdr->flags, 0x02); // SYN flag

    EXPECT_EQ(pkt.get_src_port(), 49153);
    EXPECT_EQ(pkt.get_dst_port(), 80);
}

TEST(L4Parsing, ParseUdpPacket) {
    Packet pkt(sample_eth_vlan_ip_udp_packet_data, sizeof(sample_eth_vlan_ip_udp_packet_data));
    ASSERT_EQ(pkt.get_ip_protocol(), netflow::packet::IPPROTO_UDP);

    auto udp_hdr = pkt.udp();
    ASSERT_NE(udp_hdr, nullptr);
    
    EXPECT_EQ(ntohs(udp_hdr->src_port), 12345);
    EXPECT_EQ(ntohs(udp_hdr->dst_port), 54321);
    EXPECT_EQ(ntohs(udp_hdr->length), 12); // 8 UDP + 4 data

    EXPECT_EQ(pkt.get_src_port(), 12345);
    EXPECT_EQ(pkt.get_dst_port(), 54321);
}

TEST(L4Parsing, ParseIcmpOverIp) {
    Packet pkt(sample_eth_ip_icmp_packet_data, sizeof(sample_eth_ip_icmp_packet_data));
    ASSERT_EQ(pkt.get_ip_protocol(), netflow::packet::IPPROTO_ICMP);
    
    // Access ICMP header using get_header with l4_offset
    ASSERT_NE(pkt.ipv4(), nullptr); // Ensure L3 is parsed
    ASSERT_NE(pkt.l4_offset(), -1); // Ensure L4 offset is valid

    auto icmp_hdr = pkt.get_header<netflow::protocols::icmp::IcmpHeader>(pkt.l4_offset());
    ASSERT_NE(icmp_hdr, nullptr);

    EXPECT_EQ(icmp_hdr->type, netflow::protocols::icmp::ICMP_TYPE_ECHO_REQUEST);
    EXPECT_EQ(icmp_hdr->code, 0);
    // Identifier and Sequence Number are in rest_of_header for ICMP Echo
    // The IcmpHeader struct has rest_of_header as uint32_t.
    // To get id/seq, we need to interpret this.
    // For this test, just checking type/code is sufficient for basic parsing.
    uint16_t identifier = ntohs(*reinterpret_cast<const uint16_t*>(&icmp_hdr->rest_of_header));
    uint16_t sequence = ntohs(*(reinterpret_cast<const uint16_t*>(&icmp_hdr->rest_of_header) + 1));

    EXPECT_EQ(identifier, 0xABCD);
    EXPECT_EQ(sequence, 0x1234);
}

// 5. ArpParsing Test Suite
TEST(ArpParsing, ParseArpPacket) {
    Packet pkt(sample_eth_arp_packet_data, sizeof(sample_eth_arp_packet_data));
    ASSERT_EQ(pkt.get_actual_ethertype(), netflow::packet::ETHERTYPE_ARP);

    ASSERT_NE(pkt.l3_offset(), -1);
    auto arp_hdr = pkt.get_header<netflow::protocols::arp::ArpHeader>(pkt.l3_offset());
    ASSERT_NE(arp_hdr, nullptr);

    EXPECT_EQ(ntohs(arp_hdr->hrd_type), netflow::protocols::arp::ARP_HRD_ETHERNET);
    EXPECT_EQ(ntohs(arp_hdr->pro_type), netflow::packet::ETHERTYPE_IP); // ARP_PRO_IPV4 is 0x0800
    EXPECT_EQ(arp_hdr->hrd_len, 6);
    EXPECT_EQ(arp_hdr->pro_len, 4);
    EXPECT_EQ(ntohs(arp_hdr->opcode), netflow::protocols::arp::ARP_OP_REQUEST);

    std::array<uint8_t, 6> expected_sender_mac = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xBB};
    ExpectMacEq(arp_hdr->sender_mac, expected_sender_mac);
    EXPECT_EQ(ntohl(arp_hdr->sender_ip), 0xC0A8010A);
}

// 6. VlanManipulation Test Suite
TEST(VlanManipulation, PushVlan) {
    // Use a copy of a non-VLAN packet data to modify
    std::vector<unsigned char> raw_data(sample_eth_ip_tcp_packet_data, 
                                        sample_eth_ip_tcp_packet_data + sizeof(sample_eth_ip_tcp_packet_data));
    Packet pkt(raw_data.data(), raw_data.size());

    ASSERT_FALSE(pkt.has_vlan());
    uint16_t original_ethertype = pkt.get_actual_ethertype();
    size_t original_length = pkt.length();
    uint16_t vlan_to_push = 123;
    uint8_t prio_to_push = 5;
    uint16_t tci = (prio_to_push << 13) | vlan_to_push;

    ASSERT_TRUE(pkt.push_vlan(tci));
    
    EXPECT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pkt.vlan_id(), vlan_to_push);
    EXPECT_EQ(pkt.vlan_priority(), prio_to_push);
    ASSERT_NE(pkt.vlan_tag_header(), nullptr);
    EXPECT_EQ(ntohs(pkt.vlan_tag_header()->ethertype), original_ethertype);
    EXPECT_EQ(pkt.length(), original_length + sizeof(netflow::packet::VlanTag));
    
    // Check that the outer EtherType is now VLAN_TPID
    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(ntohs(pkt.ethernet()->type), netflow::packet::VLAN_TPID);

    // Attempt to push a second VLAN tag (should fail as current impl doesn't support Q-in-Q)
    EXPECT_FALSE(pkt.push_vlan(tci + 1)); 
}

TEST(VlanManipulation, PopVlan) {
    std::vector<unsigned char> raw_data(sample_eth_vlan_ip_udp_packet_data, 
                                        sample_eth_vlan_ip_udp_packet_data + sizeof(sample_eth_vlan_ip_udp_packet_data));
    Packet pkt(raw_data.data(), raw_data.size());

    ASSERT_TRUE(pkt.has_vlan());
    uint16_t original_inner_ethertype = pkt.get_actual_ethertype(); // This is already the inner one
    size_t original_length = pkt.length();

    ASSERT_TRUE(pkt.pop_vlan());

    EXPECT_FALSE(pkt.has_vlan());
    EXPECT_EQ(pkt.get_actual_ethertype(), original_inner_ethertype);
    EXPECT_EQ(pkt.length(), original_length - sizeof(netflow::packet::VlanTag));

    // Check that the outer EtherType is now the inner one
    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(ntohs(pkt.ethernet()->type), original_inner_ethertype);

    // Attempt to pop VLAN from a non-VLAN packet (should fail)
    EXPECT_FALSE(pkt.pop_vlan());
}

// 7. IpChecksumUpdate Test Suite
// Helper to create a simple IP packet for checksum tests
Packet create_simple_ip_packet(uint8_t ttl, uint32_t saddr, uint32_t daddr, uint16_t id_val_host) {
    unsigned char buffer[20 + 14]; // Eth + IP
    // Ethernet
    std::fill(buffer, buffer + 12, 0xAA); // Dst/Src MAC
    buffer[12] = 0x08; buffer[13] = 0x00; // Type IP

    // IP Header
    netflow::packet::IpHeader* ip_h = reinterpret_cast<netflow::packet::IpHeader*>(buffer + 14);
    ip_h->version = 4;
    ip_h->ihl = 5;
    ip_h->tos = 0;
    ip_h->tot_len = htons(20); // IP header only
    ip_h->id = htons(id_val_host);
    ip_h->frag_off = 0;
    ip_h->ttl = ttl;
    ip_h->protocol = netflow::packet::IPPROTO_TCP; // Dummy protocol
    ip_h->check = 0; // Must be 0 for calculation
    ip_h->saddr = htonl(saddr);
    ip_h->daddr = htonl(daddr);
    
    return Packet(buffer, sizeof(buffer));
}

TEST(IpChecksumUpdate, TestChecksumCalculation) {
    Packet pkt = create_simple_ip_packet(64, 0xC0A80001, 0xC0A80002, 0x1234);
    ASSERT_NE(pkt.ipv4(), nullptr);

    pkt.update_ip_checksum();
    uint16_t calculated_checksum_net = pkt.ipv4()->check; // Already in network order

    // Manually calculate for the same header data (using the utility directly)
    // Create a const copy of the header to pass to the utility
    netflow::packet::IpHeader ip_header_copy = *(pkt.ipv4());
    ip_header_copy.check = 0; // Zero out for manual calculation
    uint16_t expected_checksum_net = netflow::packet::calculate_ip_header_checksum(&ip_header_copy);
    
    EXPECT_EQ(calculated_checksum_net, expected_checksum_net);

    // Known checksum for a specific header (example from RFC 1071, slightly adapted)
    // 4500 001C 1C46 4000 4001 ---- C0A8 0001 C0A8 0002 -> Checksum should be B1E6
    // Values: IHL 5, ToS 0, Len 28, ID 0x1C46, Flags/Frag 0x4000 (DF bit)
    // TTL 64, Proto 1 (ICMP)
    // Src 192.168.0.1, Dst 192.168.0.2
    unsigned char rfc_header_data[20] = {
        0x45, 0x00, 0x00, 0x1C, 0x1C, 0x46, 0x40, 0x00,
        0x40, 0x01, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01,
        0xC0, 0xA8, 0x00, 0x02
    };
    netflow::packet::IpHeader* rfc_ip_hdr = reinterpret_cast<netflow::packet::IpHeader*>(rfc_header_data);
    uint16_t rfc_expected_checksum = netflow::packet::calculate_ip_header_checksum(rfc_ip_hdr);
    EXPECT_EQ(ntohs(rfc_expected_checksum), 0xB1E6); // RFC 1071 uses 0xB1E6
}


TEST(IpChecksumUpdate, TestChecksumAfterModification) {
    Packet pkt = create_simple_ip_packet(64, 0xC0A80001, 0xC0A80002, 0x0001);
    pkt.update_ip_checksum();
    uint16_t checksum1 = pkt.ipv4()->check;

    // Modify TTL
    pkt.ipv4()->ttl = 32;
    pkt.update_ip_checksum(); // Recalculate
    uint16_t checksum2 = pkt.ipv4()->check;

    EXPECT_NE(checksum1, checksum2);

    // Verify checksum2 is correct for the modified header
    netflow::packet::IpHeader ip_header_copy = *(pkt.ipv4());
    ip_header_copy.check = 0; // Zero out for manual calculation
    uint16_t expected_checksum_for_modified = netflow::packet::calculate_ip_header_checksum(&ip_header_copy);
    EXPECT_EQ(checksum2, expected_checksum_for_modified);
}

// Main function for Google Test (optional, can be linked separately)
// int main(int argc, char **argv) {
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }

// --- End of test_packet_class.cpp ---
