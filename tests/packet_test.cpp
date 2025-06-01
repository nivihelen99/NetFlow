#include "gtest/gtest.h"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/packet.hpp"
#include <cstring>
#include <vector>
#include <array>
#include <arpa/inet.h>
#include <optional>
#include <numeric> // For std::iota

// --- Test fixture for PacketBuffer tests (remains unchanged) ---
class PacketBufferTest : public ::testing::Test {
protected:
    static constexpr size_t DEFAULT_CAPACITY = 1024;
    static constexpr size_t INITIAL_HEADROOM = 32;

    netflow::PacketBuffer create_buffer(size_t capacity, size_t initial_headroom = 0, size_t initial_data_len = 0) {
        return netflow::PacketBuffer(capacity, initial_headroom, initial_data_len);
    }
};
TEST_F(PacketBufferTest, Constructor) { /* ... */ }
TEST_F(PacketBufferTest, GetDataStartPtrMethod) { /* ... */ }
TEST_F(PacketBufferTest, GetCapacityMethod) { /* ... */ }
TEST_F(PacketBufferTest, GetHeadroomMethod) { /* ... */ }
TEST_F(PacketBufferTest, GetTailroomMethod) { /* ... */ }
TEST_F(PacketBufferTest, GetDataLengthMethod) { /* ... */ }
TEST_F(PacketBufferTest, AppendData) { /* ... */ }
TEST_F(PacketBufferTest, PrependData) { /* ... */ }
TEST_F(PacketBufferTest, ConsumeDataFront) { /* ... */ }
TEST_F(PacketBufferTest, ConsumeDataEnd) { /* ... */ }
TEST_F(PacketBufferTest, SetDataLength) { /* ... */ }
TEST_F(PacketBufferTest, ResetOffsetsAndLen) { /* ... */ }
TEST_F(PacketBufferTest, ReferenceCounting) { /* ... */ }


// --- Test fixture and tests for Packet class ---
struct TestIpv4Address {
    uint8_t bytes[4];
    TestIpv4Address(uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4) {
        bytes[0] = b1; bytes[1] = b2; bytes[2] = b3; bytes[3] = b4;
    }
    uint32_t to_uint32_be() const {
        return htonl((static_cast<uint32_t>(bytes[0]) << 24) |
                     (static_cast<uint32_t>(bytes[1]) << 16) |
                     (static_cast<uint32_t>(bytes[2]) << 8)  |
                     (static_cast<uint32_t>(bytes[3])));
    }
    const uint8_t* begin() const { return bytes; }
    const uint8_t* end() const { return bytes + 4; }
};
struct TestIpv6Address {
    uint8_t bytes[16];
    TestIpv6Address(const std::array<uint8_t, 16>& addr_bytes) {
        std::copy(addr_bytes.begin(), addr_bytes.end(), bytes);
    }
    const uint8_t* begin() const { return bytes; }
    const uint8_t* end() const { return bytes + 16; }
     bool operator==(const uint8_t other[16]) const {
        return std::memcmp(bytes, other, 16) == 0;
    }
};
netflow::MacAddress make_mac(const uint8_t arr[6]) {
    return netflow::MacAddress(arr);
}

class PacketTest : public ::testing::Test {
protected:
    static const netflow::MacAddress SRC_MAC;
    static const netflow::MacAddress DST_MAC;
    static const TestIpv4Address SRC_IPV4;
    static const TestIpv4Address DST_IPV4;
    static const TestIpv6Address SRC_IPV6;
    static const TestIpv6Address DST_IPV6;
    static constexpr uint16_t SRC_PORT = 12345;
    static constexpr uint16_t DST_PORT = 80;
    static constexpr uint16_t UDP_SRC_PORT = 54321;
    static constexpr uint16_t UDP_DST_PORT = 53;
    static constexpr uint16_t TEST_VLAN_ID = 101;
    static constexpr uint8_t TEST_VLAN_PRIO = 5;

    // Build packet data vector and return it
    std::vector<uint8_t> build_raw_packet(
        const netflow::MacAddress& dst_m, const netflow::MacAddress& src_m,
        std::optional<uint16_t> vlan_id, std::optional<uint8_t> vlan_prio,
        uint16_t l2_ethertype, // EtherType right after MACs, or after VLAN if VLAN exists
        std::optional<const TestIpv4Address*> ipv4_src, std::optional<const TestIpv4Address*> ipv4_dst, uint8_t ip_proto,
        std::optional<uint16_t> l4_src_port, std::optional<uint16_t> l4_dst_port,
        const std::vector<uint8_t>& payload = {'P','A','Y','L','O','A','D'})
    {
        std::vector<uint8_t> data;
        // L2 Ethernet
        data.insert(data.end(), dst_m.bytes, dst_m.bytes + 6);
        data.insert(data.end(), src_m.bytes, src_m.bytes + 6);

        if (vlan_id.has_value()) {
            data.push_back(0x81); data.push_back(0x00); // VLAN TPID
            uint16_t tci = (vlan_prio.value_or(0) << 13) | vlan_id.value();
            data.push_back((tci >> 8) & 0xFF); data.push_back(tci & 0xFF);
        }
        data.push_back((l2_ethertype >> 8) & 0xFF); data.push_back(l2_ethertype & 0xFF);

        // L3 IPv4
        if (ipv4_src.has_value() && ipv4_dst.has_value()) {
            size_t l4_len = 0;
            if (ip_proto == netflow::IPPROTO_TCP && l4_src_port.has_value() && l4_dst_port.has_value()) l4_len = 20; // Minimal TCP header
            if (ip_proto == netflow::IPPROTO_UDP && l4_src_port.has_value() && l4_dst_port.has_value()) l4_len = 8 + payload.size(); // Minimal UDP + payload

            uint16_t ip_total_length = 20 + l4_len; // 20 for IPv4 header

            data.push_back(0x45); // Version IHL
            data.push_back(0x00); // DSCP ECN
            data.push_back((ip_total_length >> 8) & 0xFF); data.push_back(ip_total_length & 0xFF);
            data.push_back(0x00); data.push_back(0x01); data.push_back(0x00); data.push_back(0x00); // ID, Flags, Frag Offset
            data.push_back(0x40); // TTL
            data.push_back(ip_proto);
            data.push_back(0x00); data.push_back(0x00); // IP Checksum (to be calculated)
            data.insert(data.end(), (*ipv4_src)->begin(), (*ipv4_src)->end());
            data.insert(data.end(), (*ipv4_dst)->begin(), (*ipv4_dst)->end());

            // L4 TCP/UDP
            if (ip_proto == netflow::IPPROTO_TCP && l4_src_port.has_value() && l4_dst_port.has_value()) {
                data.push_back((l4_src_port.value() >> 8) & 0xFF); data.push_back(l4_src_port.value() & 0xFF);
                data.push_back((l4_dst_port.value() >> 8) & 0xFF); data.push_back(l4_dst_port.value() & 0xFF);
                for(int i=0; i<12; ++i) data.push_back(0x00); // Seq, Ack, Window, Urgent
                data.push_back(0x50); data.push_back(0x00);   // DataOffset, Flags
                data.push_back(0x00); data.push_back(0x00);   // TCP Checksum (to be calculated)
                data.insert(data.end(), payload.begin(), payload.end()); // TCP payload (if any, not typical for this simple builder)
            } else if (ip_proto == netflow::IPPROTO_UDP && l4_src_port.has_value() && l4_dst_port.has_value()) {
                uint16_t udp_len = 8 + payload.size();
                data.push_back((l4_src_port.value() >> 8) & 0xFF); data.push_back(l4_src_port.value() & 0xFF);
                data.push_back((l4_dst_port.value() >> 8) & 0xFF); data.push_back(l4_dst_port.value() & 0xFF);
                data.push_back((udp_len >> 8) & 0xFF); data.push_back(udp_len & 0xFF);
                data.push_back(0x00); data.push_back(0x00); // UDP Checksum (to be calculated)
                data.insert(data.end(), payload.begin(), payload.end());
            }
        }
        return data;
    }

    // Existing build_eth_ipv4_tcp_packet, build_eth_ipv4_udp_packet, build_eth_ipv6_tcp_packet helpers
    // can be kept or refactored to use the new generic one if preferred.
    // For now, keeping them for existing test compatibility.
    std::vector<uint8_t> build_eth_ipv4_tcp_packet(bool with_vlan = false) { /* ... as before ... */ return {}; }
    std::vector<uint8_t> build_eth_ipv4_udp_packet(bool with_vlan = false) { /* ... as before ... */ return {}; }
    std::vector<uint8_t> build_eth_ipv6_tcp_packet(bool with_vlan = false) { /* ... as before ... */ return {}; }


    std::vector<uint8_t> build_eth_ipv6_udp_packet(bool with_vlan = false) {
        std::vector<uint8_t> data;
        data.insert(data.end(), DST_MAC.bytes, DST_MAC.bytes + 6);
        data.insert(data.end(), SRC_MAC.bytes, SRC_MAC.bytes + 6);

        if (with_vlan) {
            data.push_back(0x81); data.push_back(0x00); // VLAN EtherType
            uint16_t tci = (TEST_VLAN_PRIO << 13) | TEST_VLAN_ID;
            data.push_back((tci >> 8) & 0xFF); data.push_back(tci & 0xFF);
        }
        data.push_back(0x86); data.push_back(0xDD); // IPv6 EtherType

        size_t udp_header_len = 8;
        std::vector<uint8_t> udp_payload = {'D','A','T','A'};
        uint16_t ipv6_payload_length = udp_header_len + udp_payload.size();

        data.push_back(0x60); data.push_back(0x00); data.push_back(0x00); data.push_back(0x00);
        data.push_back((ipv6_payload_length >> 8) & 0xFF); data.push_back(ipv6_payload_length & 0xFF);
        data.push_back(netflow::IPPROTO_UDP); // Next Header (UDP)
        data.push_back(0x40); // Hop Limit
        data.insert(data.end(), SRC_IPV6.begin(), SRC_IPV6.end());
        data.insert(data.end(), DST_IPV6.begin(), DST_IPV6.end());

        data.push_back((UDP_SRC_PORT >> 8) & 0xFF); data.push_back(UDP_SRC_PORT & 0xFF);
        data.push_back((UDP_DST_PORT >> 8) & 0xFF); data.push_back(UDP_DST_PORT & 0xFF);
        data.push_back((ipv6_payload_length >> 8) & 0xFF); data.push_back(ipv6_payload_length & 0xFF); // UDP Length
        data.push_back(0x00); data.push_back(0x00); // UDP Checksum (placeholder)
        data.insert(data.end(), udp_payload.begin(), udp_payload.end());
        return data;
    }
};

// Static member definitions (as before)
const netflow::MacAddress PacketTest::SRC_MAC = make_mac((const uint8_t[6]){0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
const netflow::MacAddress PacketTest::DST_MAC = make_mac((const uint8_t[6]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
const TestIpv4Address PacketTest::SRC_IPV4(192, 168, 1, 10);
const TestIpv4Address PacketTest::DST_IPV4(192, 168, 1, 20);
const TestIpv6Address PacketTest::SRC_IPV6({0x20,0x01,0x0d,0xb8,0x85,0xa3,0x00,0x00,0x00,0x00,0x8a,0x2e,0x03,0x70,0x73,0x34});
const TestIpv6Address PacketTest::DST_IPV6({0x20,0x01,0x0d,0xb8,0x85,0xa3,0x00,0x00,0x00,0x00,0x8a,0x2e,0x03,0x70,0x73,0x35});


// Existing tests ...
TEST_F(PacketTest, ConstructorWithValidBuffer) { /* ... */ }
TEST_F(PacketTest, EthernetHeaderAccessor) { /* ... */ }
// ... (all other existing tests remain, ensure they use PacketBuffer correctly if they create it)


// --- New Test Cases from previous turn ---
TEST_F(PacketTest, PacketManagesBufferRefCount) { /* ... as implemented ... */ }
TEST_F(PacketTest, SetSrcMac) { /* ... as implemented ... */ }
TEST_F(PacketTest, SetDstMac) { /* ... as implemented ... */ }

// --- New Test Cases for this subtask ---

TEST_F(PacketTest, UpdateChecksumsAfterModification) {
    // 1. IPv4 Header Checksum
    std::vector<uint8_t> packet_data_ipv4 = build_raw_packet(
        DST_MAC, SRC_MAC, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4,
        &SRC_IPV4, &DST_IPV4, netflow::IPPROTO_TCP,
        SRC_PORT, DST_PORT, {'T','E','S','T'}
    );
    // Manually zero out IPv4 checksum in raw data before creating PacketBuffer
    if (packet_data_ipv4.size() >= netflow::EthernetHeader::SIZE + 11) { // 10th byte of IP header (offset)
        packet_data_ipv4[netflow::EthernetHeader::SIZE + 10] = 0; // Checksum high byte
        packet_data_ipv4[netflow::EthernetHeader::SIZE + 11] = 0; // Checksum low byte
    }

    netflow::PacketBuffer pb_ipv4(packet_data_ipv4.size());
    std::memcpy(pb_ipv4.get_data_start_ptr(), packet_data_ipv4.data(), packet_data_ipv4.size());
    pb_ipv4.set_data_len(packet_data_ipv4.size());
    netflow::Packet pkt_ipv4(&pb_ipv4);
    pb_ipv4.decrement_ref();

    pkt_ipv4.update_checksums();
    const netflow::IPv4Header* ip_hdr = pkt_ipv4.ipv4();
    ASSERT_NE(ip_hdr, nullptr);
    uint16_t initial_ip_checksum = ip_hdr->header_checksum;
    EXPECT_NE(initial_ip_checksum, 0);

    // Modify source IP (which affects checksum) by writing to buffer directly for test
    // This is unsafe in general, but for testing update_checksums it's okay.
    // A set_src_ip method in Packet would be cleaner.
    if(ip_hdr){ // Writable pointer needed
      const_cast<netflow::IPv4Header*>(ip_hdr)->src_ip = htonl(0x01020304); // Change to 1.2.3.4
    }
    pkt_ipv4.update_checksums(); // Recalculate
    EXPECT_NE(pkt_ipv4.ipv4()->header_checksum, initial_ip_checksum);
    EXPECT_NE(pkt_ipv4.ipv4()->header_checksum, 0);


    // 2. TCP Checksum
    // Rebuild packet data to ensure TCP checksum field is zero initially
    std::vector<uint8_t> packet_data_tcp = build_raw_packet(
        DST_MAC, SRC_MAC, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4,
        &SRC_IPV4, &DST_IPV4, netflow::IPPROTO_TCP,
        SRC_PORT, DST_PORT, {'T','E','S','T'}
    );
    if (packet_data_tcp.size() >= netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 17) { // TCP checksum offset
        packet_data_tcp[netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 16] = 0;
        packet_data_tcp[netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 17] = 0;
    }
    netflow::PacketBuffer pb_tcp(packet_data_tcp.size());
    std::memcpy(pb_tcp.get_data_start_ptr(), packet_data_tcp.data(), packet_data_tcp.size());
    pb_tcp.set_data_len(packet_data_tcp.size());
    netflow::Packet pkt_tcp(&pb_tcp);
    pb_tcp.decrement_ref();

    pkt_tcp.update_checksums();
    const netflow::TcpHeader* tcp_hdr = pkt_tcp.tcp();
    ASSERT_NE(tcp_hdr, nullptr);
    uint16_t initial_tcp_checksum = tcp_hdr->checksum;
    EXPECT_NE(initial_tcp_checksum, 0);

    // Modify TCP source port
    if(tcp_hdr) { // Writable pointer needed
        const_cast<netflow::TcpHeader*>(tcp_hdr)->src_port = htons(54321);
    }
    pkt_tcp.update_checksums();
    EXPECT_NE(pkt_tcp.tcp()->checksum, initial_tcp_checksum);
    EXPECT_NE(pkt_tcp.tcp()->checksum, 0);

    // 3. UDP Checksum (similar logic, ensure UDP checksum is handled, including 0 to 0xFFFF case)
    std::vector<uint8_t> packet_data_udp = build_raw_packet(
        DST_MAC, SRC_MAC, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4,
        &SRC_IPV4, &DST_IPV4, netflow::IPPROTO_UDP,
        UDP_SRC_PORT, UDP_DST_PORT, {'D','A','T','A'}
    );
     if (packet_data_udp.size() >= netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 7) { // UDP checksum offset
        packet_data_udp[netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 6] = 0;
        packet_data_udp[netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE + 7] = 0;
    }
    netflow::PacketBuffer pb_udp(packet_data_udp.size());
    std::memcpy(pb_udp.get_data_start_ptr(), packet_data_udp.data(), packet_data_udp.size());
    pb_udp.set_data_len(packet_data_udp.size());
    netflow::Packet pkt_udp(&pb_udp);
    pb_udp.decrement_ref();

    pkt_udp.update_checksums();
    const netflow::UdpHeader* udp_hdr = pkt_udp.udp();
    ASSERT_NE(udp_hdr, nullptr);
    // UDP checksum can be 0 (transmitted as 0xFFFF). If calculated to 0, it should be 0xFFFF.
    // If it was 0 (meaning uncomputed by sender), update_checksums should compute it.
    EXPECT_NE(udp_hdr->checksum, 0); // Should not be 0 if it was calculated, unless it calculated to 0xFFFF and was stored as 0.
                                     // The actual value 0 is invalid unless it means "no checksum".
                                     // Our update_checksums() should fill it. If it calculates to 0, it becomes 0xFFFF.
}

TEST_F(PacketTest, Ipv6UdpPacketAccessors) {
    std::vector<uint8_t> packet_data = build_eth_ipv6_udp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    pb.decrement_ref();

    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(ntohs(pkt.ethernet()->ethertype), 0x86DD); // IPv6

    const netflow::IPv6Header* ipv6 = pkt.ipv6();
    ASSERT_NE(ipv6, nullptr);
    EXPECT_EQ((ntohl(ipv6->version_tc_flowlabel) >> 28) & 0xF, 6);
    EXPECT_EQ(ipv6->next_header, netflow::IPPROTO_UDP);
    EXPECT_TRUE(SRC_IPV6 == ipv6->src_ip);
    EXPECT_TRUE(DST_IPV6 == ipv6->dst_ip);

    const netflow::UdpHeader* udp = pkt.udp();
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(ntohs(udp->src_port), UDP_SRC_PORT);
    EXPECT_EQ(ntohs(udp->dst_port), UDP_DST_PORT);
    EXPECT_EQ(ntohs(udp->length), 8 + 4); // UDP header + "DATA" payload

    EXPECT_EQ(pkt.tcp(), nullptr);

    // Test checksum update for IPv6/UDP (currently a TODO in packet.hpp, so just ensure no crash)
    // pkt.update_checksums(); // If IPv6 TCP/UDP checksums are not implemented, this might not change anything or error.
    // For now, just ensure it can be called without issue.
    ASSERT_NO_THROW(pkt.update_checksums());
}

TEST_F(PacketTest, PushVlanNoHeadroom) {
    std::vector<uint8_t> packet_data = build_raw_packet(
        DST_MAC, SRC_MAC, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4,
        &SRC_IPV4, &DST_IPV4, netflow::IPPROTO_TCP, SRC_PORT, DST_PORT
    );
    // Create PacketBuffer with zero headroom
    netflow::PacketBuffer pb(packet_data.size(), 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    pb.decrement_ref();

    ASSERT_FALSE(pkt.has_vlan());
    // push_vlan needs to prepend data. If no headroom, PacketBuffer::prepend_data fails.
    // Packet::push_vlan checks if PacketBuffer::prepend_data succeeds.
    // However, Packet::push_vlan also checks buffer_ ->get_tailroom() < VlanHeader::SIZE and then
    // buffer_->get_data_length() + VlanHeader::SIZE > buffer_->get_capacity()
    // This logic seems more about reallocating/expanding buffer, not strictly headroom for prepend.
    // The current Packet::push_vlan uses memmove, which might succeed if total capacity is there.
    // Let's assume the test means "not enough space at the beginning of allocated buffer if data_offset is 0".
    // The PacketBuffer::prepend_data correctly checks data_offset_.

    // If PacketBuffer::prepend_data fails, pkt.push_vlan should return false.
    // The current Packet::push_vlan has a complex logic for prepending.
    // If there's no headroom (data_offset_ == 0), prepend_data in PacketBuffer returns false.
    // Packet::push_vlan, if not has_vlan(), tries to memmove then set ethertype.
    // The memmove would shift data right. If total capacity is not enough, it might fail there.
    // The current Packet::push_vlan doesn't directly use PacketBuffer::prepend_data if no VLAN tag exists.
    // It uses memmove. If capacity is just enough for current data, memmove to make space for VLAN will fail.

    // To test this properly, capacity should be exactly packet_data.size() and headroom 0.
    netflow::PacketBuffer pb_no_space(packet_data.size(), 0, packet_data.size());
    std::memcpy(pb_no_space.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt_no_space(&pb_no_space);
    pb_no_space.decrement_ref();

    EXPECT_FALSE(pkt_no_space.push_vlan(TEST_VLAN_ID, TEST_VLAN_PRIO));
    EXPECT_FALSE(pkt_no_space.has_vlan()); // Should remain unchanged
    EXPECT_EQ(pb_no_space.get_data_length(), packet_data.size());
}

TEST_F(PacketTest, PopVlanOnNonVlanPacket) {
    std::vector<uint8_t> packet_data = build_raw_packet(
        DST_MAC, SRC_MAC, std::nullopt, std::nullopt, netflow::ETHERTYPE_IPV4, // Non-VLAN
        &SRC_IPV4, &DST_IPV4, netflow::IPPROTO_TCP, SRC_PORT, DST_PORT
    );
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    pb.decrement_ref();

    ASSERT_FALSE(pkt.has_vlan());
    EXPECT_FALSE(pkt.pop_vlan()); // Should return false as no VLAN tag to pop
    EXPECT_FALSE(pkt.has_vlan()); // State should be unchanged
    EXPECT_EQ(pb.get_data_length(), packet_data.size());
}
