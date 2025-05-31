#include "gtest/gtest.h"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/packet.hpp"
#include <cstring>
#include <vector>
#include <array>
#include <arpa/inet.h>
#include <optional>

// --- Test fixture for PacketBuffer tests (remains unchanged) ---
class PacketBufferTest : public ::testing::Test {
protected:
    static constexpr size_t DEFAULT_CAPACITY = 1024;
    static constexpr size_t INITIAL_HEADROOM = 32;

    netflow::PacketBuffer create_buffer(size_t capacity, size_t initial_headroom = 0, size_t initial_data_len = 0) {
        return netflow::PacketBuffer(capacity, initial_headroom, initial_data_len);
    }
};
TEST_F(PacketBufferTest, Constructor) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    EXPECT_NE(pb.get_data_start_ptr(), nullptr);
    EXPECT_EQ(pb.get_capacity(), DEFAULT_CAPACITY);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_data_length(), 0);
    EXPECT_EQ(pb.ref_count.load(), 1);

    netflow::PacketBuffer pb_no_headroom(DEFAULT_CAPACITY);
    EXPECT_EQ(pb_no_headroom.get_headroom(), 0);
    EXPECT_EQ(pb_no_headroom.get_tailroom(), DEFAULT_CAPACITY);
}
TEST_F(PacketBufferTest, GetDataStartPtrMethod) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    EXPECT_NE(pb.get_data_start_ptr(), nullptr);
    EXPECT_EQ(pb.get_data_start_ptr(), pb.raw_data_ptr_ + INITIAL_HEADROOM);
}
TEST_F(PacketBufferTest, GetCapacityMethod) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY);
    EXPECT_EQ(pb.get_capacity(), DEFAULT_CAPACITY);
    netflow::PacketBuffer pb_small(128);
    EXPECT_EQ(pb_small.get_capacity(), 128);
}
TEST_F(PacketBufferTest, GetHeadroomMethod) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM);
    netflow::PacketBuffer pb_no_headroom(DEFAULT_CAPACITY);
    EXPECT_EQ(pb_no_headroom.get_headroom(), 0);
}
TEST_F(PacketBufferTest, GetTailroomMethod) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM);
    pb.append_data(100);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM - 100);
}
TEST_F(PacketBufferTest, GetDataLengthMethod) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY);
    EXPECT_EQ(pb.get_data_length(), 0);
}
TEST_F(PacketBufferTest, AppendData) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    const size_t len_to_append = 100;
    ASSERT_TRUE(pb.append_data(len_to_append));
    EXPECT_EQ(pb.get_data_length(), len_to_append);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM - len_to_append);
    const size_t another_len_to_append = 50;
    ASSERT_TRUE(pb.append_data(another_len_to_append));
    EXPECT_EQ(pb.get_data_length(), len_to_append + another_len_to_append);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM - (len_to_append + another_len_to_append));
    size_t remaining_tailroom = pb.get_tailroom();
    EXPECT_FALSE(pb.append_data(remaining_tailroom + 10));
    EXPECT_EQ(pb.get_data_length(), len_to_append + another_len_to_append);
    ASSERT_TRUE(pb.append_data(remaining_tailroom));
    EXPECT_EQ(pb.get_data_length(), DEFAULT_CAPACITY - INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_tailroom(), 0);
}
TEST_F(PacketBufferTest, PrependData) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    unsigned char* initial_data_start_ptr = pb.get_data_start_ptr();
    const size_t len_to_prepend = 30;
    ASSERT_LE(len_to_prepend, INITIAL_HEADROOM);
    ASSERT_TRUE(pb.prepend_data(len_to_prepend));
    EXPECT_EQ(pb.get_data_length(), len_to_prepend);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM - len_to_prepend);
    EXPECT_EQ(pb.get_data_start_ptr(), initial_data_start_ptr - len_to_prepend);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM);
    const size_t another_len_to_prepend = 2;
    ASSERT_LE(another_len_to_prepend, pb.get_headroom());
    ASSERT_TRUE(pb.prepend_data(another_len_to_prepend));
    EXPECT_EQ(pb.get_data_length(), len_to_prepend + another_len_to_prepend);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM - (len_to_prepend + another_len_to_prepend));
    EXPECT_EQ(pb.get_data_start_ptr(), initial_data_start_ptr - (len_to_prepend + another_len_to_prepend));
    size_t remaining_headroom = pb.get_headroom();
    EXPECT_FALSE(pb.prepend_data(remaining_headroom + 10));
    EXPECT_EQ(pb.get_data_length(), len_to_prepend + another_len_to_prepend);
    ASSERT_TRUE(pb.prepend_data(remaining_headroom));
    EXPECT_EQ(pb.get_data_length(), INITIAL_HEADROOM);
    EXPECT_EQ(pb.get_headroom(), 0);
    EXPECT_EQ(pb.get_data_start_ptr(), pb.raw_data_ptr_);
}
TEST_F(PacketBufferTest, ConsumeDataFront) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    const size_t len_to_add = 200;
    pb.append_data(len_to_add);
    unsigned char* data_ptr_after_append = pb.get_data_start_ptr();
    const size_t len_to_consume = 70;
    ASSERT_TRUE(pb.consume_data_front(len_to_consume));
    EXPECT_EQ(pb.get_data_length(), len_to_add - len_to_consume);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM + len_to_consume);
    EXPECT_EQ(pb.get_data_start_ptr(), data_ptr_after_append + len_to_consume);
    const size_t another_len_to_consume = 30;
    ASSERT_TRUE(pb.consume_data_front(another_len_to_consume));
    EXPECT_EQ(pb.get_data_length(), len_to_add - len_to_consume - another_len_to_consume);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM + len_to_consume + another_len_to_consume);
    EXPECT_EQ(pb.get_data_start_ptr(), data_ptr_after_append + len_to_consume + another_len_to_consume);
    size_t remaining_data_len = pb.get_data_length();
    EXPECT_FALSE(pb.consume_data_front(remaining_data_len + 10));
    EXPECT_EQ(pb.get_data_length(), remaining_data_len);
    ASSERT_TRUE(pb.consume_data_front(remaining_data_len));
    EXPECT_EQ(pb.get_data_length(), 0);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM + len_to_add);
    EXPECT_EQ(pb.get_data_start_ptr(), data_ptr_after_append + len_to_add);
}
TEST_F(PacketBufferTest, ConsumeDataEnd) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    const size_t len_to_add = 300;
    pb.append_data(len_to_add);
    size_t initial_tailroom = pb.get_tailroom();
    const size_t len_to_consume = 80;
    ASSERT_TRUE(pb.consume_data_end(len_to_consume));
    EXPECT_EQ(pb.get_data_length(), len_to_add - len_to_consume);
    EXPECT_EQ(pb.get_tailroom(), initial_tailroom + len_to_consume);
    EXPECT_EQ(pb.get_headroom(), INITIAL_HEADROOM);
    const size_t another_len_to_consume = 40;
    ASSERT_TRUE(pb.consume_data_end(another_len_to_consume));
    EXPECT_EQ(pb.get_data_length(), len_to_add - len_to_consume - another_len_to_consume);
    EXPECT_EQ(pb.get_tailroom(), initial_tailroom + len_to_consume + another_len_to_consume);
    size_t remaining_data_len = pb.get_data_length();
    EXPECT_FALSE(pb.consume_data_end(remaining_data_len + 10));
    EXPECT_EQ(pb.get_data_length(), remaining_data_len);
    ASSERT_TRUE(pb.consume_data_end(remaining_data_len));
    EXPECT_EQ(pb.get_data_length(), 0);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM);
}
TEST_F(PacketBufferTest, SetDataLength) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    EXPECT_TRUE(pb.set_data_len(100));
    EXPECT_EQ(pb.get_data_length(), 100);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - INITIAL_HEADROOM - 100);
    EXPECT_FALSE(pb.set_data_len(DEFAULT_CAPACITY - INITIAL_HEADROOM + 1));
    EXPECT_EQ(pb.get_data_length(), 100);
    EXPECT_TRUE(pb.set_data_len(0));
    EXPECT_EQ(pb.get_data_length(), 0);
}
TEST_F(PacketBufferTest, ResetOffsetsAndLen) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY, INITIAL_HEADROOM);
    pb.append_data(100);
    size_t new_offset = 50;
    size_t new_len = 200;
    pb.reset_offsets_and_len(new_offset, new_len);
    EXPECT_EQ(pb.get_headroom(), new_offset);
    EXPECT_EQ(pb.get_data_length(), new_len);
    EXPECT_EQ(pb.get_data_start_ptr(), pb.raw_data_ptr_ + new_offset);
    EXPECT_EQ(pb.get_tailroom(), DEFAULT_CAPACITY - new_offset - new_len);
    EXPECT_THROW(pb.reset_offsets_and_len(DEFAULT_CAPACITY - 10, 20), std::out_of_range);
    EXPECT_EQ(pb.get_headroom(), new_offset);
    EXPECT_EQ(pb.get_data_length(), new_len);
}
TEST_F(PacketBufferTest, ReferenceCounting) {
    netflow::PacketBuffer pb(DEFAULT_CAPACITY);
    EXPECT_EQ(pb.ref_count.load(), 1);
    pb.increment_ref();
    EXPECT_EQ(pb.ref_count.load(), 2);
    EXPECT_FALSE(pb.decrement_ref());
    EXPECT_EQ(pb.ref_count.load(), 1);
    EXPECT_TRUE(pb.decrement_ref());
    EXPECT_EQ(pb.ref_count.load(), 0);
}

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


    std::vector<uint8_t> build_eth_ipv4_tcp_packet(bool with_vlan = false) {
        std::vector<uint8_t> data;
        data.insert(data.end(), DST_MAC.bytes, DST_MAC.bytes + 6);
        data.insert(data.end(), SRC_MAC.bytes, SRC_MAC.bytes + 6);

        if (with_vlan) {
            data.push_back(0x81); data.push_back(0x00);
            uint16_t tci = (TEST_VLAN_PRIO << 13) | TEST_VLAN_ID;
            data.push_back((tci >> 8) & 0xFF); data.push_back(tci & 0xFF);
        }
        data.push_back(0x08); data.push_back(0x00); // IPv4 EtherType

        size_t ip_header_len = 20;
        size_t tcp_header_len = 20;
        uint16_t ip_total_length = ip_header_len + tcp_header_len;

        data.push_back(0x45);
        data.push_back(0x00);
        data.push_back((ip_total_length >> 8) & 0xFF); data.push_back(ip_total_length & 0xFF);
        data.push_back(0x00); data.push_back(0x01);
        data.push_back(0x00); data.push_back(0x00);
        data.push_back(0x40);
        data.push_back(0x06); // TCP
        data.push_back(0x00); data.push_back(0x00);
        data.insert(data.end(), SRC_IPV4.begin(), SRC_IPV4.end());
        data.insert(data.end(), DST_IPV4.begin(), DST_IPV4.end());

        data.push_back((SRC_PORT >> 8) & 0xFF); data.push_back(SRC_PORT & 0xFF);
        data.push_back((DST_PORT >> 8) & 0xFF); data.push_back(DST_PORT & 0xFF);
        data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); data.push_back(0x01);
        data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); data.push_back(0x02);
        data.push_back(0x50);
        data.push_back(0x02); // SYN
        data.push_back(0x72); data.push_back(0x10);
        data.push_back(0x00); data.push_back(0x00);
        data.push_back(0x00); data.push_back(0x00);
        return data;
    }

    std::vector<uint8_t> build_eth_ipv4_udp_packet(bool with_vlan = false) {
        std::vector<uint8_t> data;
        data.insert(data.end(), DST_MAC.bytes, DST_MAC.bytes + 6);
        data.insert(data.end(), SRC_MAC.bytes, SRC_MAC.bytes + 6);

        if (with_vlan) {
            data.push_back(0x81); data.push_back(0x00); // VLAN EtherType
            uint16_t tci = (TEST_VLAN_PRIO << 13) | TEST_VLAN_ID;
            data.push_back((tci >> 8) & 0xFF); data.push_back(tci & 0xFF);
        }
        data.push_back(0x08); data.push_back(0x00); // IPv4 EtherType

        size_t ip_header_len = 20;
        size_t udp_header_len = 8;
        size_t payload_len = 4; // Sample payload "DATA"
        uint16_t ip_total_length = ip_header_len + udp_header_len + payload_len;
        uint16_t udp_total_length = udp_header_len + payload_len;


        data.push_back(0x45); // Version IHL
        data.push_back(0x00); // DSCP ECN
        data.push_back((ip_total_length >> 8) & 0xFF); data.push_back(ip_total_length & 0xFF);
        data.push_back(0x00); data.push_back(0x02); // ID
        data.push_back(0x00); data.push_back(0x00); // Flags Offset
        data.push_back(0x40); // TTL
        data.push_back(0x11); // Protocol UDP (17)
        data.push_back(0x00); data.push_back(0x00); // IP Checksum
        data.insert(data.end(), SRC_IPV4.begin(), SRC_IPV4.end());
        data.insert(data.end(), DST_IPV4.begin(), DST_IPV4.end());

        data.push_back((UDP_SRC_PORT >> 8) & 0xFF); data.push_back(UDP_SRC_PORT & 0xFF);
        data.push_back((UDP_DST_PORT >> 8) & 0xFF); data.push_back(UDP_DST_PORT & 0xFF);
        data.push_back((udp_total_length >> 8) & 0xFF); data.push_back(udp_total_length & 0xFF);
        data.push_back(0x00); data.push_back(0x00); // UDP Checksum

        // Payload "DATA"
        data.push_back('D'); data.push_back('A'); data.push_back('T'); data.push_back('A');
        return data;
    }

    std::vector<uint8_t> build_eth_ipv6_tcp_packet(bool with_vlan = false) {
        std::vector<uint8_t> data;
        data.insert(data.end(), DST_MAC.bytes, DST_MAC.bytes + 6);
        data.insert(data.end(), SRC_MAC.bytes, SRC_MAC.bytes + 6);

        if (with_vlan) {
            data.push_back(0x81); data.push_back(0x00); // VLAN EtherType
            uint16_t tci = (TEST_VLAN_PRIO << 13) | TEST_VLAN_ID;
            data.push_back((tci >> 8) & 0xFF); data.push_back(tci & 0xFF);
        }
        data.push_back(0x86); data.push_back(0xDD); // IPv6 EtherType

        // IPv6 Header (40 bytes)
        size_t tcp_header_len = 20;
        uint16_t ipv6_payload_length = tcp_header_len; // TCP header is the payload

        data.push_back(0x60); data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); // Version, TC, Flow Label
        data.push_back((ipv6_payload_length >> 8) & 0xFF); data.push_back(ipv6_payload_length & 0xFF); // Payload Length
        data.push_back(0x06); // Next Header (TCP)
        data.push_back(0x40); // Hop Limit
        data.insert(data.end(), SRC_IPV6.begin(), SRC_IPV6.end());
        data.insert(data.end(), DST_IPV6.begin(), DST_IPV6.end());

        // TCP Header (20 bytes)
        data.push_back((SRC_PORT >> 8) & 0xFF); data.push_back(SRC_PORT & 0xFF);
        data.push_back((DST_PORT >> 8) & 0xFF); data.push_back(DST_PORT & 0xFF);
        data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); data.push_back(0x01); // Seq
        data.push_back(0x00); data.push_back(0x00); data.push_back(0x00); data.push_back(0x02); // Ack
        data.push_back(0x50); // Data Offset
        data.push_back(0x02); // Flags (SYN)
        data.push_back(0x72); data.push_back(0x10); // Window
        data.push_back(0x00); data.push_back(0x00); // TCP Checksum
        data.push_back(0x00); data.push_back(0x00); // Urgent Ptr
        return data;
    }
};

const netflow::MacAddress PacketTest::SRC_MAC = make_mac((const uint8_t[6]){0x00, 0x11, 0x22, 0x33, 0x44, 0x55});
const netflow::MacAddress PacketTest::DST_MAC = make_mac((const uint8_t[6]){0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF});
const TestIpv4Address PacketTest::SRC_IPV4(192, 168, 1, 10);
const TestIpv4Address PacketTest::DST_IPV4(192, 168, 1, 20);
const TestIpv6Address PacketTest::SRC_IPV6({0x20,0x01,0x0d,0xb8,0x85,0xa3,0x00,0x00,0x00,0x00,0x8a,0x2e,0x03,0x70,0x73,0x34});
const TestIpv6Address PacketTest::DST_IPV6({0x20,0x01,0x0d,0xb8,0x85,0xa3,0x00,0x00,0x00,0x00,0x8a,0x2e,0x03,0x70,0x73,0x35});


TEST_F(PacketTest, ConstructorWithValidBuffer) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 32, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    EXPECT_NE(pkt.ethernet(), nullptr);
    EXPECT_NE(pkt.ipv4(), nullptr);
    EXPECT_NE(pkt.tcp(), nullptr);
    EXPECT_EQ(pkt.udp(), nullptr);
    EXPECT_FALSE(pkt.has_vlan());
}

TEST_F(PacketTest, EthernetHeaderAccessor) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    const netflow::EthernetHeader* eth = pkt.ethernet();
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(eth->src_mac, SRC_MAC);
    EXPECT_EQ(eth->dst_mac, DST_MAC);
    EXPECT_EQ(ntohs(eth->ethertype), 0x0800);
    ASSERT_TRUE(pkt.src_mac().has_value());
    EXPECT_EQ(pkt.src_mac().value(), SRC_MAC);
    ASSERT_TRUE(pkt.dst_mac().has_value());
    EXPECT_EQ(pkt.dst_mac().value(), DST_MAC);
}

TEST_F(PacketTest, Ipv4HeaderAccessor) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    const netflow::IPv4Header* ip = pkt.ipv4();
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->src_ip, SRC_IPV4.to_uint32_be());
    EXPECT_EQ(ip->dst_ip, DST_IPV4.to_uint32_be());
    EXPECT_EQ(ip->protocol, 0x06);
    EXPECT_EQ(ntohs(ip->total_length), 40);
    EXPECT_EQ(ip->get_header_length(), 20);
}

TEST_F(PacketTest, TcpHeaderAccessor) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    const netflow::TcpHeader* tcp = pkt.tcp();
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(ntohs(tcp->src_port), SRC_PORT);
    EXPECT_EQ(ntohs(tcp->dst_port), DST_PORT);
}

TEST_F(PacketTest, PacketWithTooSmallBuffer) {
    std::vector<uint8_t> tiny_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    netflow::PacketBuffer pb(tiny_data.size() + 128, 0, tiny_data.size());
    std::memcpy(pb.get_data_start_ptr(), tiny_data.data(), tiny_data.size());
    netflow::Packet pkt(&pb);
    EXPECT_EQ(pkt.ethernet(), nullptr);
    EXPECT_EQ(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.tcp(), nullptr);
}

TEST_F(PacketTest, PacketWithOnlyEthernet) {
    std::vector<uint8_t> eth_only_data;
    eth_only_data.insert(eth_only_data.end(), DST_MAC.bytes, DST_MAC.bytes + 6);
    eth_only_data.insert(eth_only_data.end(), SRC_MAC.bytes, SRC_MAC.bytes + 6);
    eth_only_data.push_back(0x08); eth_only_data.push_back(0x06); // ARP
    netflow::PacketBuffer pb(eth_only_data.size() + 128, 0, eth_only_data.size());
    std::memcpy(pb.get_data_start_ptr(), eth_only_data.data(), eth_only_data.size());
    netflow::Packet pkt(&pb);
    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(ntohs(pkt.ethernet()->ethertype), 0x0806);
    EXPECT_EQ(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.tcp(), nullptr);
}

TEST_F(PacketTest, GetHeaderTemplate) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);
    const netflow::EthernetHeader* eth = pkt.get_header<netflow::EthernetHeader>(0);
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(eth->src_mac, SRC_MAC);
    const netflow::IPv4Header* ip = pkt.get_header<netflow::IPv4Header>(netflow::EthernetHeader::SIZE);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->src_ip, SRC_IPV4.to_uint32_be());
    const netflow::TcpHeader* tcp = pkt.get_header<netflow::TcpHeader>(netflow::EthernetHeader::SIZE + netflow::IPv4Header::MIN_SIZE);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(ntohs(tcp->src_port), SRC_PORT);
}

// --- VLAN Tests ---
TEST_F(PacketTest, VlanPacketAccessors) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet(true /* with_vlan */);
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_TRUE(pkt.has_vlan());

    std::optional<uint16_t> vlan_id = pkt.vlan_id();
    ASSERT_TRUE(vlan_id.has_value());
    EXPECT_EQ(vlan_id.value(), TEST_VLAN_ID);

    std::optional<uint8_t> vlan_prio = pkt.vlan_priority();
    ASSERT_TRUE(vlan_prio.has_value());
    EXPECT_EQ(vlan_prio.value(), TEST_VLAN_PRIO);

    const netflow::VlanHeader* vlan_hdr = pkt.vlan();
    ASSERT_NE(vlan_hdr, nullptr);
    EXPECT_EQ(vlan_hdr->get_vlan_id(), TEST_VLAN_ID);
    EXPECT_EQ(vlan_hdr->get_priority(), TEST_VLAN_PRIO);
    EXPECT_EQ(ntohs(vlan_hdr->ethertype), 0x0800);

    ASSERT_NE(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.ipv4()->src_ip, SRC_IPV4.to_uint32_be());
    ASSERT_NE(pkt.tcp(), nullptr);
    EXPECT_EQ(ntohs(pkt.tcp()->src_port), SRC_PORT);
}

TEST_F(PacketTest, PushVlan) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet(false);
    size_t original_len = packet_data.size();
    netflow::PacketBuffer pb(packet_data.size() + 128, 32, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_FALSE(pkt.has_vlan());
    ASSERT_TRUE(pkt.push_vlan(TEST_VLAN_ID, TEST_VLAN_PRIO));

    EXPECT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pb.get_data_length(), original_len + netflow::VlanHeader::SIZE);

    std::optional<uint16_t> vlan_id = pkt.vlan_id();
    ASSERT_TRUE(vlan_id.has_value());
    EXPECT_EQ(vlan_id.value(), TEST_VLAN_ID);

    const netflow::EthernetHeader* eth = pkt.ethernet();
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(ntohs(eth->ethertype), 0x8100);

    const netflow::VlanHeader* vlan_hdr = pkt.vlan();
    ASSERT_NE(vlan_hdr, nullptr);
    EXPECT_EQ(ntohs(vlan_hdr->ethertype), 0x0800);

    ASSERT_NE(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.ipv4()->src_ip, SRC_IPV4.to_uint32_be());
}

TEST_F(PacketTest, PopVlan) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet(true);
    size_t original_len = packet_data.size();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_TRUE(pkt.has_vlan());
    ASSERT_TRUE(pkt.pop_vlan());

    EXPECT_FALSE(pkt.has_vlan());
    EXPECT_EQ(pb.get_data_length(), original_len - netflow::VlanHeader::SIZE);

    const netflow::EthernetHeader* eth = pkt.ethernet();
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(ntohs(eth->ethertype), 0x0800);

    ASSERT_NE(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.ipv4()->src_ip, SRC_IPV4.to_uint32_be());
}

TEST_F(PacketTest, PushVlanOnExistingVlan) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet(true);
    size_t original_len = packet_data.size();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    uint16_t new_vlan_id = 202;
    uint8_t new_vlan_prio = 2;

    ASSERT_TRUE(pkt.push_vlan(new_vlan_id, new_vlan_prio));
    EXPECT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pb.get_data_length(), original_len);

    std::optional<uint16_t> vlan_id = pkt.vlan_id();
    ASSERT_TRUE(vlan_id.has_value());
    EXPECT_EQ(vlan_id.value(), new_vlan_id);

    std::optional<uint8_t> vlan_prio = pkt.vlan_priority();
    ASSERT_TRUE(vlan_prio.has_value());
    EXPECT_EQ(vlan_prio.value(), new_vlan_prio);
}

// --- IPv6 Tests ---
TEST_F(PacketTest, Ipv6HeaderAccessor) {
    std::vector<uint8_t> packet_data = build_eth_ipv6_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(ntohs(pkt.ethernet()->ethertype), 0x86DD); // IPv6 EtherType

    const netflow::IPv6Header* ipv6 = pkt.ipv6();
    ASSERT_NE(ipv6, nullptr);
    EXPECT_EQ((ntohl(ipv6->version_tc_flowlabel) >> 28) & 0xF, 6); // Version is 6
    EXPECT_EQ(ipv6->next_header, 0x06); // TCP
    EXPECT_TRUE(SRC_IPV6 == ipv6->src_ip); // Use TestIpv6Address::operator==
    EXPECT_TRUE(DST_IPV6 == ipv6->dst_ip); // Use TestIpv6Address::operator==

    ASSERT_NE(pkt.tcp(), nullptr); // Check TCP parsing after IPv6
    EXPECT_EQ(ntohs(pkt.tcp()->src_port), SRC_PORT);

    // Test with non-IPv6 packet
    std::vector<uint8_t> ipv4_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb_ipv4(ipv4_data.size() + 128, 0, ipv4_data.size());
    std::memcpy(pb_ipv4.get_data_start_ptr(), ipv4_data.data(), ipv4_data.size());
    netflow::Packet pkt_ipv4(&pb_ipv4);
    EXPECT_EQ(pkt_ipv4.ipv6(), nullptr);
}

// --- UDP Tests ---
TEST_F(PacketTest, UdpHeaderAccessor) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_udp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_NE(pkt.ethernet(), nullptr);
    ASSERT_NE(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.ipv4()->protocol, 0x11); // UDP Protocol

    const netflow::UdpHeader* udp = pkt.udp();
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(ntohs(udp->src_port), UDP_SRC_PORT);
    EXPECT_EQ(ntohs(udp->dst_port), UDP_DST_PORT);
    EXPECT_EQ(ntohs(udp->length), 8 + 4); // UDP header + "DATA" payload

    // Test with non-UDP packet (TCP packet)
    std::vector<uint8_t> tcp_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb_tcp(tcp_data.size() + 128, 0, tcp_data.size());
    std::memcpy(pb_tcp.get_data_start_ptr(), tcp_data.data(), tcp_data.size());
    netflow::Packet pkt_tcp(&pb_tcp);
    EXPECT_EQ(pkt_tcp.udp(), nullptr);
}

TEST_F(PacketTest, VlanUdpPacketAccessors) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_udp_packet(true /* with_vlan */);
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_TRUE(pkt.has_vlan());
    ASSERT_NE(pkt.vlan(), nullptr);
    EXPECT_EQ(pkt.vlan_id().value_or(0), TEST_VLAN_ID);

    ASSERT_NE(pkt.ipv4(), nullptr);
    EXPECT_EQ(pkt.ipv4()->protocol, 0x11); // UDP

    const netflow::UdpHeader* udp = pkt.udp();
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(ntohs(udp->src_port), UDP_SRC_PORT);
    EXPECT_EQ(ntohs(udp->dst_port), UDP_DST_PORT);
}


// --- L2 Manipulation Tests ---
TEST_F(PacketTest, SetDstMac) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    const uint8_t new_mac_arr[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34};
    netflow::MacAddress new_mac = make_mac(new_mac_arr);

    ASSERT_TRUE(pkt.set_dst_mac(new_mac));
    ASSERT_NE(pkt.ethernet(), nullptr);
    EXPECT_EQ(pkt.ethernet()->dst_mac, new_mac);
    EXPECT_EQ(pkt.dst_mac().value(), new_mac);
    EXPECT_EQ(pkt.ethernet()->src_mac, SRC_MAC); // Ensure src_mac is unchanged
}

// --- Checksum Tests ---
TEST_F(PacketTest, UpdateChecksumsCall) {
    std::vector<uint8_t> packet_data = build_eth_ipv4_tcp_packet();
    netflow::PacketBuffer pb(packet_data.size() + 128, 0, packet_data.size());
    std::memcpy(pb.get_data_start_ptr(), packet_data.data(), packet_data.size());
    netflow::Packet pkt(&pb);

    // Get original checksums (if they are non-zero in test data)
    const netflow::IPv4Header* ip_before = pkt.ipv4();
    ASSERT_NE(ip_before, nullptr);
    uint16_t ip_checksum_before = ip_before->header_checksum;

    const netflow::TcpHeader* tcp_before = pkt.tcp();
    ASSERT_NE(tcp_before, nullptr);
    uint16_t tcp_checksum_before = tcp_before->checksum;

    pkt.update_checksums(); // This should recalculate

    const netflow::IPv4Header* ip_after = pkt.ipv4();
    ASSERT_NE(ip_after, nullptr);
    // Checksum should be recalculated. If it was 0, it should be non-zero now (usually).
    // If it was non-zero, it might be the same if nothing changed, or different.
    // For this test, just ensure it runs. A more advanced test would modify data.
    // If the original checksum in test data was 0x0000, it should change.
    if (ip_checksum_before == 0) {
         EXPECT_NE(ip_after->header_checksum, 0);
    }
    // A very basic check: if input checksums were non-zero, they might change or stay same.
    // If they were zero, they should ideally become non-zero.
    // This test mainly ensures the call completes and potentially modifies the checksum fields.

    const netflow::TcpHeader* tcp_after = pkt.tcp();
    ASSERT_NE(tcp_after, nullptr);
    if (tcp_checksum_before == 0) {
        EXPECT_NE(tcp_after->checksum, 0);
    }
}

// TODO: More advanced checksum tests (modify data, check specific values)
// TODO: Test Packet's reference counting if it owns the PacketBuffer (e.g. copy constructor, assignment for Packet itself)
// TODO: IPv6 UDP packet tests.
