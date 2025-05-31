#include "gtest/gtest.h"
#include "netflow++/packet_classifier.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/packet_buffer.hpp"
// Assuming MacAddress, EthernetHeader, VlanHeader, IPv4Header, IPv6Header, TcpHeader, UdpHeader are included via packet.hpp
// or are standard types accessible through netflow namespace.

#include <vector>
#include <array>
#include <cstring> // For memcpy, memset
#include <stdexcept> // For std::runtime_error

// --- Helper Functions for Packet Creation ---
namespace PacketCreationHelpers {

using namespace netflow;

// Note: These helpers assume PacketBuffer has enough capacity.
// They append data and update the buffer's data_len.

size_t populate_eth_header(PacketBuffer& pb, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype_host_order) {
    if (pb.get_tailroom() < EthernetHeader::SIZE) {
        throw std::runtime_error("Not enough tailroom for Ethernet header");
    }
    EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(pb.get_data_start_ptr() + pb.get_data_length());
    eth->dst_mac = dst_mac;
    eth->src_mac = src_mac;
    eth->ethertype = htons(ethertype_host_order);
    pb.append_data(EthernetHeader::SIZE);
    return EthernetHeader::SIZE;
}

size_t populate_vlan_header(PacketBuffer& pb, uint16_t vlan_id, uint8_t priority, uint16_t ethertype_host_order) {
    if (pb.get_tailroom() < VlanHeader::SIZE) {
        throw std::runtime_error("Not enough tailroom for VLAN header");
    }
    VlanHeader* vlan = reinterpret_cast<VlanHeader*>(pb.get_data_start_ptr() + pb.get_data_length());
    vlan->set_vlan_id(vlan_id);
    vlan->set_priority(priority);
    vlan->ethertype = htons(ethertype_host_order);
    pb.append_data(VlanHeader::SIZE);
    return VlanHeader::SIZE;
}

size_t populate_ipv4_header(PacketBuffer& pb, uint32_t src_ip, uint32_t dst_ip, uint8_t protocol, uint16_t total_len_host_order = 20) {
    if (pb.get_tailroom() < IPv4Header::MIN_SIZE) {
        throw std::runtime_error("Not enough tailroom for IPv4 header");
    }
    IPv4Header* ip = reinterpret_cast<IPv4Header*>(pb.get_data_start_ptr() + pb.get_data_length());
    ip->version_ihl = (4 << 4) | (IPv4Header::MIN_SIZE / 4); // IPv4, 20-byte header
    ip->dscp_ecn = 0;
    ip->total_length = htons(total_len_host_order); // Min header size for this example
    ip->identification = htons(12345);
    ip->flags_fragment_offset = 0;
    ip->ttl = 64;
    ip->protocol = protocol;
    ip->header_checksum = 0; // Calculate later if needed
    ip->src_ip = htonl(src_ip);
    ip->dst_ip = htonl(dst_ip);
    // Simplified: checksum calculation would normally be done here or by Packet::update_checksums()
    pb.append_data(IPv4Header::MIN_SIZE);
    return IPv4Header::MIN_SIZE;
}

size_t populate_ipv6_header(PacketBuffer& pb, const std::array<uint8_t, 16>& src_ip, const std::array<uint8_t, 16>& dst_ip, uint8_t next_header) {
    if (pb.get_tailroom() < IPv6Header::SIZE) {
        throw std::runtime_error("Not enough tailroom for IPv6 header");
    }
    IPv6Header* ip6 = reinterpret_cast<IPv6Header*>(pb.get_data_start_ptr() + pb.get_data_length());
    ip6->version_tc_flowlabel = htonl(6 << 28); // Version 6
    ip6->payload_length = htons(0); // Will be updated if L4 is added
    ip6->next_header = next_header;
    ip6->hop_limit = 64;
    std::memcpy(ip6->src_ip, src_ip.data(), 16);
    std::memcpy(ip6->dst_ip, dst_ip.data(), 16);
    pb.append_data(IPv6Header::SIZE);
    return IPv6Header::SIZE;
}

size_t populate_tcp_header(PacketBuffer& pb, uint16_t src_port, uint16_t dst_port) {
    if (pb.get_tailroom() < TcpHeader::MIN_SIZE) {
        throw std::runtime_error("Not enough tailroom for TCP header");
    }
    TcpHeader* tcp = reinterpret_cast<TcpHeader*>(pb.get_data_start_ptr() + pb.get_data_length());
    tcp->src_port = htons(src_port);
    tcp->dst_port = htons(dst_port);
    tcp->seq_number = htonl(1000);
    tcp->ack_number = htonl(0);
    tcp->data_offset_reserved_flags = (TcpHeader::MIN_SIZE / 4) << 4; // Min header size
    tcp->window_size = htons(8192);
    tcp->checksum = 0;
    tcp->urgent_pointer = 0;
    pb.append_data(TcpHeader::MIN_SIZE);

    // Update IPv4 total length or IPv6 payload length if they exist
    // This is a simplification; a real packet constructor would handle this better.
    // Check if L3 was IPv4
    if(pb.get_data_length() > (EthernetHeader::SIZE + IPv4Header::MIN_SIZE + TcpHeader::MIN_SIZE -1) ) { // rough check
        IPv4Header* ip4 = reinterpret_cast<IPv4Header*>(pb.get_data_start_ptr() + pb.get_data_length() - TcpHeader::MIN_SIZE - IPv4Header::MIN_SIZE);
        if((ip4->version_ihl >> 4) == 4) {
             ip4->total_length = htons(ntohs(ip4->total_length) + TcpHeader::MIN_SIZE);
        }
    }
    // Check if L3 was IPv6
    else if (pb.get_data_length() > (EthernetHeader::SIZE + IPv6Header::SIZE + TcpHeader::MIN_SIZE -1)) {
         IPv6Header* ip6 = reinterpret_cast<IPv6Header*>(pb.get_data_start_ptr() + pb.get_data_length() - TcpHeader::MIN_SIZE - IPv6Header::SIZE);
         if((ntohl(ip6->version_tc_flowlabel) >> 28) == 6) {
            ip6->payload_length = htons(ntohs(ip6->payload_length) + TcpHeader::MIN_SIZE);
         }
    }


    return TcpHeader::MIN_SIZE;
}

size_t populate_udp_header(PacketBuffer& pb, uint16_t src_port, uint16_t dst_port) {
    if (pb.get_tailroom() < UdpHeader::SIZE) {
        throw std::runtime_error("Not enough tailroom for UDP header");
    }
    UdpHeader* udp = reinterpret_cast<UdpHeader*>(pb.get_data_start_ptr() + pb.get_data_length());
    udp->src_port = htons(src_port);
    udp->dst_port = htons(dst_port);
    udp->length = htons(UdpHeader::SIZE); // Length of UDP header itself, payload would be added
    udp->checksum = 0;
    pb.append_data(UdpHeader::SIZE);

    // Update IPv4 total length or IPv6 payload length
     if(pb.get_data_length() > (EthernetHeader::SIZE + IPv4Header::MIN_SIZE + UdpHeader::SIZE -1) ) {
        IPv4Header* ip4 = reinterpret_cast<IPv4Header*>(pb.get_data_start_ptr() + pb.get_data_length() - UdpHeader::SIZE - IPv4Header::MIN_SIZE);
         if((ip4->version_ihl >> 4) == 4) {
            ip4->total_length = htons(ntohs(ip4->total_length) + UdpHeader::SIZE);
         }
    } else if (pb.get_data_length() > (EthernetHeader::SIZE + IPv6Header::SIZE + UdpHeader::SIZE -1)) {
         IPv6Header* ip6 = reinterpret_cast<IPv6Header*>(pb.get_data_start_ptr() + pb.get_data_length() - UdpHeader::SIZE - IPv6Header::SIZE);
          if((ntohl(ip6->version_tc_flowlabel) >> 28) == 6) {
            ip6->payload_length = htons(ntohs(ip6->payload_length) + UdpHeader::SIZE);
          }
    }
    return UdpHeader::SIZE;
}

} // namespace PacketCreationHelpers

// Test fixture
class PacketClassifierTest : public ::testing::Test {
protected:
    netflow::PacketClassifier classifier;
    netflow::MacAddress src_mac_val;
    netflow::MacAddress dst_mac_val;
    std::array<uint8_t, 16> src_ipv6_val;
    std::array<uint8_t, 16> dst_ipv6_val;

    void SetUp() override {
        uint8_t sm[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        uint8_t dm[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        src_mac_val = netflow::MacAddress(sm);
        dst_mac_val = netflow::MacAddress(dm);

        // 2001:db8::1
        src_ipv6_val = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1};
        // 2001:db8::2
        dst_ipv6_val = {0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,2};
    }
};

// --- Flow Key Extraction Tests ---
TEST_F(PacketClassifierTest, ExtractFlowKey_EthOnly) {
    netflow::PacketBuffer pb(128, 0, 0); // Start with 0 data_len
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x0806); // ARP
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.src_mac, src_mac_val);
    EXPECT_EQ(key.dst_mac, dst_mac_val);
    EXPECT_EQ(key.vlan_id, 0);
    EXPECT_EQ(key.ethertype, 0x0806);
    EXPECT_FALSE(key.is_ipv6);
    EXPECT_EQ(key.src_ip, 0);
    EXPECT_EQ(key.dst_ip, 0);
    EXPECT_EQ(key.protocol, 0);
    EXPECT_EQ(key.src_port, 0);
    EXPECT_EQ(key.dst_port, 0);
}

TEST_F(PacketClassifierTest, ExtractFlowKey_EthIPv4) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x0800); // IPv4
    PacketCreationHelpers::populate_ipv4_header(pb, 0xC0A80101, 0xC0A80102, 0); // 192.168.1.1 -> 192.168.1.2, proto 0 (IP)
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.src_mac, src_mac_val);
    EXPECT_EQ(key.dst_mac, dst_mac_val);
    EXPECT_EQ(key.vlan_id, 0);
    EXPECT_EQ(key.ethertype, 0x0800);
    EXPECT_FALSE(key.is_ipv6);
    EXPECT_EQ(key.src_ip, 0xC0A80101); // IPs in FlowKey are stored in host byte order
    EXPECT_EQ(key.dst_ip, 0xC0A80102);
    EXPECT_EQ(key.protocol, 0); // From IPv4 header
    EXPECT_EQ(key.src_port, 0);
    EXPECT_EQ(key.dst_port, 0);
}

TEST_F(PacketClassifierTest, ExtractFlowKey_EthIPv6) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x86DD); // IPv6
    PacketCreationHelpers::populate_ipv6_header(pb, src_ipv6_val, dst_ipv6_val, 0); // Proto 0 (HOPOPT)
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.src_mac, src_mac_val);
    EXPECT_EQ(key.dst_mac, dst_mac_val);
    EXPECT_EQ(key.vlan_id, 0);
    EXPECT_EQ(key.ethertype, 0x86DD);
    EXPECT_TRUE(key.is_ipv6);
    EXPECT_EQ(key.src_ipv6, src_ipv6_val);
    EXPECT_EQ(key.dst_ipv6, dst_ipv6_val);
    EXPECT_EQ(key.protocol, 0);
    EXPECT_EQ(key.src_port, 0);
    EXPECT_EQ(key.dst_port, 0);
}

TEST_F(PacketClassifierTest, ExtractFlowKey_VlanEthIPv4Tcp) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x8100); // VLAN
    PacketCreationHelpers::populate_vlan_header(pb, 101, 0, 0x0800); // VLAN 101, inner type IPv4
    size_t l3_offset = netflow::EthernetHeader::SIZE + netflow::VlanHeader::SIZE;
    PacketCreationHelpers::populate_ipv4_header(pb, 0xC0A80101, 0xC0A80102, 6, 20 + 20); // Proto 6 (TCP), total_len includes TCP header
    PacketCreationHelpers::populate_tcp_header(pb, 12345, 80);
    netflow::Packet pkt(&pb);

    // Manually update IPv4 total length as helpers might not be perfect yet for chained calls.
    // The packet parser in PacketClassifier should correctly interpret based on headers.
    // Forcing a re-parse or trusting the packet structure.
    // The extract_flow_key should parse this correctly.

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.src_mac, src_mac_val);
    EXPECT_EQ(key.dst_mac, dst_mac_val);
    EXPECT_EQ(key.vlan_id, 101);
    EXPECT_EQ(key.ethertype, 0x0800); // Inner EtherType
    EXPECT_FALSE(key.is_ipv6);
    EXPECT_EQ(key.src_ip, 0xC0A80101); // IPs in FlowKey are stored in host byte order
    EXPECT_EQ(key.dst_ip, 0xC0A80102);
    EXPECT_EQ(key.protocol, 6); // TCP
    EXPECT_EQ(key.src_port, 12345);
    EXPECT_EQ(key.dst_port, 80);
}


TEST_F(PacketClassifierTest, ExtractFlowKey_VlanEthIPv4Udp) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x8100); // VLAN
    PacketCreationHelpers::populate_vlan_header(pb, 102, 0, 0x0800); // VLAN 102, inner type IPv4
    PacketCreationHelpers::populate_ipv4_header(pb, 0x0A000001, 0x0A000002, 17, 20 + 8); // Proto 17 (UDP), total_len includes UDP header
    PacketCreationHelpers::populate_udp_header(pb, 54321, 53);
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.vlan_id, 102);
    EXPECT_EQ(key.ethertype, 0x0800);
    EXPECT_FALSE(key.is_ipv6);
    EXPECT_EQ(key.src_ip, 0x0A000001); // IPs in FlowKey are stored in host byte order
    EXPECT_EQ(key.dst_ip, 0x0A000002);
    EXPECT_EQ(key.protocol, 17); // UDP
    EXPECT_EQ(key.src_port, 54321);
    EXPECT_EQ(key.dst_port, 53);
}

TEST_F(PacketClassifierTest, ExtractFlowKey_VlanEthIPv6Tcp) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x8100); // VLAN
    PacketCreationHelpers::populate_vlan_header(pb, 103, 0, 0x86DD); // VLAN 103, inner type IPv6
    PacketCreationHelpers::populate_ipv6_header(pb, src_ipv6_val, dst_ipv6_val, 6); // Next header TCP
    PacketCreationHelpers::populate_tcp_header(pb, 12346, 443);
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.vlan_id, 103);
    EXPECT_EQ(key.ethertype, 0x86DD);
    EXPECT_TRUE(key.is_ipv6);
    EXPECT_EQ(key.src_ipv6, src_ipv6_val);
    EXPECT_EQ(key.dst_ipv6, dst_ipv6_val);
    EXPECT_EQ(key.protocol, 6); // TCP
    EXPECT_EQ(key.src_port, 12346);
    EXPECT_EQ(key.dst_port, 443);
}

TEST_F(PacketClassifierTest, ExtractFlowKey_VlanEthIPv6Udp) {
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x8100); // VLAN
    PacketCreationHelpers::populate_vlan_header(pb, 104, 0, 0x86DD); // VLAN 104, inner type IPv6
    PacketCreationHelpers::populate_ipv6_header(pb, src_ipv6_val, dst_ipv6_val, 17); // Next header UDP
    PacketCreationHelpers::populate_udp_header(pb, 54322, 5353);
    netflow::Packet pkt(&pb);

    netflow::PacketClassifier::FlowKey key = classifier.extract_flow_key(pkt);

    EXPECT_EQ(key.vlan_id, 104);
    EXPECT_EQ(key.ethertype, 0x86DD);
    EXPECT_TRUE(key.is_ipv6);
    EXPECT_EQ(key.src_ipv6, src_ipv6_val);
    EXPECT_EQ(key.dst_ipv6, dst_ipv6_val);
    EXPECT_EQ(key.protocol, 17); // UDP
    EXPECT_EQ(key.src_port, 54322);
    EXPECT_EQ(key.dst_port, 5353);
}


// --- Flow Hashing Tests ---
TEST_F(PacketClassifierTest, HashFlow_DifferentKeys) {
    netflow::PacketClassifier::FlowKey key1;
    key1.src_mac = src_mac_val;
    key1.dst_mac = dst_mac_val;
    key1.src_ip = htonl(0xC0A80101);
    key1.dst_ip = htonl(0xC0A80102);
    key1.protocol = 6; // TCP
    key1.src_port = 1000;
    key1.dst_port = 80;

    netflow::PacketClassifier::FlowKey key2;
    key2.src_mac = dst_mac_val; // Different MAC
    key2.dst_mac = src_mac_val;
    key2.src_ip = htonl(0xC0A80103);
    key2.dst_ip = htonl(0xC0A80104);
    key2.protocol = 17; // UDP
    key2.src_port = 2000;
    key2.dst_port = 53;

    EXPECT_NE(netflow::PacketClassifier::hash_flow(key1), netflow::PacketClassifier::hash_flow(key2));
}

TEST_F(PacketClassifierTest, HashFlow_IdenticalKeys) {
    netflow::PacketClassifier::FlowKey key1;
    key1.src_mac = src_mac_val;
    key1.dst_mac = dst_mac_val;
    key1.vlan_id = 100;
    key1.ethertype = 0x0800;
    key1.src_ip = htonl(0xC0A80101);
    key1.dst_ip = htonl(0xC0A80102);
    key1.protocol = 6;
    key1.src_port = 1000;
    key1.dst_port = 80;

    netflow::PacketClassifier::FlowKey key2 = key1; // Identical copy

    EXPECT_EQ(netflow::PacketClassifier::hash_flow(key1), netflow::PacketClassifier::hash_flow(key2));
}

TEST_F(PacketClassifierTest, HashFlow_MinorChange) {
    netflow::PacketClassifier::FlowKey key1;
    key1.src_mac = src_mac_val;
    key1.dst_mac = dst_mac_val;
    key1.vlan_id = 100;
    key1.ethertype = 0x0800;
    key1.is_ipv6 = false;
    key1.src_ip = htonl(0xC0A80101);
    key1.dst_ip = htonl(0xC0A80102);
    key1.protocol = 6;
    key1.src_port = 1000;
    key1.dst_port = 80;

    netflow::PacketClassifier::FlowKey key2 = key1;
    key2.dst_port = 81; // Minor change: destination port

    EXPECT_NE(netflow::PacketClassifier::hash_flow(key1), netflow::PacketClassifier::hash_flow(key2));

    netflow::PacketClassifier::FlowKey key3 = key1;
    key3.vlan_id = 101; // Minor change: vlan id
    EXPECT_NE(netflow::PacketClassifier::hash_flow(key1), netflow::PacketClassifier::hash_flow(key3));
}


// --- Classification Rule Tests ---
// Helper to create a "don't care" mask for FlowKey fields that are structs (MacAddress, IPv6 arrays)
// For integral types, 0 means don't care if logic is (extracted & mask) == (template & mask)
// or specific logic in match_key. PacketClassifier::match_key uses direct comparison for MACs
// if mask field for MAC is non-zero. A zero MAC in mask means wildcard.
// For IPs/ports, bitwise AND is used. So 0 in mask means wildcard for those bits.
netflow::PacketClassifier::FlowKey CreateWildcardMask() {
    netflow::PacketClassifier::FlowKey mask;
    // MAC addresses: A zeroed MAC address in the mask means wildcard for that MAC.
    // std::memset(&mask.src_mac, 0, sizeof(netflow::MacAddress)); // Default constructor already does this
    // std::memset(&mask.dst_mac, 0, sizeof(netflow::MacAddress)); // Default constructor already does this

    // For integral types, 0 means "don't care" / wildcard for that field if match is (extracted & mask) == (template & mask)
    // Or if logic is "if (mask.field != 0 && extracted.field != template.field) return false".
    // PacketClassifier::match_key seems to use (extracted.field & mask.field) == (template.field & mask.field) for IPs/ports.
    // And direct equality for MACs if mask MAC is not all zeros.
    // And direct equality for ethertype, protocol, vlan_id if their mask fields are non-zero.

    // To wildcard a field like src_ip, set mask.src_ip = 0.
    // To match a specific src_ip, set mask.src_ip = 0xFFFFFFFF.
    return mask; // All fields zero by default, meaning wildcard for most fields in current classifier logic.
}


TEST_F(PacketClassifierTest, Classify_SimpleSourceMacRule) {
    netflow::PacketClassifier::FlowKey rule_key;
    netflow::PacketClassifier::FlowKey rule_mask;
    uint32_t action_id = 1001;
    int priority = 10;

    rule_key.src_mac = src_mac_val;
    // Mask: only match source MAC. For MACs, any non-zero byte in mask means "match this byte".
    // To match the whole MAC, set all mask bytes to 0xFF.
    // The current match_key logic: "if (!is_mac_zero(mask.src_mac) && !(extracted.src_mac == templ.src_mac)) return false;"
    // This means if mask.src_mac is NOT zero, it will compare. So to make it specific, set it to something non-zero.
    // A common way is to set all bits to 1 for fields we care about.
    std::memset(rule_mask.src_mac.bytes, 0xFF, sizeof(rule_mask.src_mac.bytes));


    classifier.add_rule(netflow::PacketClassifier::ClassificationRule(rule_key, rule_mask, action_id, priority));

    // Create a matching packet
    netflow::PacketBuffer pb_match(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_match, dst_mac_val, src_mac_val, 0x0800);
    netflow::Packet pkt_match(&pb_match);
    EXPECT_EQ(classifier.classify(pkt_match), action_id);

    // Create a non-matching packet (different source MAC)
    netflow::PacketBuffer pb_no_match(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_no_match, dst_mac_val, dst_mac_val, 0x0800); // src_mac is dst_mac_val
    netflow::Packet pkt_no_match(&pb_no_match);
    EXPECT_EQ(classifier.classify(pkt_no_match), 0); // Default action
}

TEST_F(PacketClassifierTest, Classify_DstIpAndDstPortRule) {
    netflow::PacketClassifier::FlowKey rule_key;
    netflow::PacketClassifier::FlowKey rule_mask;
    uint32_t action_id = 1002;
    int priority = 10;

    rule_key.dst_ip = htonl(0x0A0A0A0A); // 10.10.10.10
    rule_key.dst_port = 8080;
    rule_key.protocol = 6; // TCP

    rule_mask.dst_ip = 0xFFFFFFFF; // Match specific dst_ip
    rule_mask.dst_port = 0xFFFF;   // Match specific dst_port
    rule_mask.protocol = 0xFF;     // Match specific protocol
    // Also need to match ethertype for IP
    rule_key.ethertype = 0x0800;
    rule_mask.ethertype = 0xFFFF;


    classifier.add_rule(netflow::PacketClassifier::ClassificationRule(rule_key, rule_mask, action_id, priority));

    // Matching packet
    netflow::PacketBuffer pb_match(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_match, dst_mac_val, src_mac_val, 0x0800);
    PacketCreationHelpers::populate_ipv4_header(pb_match, htonl(0xC0A80101), htonl(0x0A0A0A0A), 6); // TCP
    PacketCreationHelpers::populate_tcp_header(pb_match, 12345, 8080);
    netflow::Packet pkt_match(&pb_match);
    EXPECT_EQ(classifier.classify(pkt_match), action_id);

    // Non-matching packet (different dst_port)
    netflow::PacketBuffer pb_no_match_port(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_no_match_port, dst_mac_val, src_mac_val, 0x0800);
    PacketCreationHelpers::populate_ipv4_header(pb_no_match_port, htonl(0xC0A80101), htonl(0x0A0A0A0A), 6);
    PacketCreationHelpers::populate_tcp_header(pb_no_match_port, 12345, 80); // Different port
    netflow::Packet pkt_no_match_port(&pb_no_match_port);
    EXPECT_EQ(classifier.classify(pkt_no_match_port), 0);

    // Non-matching packet (different dst_ip)
    netflow::PacketBuffer pb_no_match_ip(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_no_match_ip, dst_mac_val, src_mac_val, 0x0800);
    PacketCreationHelpers::populate_ipv4_header(pb_no_match_ip, htonl(0xC0A80101), htonl(0x0A0A0A0B), 6); // Different IP
    PacketCreationHelpers::populate_tcp_header(pb_no_match_ip, 12345, 8080);
    netflow::Packet pkt_no_match_ip(&pb_no_match_ip);
    EXPECT_EQ(classifier.classify(pkt_no_match_ip), 0);
}

TEST_F(PacketClassifierTest, Classify_RuleWithVlan) {
    netflow::PacketClassifier::FlowKey rule_key;
    netflow::PacketClassifier::FlowKey rule_mask;
    uint32_t action_id = 1003;
    int priority = 10;

    rule_key.vlan_id = 200;
    rule_mask.vlan_id = 0xFFFF; // Match specific vlan_id

    classifier.add_rule(netflow::PacketClassifier::ClassificationRule(rule_key, rule_mask, action_id, priority));

    // Matching packet (with VLAN)
    netflow::PacketBuffer pb_match(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_match, dst_mac_val, src_mac_val, 0x8100); // VLAN ethertype
    PacketCreationHelpers::populate_vlan_header(pb_match, 200, 0, 0x0800); // VLAN 200
    PacketCreationHelpers::populate_ipv4_header(pb_match, 0xC0A80101, 0xC0A80102, 6);
    netflow::Packet pkt_match(&pb_match);
    EXPECT_EQ(classifier.classify(pkt_match), action_id);

    // Non-matching packet (different VLAN)
    netflow::PacketBuffer pb_no_match_vlan(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_no_match_vlan, dst_mac_val, src_mac_val, 0x8100);
    PacketCreationHelpers::populate_vlan_header(pb_no_match_vlan, 201, 0, 0x0800); // Different VLAN
    PacketCreationHelpers::populate_ipv4_header(pb_no_match_vlan, 0xC0A80101, 0xC0A80102, 6);
    netflow::Packet pkt_no_match_vlan(&pb_no_match_vlan);
    EXPECT_EQ(classifier.classify(pkt_no_match_vlan), 0);

    // Non-matching packet (no VLAN)
    netflow::PacketBuffer pb_no_vlan(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_no_vlan, dst_mac_val, src_mac_val, 0x0800); // No VLAN
    PacketCreationHelpers::populate_ipv4_header(pb_no_vlan, 0xC0A80101, 0xC0A80102, 6);
    netflow::Packet pkt_no_vlan(&pb_no_vlan);
    EXPECT_EQ(classifier.classify(pkt_no_vlan), 0);
}

TEST_F(PacketClassifierTest, Classify_RulePriority) {
    netflow::PacketClassifier::FlowKey rule_key_general;
    netflow::PacketClassifier::FlowKey rule_mask_general;
    std::memset(rule_mask_general.src_mac.bytes, 0xFF, sizeof(rule_mask_general.src_mac.bytes));
    rule_key_general.src_mac = src_mac_val;
    uint32_t action_general = 2001;
    classifier.add_rule(netflow::PacketClassifier::ClassificationRule(rule_key_general, rule_mask_general, action_general, 10));

    netflow::PacketClassifier::FlowKey rule_key_specific = rule_key_general; // Copy general key
    netflow::PacketClassifier::FlowKey rule_mask_specific = rule_mask_general; // Copy general mask
    rule_key_specific.dst_port = 80;
    rule_mask_specific.dst_port = 0xFFFF; // Add specific port match
    rule_key_specific.protocol = 6;       // TCP
    rule_mask_specific.protocol = 0xFF;
    rule_key_specific.ethertype = 0x0800; // IPv4
    rule_mask_specific.ethertype = 0xFFFF;

    uint32_t action_specific = 2002;
    // Add specific rule with higher priority
    classifier.add_rule(netflow::PacketClassifier::ClassificationRule(rule_key_specific, rule_mask_specific, action_specific, 20));


    // Packet that matches both rules
    netflow::PacketBuffer pb(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb, dst_mac_val, src_mac_val, 0x0800); // src_mac_val matches general
    PacketCreationHelpers::populate_ipv4_header(pb, 0xC0A80101, 0xC0A80102, 6);    // TCP
    PacketCreationHelpers::populate_tcp_header(pb, 12345, 80);                     // Dst port 80 matches specific
    netflow::Packet pkt(&pb);

    EXPECT_EQ(classifier.classify(pkt), action_specific); // Expect higher priority rule to match

    // Packet that matches only general rule
    netflow::PacketBuffer pb_general(128, 0, 0);
    PacketCreationHelpers::populate_eth_header(pb_general, dst_mac_val, src_mac_val, 0x0800); // src_mac_val matches general
    PacketCreationHelpers::populate_ipv4_header(pb_general, 0xC0A80101, 0xC0A80102, 17);   // UDP (not TCP)
    PacketCreationHelpers::populate_udp_header(pb_general, 12345, 53);                    // Different port
    netflow::Packet pkt_general(&pb_general);

    EXPECT_EQ(classifier.classify(pkt_general), action_general);
}


// For now, a placeholder main for GTest
// int main(int argc, char **argv) {
//     ::testing::InitGoogleTest(&argc, argv);
//     return RUN_ALL_TESTS();
// }
