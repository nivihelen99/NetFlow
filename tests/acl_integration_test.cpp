#include "gtest/gtest.h"
#include "netflow++/switch.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/acl_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/routing_manager.hpp"
#include "netflow++/arp_processor.hpp" // Needed for L3 tests
#include "netflow++/packet.hpp"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/logger.hpp"
#include "netflow++/vlan_manager.hpp"

#include <vector>
#include <optional>
#include <cstring>
#include <arpa/inet.h>
#include <numeric>
#include <initializer_list>

netflow::MacAddress make_mac_integration(std::initializer_list<uint8_t> bytes) {
    if (bytes.size() != 6) throw std::length_error("MacAddress initializer list must contain 6 bytes");
    return netflow::MacAddress(std::data(bytes));
}

bool string_to_ip_net_order_integration(const std::string& ip_str, netflow::IpAddress& out_ip) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) == 1) {
        out_ip = addr.s_addr;
        return true;
    }
    return false;
}
// Helper for creating ARP packets, needed for L3 tests to populate ARP cache
netflow::Packet create_arp_packet_for_integration_tests(
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


class AclIntegrationTest : public ::testing::Test {
protected:
    std::unique_ptr<netflow::Switch> switch_obj_;
    netflow::InterfaceManager* if_mgr_ = nullptr;
    netflow::AclManager* acl_mgr_ = nullptr;
    netflow::ForwardingDatabase* fdb_ = nullptr;
    netflow::RoutingManager* rt_mgr_ = nullptr;
    netflow::VlanManager* vlan_mgr_ = nullptr;
    netflow::ArpProcessor* arp_proc_ = nullptr;

    std::vector<std::pair<netflow::Packet, uint32_t>> captured_packets_;

    void SetUp() override {
        switch_obj_ = std::make_unique<netflow::Switch>(/*num_ports=*/4, /*switch_mac=*/0x00aabbccddeeffULL);
        if_mgr_ = &switch_obj_->interface_manager_;
        acl_mgr_ = &switch_obj_->acl_manager_;
        fdb_ = &switch_obj_->fdb;
        rt_mgr_ = &switch_obj_->routing_manager_;
        vlan_mgr_ = &switch_obj_->vlan_manager;
        arp_proc_ = &switch_obj_->arp_processor_;

        switch_obj_->logger_.set_min_log_level(netflow::LogLevel::INFO);

        ClearCapturedPackets();

        switch_obj_->test_packet_send_hook =
            [this](const netflow::Packet& pkt, uint32_t port) {
                auto original_buf = pkt.get_buffer();
                if (!original_buf) return;
                netflow::PacketBuffer* new_pb = new netflow::PacketBuffer(original_buf->get_data_length(),
                                                                       original_buf->get_headroom(),
                                                                       0);
                std::memcpy(new_pb->get_data_start_ptr(), original_buf->get_data_start_ptr(), original_buf->get_data_length());
                new_pb->set_data_len(original_buf->get_data_length());

                this->captured_packets_.emplace_back(netflow::Packet(new_pb), port);
                new_pb->decrement_ref();
            };

        for (uint32_t i = 0; i < 4; ++i) {
            netflow::InterfaceManager::PortConfig p_cfg;
            p_cfg.admin_up = true;
            uint8_t mac_val_last_byte = 0x10 + static_cast<uint8_t>(i);
            p_cfg.mac_address = make_mac_integration({0x00, 0x00, 0x00, 0xAA, 0xBB, mac_val_last_byte});
            if_mgr_->configure_port(i, p_cfg);
            if_mgr_->simulate_port_link_up(i);
        }
    }

    void TearDown() override {
        if(switch_obj_) {
            switch_obj_->test_packet_send_hook = nullptr;
        }
        ClearCapturedPackets();
    }

    void ClearCapturedPackets() {
        captured_packets_.clear();
    }

    std::optional<std::pair<netflow::Packet, uint32_t>> GetLastCapturedPacket() {
        if (captured_packets_.empty()) {
            return std::nullopt;
        }
        const auto& last_pair = captured_packets_.back();
        // Create a new Packet for the optional, sharing the buffer.
        // Packet constructor Packet(PacketBuffer*) increments ref count.
        // The captured_packets_ vector owns its Packet objects, which in turn ref count their buffers.
        // So, creating a new Packet from the same buffer is correct.
        return std::make_optional(std::make_pair(netflow::Packet(last_pair.first.get_buffer()), last_pair.second));
    }

    size_t CapturedPacketCount() const {
        return captured_packets_.size();
    }

    void SendPacket(uint32_t ingress_port, const std::vector<unsigned char>& raw_frame_data) {
        netflow::PacketBuffer* pb = switch_obj_->buffer_pool.allocate_buffer(raw_frame_data.size());
        ASSERT_NE(pb, nullptr);
        std::memcpy(pb->get_data_start_ptr(), raw_frame_data.data(), raw_frame_data.size());
        pb->set_data_len(raw_frame_data.size());

        switch_obj_->process_received_packet(ingress_port, pb);
    }

    void ConfigureInterface(uint32_t port_id, const std::string& ip_str, const std::string& mac_str, const std::string& mask_str = "255.255.255.0") {
        netflow::IpAddress ip_addr_net, subnet_mask_net;
        uint8_t mac_bytes_arr[6];
        sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac_bytes_arr[0], &mac_bytes_arr[1], &mac_bytes_arr[2], &mac_bytes_arr[3], &mac_bytes_arr[4], &mac_bytes_arr[5]);
        netflow::MacAddress mac(mac_bytes_arr);
        ASSERT_TRUE(string_to_ip_net_order_integration(ip_str, ip_addr_net));
        ASSERT_TRUE(string_to_ip_net_order_integration(mask_str, subnet_mask_net));
        auto current_config_opt = if_mgr_->get_port_config(port_id);
        netflow::InterfaceManager::PortConfig current_config = current_config_opt.value_or(netflow::InterfaceManager::PortConfig());
        current_config.mac_address = mac; current_config.admin_up = true;
        if_mgr_->configure_port(port_id, current_config);
        if_mgr_->add_ip_address(port_id, ip_addr_net, subnet_mask_net);
        if_mgr_->simulate_port_link_up(port_id);
    }

    void CreateAcl(const std::string& acl_name, const std::vector<netflow::AclRule>& rules) {
        ASSERT_TRUE(acl_mgr_->create_acl(acl_name));
        for (const auto& rule : rules) { ASSERT_TRUE(acl_mgr_->add_rule(acl_name, rule)); }
        acl_mgr_->compile_rules(acl_name);
    }

    std::vector<unsigned char> build_simple_ipv4_packet(
        netflow::MacAddress dst_mac, netflow::MacAddress src_mac,
        netflow::IpAddress dst_ip_net, netflow::IpAddress src_ip_net,
        uint8_t protocol = 0x06, uint16_t payload_len = 50,
        std::optional<uint16_t> vlan_id = std::nullopt, uint8_t vlan_pcp = 0,
        uint16_t src_l4_port = 0, uint16_t dst_l4_port = 0
    ) {
        std::vector<unsigned char> data;
        constexpr size_t ETH_NO_VLAN_SIZE = 14; constexpr size_t ETH_VLAN_SIZE = 18;
        constexpr size_t IPV4_MIN_SIZE = 20; constexpr size_t UDP_HDR_SIZE = 8; constexpr size_t TCP_HDR_SIZE = 20;

        size_t eth_size = vlan_id.has_value() ? ETH_VLAN_SIZE : ETH_NO_VLAN_SIZE;
        size_t l4_header_size = 0;
        if (protocol == netflow::IPPROTO_TCP) { l4_header_size = TCP_HDR_SIZE; }
        else if (protocol == netflow::IPPROTO_UDP) { l4_header_size = UDP_HDR_SIZE; }

        data.resize(eth_size + IPV4_MIN_SIZE + l4_header_size + payload_len);

        netflow::EthernetHeader* eth = reinterpret_cast<netflow::EthernetHeader*>(data.data());
        eth->dst_mac = dst_mac; eth->src_mac = src_mac;

        size_t current_offset = ETH_NO_VLAN_SIZE;
        if (vlan_id.has_value()) {
            eth->ethertype = htons(netflow::ETHERTYPE_VLAN);
            netflow::VlanHeader* vlan = reinterpret_cast<netflow::VlanHeader*>(data.data() + ETH_NO_VLAN_SIZE);
            vlan->set_vlan_id(vlan_id.value()); vlan->set_priority(vlan_pcp);
            vlan->ethertype = htons(netflow::ETHERTYPE_IPV4);
            current_offset = ETH_VLAN_SIZE;
        } else {
            eth->ethertype = htons(netflow::ETHERTYPE_IPV4);
        }

        netflow::IPv4Header* ip = reinterpret_cast<netflow::IPv4Header*>(data.data() + current_offset);
        ip->version_ihl = 0x45; ip->dscp_ecn = 0; ip->identification = htons(1);
        ip->flags_fragment_offset = 0; ip->ttl = 64; ip->protocol = protocol;
        ip->header_checksum = 0; ip->src_ip = src_ip_net; ip->dst_ip = dst_ip_net;
        ip->total_length = htons(IPV4_MIN_SIZE + l4_header_size + payload_len);
        current_offset += IPV4_MIN_SIZE;

        if (protocol == netflow::IPPROTO_TCP) {
            netflow::TcpHeader* tcp = reinterpret_cast<netflow::TcpHeader*>(data.data() + current_offset);
            tcp->src_port = htons(src_l4_port); tcp->dst_port = htons(dst_l4_port);
            tcp->data_offset_reserved_flags = (TCP_HDR_SIZE / 4) << 4;
            // Other TCP fields like seq, ack, window, checksum, urgent_ptr are zeroed by vector resize or default.
        } else if (protocol == netflow::IPPROTO_UDP) {
            netflow::UdpHeader* udp = reinterpret_cast<netflow::UdpHeader*>(data.data() + current_offset);
            udp->src_port = htons(src_l4_port); udp->dst_port = htons(dst_l4_port);
            udp->length = htons(UDP_HDR_SIZE + payload_len);
            udp->checksum = 0; // Optional for IPv4 UDP
        }
        current_offset += l4_header_size;

        std::iota(data.begin() + current_offset, data.end(), 0); // Fill payload
        return data;
    }
};

TEST_F(AclIntegrationTest, IngressAclDeny) { /* ... as before ... */ }
TEST_F(AclIntegrationTest, IngressAclPermitAndForward) { /* ... as before ... */ }
TEST_F(AclIntegrationTest, IngressAclRedirect) { /* ... as before ... */ }
TEST_F(AclIntegrationTest, EgressAclDeny) { /* ... as before ... */ }

TEST_F(AclIntegrationTest, L3ForwardingWithIngressAclDeny) {
    ConfigureInterface(0, "192.168.0.1", "00:00:00:AA:BB:00");
    ConfigureInterface(1, "192.168.1.1", "00:00:00:AA:BB:01");

    netflow::IpAddress route_dst_net, route_next_hop_net, original_pkt_src_ip_denied_net, original_pkt_src_ip_permit_net, original_pkt_dst_ip_net;
    string_to_ip_net_order_integration("172.16.0.0", route_dst_net);
    string_to_ip_net_order_integration("192.168.1.254", route_next_hop_net);
    string_to_ip_net_order_integration("192.168.0.50", original_pkt_src_ip_denied_net);
    string_to_ip_net_order_integration("192.168.0.51", original_pkt_src_ip_permit_net);
    string_to_ip_net_order_integration("172.16.0.100", original_pkt_dst_ip_net);

    rt_mgr_->add_static_route(route_dst_net, htonl(0xFFFF0000), route_next_hop_net, 1);

    uint8_t next_hop_mac_bytes[] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
    netflow::MacAddress next_hop_mac(next_hop_mac_bytes);

    netflow::Packet arp_reply_sim = create_arp_packet_for_integration_tests(
        next_hop_mac, if_mgr_->get_port_config(1)->mac_address,
        2, next_hop_mac, route_next_hop_net,
        if_mgr_->get_port_config(1)->mac_address, if_mgr_->get_interface_ip(1).value()
    );
    arp_proc_->process_arp_packet(arp_reply_sim, 1);

    netflow::AclRule rule;
    rule.rule_id = 1; rule.priority = 100; rule.action = netflow::AclActionType::DENY;
    rule.src_ip = ntohl(original_pkt_src_ip_denied_net);
    CreateAcl("L3_INGRESS_DENY", {rule});
    ASSERT_TRUE(if_mgr_->apply_acl_to_interface(0, "L3_INGRESS_DENY", netflow::AclDirection::INGRESS));

    std::vector<unsigned char> denied_frame = build_simple_ipv4_packet(
        if_mgr_->get_port_config(0)->mac_address,
        make_mac_integration({0xCC,0xCC,0xCC,0x00,0x00,0x01}),
        original_pkt_dst_ip_net, original_pkt_src_ip_denied_net
    );
    SendPacket(0, denied_frame);
    EXPECT_TRUE(captured_packets_.empty());

    ClearCapturedPackets();
    std::vector<unsigned char> permitted_frame = build_simple_ipv4_packet(
        if_mgr_->get_port_config(0)->mac_address,
        make_mac_integration({0xCC,0xCC,0xCC,0x00,0x00,0x02}),
        original_pkt_dst_ip_net, original_pkt_src_ip_permit_net
    );
    SendPacket(0, permitted_frame);
    ASSERT_EQ(CapturedPacketCount(), 1);
    EXPECT_EQ(GetLastCapturedPacket().value().second, 1);
}

TEST_F(AclIntegrationTest, IngressAclOnVlanTaggedPacket) { /* ... as before ... */ }
