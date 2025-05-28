#include "gtest/gtest.h"
#include "NetFlow/include/netflow/switch/VlanManager.h" // Adjusted path
#include "NetFlow/include/netflow/packet/Packet.h"
#include "NetFlow/include/netflow/core/PacketBuffer.h"
#include "NetFlow/include/netflow/packet/ethernet.h"
#include "NetFlow/include/netflow/packet/ip.h" // For IP ethertype, not strictly needed for VLAN tests but good for packet construction

#include <vector>
#include <array>
#include <cstring> // For memcpy

// Type alias for convenience
using MACAddress = std::array<uint8_t, 6>;

// Helper function to create a simple Ethernet frame (untagged or tagged)
// For VLAN tests, we often only care about the Ethernet header and VLAN tag.
Packet create_test_packet(
    const MACAddress& dst_mac, 
    const MACAddress& src_mac,
    uint16_t ethertype_or_tpid_net_order, // e.g., htons(ETHERTYPE_IP) or htons(VLAN_TPID)
    bool is_tagged = false, 
    uint16_t vlan_tci_host_order = 0, // e.g., (prio << 13) | vid
    uint16_t inner_ethertype_net_order = 0 // e.g., htons(ETHERTYPE_IP), if tagged
) {
    std::vector<unsigned char> data;
    data.resize(sizeof(netflow::packet::EthernetHeader) + (is_tagged ? sizeof(netflow::packet::VlanTag) : 0) + 20); // +20 for some dummy payload
    std::fill(data.begin() + sizeof(netflow::packet::EthernetHeader) + (is_tagged ? sizeof(netflow::packet::VlanTag) : 0), data.end(), 0xAA);


    netflow::packet::EthernetHeader* eth_h = reinterpret_cast<netflow::packet::EthernetHeader*>(data.data());
    eth_h->dest_mac = dst_mac;
    eth_h->src_mac = src_mac;
    eth_h->type = ethertype_or_tpid_net_order;

    if (is_tagged) {
        netflow::packet::VlanTag* vlan_h = reinterpret_cast<netflow::packet::VlanTag*>(data.data() + sizeof(netflow::packet::EthernetHeader));
        vlan_h->tci = htons(vlan_tci_host_order);
        vlan_h->ethertype = inner_ethertype_net_order;
    }
    
    return Packet(data.data(), data.size());
}

// Sample MACs
const MACAddress sample_dst_mac = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
const MACAddress sample_src_mac = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};


// --- Test Suites ---

// 1. VlanManagerConstruction Test Suite
TEST(VlanManagerConstruction, DefaultConstructor) {
    VlanManager vm;
    // Check if a default port config exists for port 0 or 1 (if any defaults are set)
    // For now, just ensure it constructs.
    // Example: Check a known default if VlanManager initializes one.
    // const VlanManager::PortConfig* p_config = vm.get_port_config(1); // Assuming port 1 might have a default
    // if (p_config) {
    //     EXPECT_EQ(p_config->type, VlanManager::PortType::ACCESS);
    //     EXPECT_EQ(p_config->access_vlan_id, DEFAULT_VLAN_ID);
    // }
    SUCCEED(); // If it constructs without crashing, it's a basic pass.
}

// Test Fixture for VlanManager tests
class VlanManagerTest : public ::testing::Test {
protected:
    VlanManager vm;
    uint16_t port_id1 = 1;
    uint16_t port_id2 = 2;
    uint16_t vlan10 = 10;
    uint16_t vlan20 = 20;
    uint16_t vlan30 = 30;
    uint16_t invalid_vlan_low = 0;
    uint16_t invalid_vlan_high = MAX_VLAN_ID + 1; // 4095
};

// 2. PortConfiguration Test Suite
TEST_F(VlanManagerTest, ConfigureAccessPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::ACCESS;
    config.access_vlan_id = vlan10;

    EXPECT_TRUE(vm.configure_port(port_id1, config));
    const VlanManager::PortConfig* p_config = vm.get_port_config(port_id1);
    ASSERT_NE(p_config, nullptr);
    EXPECT_EQ(p_config->type, VlanManager::PortType::ACCESS);
    EXPECT_EQ(p_config->access_vlan_id, vlan10);

    // Test invalid VLAN ID
    config.access_vlan_id = invalid_vlan_low;
    EXPECT_FALSE(vm.configure_port(port_id1, config)); // Should fail for VLAN 0
    config.access_vlan_id = invalid_vlan_high;
    EXPECT_FALSE(vm.configure_port(port_id1, config)); // Should fail for VLAN > MAX_VLAN_ID
}

TEST_F(VlanManagerTest, ConfigureTrunkPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.native_vlan_id = vlan10; // Native VLAN for this trunk
    config.allowed_vlans = {vlan10, vlan20};

    EXPECT_TRUE(vm.configure_port(port_id1, config));
    const VlanManager::PortConfig* p_config = vm.get_port_config(port_id1);
    ASSERT_NE(p_config, nullptr);
    EXPECT_EQ(p_config->type, VlanManager::PortType::TRUNK);
    EXPECT_EQ(p_config->native_vlan_id, vlan10);
    ASSERT_EQ(p_config->allowed_vlans.size(), 2);
    EXPECT_TRUE(p_config->allowed_vlans.count(vlan10));
    EXPECT_TRUE(p_config->allowed_vlans.count(vlan20));

    // Test with empty allowed_vlans (all allowed)
    config.allowed_vlans.clear();
    EXPECT_TRUE(vm.configure_port(port_id2, config));
    const VlanManager::PortConfig* p_config2 = vm.get_port_config(port_id2);
    ASSERT_NE(p_config2, nullptr);
    EXPECT_TRUE(p_config2->allowed_vlans.empty());
}

TEST_F(VlanManagerTest, ConfigureNativeVlanPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan20;
    config.allowed_vlans = {vlan20, vlan30}; // Native VLAN should typically be in allowed_vlans

    EXPECT_TRUE(vm.configure_port(port_id1, config));
    const VlanManager::PortConfig* p_config = vm.get_port_config(port_id1);
    ASSERT_NE(p_config, nullptr);
    EXPECT_EQ(p_config->type, VlanManager::PortType::NATIVE_VLAN);
    EXPECT_EQ(p_config->native_vlan_id, vlan20);
    ASSERT_EQ(p_config->allowed_vlans.size(), 2);
    EXPECT_TRUE(p_config->allowed_vlans.count(vlan20));
    EXPECT_TRUE(p_config->allowed_vlans.count(vlan30));
}

TEST_F(VlanManagerTest, ConfigurePortWithOverload) {
    // Test ACCESS type
    EXPECT_TRUE(vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10));
    const VlanManager::PortConfig* p_config_access = vm.get_port_config(port_id1);
    ASSERT_NE(p_config_access, nullptr);
    EXPECT_EQ(p_config_access->type, VlanManager::PortType::ACCESS);
    EXPECT_EQ(p_config_access->access_vlan_id, vlan10);

    // Test TRUNK type with specific native vlan
    EXPECT_TRUE(vm.configure_port(port_id2, VlanManager::PortType::TRUNK, vlan20));
    const VlanManager::PortConfig* p_config_trunk = vm.get_port_config(port_id2);
    ASSERT_NE(p_config_trunk, nullptr);
    EXPECT_EQ(p_config_trunk->type, VlanManager::PortType::TRUNK);
    EXPECT_EQ(p_config_trunk->native_vlan_id, vlan20); // Overload sets it as native
    EXPECT_TRUE(p_config_trunk->allowed_vlans.count(vlan20)); // And allows it

    // Test TRUNK type with vlan_id 0 (default native vlan, all allowed)
    EXPECT_TRUE(vm.configure_port(port_id1, VlanManager::PortType::TRUNK, 0));
    const VlanManager::PortConfig* p_config_trunk_default = vm.get_port_config(port_id1);
    ASSERT_NE(p_config_trunk_default, nullptr);
    EXPECT_EQ(p_config_trunk_default->type, VlanManager::PortType::TRUNK);
    EXPECT_EQ(p_config_trunk_default->native_vlan_id, DEFAULT_VLAN_ID); // Should be default
    EXPECT_TRUE(p_config_trunk_default->allowed_vlans.empty()); // All allowed
}

TEST_F(VlanManagerTest, GetNonExistentPortConfig) {
    EXPECT_EQ(vm.get_port_config(999), nullptr); // Assuming port 999 is not configured
}

// 3. VlanMembership Test Suite
TEST_F(VlanManagerTest, AddRemoveVlanMemberOnTrunk) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.native_vlan_id = DEFAULT_VLAN_ID; // e.g., 1
    vm.configure_port(port_id1, config);

    EXPECT_FALSE(vm.is_vlan_member(port_id1, vlan10)); // Initially not a member if allowed_vlans is empty but interpreted as all
                                                     // Or, if allowed_vlans empty means *only* native, this would be true.
                                                     // Current `is_vlan_member` uses `should_forward`.
                                                     // If allowed_vlans is empty for TRUNK, it means all VLANs are allowed.
    EXPECT_TRUE(vm.should_forward(port_id1, vlan10)); // So, should_forward should be true initially

    EXPECT_TRUE(vm.add_vlan_member(port_id1, vlan10));
    EXPECT_TRUE(vm.is_vlan_member(port_id1, vlan10));
    EXPECT_TRUE(vm.should_forward(port_id1, vlan10));
    const VlanManager::PortConfig* p_config = vm.get_port_config(port_id1);
    ASSERT_NE(p_config, nullptr);
    EXPECT_TRUE(p_config->allowed_vlans.count(vlan10));

    EXPECT_TRUE(vm.remove_vlan_member(port_id1, vlan10));
    EXPECT_FALSE(vm.is_vlan_member(port_id1, vlan10));
    EXPECT_FALSE(vm.should_forward(port_id1, vlan10)); // Now it's explicitly removed
    ASSERT_NE(p_config, nullptr); // p_config pointer still valid
    EXPECT_FALSE(p_config->allowed_vlans.count(vlan10));

    // If allowed_vlans becomes non-empty, then empty means "none of these specific ones"
    // If it was initially empty (all allowed), after add/remove, it's no longer empty.
    // So should_forward for another VLAN (e.g. vlan20) should now be false.
    EXPECT_FALSE(vm.should_forward(port_id1, vlan20));
}


TEST_F(VlanManagerTest, AddRemoveVlanMemberOnAccess) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::ACCESS;
    config.access_vlan_id = vlan10;
    vm.configure_port(port_id1, config);

    EXPECT_FALSE(vm.add_vlan_member(port_id1, vlan20)); // Cannot add other VLANs to access port
    EXPECT_TRUE(vm.is_vlan_member(port_id1, vlan10));
    EXPECT_FALSE(vm.is_vlan_member(port_id1, vlan20));
    EXPECT_TRUE(vm.should_forward(port_id1, vlan10));
    EXPECT_FALSE(vm.should_forward(port_id1, vlan20));

    // Attempting to remove the access_vlan_id via remove_vlan_member should also fail/have no effect
    EXPECT_FALSE(vm.remove_vlan_member(port_id1, vlan10));
    EXPECT_TRUE(vm.is_vlan_member(port_id1, vlan10));
}

// 4. IngressProcessing Test Suite
TEST_F(VlanManagerTest, UntaggedToAccess) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, htons(netflow::packet::ETHERTYPE_IP));
    
    ASSERT_FALSE(pkt.has_vlan());
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    
    EXPECT_EQ(effective_vlan, vlan10);
    EXPECT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pkt.vlan_id(), vlan10);
}

TEST_F(VlanManagerTest, TaggedMatchingAccess) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    
    ASSERT_TRUE(pkt.has_vlan());
    ASSERT_EQ(pkt.vlan_id(), vlan10);
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);

    EXPECT_EQ(effective_vlan, vlan10);
    EXPECT_TRUE(pkt.has_vlan()); // Should still have its tag
    EXPECT_EQ(pkt.vlan_id(), vlan10);
}

TEST_F(VlanManagerTest, TaggedMismatchAccess) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan20, htons(netflow::packet::ETHERTYPE_IP));
    
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    EXPECT_EQ(effective_vlan, VlanManager::VLAN_DROP);
}

TEST_F(VlanManagerTest, UntaggedToTrunkNoNative) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    // No native_vlan_id explicitly set for PortType::TRUNK, it defaults to 1 but isn't used for ingress untagged
    // unless type is NATIVE_VLAN.
    // The VlanManager::process_ingress for TRUNK drops untagged packets.
    vm.configure_port(port_id1, config);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, htons(netflow::packet::ETHERTYPE_IP));

    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    EXPECT_EQ(effective_vlan, VlanManager::VLAN_DROP);
}

TEST_F(VlanManagerTest, TaggedAllowedToTrunk) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.allowed_vlans = {vlan10, vlan20};
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    EXPECT_EQ(effective_vlan, vlan10);
}

TEST_F(VlanManagerTest, TaggedNotAllowedToTrunk) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.allowed_vlans = {vlan10, vlan20}; // vlan30 is not allowed
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan30, htons(netflow::packet::ETHERTYPE_IP));
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    EXPECT_EQ(effective_vlan, VlanManager::VLAN_DROP);
}


TEST_F(VlanManagerTest, UntaggedToNativeVlanPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, htons(netflow::packet::ETHERTYPE_IP));
    ASSERT_FALSE(pkt.has_vlan());
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);

    EXPECT_EQ(effective_vlan, vlan10);
    EXPECT_TRUE(pkt.has_vlan());
    EXPECT_EQ(pkt.vlan_id(), vlan10);
}

TEST_F(VlanManagerTest, TaggedNativeToNativeVlanPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    config.allowed_vlans = {vlan10, vlan20}; // Native VLAN must be in allowed_vlans if it's a non-empty set.
                                            // If allowed_vlans is empty, all are allowed.
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    // Current VlanManager process_ingress for NATIVE_VLAN:
    // If tagged with native_vlan_id, it's treated like any other allowed tagged packet.
    // Some switch implementations might drop this.
    EXPECT_EQ(effective_vlan, vlan10); 
}

TEST_F(VlanManagerTest, TaggedAllowedToNativeVlanPort) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    config.allowed_vlans = {vlan10, vlan20}; // vlan20 is allowed, not native
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan20, htons(netflow::packet::ETHERTYPE_IP));
    uint16_t effective_vlan = vm.process_ingress(pkt, port_id1);
    EXPECT_EQ(effective_vlan, vlan20);
}


// 5. EgressProcessing Test Suite
TEST_F(VlanManagerTest, PacketMatchingAccessEgress) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    
    ASSERT_TRUE(pkt.has_vlan());
    EXPECT_TRUE(vm.process_egress(pkt, port_id1, vlan10));
    EXPECT_FALSE(pkt.has_vlan()); // Tag should be popped
}

TEST_F(VlanManagerTest, PacketMismatchAccessEgress) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan20, htons(netflow::packet::ETHERTYPE_IP));
    
    EXPECT_FALSE(vm.process_egress(pkt, port_id1, vlan20)); // Packet's VLAN is vlan20, port access is vlan10
}

TEST_F(VlanManagerTest, AllowedTaggedToTrunkEgress) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.allowed_vlans = {vlan10, vlan20};
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    
    EXPECT_TRUE(vm.process_egress(pkt, port_id1, vlan10));
    EXPECT_TRUE(pkt.has_vlan()); // Tag should remain
}

TEST_F(VlanManagerTest, NotAllowedTaggedToTrunkEgress) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.allowed_vlans = {vlan10, vlan20}; // vlan30 not allowed
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan30, htons(netflow::packet::ETHERTYPE_IP));
    
    EXPECT_FALSE(vm.process_egress(pkt, port_id1, vlan30));
}

TEST_F(VlanManagerTest, NativeVlanToNativeEgress) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    config.allowed_vlans = {vlan10, vlan20}; // native vlan is also allowed
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan10, htons(netflow::packet::ETHERTYPE_IP));
    
    ASSERT_TRUE(pkt.has_vlan());
    EXPECT_TRUE(vm.process_egress(pkt, port_id1, vlan10));
    EXPECT_FALSE(pkt.has_vlan()); // Tag should be popped as it's native
}

TEST_F(VlanManagerTest, AllowedTaggedToNativeEgress) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    config.allowed_vlans = {vlan10, vlan20}; // vlan20 is allowed, not native
    vm.configure_port(port_id1, config);

    Packet pkt = create_test_packet(sample_dst_mac, sample_src_mac, 
                                    htons(netflow::packet::VLAN_TPID), true, vlan20, htons(netflow::packet::ETHERTYPE_IP));
    
    EXPECT_TRUE(vm.process_egress(pkt, port_id1, vlan20));
    EXPECT_TRUE(pkt.has_vlan()); // Tag should remain as it's not native
}


// 6. ShouldForwardLogic Test Suite
TEST_F(VlanManagerTest, ShouldForwardAccess) {
    vm.configure_port(port_id1, VlanManager::PortType::ACCESS, vlan10);
    EXPECT_TRUE(vm.should_forward(port_id1, vlan10));
    EXPECT_FALSE(vm.should_forward(port_id1, vlan20));
}

TEST_F(VlanManagerTest, ShouldForwardTrunk) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::TRUNK;
    config.allowed_vlans = {vlan10, vlan20};
    vm.configure_port(port_id1, config);

    EXPECT_TRUE(vm.should_forward(port_id1, vlan10));
    EXPECT_TRUE(vm.should_forward(port_id1, vlan20));
    EXPECT_FALSE(vm.should_forward(port_id1, vlan30));

    // Trunk with all VLANs allowed (empty allowed_vlans set)
    config.allowed_vlans.clear();
    vm.configure_port(port_id2, config);
    EXPECT_TRUE(vm.should_forward(port_id2, vlan10));
    EXPECT_TRUE(vm.should_forward(port_id2, vlan30)); // Any valid VLAN
}

TEST_F(VlanManagerTest, ShouldForwardNativeVlan) {
    VlanManager::PortConfig config;
    config.type = VlanManager::PortType::NATIVE_VLAN;
    config.native_vlan_id = vlan10;
    config.allowed_vlans = {vlan10, vlan20};
    vm.configure_port(port_id1, config);

    EXPECT_TRUE(vm.should_forward(port_id1, vlan10)); // Native VLAN
    EXPECT_TRUE(vm.should_forward(port_id1, vlan20)); // Allowed tagged VLAN
    EXPECT_FALSE(vm.should_forward(port_id1, vlan30)); // Not allowed
}

// CreateVlan stub test (as implemented, it's just a validator)
TEST_F(VlanManagerTest, CreateVlanBasic) {
    EXPECT_TRUE(vm.create_vlan(100, "TestVLAN100"));
    EXPECT_FALSE(vm.create_vlan(0)); // Invalid
    EXPECT_FALSE(vm.create_vlan(4095)); // Invalid (MAX_VLAN_ID is 4094)
    EXPECT_TRUE(vm.create_vlan(MAX_VLAN_ID));
}

// --- End of test_vlan_manager.cpp ---
