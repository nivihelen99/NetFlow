#include "gtest/gtest.h"
#include "NetFlow/include/netflow/switch/StpManager.h" // Adjusted path as per previous examples
#include <chrono>
#include <thread>   // For std::this_thread::sleep_for
#include <vector>
#include <array>
#include <cstring>  // For memcpy
#include <algorithm> // For std::fill
#include <arpa/inet.h> // For htons, htonl, htobe64, be64toh (if not available, implement simple versions)

// Assume MACAddress is std::array<uint8_t, 6>
using MACAddress = std::array<uint8_t, 6>;

// Helper to create a Bridge ID from priority and MAC
// This mirrors the logic that might be in StpManager or a utility.
uint64_t test_make_bridge_id(uint16_t priority, const MACAddress& mac) {
    uint64_t id = static_cast<uint64_t>(priority) << 48;
    for (int i = 0; i < 6; ++i) {
        id |= static_cast<uint64_t>(mac[i]) << (8 * (5 - i));
    }
    return id;
}

// Helper to serialize SimpleBpdu to std::vector<unsigned char> for process_bpdu
std::vector<unsigned char> serialize_bpdu_for_test(const StpManager::SimpleBpdu& bpdu_fields) {
    std::vector<unsigned char> buffer(35); // Standard configuration BPDU length
    std::fill(buffer.begin(), buffer.end(), 0);

    // Protocol ID (2 bytes): 0x0000 (STP)
    // Version ID (1 byte): 0x00 (STP)
    // BPDU Type (1 byte): 0x00 (Configuration BPDU)
    // These are implicitly 0 by fill and what StpManager expects for Config BPDU

    buffer[3] = 0x00; // BPDU Type Configuration
    buffer[4] = bpdu_fields.flags; // Flags (1 byte)
    
    uint64_t root_id_be = htobe64(bpdu_fields.root_id);
    std::memcpy(&buffer[5], &root_id_be, 8);
    
    uint32_t cost_be = htonl(bpdu_fields.root_path_cost);
    std::memcpy(&buffer[13], &cost_be, 4);
    
    uint64_t bridge_id_be = htobe64(bpdu_fields.sender_bridge_id);
    std::memcpy(&buffer[17], &bridge_id_be, 8);
    
    uint16_t port_id_be = htons(bpdu_fields.sender_port_id);
    std::memcpy(&buffer[25], &port_id_be, 2);
    
    // Timers are converted to BPDU format (1/256th of a second)
    uint16_t message_age_bpdu_units = StpManager::seconds_to_bpdu_time(bpdu_fields.message_age_sec);
    uint16_t message_age_be = htons(message_age_bpdu_units);
    std::memcpy(&buffer[27], &message_age_be, 2);
    
    uint16_t max_age_bpdu_units = StpManager::seconds_to_bpdu_time(bpdu_fields.max_age_sec);
    uint16_t max_age_be = htons(max_age_bpdu_units);
    std::memcpy(&buffer[29], &max_age_be, 2);

    uint16_t hello_time_bpdu_units = StpManager::seconds_to_bpdu_time(bpdu_fields.hello_time_sec);
    uint16_t hello_time_be = htons(hello_time_bpdu_units);
    std::memcpy(&buffer[31], &hello_time_be, 2);

    uint16_t forward_delay_bpdu_units = StpManager::seconds_to_bpdu_time(bpdu_fields.forward_delay_sec);
    uint16_t forward_delay_be = htons(forward_delay_bpdu_units);
    std::memcpy(&buffer[33], &forward_delay_be, 2);
    
    return buffer;
}


// --- Test Suites ---

// 1. StpManagerConstruction Test Suite
TEST(StpManagerConstruction, DefaultConstructor) {
    StpManager stp(16); 
    StpManager::BridgeConfig bridge_cfg = stp.get_bridge_config();
    
    uint64_t expected_bridge_id = test_make_bridge_id(StpManager::DEFAULT_BRIDGE_PRIORITY, bridge_cfg.mac_address);
    EXPECT_EQ(bridge_cfg.bridge_id, expected_bridge_id);
    EXPECT_EQ(stp.get_current_root_bridge_id(), expected_bridge_id); 
    EXPECT_EQ(stp.get_current_root_path_cost(), 0);
    EXPECT_EQ(stp.get_root_port_id(), StpManager::INVALID_PORT_ID); 

    EXPECT_EQ(bridge_cfg.hello_time_sec, StpManager::DEFAULT_HELLO_TIME_SEC);
    EXPECT_EQ(bridge_cfg.max_age_sec, StpManager::DEFAULT_MAX_AGE_SEC);
    EXPECT_EQ(bridge_cfg.forward_delay_sec, StpManager::DEFAULT_FORWARD_DELAY_SEC);
}

// Test Fixture for StpManager tests
class StpManagerTest : public ::testing::Test {
protected:
    StpManager stp; // DUT - Bridge A
    uint32_t port0 = 0;
    uint32_t port1 = 1;
    uint32_t port2 = 2;
    
    MACAddress mac_a = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}; 
    MACAddress mac_b = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB}; 
    MACAddress mac_c = {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

    uint64_t bridge_id_a; // DUT's ID
    uint64_t bridge_id_b; // Lower ID, better root candidate
    uint64_t bridge_id_c; // Higher ID

    StpManagerTest() : stp(3) {} 

    void SetUp() override {
        StpManager::BridgeConfig config_a;
        config_a.mac_address = mac_a;
        config_a.priority = 32768; // Default priority
        config_a.bridge_id = test_make_bridge_id(config_a.priority, config_a.mac_address);
        bridge_id_a = config_a.bridge_id;
        stp.set_bridge_config(config_a);

        stp.configure_port(port0, StpManager::DEFAULT_PATH_COST, true);
        stp.configure_port(port1, StpManager::DEFAULT_PATH_COST, true);
        stp.configure_port(port2, StpManager::DEFAULT_PATH_COST, true);
        
        stp.run_stp_iteration(); // Initial state: self is root, ports are designated/blocking
        
        bridge_id_b = test_make_bridge_id(1000, mac_b); // Lower priority = better root
        bridge_id_c = test_make_bridge_id(40000, mac_c); // Higher priority
    }

    // Helper to advance time by simulating iterations and sleeps for timer tests
    void advance_time_by_iterations(int iterations, int sleep_per_iteration_ms = 0) {
        for (int i = 0; i < iterations; ++i) {
            stp.run_stp_iteration();
            if (sleep_per_iteration_ms > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(sleep_per_iteration_ms));
            }
        }
    }
};

// 2. BridgeConfiguration Test Suite
TEST_F(StpManagerTest, SetAndGetBridgeConfig) {
    StpManager::BridgeConfig new_config;
    new_config.mac_address = mac_b; 
    new_config.priority = 1000;     
    new_config.bridge_id = test_make_bridge_id(new_config.priority, new_config.mac_address);
    new_config.hello_time_sec = 5;
    new_config.max_age_sec = 30;
    new_config.forward_delay_sec = 20;

    stp.set_bridge_config(new_config);
    stp.run_stp_iteration(); 

    StpManager::BridgeConfig current_config = stp.get_bridge_config();
    EXPECT_EQ(current_config.priority, new_config.priority);
    EXPECT_EQ(current_config.mac_address, new_config.mac_address);
    EXPECT_EQ(current_config.bridge_id, new_config.bridge_id);
    EXPECT_EQ(current_config.hello_time_sec, new_config.hello_time_sec);
    EXPECT_EQ(current_config.max_age_sec, new_config.max_age_sec);
    EXPECT_EQ(current_config.forward_delay_sec, new_config.forward_delay_sec);
    EXPECT_EQ(stp.get_current_root_bridge_id(), new_config.bridge_id);
}

// 3. PortConfigurationAndState Test Suite
TEST_F(StpManagerTest, ConfigurePort) {
    uint32_t new_port = port2; 
    uint32_t path_cost = 10;
    stp.configure_port(new_port, path_cost, true);
    
    StpManager::PortStpInfo port_info = stp.get_port_stp_info(new_port);
    EXPECT_EQ(port_info.path_cost, path_cost);
    EXPECT_TRUE(port_info.stp_enabled);
    EXPECT_EQ(port_info.state, StpManager::StpPortState::BLOCKING); 
}

TEST_F(StpManagerTest, DisableStpOnPort) {
    stp.configure_port(port1, 10, true); 
    EXPECT_EQ(stp.get_port_stp_info(port1).state, StpManager::StpPortState::BLOCKING);

    stp.configure_port(port1, 10, false); 
    StpManager::PortStpInfo port_info = stp.get_port_stp_info(port1);
    EXPECT_FALSE(port_info.stp_enabled);
    EXPECT_EQ(port_info.state, StpManager::StpPortState::DISABLED); 
}

TEST_F(StpManagerTest, GetPortState) {
    EXPECT_NE(stp.get_port_state(port0), StpManager::StpPortState::BROKEN); 
    stp.configure_port(port0, 10, false); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::DISABLED);
}

TEST_F(StpManagerTest, SetPortStateAdminDisable) {
    stp.set_port_state_admin(port0, false); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::DISABLED);

    stp.set_port_state_admin(port0, true); 
    stp.run_stp_iteration(); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::BLOCKING);
}

// 4. BpduProcessing Test Suite
TEST_F(StpManagerTest, ProcessSuperiorBpdu) {
    StpManager::SimpleBpdu superior_bpdu;
    superior_bpdu.root_id = bridge_id_b;
    superior_bpdu.root_path_cost = 0; 
    superior_bpdu.sender_bridge_id = bridge_id_b;
    superior_bpdu.sender_port_id = 1; 
    superior_bpdu.message_age_sec = 0;
    superior_bpdu.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    superior_bpdu.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    superior_bpdu.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;
    superior_bpdu.flags = 0;

    std::vector<unsigned char> bpdu_data = serialize_bpdu_for_test(superior_bpdu);
    stp.process_bpdu(bpdu_data.data(), bpdu_data.size(), port1); 

    EXPECT_EQ(stp.get_current_root_bridge_id(), bridge_id_b);
    StpManager::PortStpInfo port1_info = stp.get_port_stp_info(port1);
    EXPECT_EQ(stp.get_current_root_path_cost(), port1_info.path_cost); 
    EXPECT_EQ(stp.get_root_port_id(), port1);
    EXPECT_EQ(port1_info.state, StpManager::StpPortState::BLOCKING); 
}

TEST_F(StpManagerTest, ProcessInferiorBpduOnRootPort) {
    StpManager::SimpleBpdu superior_bpdu_from_b; 
    superior_bpdu_from_b.root_id = bridge_id_b;
    superior_bpdu_from_b.root_path_cost = 0;
    superior_bpdu_from_b.sender_bridge_id = bridge_id_b;
    superior_bpdu_from_b.sender_port_id = 1;
    superior_bpdu_from_b.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    superior_bpdu_from_b.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    superior_bpdu_from_b.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;
    stp.process_bpdu(serialize_bpdu_for_test(superior_bpdu_from_b).data(), 35, port1);
    ASSERT_EQ(stp.get_root_port_id(), port1);
    uint64_t initial_root = stp.get_current_root_bridge_id();
    uint32_t initial_cost = stp.get_current_root_path_cost();

    StpManager::SimpleBpdu inferior_bpdu;
    inferior_bpdu.root_id = bridge_id_a; 
    inferior_bpdu.root_path_cost = 0;
    inferior_bpdu.sender_bridge_id = bridge_id_a;
    inferior_bpdu.sender_port_id = 1; 
    inferior_bpdu.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    inferior_bpdu.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    inferior_bpdu.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;
    
    stp.process_bpdu(serialize_bpdu_for_test(inferior_bpdu).data(), 35, port1);
    
    EXPECT_EQ(stp.get_current_root_bridge_id(), initial_root); 
    EXPECT_EQ(stp.get_current_root_path_cost(), initial_cost); 
    EXPECT_EQ(stp.get_port_stp_info(port1).role, StpManager::PortRole::ROOT_PORT); 
}


TEST_F(StpManagerTest, IgnoreOwnBpdu) {
    StpManager::SimpleBpdu own_bpdu; 
    own_bpdu.root_id = bridge_id_a;
    own_bpdu.root_path_cost = 0;
    own_bpdu.sender_bridge_id = bridge_id_a;
    own_bpdu.sender_port_id = stp.get_port_stp_info(port0).port_id_val; 
    own_bpdu.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    own_bpdu.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    own_bpdu.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;
    
    uint64_t initial_root = stp.get_current_root_bridge_id();
    StpManager::PortStpInfo port0_info_before = stp.get_port_stp_info(port0);

    stp.process_bpdu(serialize_bpdu_for_test(own_bpdu).data(), 35, port0); 
    
    EXPECT_EQ(stp.get_current_root_bridge_id(), initial_root);
    StpManager::PortStpInfo port0_info_after = stp.get_port_stp_info(port0);
    EXPECT_EQ(port0_info_after.role, port0_info_before.role); 
}

TEST_F(StpManagerTest, ProcessBpduOnDesignatedPort) {
    // DUT (A) is root. Port0 is Designated.
    ASSERT_EQ(stp.get_current_root_bridge_id(), bridge_id_a);
    ASSERT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::DESIGNATED_PORT);

    // BPDU from Bridge C (inferior, bridge_id_c > bridge_id_a) on same segment as port0
    StpManager::SimpleBpdu bpdu_from_c;
    bpdu_from_c.root_id = bridge_id_a; // C also thinks A is root
    bpdu_from_c.root_path_cost = stp.get_port_stp_info(port0).path_cost + 10; // C has a higher path cost to A
    bpdu_from_c.sender_bridge_id = bridge_id_c;
    bpdu_from_c.sender_port_id = 0x8001; // Port 1 on C
    bpdu_from_c.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    bpdu_from_c.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    bpdu_from_c.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;
    
    stp.process_bpdu(serialize_bpdu_for_test(bpdu_from_c).data(), 35, port0);
    stp.run_stp_iteration();

    // Port0 should remain Designated because its BPDU (from A) is superior for the segment
    // compared to the BPDU from C.
    EXPECT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::DESIGNATED_PORT);

    // Now, a BPDU from Bridge B (superior sender_bridge_id for the segment, assuming B also sees A as root)
    // This simulates another bridge on the same segment that becomes the designated bridge for that segment.
    StpManager::SimpleBpdu bpdu_from_b_on_segment;
    bpdu_from_b_on_segment.root_id = bridge_id_a; // B also thinks A is root
    bpdu_from_b_on_segment.root_path_cost = 0; // B is directly connected to A (or is A itself for this test)
                                               // Let's make B's sender_bridge_id better than A's for this segment.
                                               // This scenario is a bit contrived if A is root.
                                               // A better test: A is root. Port0 is Designated.
                                               // Another bridge B on segment of port0 sends a BPDU *claiming to be root*
                                               // and B's ID < A's ID. This was covered in ProcessSuperiorBpdu.
                                               //
                                               // Let's test if port0 receives a BPDU that is *better for the segment*
                                               // even if the root is the same.
                                               // This means the sender_bridge_id is better, or path cost is better.
    
    // Assume Bridge B is also connected to the same segment as Port0.
    // Bridge B also sees A as root, but B's ID is lower than A's port0's designated bridge ID (which is A's ID).
    // Or B's path cost to A is lower than A's path cost for port0 (0 if A is root).
    // Or B's designated port ID is lower.
    // This means B should be the designated bridge for the segment.
    StpManager::SimpleBpdu bpdu_segment_contender;
    bpdu_segment_contender.root_id = bridge_id_a; // Same root
    bpdu_segment_contender.root_path_cost = 0;    // Same path cost to root for sender
    bpdu_segment_contender.sender_bridge_id = bridge_id_b; // B's ID < A's ID
    bpdu_segment_contender.sender_port_id = 0x8001; // B's port 1
    bpdu_segment_contender.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    bpdu_segment_contender.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    bpdu_segment_contender.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;

    stp.process_bpdu(serialize_bpdu_for_test(bpdu_segment_contender).data(), 35, port0);
    stp.run_stp_iteration();

    // Port0 should yield and become an Alternate/Blocking port because B's BPDU is better for the segment.
    EXPECT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::ALTERNATE_PORT);
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::BLOCKING);
}


// 5. RoleElectionLogic Test Suite
TEST_F(StpManagerTest, SingleBridgeIsRoot) {
    EXPECT_EQ(stp.get_current_root_bridge_id(), bridge_id_a);
    for(uint32_t p_id : {port0, port1, port2}) {
        EXPECT_EQ(stp.get_port_stp_info(p_id).role, StpManager::PortRole::DESIGNATED_PORT);
    }
}

TEST_F(StpManagerTest, TwoBridgesRootElection) {
    StpManager::SimpleBpdu bpdu_from_b;
    bpdu_from_b.root_id = bridge_id_b;
    bpdu_from_b.root_path_cost = 0;
    bpdu_from_b.sender_bridge_id = bridge_id_b;
    bpdu_from_b.sender_port_id = 0x8001; 
    bpdu_from_b.message_age_sec = 0;
    bpdu_from_b.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    bpdu_from_b.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    bpdu_from_b.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;

    stp.process_bpdu(serialize_bpdu_for_test(bpdu_from_b).data(), 35, port1);
    stp.run_stp_iteration(); 

    EXPECT_EQ(stp.get_current_root_bridge_id(), bridge_id_b);
    EXPECT_EQ(stp.get_root_port_id(), port1);
    EXPECT_EQ(stp.get_port_stp_info(port1).role, StpManager::PortRole::ROOT_PORT);
    
    EXPECT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::DESIGNATED_PORT);
    EXPECT_EQ(stp.get_port_stp_info(port2).role, StpManager::PortRole::DESIGNATED_PORT);
}

TEST_F(StpManagerTest, DesignatedPortSelection) {
    // DUT (A) is root. Port0, Port1, Port2 are all DESIGNATED.
    // This test is more about how a port decides it's DESIGNATED vs. something else
    // when it receives BPDUs from other bridges on its segment.
    // If no BPDUs are received, or if its own BPDUs are superior, it's DESIGNATED.
    
    // Scenario: Bridge A (DUT) is root. Port0 is connected to a segment.
    // Bridge C is on the same segment but has a worse bridge ID (bridge_id_c).
    // C sends BPDUs claiming A as root, but C's sender_bridge_id is worse than A's.
    StpManager::SimpleBpdu bpdu_from_c;
    bpdu_from_c.root_id = bridge_id_a; // C agrees A is root
    bpdu_from_c.root_path_cost = 0;    // C is also directly connected to A (or thinks so)
    bpdu_from_c.sender_bridge_id = bridge_id_c; // C's ID (worse than A's)
    bpdu_from_c.sender_port_id = 0x8001; // C's port 1
    // ... set timers ...
    bpdu_from_c.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    bpdu_from_c.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    bpdu_from_c.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;


    stp.process_bpdu(serialize_bpdu_for_test(bpdu_from_c).data(), 35, port0);
    stp.run_stp_iteration();

    // Port0 should remain DESIGNATED because its own BPDU (from A) is superior to C's BPDU for the segment.
    EXPECT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::DESIGNATED_PORT);

    // Scenario: Bridge A (DUT) is root. Port1 is connected to a segment.
    // Bridge B is on the same segment. B's ID (bridge_id_b) is lower than A's.
    // B sends BPDUs claiming A as root, but B's sender_bridge_id is better than A's.
    // This implies B should be the designated bridge for that segment.
    StpManager::SimpleBpdu bpdu_from_b;
    bpdu_from_b.root_id = bridge_id_a; // B agrees A is root
    bpdu_from_b.root_path_cost = 0;    // B is also directly connected to A
    bpdu_from_b.sender_bridge_id = bridge_id_b; // B's ID (better than A's)
    bpdu_from_b.sender_port_id = 0x8002; // B's port 2
    // ... set timers ...
    bpdu_from_b.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC;
    bpdu_from_b.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC;
    bpdu_from_b.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC;


    stp.process_bpdu(serialize_bpdu_for_test(bpdu_from_b).data(), 35, port1);
    stp.run_stp_iteration();

    // Port1 should become ALTERNATE (BLOCKING) because B is the designated bridge for the segment.
    EXPECT_EQ(stp.get_port_stp_info(port1).role, StpManager::PortRole::ALTERNATE_PORT);
    EXPECT_EQ(stp.get_port_state(port1), StpManager::StpPortState::BLOCKING);
}


// 6. StateTransitionTimers Test Suite
TEST_F(StpManagerTest, BlockingToListeningToLearningToForwarding) {
    ASSERT_EQ(stp.get_current_root_bridge_id(), bridge_id_a);
    ASSERT_EQ(stp.get_port_stp_info(port0).role, StpManager::PortRole::DESIGNATED_PORT);
    ASSERT_EQ(stp.get_port_state(port0), StpManager::StpPortState::BLOCKING); 

    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::LISTENING);

    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::LEARNING);

    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    EXPECT_EQ(stp.get_port_state(port0), StpManager::StpPortState::FORWARDING);
}

TEST_F(StpManagerTest, MaxAgeTimerExpires) {
    StpManager::SimpleBpdu bpdu_from_b;
    bpdu_from_b.root_id = bridge_id_b; 
    bpdu_from_b.sender_bridge_id = bridge_id_b;
    bpdu_from_b.max_age_sec = StpManager::DEFAULT_MAX_AGE_SEC; 
    bpdu_from_b.hello_time_sec = StpManager::DEFAULT_HELLO_TIME_SEC; 
    bpdu_from_b.forward_delay_sec = StpManager::DEFAULT_FORWARD_DELAY_SEC; 

    stp.process_bpdu(serialize_bpdu_for_test(bpdu_from_b).data(), 35, port1);
    stp.run_stp_iteration();
    ASSERT_EQ(stp.get_root_port_id(), port1);
    ASSERT_EQ(stp.get_current_root_bridge_id(), bridge_id_b);

    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_MAX_AGE_SEC + 1));
    stp.run_stp_iteration(); 

    EXPECT_EQ(stp.get_current_root_bridge_id(), bridge_id_a);
    EXPECT_EQ(stp.get_root_port_id(), StpManager::INVALID_PORT_ID); 
    EXPECT_EQ(stp.get_port_stp_info(port1).role, StpManager::PortRole::DESIGNATED_PORT);
    EXPECT_EQ(stp.get_port_state(port1), StpManager::StpPortState::BLOCKING);
}


// 7. ShouldForwardLogic Test Suite
TEST_F(StpManagerTest, ShouldForwardStates) {
    EXPECT_FALSE(stp.should_forward(port0)); 

    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    std::this_thread::sleep_for(std::chrono::seconds(StpManager::DEFAULT_FORWARD_DELAY_SEC + 1));
    stp.run_stp_iteration(); 
    EXPECT_TRUE(stp.should_forward(port0)); 

    stp.configure_port(port1, 10, false); 
    EXPECT_FALSE(stp.should_forward(port1)); 
}

// --- End of test_stp_manager.cpp ---
