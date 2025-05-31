#include "gtest/gtest.h"
#include "gmock/gmock.h" // For GMock framework

#include "netflow++/lldp_manager.hpp"
#include "netflow++/lldp_defs.hpp"
#include "netflow++/interface_manager.hpp"
#include "netflow++/switch.hpp" // Real Switch needed for MockSwitch to inherit from
#include "netflow++/packet.hpp"
#include "netflow++/packet_buffer.hpp"
#include "netflow++/buffer_pool.hpp"    // For MockSwitch constructor if needed
#include "netflow++/logger.hpp"         // For MockSwitch constructor if needed

#include <vector>
#include <string>
#include <chrono>
#include <memory> // For std::make_shared

using namespace netflow;
using ::testing::_;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::ElementsAreArray;
using ::testing::Truly; // For custom matchers

// --- Mock Classes ---

// Mock for InterfaceManager
class MockInterfaceManager : public netflow::InterfaceManager {
public:
    // Constructor: Initialize with a logger if the base class requires it.
    // If InterfaceManager has a default constructor or one that can be called with minimal setup, use that.
    // For this example, assuming it might need a logger and buffer_pool like the real one.
    // This is a simplified constructor for mock purposes.
    MockInterfaceManager() : netflow::InterfaceManager(/* provide necessary constructor args if any, e.g., port_names, logger, buffer_pool */) {
        // If the base class constructor needs complex objects, they might also need to be mocked or simplified.
        // For instance, if it needs a logger:
        // static SwitchLogger dummy_logger(LogLevel::DEBUG); // static to ensure lifetime
        // This part is tricky if the base InterfaceManager constructor is complex.
        // A common pattern is to have a simplified constructor for testing or make members protected.
    }
    MOCK_METHOD(std::optional<MacAddress>, get_interface_mac, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::string, get_port_name, (uint32_t port_id), (const, override));
    MOCK_METHOD(bool, is_port_link_up, (uint32_t port_id), (const, override));
    MOCK_METHOD(bool, is_port_valid, (uint32_t port_id), (const, override));
    MOCK_METHOD(std::vector<uint32_t>, get_all_interface_ids, (), (const, override));
    // Add other methods LldpManager might use if any
};

// Mock for Switch
// The Switch class has a complex constructor. We need to provide a way to construct it.
// One way is to provide dummy/mock dependencies for its constructor.
class MockSwitch : public netflow::Switch {
public:
    // Simplified constructor for MockSwitch.
    // It needs to call the base Switch constructor.
    // We provide minimal, possibly dummy, arguments needed by the base Switch.
    MockSwitch(uint32_t num_ports = 1)
        : netflow::Switch(num_ports, 0x112233445566ULL /* dummy MAC */) {
        // The base Switch constructor does a lot. If that's problematic for mocking,
        // it might indicate a need for refactoring Switch for better testability
        // (e.g., dependency injection for all its managers).
    }

    MOCK_METHOD(void, send_control_plane_frame, (uint32_t egress_port_id, const MacAddress& dst_mac, const MacAddress& src_mac, uint16_t ethertype, const std::vector<uint8_t>& payload), (override));
    // Add other methods LldpManager might call on Switch if any
};

// --- Test Fixture ---
class LldpManagerTest : public ::testing::Test {
protected:
    std::shared_ptr<MockInterfaceManager> mock_if_mgr_;
    std::shared_ptr<MockSwitch> mock_switch_;
    std::unique_ptr<LldpManager> lldp_manager_;

    uint32_t test_port_id_0_ = 0;
    uint32_t test_port_id_1_ = 1;
    MacAddress test_mac_0_ = {{0x00, 0x01, 0x02, 0x03, 0x04, 0x00}};
    std::string test_port_name_0_ = "eth0";


    void SetUp() override {
        mock_if_mgr_ = std::make_shared<MockInterfaceManager>();
        // Provide the mock_if_mgr_ to the MockSwitch if its constructor needs it,
        // or ensure MockSwitch can be constructed stand-alone for LldpManager tests.
        // The LldpManager takes the Switch and InterfaceManager.
        mock_switch_ = std::make_shared<MockSwitch>(2 /* num_ports for mock switch */);

        // LldpManager takes references, so we pass the dereferenced mocks.
        lldp_manager_ = std::make_unique<LldpManager>(*mock_switch_, *mock_if_mgr_);

        // Default mock behaviors
        ON_CALL(*mock_if_mgr_, is_port_valid(_)).WillByDefault(Return(true));
        ON_CALL(*mock_if_mgr_, is_port_link_up(_)).WillByDefault(Return(true));
    }

    void TearDown() override {
        // Cleanup if necessary
    }

    // Helper to construct a simple LLDPDU for testing process_lldp_frame
    // This is a simplified version. A real test might need more TLVs or more configurability.
    std::vector<uint8_t> create_test_lldpdu(const MacAddress& chassis_mac, uint8_t chassis_subtype,
                                           const std::string& port_id_str, uint8_t port_subtype,
                                           uint16_t ttl_sec,
                                           const std::string& sys_name = "TestNeighbor",
                                           const std::string& sys_desc = "TestDescription") {
        std::vector<uint8_t> pdu;
        LldpTlvHeader tlv_header;

        // Chassis ID TLV
        std::vector<uint8_t> chassis_val_data;
        chassis_val_data.push_back(chassis_subtype);
        chassis_val_data.insert(chassis_val_data.end(), chassis_mac.octets.begin(), chassis_mac.octets.end());
        tlv_header.setType(TLV_TYPE_CHASSIS_ID);
        tlv_header.setLength(chassis_val_data.size());
        uint16_t ch_type_len_net = htons(tlv_header.type_length);
        pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&ch_type_len_net), reinterpret_cast<uint8_t*>(&ch_type_len_net) + 2);
        pdu.insert(pdu.end(), chassis_val_data.begin(), chassis_val_data.end());

        // Port ID TLV
        std::vector<uint8_t> port_val_data;
        port_val_data.push_back(port_subtype);
        port_val_data.insert(port_val_data.end(), port_id_str.begin(), port_id_str.end());
        tlv_header.setType(TLV_TYPE_PORT_ID);
        tlv_header.setLength(port_val_data.size());
        uint16_t port_type_len_net = htons(tlv_header.type_length);
        pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&port_type_len_net), reinterpret_cast<uint8_t*>(&port_type_len_net) + 2);
        pdu.insert(pdu.end(), port_val_data.begin(), port_val_data.end());

        // TTL TLV
        std::vector<uint8_t> ttl_val_data;
        uint16_t ttl_net = htons(ttl_sec);
        ttl_val_data.insert(ttl_val_data.end(), reinterpret_cast<uint8_t*>(&ttl_net), reinterpret_cast<uint8_t*>(&ttl_net) + 2);
        tlv_header.setType(TLV_TYPE_TTL);
        tlv_header.setLength(ttl_val_data.size());
        uint16_t ttl_type_len_net = htons(tlv_header.type_length);
        pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&ttl_type_len_net), reinterpret_cast<uint8_t*>(&ttl_type_len_net) + 2);
        pdu.insert(pdu.end(), ttl_val_data.begin(), ttl_val_data.end());

        // System Name TLV
        if (!sys_name.empty()) {
            std::vector<uint8_t> sys_name_val_data(sys_name.begin(), sys_name.end());
            tlv_header.setType(TLV_TYPE_SYSTEM_NAME);
            tlv_header.setLength(sys_name_val_data.size());
            uint16_t sn_type_len_net = htons(tlv_header.type_length);
            pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&sn_type_len_net), reinterpret_cast<uint8_t*>(&sn_type_len_net) + 2);
            pdu.insert(pdu.end(), sys_name_val_data.begin(), sys_name_val_data.end());
        }

        // System Description TLV
         if (!sys_desc.empty()) {
            std::vector<uint8_t> sys_desc_val_data(sys_desc.begin(), sys_desc.end());
            tlv_header.setType(TLV_TYPE_SYSTEM_DESCRIPTION);
            tlv_header.setLength(sys_desc_val_data.size());
            uint16_t sd_type_len_net = htons(tlv_header.type_length);
            pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&sd_type_len_net), reinterpret_cast<uint8_t*>(&sd_type_len_net) + 2);
            pdu.insert(pdu.end(), sys_desc_val_data.begin(), sys_desc_val_data.end());
        }

        // End of LLDPDU TLV
        tlv_header.setType(TLV_TYPE_END_OF_LLDPDU);
        tlv_header.setLength(0);
        uint16_t end_type_len_net = htons(tlv_header.type_length);
        pdu.insert(pdu.end(), reinterpret_cast<uint8_t*>(&end_type_len_net), reinterpret_cast<uint8_t*>(&end_type_len_net) + 2);

        return pdu;
    }
};

// --- Test Cases ---

TEST_F(LldpManagerTest, Initialization) {
    // Check default config for a port (should be disabled)
    LldpPortConfig port_config = lldp_manager_->get_port_config(test_port_id_0_);
    EXPECT_FALSE(port_config.enabled);
    EXPECT_EQ(port_config.tx_interval_seconds, 30); // Default interval
    EXPECT_EQ(port_config.ttl_multiplier, 4);    // Default multiplier
}

TEST_F(LldpManagerTest, ConfigurePort) {
    // Enable LLDP on a port
    lldp_manager_->configure_port(test_port_id_0_, true, 60, 5);
    LldpPortConfig port_config = lldp_manager_->get_port_config(test_port_id_0_);
    EXPECT_TRUE(port_config.enabled);
    EXPECT_EQ(port_config.tx_interval_seconds, 60);
    EXPECT_EQ(port_config.ttl_multiplier, 5);

    // Disable LLDP on the port
    lldp_manager_->configure_port(test_port_id_0_, false, 60, 5); // Interval/multiplier shouldn't matter when disabled but are preserved
    port_config = lldp_manager_->get_port_config(test_port_id_0_);
    EXPECT_FALSE(port_config.enabled);
    EXPECT_EQ(port_config.tx_interval_seconds, 60); // Check they are preserved
    EXPECT_EQ(port_config.ttl_multiplier, 5);
}

TEST_F(LldpManagerTest, BuildAndSendLLDPFrame) {
    uint32_t port_id = test_port_id_0_;
    uint32_t tx_interval = 30;
    uint32_t ttl_multiplier = 4;
    uint16_t expected_ttl_value = tx_interval * ttl_multiplier;

    lldp_manager_->configure_port(port_id, true, tx_interval, ttl_multiplier);

    EXPECT_CALL(*mock_if_mgr_, get_interface_mac(port_id))
        .WillOnce(Return(test_mac_0_));
    EXPECT_CALL(*mock_if_mgr_, get_port_name(port_id))
        .WillOnce(Return(test_port_name_0_));
    EXPECT_CALL(*mock_if_mgr_, is_port_link_up(port_id)) // Called by send_lldp_frame and handle_timer_tick
        .WillRepeatedly(Return(true));


    std::vector<uint8_t> captured_payload;
    MacAddress captured_dst_mac;
    MacAddress captured_src_mac;
    uint16_t captured_ethertype;

    EXPECT_CALL(*mock_switch_, send_control_plane_frame(port_id, _, _, _, _))
        .WillOnce(DoAll(
            SaveArg<1>(&captured_dst_mac),
            SaveArg<2>(&captured_src_mac),
            SaveArg<3>(&captured_ethertype),
            SaveArg<4>(&captured_payload)
        ));

    lldp_manager_->send_lldp_frame(port_id);

    // Verify MACs and Ethertype
    ASSERT_EQ(captured_dst_mac, LLDP_MULTICAST_MAC);
    ASSERT_EQ(captured_src_mac, test_mac_0_);
    ASSERT_EQ(captured_ethertype, LLDP_ETHERTYPE);

    // Basic payload validation (more detailed parsing could be done)
    ASSERT_GT(captured_payload.size(), 0);

    // Validate TLVs (simplified check, assumes TLVs are in order)
    size_t current_pos = 0;
    bool found_chassis_id = false, found_port_id = false, found_ttl = false;
    bool found_sys_name = false, found_sys_desc = false, found_end = false;

    while(current_pos + 2 <= captured_payload.size()) {
        LldpTlvHeader tlv_header_net;
        memcpy(&tlv_header_net.type_length, captured_payload.data() + current_pos, 2);

        LldpTlvHeader tlv_header;
        tlv_header.type_length = ntohs(tlv_header_net.type_length);

        uint8_t type = tlv_header.getType();
        uint16_t length = tlv_header.getLength();
        current_pos += 2;

        if (current_pos + length > captured_payload.size() && type != TLV_TYPE_END_OF_LLDPDU) { // End TLV has length 0
             FAIL() << "TLV length exceeds payload size. Type: " << (int)type << " Length: " << length;
        }

        const uint8_t* value_ptr = captured_payload.data() + current_pos;

        if (type == TLV_TYPE_CHASSIS_ID) {
            found_chassis_id = true;
            ASSERT_GE(length, 1 + 6); // Subtype + MAC address
            EXPECT_EQ(value_ptr[0], CHASSIS_ID_SUBTYPE_MAC_ADDRESS);
            MacAddress chassis_mac_in_tlv(&value_ptr[1]);
            EXPECT_EQ(chassis_mac_in_tlv, test_mac_0_);
        } else if (type == TLV_TYPE_PORT_ID) {
            found_port_id = true;
            ASSERT_GE(length, 1 + test_port_name_0_.length()); // Subtype + Port Name
            EXPECT_EQ(value_ptr[0], PORT_ID_SUBTYPE_INTERFACE_NAME);
            std::string port_name_in_tlv(reinterpret_cast<const char*>(&value_ptr[1]), test_port_name_0_.length());
            EXPECT_EQ(port_name_in_tlv, test_port_name_0_);
        } else if (type == TLV_TYPE_TTL) {
            found_ttl = true;
            ASSERT_EQ(length, 2);
            uint16_t ttl_val_net;
            memcpy(&ttl_val_net, value_ptr, 2);
            EXPECT_EQ(ntohs(ttl_val_net), expected_ttl_value);
        } else if (type == TLV_TYPE_SYSTEM_NAME) {
            found_sys_name = true;
            // Value can be checked against LldpManager::get_system_name()
        } else if (type == TLV_TYPE_SYSTEM_DESCRIPTION) {
            found_sys_desc = true;
            // Value can be checked against LldpManager::get_system_description()
        } else if (type == TLV_TYPE_END_OF_LLDPDU) {
            found_end = true;
            ASSERT_EQ(length, 0);
            break;
        }
        current_pos += length;
    }

    EXPECT_TRUE(found_chassis_id);
    EXPECT_TRUE(found_port_id);
    EXPECT_TRUE(found_ttl);
    EXPECT_TRUE(found_sys_name);
    EXPECT_TRUE(found_sys_desc);
    EXPECT_TRUE(found_end);
}


TEST_F(LldpManagerTest, ProcessValidLLDPFrame) {
    uint32_t ingress_port = test_port_id_1_;
    MacAddress neighbor_chassis_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    std::string neighbor_port_id_str = "Gig0/1";
    uint16_t neighbor_ttl_sec = 120;
    std::string neighbor_sys_name = "NeighborSwitch";
    std::string neighbor_sys_desc = "Neighbor Test System";

    std::vector<uint8_t> lldpdu = create_test_lldpdu(
        neighbor_chassis_mac, CHASSIS_ID_SUBTYPE_MAC_ADDRESS,
        neighbor_port_id_str, PORT_ID_SUBTYPE_INTERFACE_NAME,
        neighbor_ttl_sec, neighbor_sys_name, neighbor_sys_desc);

    // Create PacketBuffer and Packet
    // Dummy BufferPool for Packet creation, not directly used by LldpManager::process_lldp_frame logic itself
    BufferPool test_buffer_pool(10, 1500);
    PacketBuffer* pb = test_buffer_pool.allocate(lldpdu.size());
    ASSERT_NE(pb, nullptr);
    memcpy(pb->get_data_ptr_write(), lldpdu.data(), lldpdu.size());
    pb->set_data_length(lldpdu.size());

    Packet packet(pb); // Packet takes ownership (increments ref count)

    // Configure port for LLDP
    lldp_manager_->configure_port(ingress_port, true);

    lldp_manager_->process_lldp_frame(packet, ingress_port);

    auto neighbors = lldp_manager_->get_neighbors(ingress_port);
    ASSERT_EQ(neighbors.size(), 1);
    const auto& info = neighbors[0];

    EXPECT_EQ(info.chassis_id_subtype, CHASSIS_ID_SUBTYPE_MAC_ADDRESS);
    EXPECT_EQ(info.chassis_id_raw, std::vector<uint8_t>(neighbor_chassis_mac.octets.begin(), neighbor_chassis_mac.octets.end()));
    EXPECT_EQ(info.port_id_subtype, PORT_ID_SUBTYPE_INTERFACE_NAME);
    EXPECT_EQ(info.port_id_raw, std::vector<uint8_t>(neighbor_port_id_str.begin(), neighbor_port_id_str.end()));
    EXPECT_EQ(info.ttl, neighbor_ttl_sec);
    EXPECT_EQ(info.system_name, neighbor_sys_name);
    EXPECT_EQ(info.system_description, neighbor_sys_desc);
    EXPECT_EQ(info.ingress_port, ingress_port);

    // Check last_updated is recent (e.g., within last few seconds)
    auto now = std::chrono::steady_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - info.last_updated);
    EXPECT_LT(age.count(), 5);

    pb->decrement_ref(); // Test owns pb, Packet also took a ref. Release test's ref.
}

// TODO: NeighborUpdate Test
// TODO: NeighborAging Test
// TODO: PeriodicSend Test

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
