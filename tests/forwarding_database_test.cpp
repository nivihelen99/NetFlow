#include "gtest/gtest.h"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/packet.hpp" // For netflow::MacAddress
#include <chrono>
#include <thread>
#include <vector>
#include <optional>
#include <cstdint> // For uint16_t

// Helper to create MacAddress from bytes, similar to what's in packet_test.cpp
// This is needed because MacAddress constructor takes const uint8_t*
// and direct brace initialization might not work for static const members in all contexts.
netflow::MacAddress make_fdb_mac(const uint8_t arr[6]) {
    return netflow::MacAddress(arr);
}

// Define some sample MacAddress constants for tests
const netflow::MacAddress MAC1 = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
const netflow::MacAddress MAC2 = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
const netflow::MacAddress MAC3 = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0x00, 0x03});
const netflow::MacAddress MAC_STATIC = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0x00, 0x55}); // Corrected 0xSS to 0x55, removed duplicate
const netflow::MacAddress MAC_DYN1 = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0xDD, 0x01}); // Restored MAC_DYN1
const netflow::MacAddress MAC_STA1 = make_fdb_mac((const uint8_t[6]){0x00, 0x00, 0x00, 0x00, 0xAA, 0x01});


class ForwardingDatabaseTest : public ::testing::Test {
protected:
    netflow::ForwardingDatabase fdb;

    // Define some common port and VLAN IDs
    const uint16_t port1 = 1;
    const uint16_t port2 = 2;
    const uint16_t port3 = 3;
    const uint16_t port4 = 4;
    const uint16_t port_s = 10;

    const uint16_t vlan1 = 100;
    const uint16_t vlan2 = 200;
    const uint16_t vlan_s = 300;
    const uint16_t vlan_unknown = 999;
    const uint16_t vlan_dyn1 = 1;
    const uint16_t vlan_sta1 = 1;
     const uint16_t vlan_port1_mac1 = 1;
    const uint16_t vlan_port1_mac2 = 2;
    const uint16_t vlan_port2_mac3 = 1;
    const uint16_t vlan_port1_mac_s1 = 3;


    // Default aging time for tests if we can't control it directly in FDB
    // If FDB's default max_age is 300s, these tests will be slow or ineffective.
    // We assume for now that we can test aging with shorter, controlled durations.
    // The FDB implementation uses std::chrono::seconds(300) as default.
    // For testing, it would be ideal if age_entries took the current time or if max_age was configurable.
    // Let's assume we can call age_entries(current_time_point) and it uses its internal max_age.
    // For aging tests, we will use a small, controllable max_age for the FDB if possible.
    // If not, the tests will be structured to work with the default 300s,
    // which means we won't see entries expire unless we can inject time or wait.
    // The `age_entries` method in the provided header takes a `max_age_override`.
    // This is good! We can use this.
    const std::chrono::seconds test_max_age = std::chrono::seconds(1);
    const std::chrono::milliseconds test_half_max_age_ms = std::chrono::milliseconds(500);
    const std::chrono::milliseconds test_max_age_ms = std::chrono::milliseconds(1000);
    const std::chrono::milliseconds test_max_age_plus_bit_ms = std::chrono::milliseconds(1200);


};

TEST_F(ForwardingDatabaseTest, InitialState) {
    EXPECT_EQ(fdb.entry_count(), 0);
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan1), std::nullopt);
}

TEST_F(ForwardingDatabaseTest, LearnMac) {
    fdb.learn_mac(MAC1, port1, vlan1);
    EXPECT_EQ(fdb.entry_count(), 1);
    ASSERT_TRUE(fdb.lookup_port(MAC1, vlan1).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan1).value(), port1);
    // To check if it's dynamic, we'd iterate get_all_entries()
    bool found_dynamic = false;
    for(const auto& entry : fdb.get_all_entries()){
        if(entry.mac == MAC1 && entry.vlan_id == vlan1 && entry.port == port1 && !entry.is_static) found_dynamic = true;
    }
    EXPECT_TRUE(found_dynamic);


    // Learn same MAC+VLAN on a different port
    fdb.learn_mac(MAC1, port2, vlan1);
    EXPECT_EQ(fdb.entry_count(), 1); // Should update, not add
    ASSERT_TRUE(fdb.lookup_port(MAC1, vlan1).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan1).value(), port2);

    // Learn a different MAC
    fdb.learn_mac(MAC2, port3, vlan1);
    EXPECT_EQ(fdb.entry_count(), 2);
    ASSERT_TRUE(fdb.lookup_port(MAC2, vlan1).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC2, vlan1).value(), port3);

    // Learn MAC1 on a different VLAN
    fdb.learn_mac(MAC1, port4, vlan2);
    EXPECT_EQ(fdb.entry_count(), 3);
    ASSERT_TRUE(fdb.lookup_port(MAC1, vlan2).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan2).value(), port4);
}

TEST_F(ForwardingDatabaseTest, AddStaticEntry) {
    fdb.add_static_entry(MAC_STATIC, port_s, vlan_s);
    EXPECT_EQ(fdb.entry_count(), 1);
    ASSERT_TRUE(fdb.lookup_port(MAC_STATIC, vlan_s).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC_STATIC, vlan_s).value(), port_s);
    // Verify it's static by iterating get_all_entries()
    bool found_static = false;
    for(const auto& entry : fdb.get_all_entries()){
        if(entry.mac == MAC_STATIC && entry.vlan_id == vlan_s && entry.port == port_s && entry.is_static) found_static = true;
    }
    EXPECT_TRUE(found_static);


    // Attempt to learn over static entry
    uint16_t new_port_for_static_mac = port_s + 1;
    fdb.learn_mac(MAC_STATIC, new_port_for_static_mac, vlan_s);
    EXPECT_EQ(fdb.entry_count(), 1);

    ASSERT_TRUE(fdb.lookup_port(MAC_STATIC, vlan_s).has_value());
    EXPECT_EQ(fdb.lookup_port(MAC_STATIC, vlan_s).value(), port_s); // Port should NOT be updated
}

TEST_F(ForwardingDatabaseTest, LookupNonExistent) {
    fdb.learn_mac(MAC1, port1, vlan1);
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan_unknown), std::nullopt);

    netflow::MacAddress unknown_mac = make_fdb_mac((const uint8_t[6]){0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00});
    EXPECT_EQ(fdb.lookup_port(unknown_mac, vlan1), std::nullopt);
}
// More tests will be added here
// TODO: Aging, Flush, GetAllEntries, SetLogger, Statistics (if applicable)

// Note: The FDB header has `age_entries(std::chrono::seconds max_age_override)`
// This is excellent for testing. We don't need to mock the clock.
TEST_F(ForwardingDatabaseTest, AgingDynamicEntries) {
    fdb.learn_mac(MAC_DYN1, port1, vlan_dyn1);
    fdb.add_static_entry(MAC_STA1, port2, vlan_sta1);
    EXPECT_EQ(fdb.entry_count(), 2);

    // Sleep for a duration longer than test_max_age
    std::this_thread::sleep_for(test_max_age_plus_bit_ms);

    fdb.age_entries(test_max_age); // Use override for max_age

    EXPECT_EQ(fdb.lookup_port(MAC_DYN1, vlan_dyn1), std::nullopt) << "Dynamic entry should have aged out";
    ASSERT_TRUE(fdb.lookup_port(MAC_STA1, vlan_sta1).has_value()) << "Static entry should remain";
    EXPECT_EQ(fdb.lookup_port(MAC_STA1, vlan_sta1).value(), port2);
    EXPECT_EQ(fdb.entry_count(), 1); // Only static entry should remain
}

TEST_F(ForwardingDatabaseTest, AgingRespectsTimestampUpdate) {
    fdb.learn_mac(MAC_DYN1, port1, vlan_dyn1); // Initial learn
    EXPECT_EQ(fdb.entry_count(), 1);

    // Sleep for a period less than test_max_age but significant
    std::this_thread::sleep_for(test_half_max_age_ms);

    fdb.learn_mac(MAC_DYN1, port1, vlan_dyn1); // Re-learn, should update timestamp
    EXPECT_EQ(fdb.entry_count(), 1); // Still 1 entry

    // Sleep for another similar period. Total sleep is > test_max_age from initial learn,
    // but < test_max_age from the re-learn.
    std::this_thread::sleep_for(test_half_max_age_ms + std::chrono::milliseconds(100)); // Ensure slightly more than half

    fdb.age_entries(test_max_age); // Age with test_max_age

    ASSERT_TRUE(fdb.lookup_port(MAC_DYN1, vlan_dyn1).has_value()) << "Dynamic entry should NOT have aged out due to re-learn";
    EXPECT_EQ(fdb.lookup_port(MAC_DYN1, vlan_dyn1).value(), port1);
    EXPECT_EQ(fdb.entry_count(), 1);
}

TEST_F(ForwardingDatabaseTest, FlushPort) {
    fdb.learn_mac(MAC1, port1, vlan_port1_mac1);        // To be flushed (dynamic)
    fdb.learn_mac(MAC2, port1, vlan_port1_mac2);        // To be flushed (dynamic)
    fdb.learn_mac(MAC3, port2, vlan_port2_mac3);        // Should remain
    fdb.add_static_entry(MAC_STA1, port1, vlan_port1_mac_s1); // To be flushed (static)
    EXPECT_EQ(fdb.entry_count(), 4);

    fdb.flush_port(port1);

    EXPECT_EQ(fdb.lookup_port(MAC1, vlan_port1_mac1), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC2, vlan_port1_mac2), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC_STA1, vlan_port1_mac_s1), std::nullopt);
    ASSERT_TRUE(fdb.lookup_port(MAC3, vlan_port2_mac3).has_value());
    EXPECT_EQ(fdb.entry_count(), 1);
}

TEST_F(ForwardingDatabaseTest, FlushVlan) {
    fdb.learn_mac(MAC1, port1, vlan1);        // To be flushed (dynamic)
    fdb.learn_mac(MAC2, port2, vlan1);        // To be flushed (dynamic)
    fdb.learn_mac(MAC3, port1, vlan2);        // Should remain
    fdb.add_static_entry(MAC_STA1, port3, vlan1); // To be flushed (static)
    EXPECT_EQ(fdb.entry_count(), 4);

    fdb.flush_vlan(vlan1);

    EXPECT_EQ(fdb.lookup_port(MAC1, vlan1), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC2, vlan1), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC_STA1, vlan1), std::nullopt);
    ASSERT_TRUE(fdb.lookup_port(MAC3, vlan2).has_value());
    EXPECT_EQ(fdb.entry_count(), 1);
}

TEST_F(ForwardingDatabaseTest, FlushAll) {
    fdb.learn_mac(MAC1, port1, vlan1);
    fdb.add_static_entry(MAC_STATIC, port_s, vlan_s);
    fdb.learn_mac(MAC2, port2, vlan2);
    EXPECT_EQ(fdb.entry_count(), 3);

    fdb.flush_all();
    EXPECT_EQ(fdb.entry_count(), 0);
    EXPECT_EQ(fdb.lookup_port(MAC1, vlan1), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC_STATIC, vlan_s), std::nullopt);
    EXPECT_EQ(fdb.lookup_port(MAC2, vlan2), std::nullopt);
}

TEST_F(ForwardingDatabaseTest, Statistics) {
    EXPECT_EQ(fdb.entry_count(), 0);
    // Assuming capacity and load_factor might be simple if std::vector is used directly.
    // If ForwardingDatabase has a fixed capacity or more complex management,
    // these would be more meaningful. For now, just call them.
    EXPECT_GE(fdb.capacity(), 0); // Capacity should be >= 0
    EXPECT_FLOAT_EQ(fdb.load_factor(), 0.0f);

    fdb.learn_mac(MAC1, port1, vlan1);
    EXPECT_EQ(fdb.entry_count(), 1);
    if (fdb.capacity() > 0) { // Avoid division by zero if capacity can be 0
        EXPECT_FLOAT_EQ(fdb.load_factor(), 1.0f / static_cast<float>(fdb.capacity()));
    } else {
        EXPECT_FLOAT_EQ(fdb.load_factor(), 0.0f); // Or some other defined behavior for 0 capacity
    }

    fdb.learn_mac(MAC2, port2, vlan2);
    EXPECT_EQ(fdb.entry_count(), 2);
    // Add more entries to test load factor if FDB has resizing/max capacity
}

TEST_F(ForwardingDatabaseTest, GetAllEntries) {
    fdb.learn_mac(MAC1, port1, vlan1);
    fdb.add_static_entry(MAC_STATIC, port_s, vlan_s);
    fdb.learn_mac(MAC2, port2, vlan2);

    auto entries = fdb.get_all_entries(); // Returns std::vector<FdbEntry>
    EXPECT_EQ(entries.size(), 3); // MAC1, MAC_STATIC, MAC2

    bool found_mac1 = false;
    bool found_mac_static = false;
    bool found_mac2 = false;

    for (const auto& entry_view : entries) { // entry_view is FdbEntry
        if (entry_view.mac == MAC1 && entry_view.vlan_id == vlan1) {
            EXPECT_EQ(entry_view.port, port1);
            EXPECT_FALSE(entry_view.is_static); // Corrected field name
            found_mac1 = true;
        } else if (entry_view.mac == MAC_STATIC && entry_view.vlan_id == vlan_s) {
            EXPECT_EQ(entry_view.port, port_s);
            EXPECT_TRUE(entry_view.is_static); // Corrected field name
            found_mac_static = true;
        } else if (entry_view.mac == MAC2 && entry_view.vlan_id == vlan2) {
            EXPECT_EQ(entry_view.port, port2);
            EXPECT_FALSE(entry_view.is_static); // Corrected field name; learn_mac makes dynamic entries
            found_mac2 = true;
        }
    }
    EXPECT_TRUE(found_mac1);
    EXPECT_TRUE(found_mac_static);
    EXPECT_TRUE(found_mac2);
}

TEST_F(ForwardingDatabaseTest, SetLogger) {
    // Assuming SwitchLogger is complex or not easily mockable for this test.
    // This test just ensures set_logger can be called.
    // A real test would involve a mock logger and verifying calls.
    fdb.set_logger(nullptr); // Should be acceptable
    // If there was a dummy logger:
    // netflow::SwitchLogger dummy_logger;
    // fdb.set_logger(&dummy_logger);
    SUCCEED(); // If it didn't crash, it's a basic pass.
}
