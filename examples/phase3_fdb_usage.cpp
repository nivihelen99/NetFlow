#include "netflow_plus_plus/switching/fdb.hpp"
#include "netflow_plus_plus/core/types.hpp" // For MacAddress
#include <iostream>
#include <string>

void print_fdb_lookup(const netflow_plus_plus::switching::ForwardingDatabase& fdb,
                      const netflow_plus_plus::core::MacAddress& mac,
                      uint16_t vlan_id) {
    std::cout << "  Looking up MAC " << mac.toString() << " in VLAN " << vlan_id << ": ";
    auto port_opt = fdb.lookup_port(mac, vlan_id);
    if (port_opt) {
        std::cout << "Found on port " << *port_opt << std::endl;
    } else {
        std::cout << "Not found." << std::endl;
    }
}

int main() {
    std::cout << "--- Phase 3: Forwarding Database (FDB) Usage Example ---" << std::endl;

    netflow_plus_plus::switching::ForwardingDatabase fdb;

    std::cout << "Initial FDB entry count: " << fdb.entry_count() << std::endl;

    // Learn some MAC addresses
    netflow_plus_plus::core::MacAddress mac1("00:00:00:AA:BB:C1");
    netflow_plus_plus::core::MacAddress mac2("00:00:00:AA:BB:C2");
    netflow_plus_plus::core::MacAddress mac3("00:00:00:AA:BB:C3");
    netflow_plus_plus::core::MacAddress static_mac("00:11:22:33:44:FF");

    std::cout << "\nLearning MACs..." << std::endl;
    fdb.learn_mac(mac1, 1, 100);
    std::cout << "  Learned " << mac1.toString() << " on port 1, VLAN 100." << std::endl;
    fdb.learn_mac(mac2, 2, 100);
    std::cout << "  Learned " << mac2.toString() << " on port 2, VLAN 100." << std::endl;
    fdb.learn_mac(mac1, 3, 200); // mac1 in a different VLAN
    std::cout << "  Learned " << mac1.toString() << " on port 3, VLAN 200." << std::endl;

    std::cout << "FDB entry count after learning: " << fdb.entry_count() << std::endl;

    // Add a static entry
    std::cout << "\nAdding static MAC..." << std::endl;
    fdb.add_static_entry(static_mac, 5, 100);
    std::cout << "  Added static entry for " << static_mac.toString() << " on port 5, VLAN 100." << std::endl;
    std::cout << "FDB entry count after static add: " << fdb.entry_count() << std::endl;

    // Test lookups
    std::cout << "\nTesting lookups..." << std::endl;
    print_fdb_lookup(fdb, mac1, 100);
    print_fdb_lookup(fdb, mac2, 100);
    print_fdb_lookup(fdb, mac1, 200);
    print_fdb_lookup(fdb, mac3, 100); // Not learned
    print_fdb_lookup(fdb, static_mac, 100);

    // Test learning an existing MAC (should update port, if not static)
    std::cout << "\nRe-learning mac1 on a new port (port 4, VLAN 100)..." << std::endl;
    fdb.learn_mac(mac1, 4, 100);
    print_fdb_lookup(fdb, mac1, 100); // Should now be port 4

    // Test learning a static MAC (should not update)
    std::cout << "\nAttempting to re-learn static_mac on a new port (port 7, VLAN 100)..." << std::endl;
    bool learned_static = fdb.learn_mac(static_mac, 7, 100);
    std::cout << "  learn_mac returned: " << (learned_static ? "true (error, should be false)" : "false (correct)") << std::endl;
    print_fdb_lookup(fdb, static_mac, 100); // Should still be port 5


    // Test aging (simplified, just call it)
    std::cout << "\nTesting aging (entries might be removed if older than default 300s)..." << std::endl;
    std::cout << "  Entry count before aging: " << fdb.entry_count() << std::endl;
    // To actually see aging, you'd need to wait or use a very short max_age.
    // For now, we just call it. If any entry was added >300s ago AND this test runs long enough, it might get aged.
    fdb.age_entries(std::chrono::seconds(1)); // Use 1s to test aging more visibly if you pause
    // Or std::this_thread::sleep_for(std::chrono::seconds(2)); fdb.age_entries(std::chrono::seconds(1));
    std::cout << "  Entry count after aging (1s): " << fdb.entry_count() << std::endl;
    // Re-add one to ensure static is not aged
    fdb.learn_mac(mac2, 2, 100);
    fdb.add_static_entry(static_mac, 5, 100);
    std::cout << "  Entry count after re-adding one dynamic and one static: " << fdb.entry_count() << std::endl;
    fdb.age_entries(std::chrono::seconds(300)); // Default aging
    std::cout << "  Entry count after default aging (300s): " << fdb.entry_count() << std::endl;


    // Test flush_port
    std::cout << "\nTesting flush_port(4) (for mac1, VLAN 100)..." << std::endl;
    fdb.learn_mac(mac1, 4, 100); // ensure it's there
    std::cout << "  Entry count before flush_port(4): " << fdb.entry_count() << std::endl;
    fdb.flush_port(4);
    std::cout << "  Entry count after flush_port(4): " << fdb.entry_count() << std::endl;
    print_fdb_lookup(fdb, mac1, 100); // Should be gone


    // Test flush_vlan
    std::cout << "\nTesting flush_vlan(100)..." << std::endl;
    fdb.learn_mac(mac1, 1, 100); // re-learn
    fdb.learn_mac(mac2, 2, 100); // re-learn
    fdb.add_static_entry(static_mac, 5, 100); // re-add static
    std::cout << "  Entry count before flush_vlan(100): " << fdb.entry_count() << std::endl;
    fdb.flush_vlan(100);
    std::cout << "  Entry count after flush_vlan(100): " << fdb.entry_count() << std::endl;
    print_fdb_lookup(fdb, mac1, 100);
    print_fdb_lookup(fdb, mac2, 100);
    print_fdb_lookup(fdb, static_mac, 100);
    print_fdb_lookup(fdb, mac1, 200); // Should still be there if learned

    std::cout << "\n--- FDB Example Complete ---" << std::endl;

    return 0;
}
