#include "netflow_plus_plus/port/interface_manager.hpp"
#include "netflow_plus_plus/switching/vlan_manager.hpp"
#include <iostream>
#include <string>

void print_port_config(uint32_t port_id, const netflow_plus_plus::port::PortConfig& config) {
    std::cout << "  Port " << port_id << " Config:\n"
              << "    Admin Up: " << (config.admin_up ? "Yes" : "No") << "\n"
              << "    Speed: " << config.speed_mbps << " Mbps\n"
              << "    MTU: " << config.mtu << std::endl;
}

void print_vlan_port_config(uint32_t port_id, const netflow_plus_plus::switching::VlanPortConfig& config) {
    std::cout << "  Port " << port_id << " VLAN Config:\n"
              << "    Mode: " << (config.mode == netflow_plus_plus::switching::PortMode::ACCESS ? "ACCESS" : "TRUNK") << "\n"
              << "    Native VLAN: " << config.native_vlan << "\n"
              << "    Allowed VLANs: ";
    for (uint16_t vlan : config.allowed_vlans) {
        std::cout << vlan << " ";
    }
    std::cout << "\n    Tag Native: " << (config.tag_native_traffic ? "Yes" : "No") << std::endl;
}

int main() {
    std::cout << "--- Phase 4: Interface and VLAN Configuration Example ---" << std::endl;

    netflow_plus_plus::port::InterfaceManager if_manager;
    netflow_plus_plus::switching::VlanManager vlan_manager;

    // 1. Configure Physical Ports
    std::cout << "\n1. Configuring Physical Ports..." << std::endl;
    netflow_plus_plus::port::PortConfig p1_config;
    p1_config.admin_up = true;
    p1_config.speed_mbps = 1000;
    p1_config.mtu = 1500;
    if_manager.configure_port(1, p1_config);
    std::cout << "  Configured Port 1." << std::endl;
    print_port_config(1, if_manager.get_port_config(1));

    netflow_plus_plus::port::PortConfig p2_config = {true, 10000, true, true, 9000};
    if_manager.configure_port(2, p2_config);
    std::cout << "  Configured Port 2." << std::endl;
    print_port_config(2, if_manager.get_port_config(2));

    std::cout << "  Port 1 is up: " << (if_manager.is_port_up(1) ? "Yes" : "No") << std::endl;
    std::cout << "  Setting Port 2 admin state to down." << std::endl;
    if_manager.set_port_admin_state(2, false);
    print_port_config(2, if_manager.get_port_config(2));


    // 2. Create VLANs
    std::cout << "\n2. Creating VLANs..." << std::endl;
    vlan_manager.create_vlan(10);
    vlan_manager.create_vlan(20);
    vlan_manager.create_vlan(30);
    std::cout << "  Created VLANs 10, 20, 30." << std::endl;
    std::cout << "  Is VLAN 20 created? " << (vlan_manager.is_vlan_created(20) ? "Yes" : "No") << std::endl;
    std::cout << "  Is VLAN 40 created? " << (vlan_manager.is_vlan_created(40) ? "Yes" : "No") << std::endl;
    
    std::cout << "  Configured VLANs: ";
    for(uint16_t v_id : vlan_manager.get_configured_vlans()){
        std::cout << v_id << " ";
    }
    std::cout << std::endl;

    // 3. Configure Port VLAN properties
    std::cout << "\n3. Configuring Port VLAN properties..." << std::endl;

    // Port 1: Access mode, VLAN 10
    netflow_plus_plus::switching::VlanPortConfig p1_vlan_config;
    p1_vlan_config.mode = netflow_plus_plus::switching::PortMode::ACCESS;
    p1_vlan_config.native_vlan = 10;
    // For access mode, allowed_vlans will be automatically set to native_vlan if native_vlan is created.
    vlan_manager.configure_port(1, p1_vlan_config);
    std::cout << "  Configured Port 1 for ACCESS mode, VLAN 10." << std::endl;
    print_vlan_port_config(1, vlan_manager.get_port_vlan_config(1));

    // Port 2: Trunk mode, Native VLAN 1 (default), Allow VLANs 20, 30
    // Ensure port 2 admin state is up for this test.
    if_manager.set_port_admin_state(2, true);
    print_port_config(2, if_manager.get_port_config(2));


    netflow_plus_plus::switching::VlanPortConfig p2_vlan_config;
    p2_vlan_config.mode = netflow_plus_plus::switching::PortMode::TRUNK;
    p2_vlan_config.native_vlan = 1; // Default, often used for untagged mgmt traffic
    vlan_manager.create_vlan(1); // Ensure native VLAN 1 is created
    p2_vlan_config.allowed_vlans = {20, 30}; // Explicitly set allowed VLANs for trunk
                                           // Native VLAN 1 will also be added to allowed_vlans by configure_port
    p2_vlan_config.tag_native_traffic = false; // Untagged native traffic
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Configured Port 2 for TRUNK mode, Native 1, Allowed 20, 30." << std::endl;
    print_vlan_port_config(2, vlan_manager.get_port_vlan_config(2));
    
    // Test should_forward (placeholder logic)
    std::cout << "\n4. Testing should_forward (simplified)..." << std::endl;
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10? (P1:Access 10, P2:Trunk allow 1,20,30 native 1): "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl; // No, P2 doesn't allow 10
    vlan_manager.create_vlan(10); // ensure 10 is created
    p2_vlan_config.allowed_vlans.insert(10); // Manually add 10 to port 2 allowed for this test
    vlan_manager.configure_port(2, p2_vlan_config); // reconfigure port 2
    std::cout << "  Reconfigured Port 2 to allow VLAN 10 on trunk." << std::endl;
    print_vlan_port_config(2, vlan_manager.get_port_vlan_config(2));
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10 now? "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl; // Yes

    std::cout << "  Should Port 1 forward to Port 2 on VLAN 20? (P1:Access 10, P2:Trunk allow 1,10,20,30 native 1): "
              << (vlan_manager.should_forward(1, 2, 20) ? "Yes" : "No") << std::endl; // No, P1 is access 10


    // Test deleting a VLAN
    std::cout << "\n5. Deleting VLAN 20..." << std::endl;
    vlan_manager.delete_vlan(20);
    std::cout << "  Is VLAN 20 created? " << (vlan_manager.is_vlan_created(20) ? "Yes" : "No") << std::endl;
    std::cout << "  Port 2 VLAN config after deleting VLAN 20:" << std::endl;
    print_vlan_port_config(2, vlan_manager.get_port_vlan_config(2));


    std::cout << "\n--- Interface and VLAN Configuration Example Complete ---" << std::endl;
    return 0;
}
