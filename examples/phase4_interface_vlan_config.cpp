#include "netflow++/interface_manager.hpp" // Updated include
#include "netflow++/vlan_manager.hpp"    // Updated include
#include <iostream>
#include <string>
#include <vector> // For iterating over allowed_vlans if it's a set/vector

// Using declarations for brevity if desired, or qualify fully
// using netflow::InterfaceManager;
// using netflow::VlanManager;
// using netflow::PortType;
// using netflow::InterfaceManager::PortConfig; // This is how it's defined in interface_manager.hpp
// using VlanPortConfig = netflow::VlanManager::PortConfig; // Alias for clarity if preferred

void print_port_config(uint32_t port_id, const netflow::InterfaceManager::PortConfig& config) { // Updated namespace and type
    std::cout << "  Port " << port_id << " Config:\n"
              << "    Admin Up: " << (config.admin_up ? "Yes" : "No") << "\n"
              << "    Speed: " << config.speed_mbps << " Mbps\n"
              << "    MTU: " << config.mtu << std::endl;
}

void print_vlan_port_config(uint32_t port_id, const netflow::VlanManager::PortConfig& config) { // Updated namespace and type
    std::cout << "  Port " << port_id << " VLAN Config:\n"
              << "    Mode: ";
    switch (config.type) { // Changed from 'mode' to 'type'
        case netflow::PortType::ACCESS: std::cout << "ACCESS"; break;
        case netflow::PortType::TRUNK:  std::cout << "TRUNK"; break;
        case netflow::PortType::HYBRID: std::cout << "HYBRID"; break;
        default: std::cout << "UNKNOWN"; break;
    }
    std::cout << "\n    Native VLAN: " << config.native_vlan << "\n"
              << "    Allowed VLANs: ";
    for (uint16_t vlan : config.allowed_vlans) {
        std::cout << vlan << " ";
    }
    std::cout << "\n    Tag Native: " << (config.tag_native ? "Yes" : "No") << std::endl; // Changed from tag_native_traffic
}

int main() {
    std::cout << "--- Phase 4: Interface and VLAN Configuration Example ---" << std::endl;

    netflow::InterfaceManager if_manager; // Updated namespace
    netflow::VlanManager vlan_manager;    // Updated namespace

    // 1. Configure Physical Ports
    std::cout << "\n1. Configuring Physical Ports..." << std::endl;
    netflow::InterfaceManager::PortConfig p1_config; // Updated namespace and type
    p1_config.admin_up = true;
    p1_config.speed_mbps = 1000;
    p1_config.mtu = 1500;
    if_manager.configure_port(1, p1_config);
    std::cout << "  Configured Port 1." << std::endl;
    if (auto cfg = if_manager.get_port_config(1)) print_port_config(1, cfg.value()); else std::cout << "Port 1 config not found!\n";

    netflow::InterfaceManager::PortConfig p2_config; // Default construct
    p2_config.admin_up = true;
    p2_config.speed_mbps = 10000;
    p2_config.full_duplex = true;
    p2_config.auto_negotiation = true;
    p2_config.mtu = 9000;
    // p2_config.mac_address remains default initialized
    // p2_config.ip_configurations remains default initialized (empty)
    if_manager.configure_port(2, p2_config);
    std::cout << "  Configured Port 2." << std::endl;
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";

    std::cout << "  Port 1 is admin up: " << (if_manager.is_port_admin_up(1) ? "Yes" : "No") << std::endl; // Changed to is_port_admin_up
    std::cout << "  Setting Port 2 admin state to down." << std::endl;
    // To modify, get the config, change it, then re-configure
    std::optional<netflow::InterfaceManager::PortConfig> p2_config_opt = if_manager.get_port_config(2);
    if (p2_config_opt) {
        netflow::InterfaceManager::PortConfig p2_modifiable_config = p2_config_opt.value();
        p2_modifiable_config.admin_up = false; // Modify
        if_manager.configure_port(2, p2_modifiable_config); // Re-configure
    }
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";


    // 2. Create VLANs (VlanManager no longer has create_vlan, is_vlan_created, get_configured_vlans)
    // VLANs are implicitly "created" by being used in port configurations.
    // The VlanManager itself doesn't maintain a global list of created VLANs anymore.
    // Its role is to manage port VLAN memberships and process packets based on that.
    std::cout << "\n2. VLANs are managed via port configurations." << std::endl;
    // vlan_manager.create_vlan(10); // Removed
    // vlan_manager.create_vlan(20); // Removed
    // vlan_manager.create_vlan(30); // Removed
    // std::cout << "  VLANs 10, 20, 30 are now implicitly available if used in port configs." << std::endl;
    // std::cout << "  Is VLAN 20 'created'? (No direct query, depends on usage)" << std::endl;
    

    // 3. Configure Port VLAN properties
    std::cout << "\n3. Configuring Port VLAN properties..." << std::endl;

    // Port 1: Access mode, VLAN 10
    netflow::VlanManager::PortConfig p1_vlan_config; // Updated namespace and type
    p1_vlan_config.type = netflow::PortType::ACCESS; // Changed from mode to type
    p1_vlan_config.native_vlan = 10;
    vlan_manager.configure_port(1, p1_vlan_config); // configure_port will handle allowed_vlans for access mode
    std::cout << "  Configured Port 1 for ACCESS mode, VLAN 10." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(1)) print_vlan_port_config(1, cfg.value()); else std::cout << "Port 1 VLAN config not found!\n";

    // Port 2: Trunk mode, Native VLAN 1 (default), Allow VLANs 20, 30
    // Ensure port 2 admin state is up for this test.
    // if_manager.set_port_admin_state(2, true); // Old method
    netflow::InterfaceManager::PortConfig p2_if_cfg_temp = if_manager.get_port_config(2).value_or(netflow::InterfaceManager::PortConfig());
    p2_if_cfg_temp.admin_up = true;
    if_manager.configure_port(2, p2_if_cfg_temp);
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";


    netflow::VlanManager::PortConfig p2_vlan_config; // Updated type
    p2_vlan_config.type = netflow::PortType::TRUNK;  // Changed from mode to type
    p2_vlan_config.native_vlan = 1;
    p2_vlan_config.allowed_vlans = {1, 20, 30}; // Native VLAN 1 explicitly added to allowed for clarity on trunk
    p2_vlan_config.tag_native = false;      // Changed from tag_native_traffic
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Configured Port 2 for TRUNK mode, Native 1, Allowed 1,20,30." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value()); else std::cout << "Port 2 VLAN config not found!\n";
    
    // Test should_forward
    std::cout << "\n4. Testing should_forward..." << std::endl;
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10? (P1:Access 10, P2:Trunk allow 1,20,30 native 1): "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl;

    // Reconfigure Port 2 to allow VLAN 10 for testing should_forward
    p2_vlan_config.allowed_vlans.insert(10);
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Reconfigured Port 2 to allow VLAN 10 on trunk." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value());  else std::cout << "Port 2 VLAN config not found!\n";
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10 now? "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl;

    std::cout << "  Should Port 1 forward to Port 2 on VLAN 20? (P1:Access 10, P2 allows 1,10,20,30): "
              << (vlan_manager.should_forward(1, 2, 20) ? "Yes" : "No") << std::endl;


    // Test deleting a VLAN (VlanManager no longer has delete_vlan)
    // Deleting a VLAN now means removing it from all port configurations.
    std::cout << "\n5. Removing VLAN 20 from Port 2..." << std::endl;
    // vlan_manager.delete_vlan(20); // Removed
    p2_vlan_config = vlan_manager.get_port_config(2).value_or(netflow::VlanManager::PortConfig());
    p2_vlan_config.allowed_vlans.erase(20);
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Port 2 VLAN config after removing VLAN 20 from allowed list:" << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value()); else std::cout << "Port 2 VLAN config not found!\n";


    std::cout << "\n--- Interface and VLAN Configuration Example Complete ---" << std::endl;
    return 0;
}
