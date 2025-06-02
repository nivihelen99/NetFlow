#include "netflow++/interface_manager.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/logger.hpp"      // Added for SwitchLogger
#include "netflow++/acl_manager.hpp" // Added for AclManager
#include <iostream>
#include <string>
#include <vector>
#include <set> // For std::set in VlanManager::PortConfig if used

void print_port_config(uint32_t port_id, const netflow::InterfaceManager::PortConfig& config) {
    std::cout << "  Port " << port_id << " Config:\n"
              << "    Admin Up: " << (config.admin_up ? "Yes" : "No") << "\n"
              << "    Speed: " << config.speed_mbps << " Mbps\n"
              << "    MTU: " << config.mtu << std::endl;
}

void print_vlan_port_config(uint32_t port_id, const netflow::VlanManager::PortConfig& config) {
    std::cout << "  Port " << port_id << " VLAN Config:\n"
              << "    Mode: ";
    switch (config.type) {
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
    std::cout << "\n    Tag Native: " << (config.tag_native ? "Yes" : "No") << std::endl;
}

int main() {
    std::cout << "--- Phase 4: Interface and VLAN Configuration Example ---" << std::endl;

    netflow::SwitchLogger logger(netflow::LogLevel::INFO); // Create logger instance
    netflow::AclManager acl_manager(logger);             // Create AclManager instance
    netflow::InterfaceManager if_manager(logger, acl_manager); // Pass dependencies
    netflow::VlanManager vlan_manager;

    // 1. Configure Physical Ports
    std::cout << "\n1. Configuring Physical Ports..." << std::endl;
    netflow::InterfaceManager::PortConfig p1_config;
    p1_config.admin_up = true;
    p1_config.speed_mbps = 1000;
    p1_config.mtu = 1500;
    if_manager.configure_port(1, p1_config);
    std::cout << "  Configured Port 1." << std::endl;
    if (auto cfg = if_manager.get_port_config(1)) print_port_config(1, cfg.value()); else std::cout << "Port 1 config not found!\n";

    netflow::InterfaceManager::PortConfig p2_config;
    p2_config.admin_up = true;
    p2_config.speed_mbps = 10000;
    p2_config.full_duplex = true;
    p2_config.auto_negotiation = true;
    p2_config.mtu = 9000;
    if_manager.configure_port(2, p2_config);
    std::cout << "  Configured Port 2." << std::endl;
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";

    std::cout << "  Port 1 is admin up: " << (if_manager.is_port_admin_up(1) ? "Yes" : "No") << std::endl;
    std::cout << "  Setting Port 2 admin state to down." << std::endl;
    std::optional<netflow::InterfaceManager::PortConfig> p2_config_opt = if_manager.get_port_config(2);
    if (p2_config_opt) {
        netflow::InterfaceManager::PortConfig p2_modifiable_config = p2_config_opt.value();
        p2_modifiable_config.admin_up = false;
        if_manager.configure_port(2, p2_modifiable_config);
    }
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";


    std::cout << "\n2. VLANs are managed via port configurations." << std::endl;
    
    std::cout << "\n3. Configuring Port VLAN properties..." << std::endl;

    netflow::VlanManager::PortConfig p1_vlan_config;
    p1_vlan_config.type = netflow::PortType::ACCESS;
    p1_vlan_config.native_vlan = 10;
    vlan_manager.configure_port(1, p1_vlan_config);
    std::cout << "  Configured Port 1 for ACCESS mode, VLAN 10." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(1)) print_vlan_port_config(1, cfg.value()); else std::cout << "Port 1 VLAN config not found!\n";

    netflow::InterfaceManager::PortConfig p2_if_cfg_temp = if_manager.get_port_config(2).value_or(netflow::InterfaceManager::PortConfig());
    p2_if_cfg_temp.admin_up = true;
    if_manager.configure_port(2, p2_if_cfg_temp);
    if (auto cfg = if_manager.get_port_config(2)) print_port_config(2, cfg.value()); else std::cout << "Port 2 config not found!\n";


    netflow::VlanManager::PortConfig p2_vlan_config;
    p2_vlan_config.type = netflow::PortType::TRUNK;
    p2_vlan_config.native_vlan = 1;
    p2_vlan_config.allowed_vlans = {1, 20, 30};
    p2_vlan_config.tag_native = false;
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Configured Port 2 for TRUNK mode, Native 1, Allowed 1,20,30." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value()); else std::cout << "Port 2 VLAN config not found!\n";
    
    std::cout << "\n4. Testing should_forward..." << std::endl;
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10? (P1:Access 10, P2:Trunk allow 1,20,30 native 1): "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl;

    p2_vlan_config = vlan_manager.get_port_config(2).value_or(netflow::VlanManager::PortConfig()); // Get current before modifying
    p2_vlan_config.allowed_vlans.insert(10);
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Reconfigured Port 2 to allow VLAN 10 on trunk." << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value());  else std::cout << "Port 2 VLAN config not found!\n";
    std::cout << "  Should Port 1 forward to Port 2 on VLAN 10 now? "
              << (vlan_manager.should_forward(1, 2, 10) ? "Yes" : "No") << std::endl;

    std::cout << "  Should Port 1 forward to Port 2 on VLAN 20? (P1:Access 10, P2 allows 1,10,20,30): "
              << (vlan_manager.should_forward(1, 2, 20) ? "Yes" : "No") << std::endl;


    std::cout << "\n5. Removing VLAN 20 from Port 2..." << std::endl;
    p2_vlan_config = vlan_manager.get_port_config(2).value_or(netflow::VlanManager::PortConfig());
    p2_vlan_config.allowed_vlans.erase(20);
    vlan_manager.configure_port(2, p2_vlan_config);
    std::cout << "  Port 2 VLAN config after removing VLAN 20 from allowed list:" << std::endl;
    if(auto cfg = vlan_manager.get_port_config(2)) print_vlan_port_config(2, cfg.value()); else std::cout << "Port 2 VLAN config not found!\n";


    std::cout << "\n--- Interface and VLAN Configuration Example Complete ---" << std::endl;
    return 0;
}
