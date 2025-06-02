#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

// NetFlow++ Headers
#include "netflow++/switch.hpp" // For full Switch class definition and all its managers
#include "netflow++/management_interface.hpp"
#include "netflow++/management_service.hpp"
#include "netflow++/packet.hpp" // For MacAddress (though Switch includes it)

// Example constants
const uint32_t NUM_PORTS_EXAMPLE = 8;
const uint64_t SWITCH_BASE_MAC_EXAMPLE = 0x001122334400ULL;
const uint16_t DEFAULT_STP_PRIORITY_EXAMPLE = 32768;
const uint16_t DEFAULT_LACP_SYSTEM_PRIORITY_EXAMPLE = 32768;

// Helper to generate unique MAC for ports in the example
netflow::MacAddress generate_port_mac(uint32_t port_id) {
    uint8_t mac_bytes[6];
    mac_bytes[0] = (SWITCH_BASE_MAC_EXAMPLE >> 40) & 0xFF;
    mac_bytes[1] = (SWITCH_BASE_MAC_EXAMPLE >> 32) & 0xFF;
    mac_bytes[2] = (SWITCH_BASE_MAC_EXAMPLE >> 24) & 0xFF;
    mac_bytes[3] = (SWITCH_BASE_MAC_EXAMPLE >> 16) & 0xFF;
    mac_bytes[4] = (SWITCH_BASE_MAC_EXAMPLE >> 8) & 0xFF;
    mac_bytes[5] = (SWITCH_BASE_MAC_EXAMPLE & 0xFF) + port_id + 1;
    return netflow::MacAddress(mac_bytes);
}


void run_sample_commands(netflow::ManagementInterface& mi) {
    std::cout << "\n--- Running Sample Commands ---\n";
    std::vector<std::string> commands = {
        "help",
        // Show commands
        "show interface",
        "show interface 0",
        "show interface 0 stats",
        "show vlan",
        "show vlan 1",
        "show mac address-table",
        "show spanning-tree",
        "show spanning-tree interface 0 detail",
        "show lacp",
        "show lacp 1 internal",
        "show etherchannel summary",
        "show qos interface 0", // Added QoS show
        "show acl-rules",       // Added ACL show
        // Interface configuration
        "interface 0 shutdown",
        "interface 0 no shutdown",
        "interface 0 ip address 192.168.1.10 255.255.255.0",
        "interface 0 mtu 1600",
        "interface 0 speed 1000",
        "interface 0 duplex full",
        // VLAN configuration
        "interface 1 switchport mode access",
        "interface 1 switchport access vlan 100",
        "interface 2 switchport mode trunk",
        "interface 2 switchport trunk native vlan 99",
        "interface 2 switchport trunk allowed vlan add 10,20,30",
        "show vlan 100",
        "show vlan 99",
        // MAC configuration
        "mac address-table static 00:aa:bb:cc:dd:ee vlan 10 interface 1",
        "show mac address-table type static",
        "no mac address-table static 00:aa:bb:cc:dd:ee vlan 10",
        // STP configuration
        "spanning-tree priority 4096",
        "interface 0 spanning-tree cost 100",
        "interface 0 spanning-tree port-priority 112",
        "show spanning-tree",
        // LACP configuration
        "lacp system-priority 30000",
        "interface port-channel 1 mode active",
        "interface port-channel 1 rate fast",
        "interface 2 channel-group 1 mode active",
        "interface 3 channel-group 1",
        "interface 2 lacp port-priority 100",
        "show lacp 1 internal",
        "// --- LLDP Commands ---",
        "show lldp interface",
        "lldp enable",
        "show lldp interface 0",
        "interface 0 lldp tx-interval 10",
        "show lldp interface 0",
        "show lldp neighbors",
        "lldp disable",
        "// --- QoS Commands ---",
        "interface 0 qos enable",
        "interface 0 qos num-queues 2",
        "interface 0 qos scheduler strict-priority",
        "interface 0 qos max-depth 500",
        "show qos interface 0 config",
        "// --- ACL Commands ---",
        "acl-rule add id 1 priority 100 action permit src-ip 10.0.0.1 dst-ip 10.0.0.2 protocol tcp dst-port 80",
        "acl-rule add id 2 priority 90 action deny src-ip 10.0.0.0", // Simpler rule using default IP mask from AclRule if any
        "acl-compile",
        "show acl-rules",
        "show acl-rules id 1",
        // Clear commands
        "clear interface 0 stats",
        "clear mac address-table dynamic",
        "clear qos interface 0 stats", // Added QoS clear
        // Invalid commands for error demonstration
        "show foobar",
        "interface 999 shutdown"
    };

    for (const auto& cmd : commands) {
        std::cout << "\nRouterCLI> " << cmd << std::endl;
        std::string output = mi.handle_cli_command(cmd);
        std::cout << output << std::endl;
    }
    std::cout << "\n--- Sample Commands Finished ---\n\n";
}

int main() {
    // 1. Instantiate Switch (which owns all core managers)
    // The Switch constructor now handles logger initialization internally.
    netflow::Switch sw(NUM_PORTS_EXAMPLE, SWITCH_BASE_MAC_EXAMPLE,
                       DEFAULT_STP_PRIORITY_EXAMPLE, DEFAULT_LACP_SYSTEM_PRIORITY_EXAMPLE);

    // Pre-configure some interfaces for demonstration using the switch's InterfaceManager
    for (uint32_t i = 0; i < NUM_PORTS_EXAMPLE; ++i) {
        netflow::InterfaceManager::PortConfig p_config;
        p_config.admin_up = true;
        p_config.mac_address = generate_port_mac(i);
        p_config.mtu = 1500;
        p_config.speed_mbps = 1000;
        p_config.full_duplex = true;
        p_config.auto_negotiation = true;
        sw.interface_manager_.configure_port(i, p_config);
        sw.interface_manager_.simulate_port_link_up(i); // Ensure link is up

        if (i == 0) {
            netflow::VlanManager::PortConfig v_config;
            sw.vlan_manager.configure_port(i, v_config);
        }
    }

    // 2. Instantiate ManagementInterface (if it's standalone) and ManagementService
    // ManagementInterface is part of the Switch instance (sw.management_interface_)
    netflow::ManagementService management_service(
        sw.logger_, // Pass logger from Switch
        sw.routing_manager_,
        sw.interface_manager_,
        sw.management_interface_, // Pass ManagementInterface from Switch
        sw.vlan_manager,
        sw.fdb,
        sw.stp_manager,
        sw.lacp_manager_,
        sw.lldp_manager_,
        sw.qos_manager_,    // Pass QosManager from Switch
        sw.acl_manager_     // Pass AclManager from Switch
    );

    // 3. Register CLI commands
    management_service.register_cli_commands();

    // 4. Run predefined sample commands
    run_sample_commands(sw.management_interface_); // Pass ManagementInterface from Switch

    // 5. Start interactive console loop
    std::cout << "NetFlow++ Interactive CLI. Type 'exit' or 'quit' to exit.\n";
    std::string line;
    while (true) {
        std::cout << "RouterCLI> ";
        if (!std::getline(std::cin, line)) {
            break;
        }
        if (line == "exit" || line == "quit") {
            break;
        }
        if (line.empty()) {
            continue;
        }

        std::string output = sw.management_interface_.handle_cli_command(line);
        std::cout << output << std::endl;
    }

    std::cout << "Exiting CLI example." << std::endl;
    return 0;
}
