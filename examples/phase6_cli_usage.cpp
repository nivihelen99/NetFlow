#include <iostream>
#include <string>
#include <vector>
#include <sstream> // For std::ostringstream in case any manager needs it for string conversion
#include <iomanip>   // For std::setw, std::left if needed by any manager for string conversion

// NetFlow++ Headers
#include "netflow++/interface_manager.hpp"
#include "netflow++/vlan_manager.hpp"
#include "netflow++/forwarding_database.hpp"
#include "netflow++/stp_manager.hpp"
#include "netflow++/lacp_manager.hpp"
#include "netflow++/routing_manager.hpp"
#include "netflow++/management_interface.hpp"
#include "netflow++/management_service.hpp"
#include "netflow++/packet.hpp" // For MacAddress
#include "netflow++/switch.hpp" // For full Switch class definition

// Example constants
const uint32_t NUM_PORTS_EXAMPLE = 8;
const uint64_t SWITCH_BASE_MAC_EXAMPLE = 0x001122334400ULL; // Base MAC for the switch
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
    mac_bytes[5] = (SWITCH_BASE_MAC_EXAMPLE & 0xFF) + port_id + 1; // Make it unique per port
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
        "interface port-channel 1 mode active", // Creates PC1
        "interface port-channel 1 rate fast",
        "interface 2 channel-group 1 mode active", // Add port 2 to PC1
        "interface 3 channel-group 1",             // Add port 3 to PC1
        "interface 2 lacp port-priority 100",
        "show lacp 1 internal",
        "// --- LLDP Commands ---",
        "show lldp interface", // Show initial state (should be disabled)
        "lldp enable",         // Enable LLDP globally
        "show lldp interface 0",
        "show lldp interface 1",
        "interface 0 lldp tx-interval 10",
        "interface 0 lldp ttl-multiplier 5",
        "show lldp interface 0",
        "// Note: show lldp neighbors may be empty unless another LLDP-enabled device is connected",
        "show lldp neighbors",
        "show lldp neighbors interface 0 detail",
        "interface 1 lldp disable",
        "show lldp interface 1",
        "lldp disable",        // Disable LLDP globally
        "show lldp interface", // Show final state
        // Clear commands
        "clear interface 0 stats",
        "clear mac address-table dynamic",
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
    // 1. Instantiate Managers
    netflow::InterfaceManager interface_manager;
    netflow::VlanManager vlan_manager;
    netflow::ForwardingDatabase fdb_manager;
    netflow::StpManager stp_manager(NUM_PORTS_EXAMPLE, SWITCH_BASE_MAC_EXAMPLE, DEFAULT_STP_PRIORITY_EXAMPLE);
    netflow::LacpManager lacp_manager(SWITCH_BASE_MAC_EXAMPLE, DEFAULT_LACP_SYSTEM_PRIORITY_EXAMPLE);
    netflow::RoutingManager routing_manager; // RoutingManager might need InterfaceManager

    // In a real application, Switch would own most managers. For this example, we create them separately.
    // However, LldpManager needs a Switch reference. We'll create a minimal Switch instance.
    // Note: This Switch instance is very basic and might not reflect full system behavior
    // if other managers it owns internally are not fully configured or if it has complex startup.
    // For the purpose of this CLI example, it primarily serves to provide the LldpManager.
    netflow::Switch mock_switch_for_example(NUM_PORTS_EXAMPLE, SWITCH_BASE_MAC_EXAMPLE);
    // LldpManager requires the Switch and InterfaceManager
    netflow::LldpManager lldp_manager(mock_switch_for_example, interface_manager);


    // Pre-configure some interfaces for demonstration
    for (uint32_t i = 0; i < NUM_PORTS_EXAMPLE; ++i) {
        netflow::InterfaceManager::PortConfig p_config;
        p_config.admin_up = true; // Default admin up
        p_config.mac_address = generate_port_mac(i);
        p_config.mtu = 1500;
        p_config.speed_mbps = 1000; // Default 1Gbps
        p_config.full_duplex = true;
        p_config.auto_negotiation = true;
        interface_manager.configure_port(i, p_config);

        // Default VLAN config (Port 0 in access vlan 1, others default)
        if (i == 0) {
            netflow::VlanManager::PortConfig v_config; // Default is access, vlan 1
            vlan_manager.configure_port(i, v_config);
        }
        // Default STP config (ports are initialized by StpManager constructor)
        // Default LACP config (ports are initialized when added to a LAG)
    }

    // 2. Instantiate ManagementInterface and ManagementService
    netflow::ManagementInterface management_interface;
    netflow::ManagementService management_service(
        routing_manager,
        interface_manager,
        management_interface,
        vlan_manager,
        fdb_manager,
        stp_manager,
        lacp_manager,
        lldp_manager // Pass LldpManager to ManagementService
    );

    // 3. Register CLI commands
    management_service.register_cli_commands();

    // 4. Run predefined sample commands
    run_sample_commands(management_interface);

    // 5. Start interactive console loop
    std::cout << "NetFlow++ Interactive CLI. Type 'exit' or 'quit' to exit.\n";
    std::string line;
    while (true) {
        std::cout << "RouterCLI> ";
        if (!std::getline(std::cin, line)) {
            break; // EOF or error
        }
        if (line == "exit" || line == "quit") {
            break;
        }
        if (line.empty()) {
            continue;
        }

        std::string output = management_interface.handle_cli_command(line);
        std::cout << output << std::endl;
    }

    std::cout << "Exiting CLI example." << std::endl;
    return 0;
}
