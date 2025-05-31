#include "netflow++/switch.hpp"
#include <iostream>
#include <vector>

// Example packet handler function (optional)
void handle_cpu_packet(netflow::Packet& pkt, uint32_t ingress_port) {
    std::cout << "[CPU Handler] Received packet on port " << ingress_port
              << " (size: " << pkt.get_buffer()->size << " bytes)." << std::endl;
    // Potentially inspect the packet further
    // netflow::EthernetHeader* eth = pkt.ethernet();
    // if (eth) {
    //     std::cout << "  EthType: 0x" << std::hex << ntohs(eth->ethertype) << std::dec << std::endl;
    // }
}

int main(int argc, char* argv[]) {
    std::cout << "Netflow++ Software Switch Simulation" << std::endl;

    // Define default MAC and priorities for the switch
    uint32_t num_ports = 4; // Example: 4 ports
    uint64_t switch_main_mac = 0x0000DEADBEEF0001ULL; // Example MAC
    uint16_t default_stp_priority = 0x8000; // 32768
    uint16_t default_lacp_priority = 32768;

    // Create a switch with a specific number of ports and MAC address
    netflow::Switch sw(num_ports, switch_main_mac, default_stp_priority, default_lacp_priority);

    // Configure packet handler (optional)
    sw.set_packet_handler(handle_cpu_packet);

    // --- Example Configuration ---
    // STP Bridge configuration is now handled by Switch constructor passing MAC/priority to StpManager.
    // Old manual configuration:
    // netflow::StpManager::BridgeConfig bridge_cfg;
    // bridge_cfg.bridge_id = 0x8000000000000001ULL; // Example bridge ID (priority + MAC)
    // sw.stp_manager.set_bridge_config(bridge_cfg); // This method might be removed or changed in StpManager
    // std::cout << "STP Bridge ID set to: 0x" << std::hex << sw.stp_manager.get_bridge_config().bridge_id_value << std::dec << std::endl;


    // 2. Port Configuration (VLANs)
    netflow::VlanManager::PortConfig access_port_cfg;
    access_port_cfg.type = netflow::PortType::ACCESS;
    access_port_cfg.native_vlan = 10; // VLAN 10 for port 0
    sw.vlan_manager.configure_port(0, access_port_cfg);
    std::cout << "Port 0 configured as ACCESS, Native VLAN 10." << std::endl;

    netflow::VlanManager::PortConfig trunk_port_cfg;
    trunk_port_cfg.type = netflow::PortType::TRUNK;
    trunk_port_cfg.native_vlan = 1; // Native VLAN 1 for port 1
    trunk_port_cfg.allowed_vlans = {1, 10, 20}; // Allowed VLANs on trunk
    trunk_port_cfg.tag_native = false; // Do not tag native VLAN 1 on egress
    sw.vlan_manager.configure_port(1, trunk_port_cfg);
    std::cout << "Port 1 configured as TRUNK, Native VLAN 1, Allowed: 1,10,20." << std::endl;

    // Configure other ports as simple access ports in VLAN 1 for testing
    netflow::VlanManager::PortConfig default_access_config;
    default_access_config.type = netflow::PortType::ACCESS;
    default_access_config.native_vlan = 1;
    for(uint32_t i = 2; i < num_ports; ++i) {
        sw.vlan_manager.configure_port(i, default_access_config);
        // sw.stp_manager.set_port_state(i, netflow::StpManager::PortState::FORWARDING); // Assume STP converged - Method removed
    }
    // sw.stp_manager.set_port_state(0, netflow::StpManager::PortState::FORWARDING); // Method removed
    // sw.stp_manager.set_port_state(1, netflow::StpManager::PortState::FORWARDING); // Method removed


    // --- Logger Example ---
    sw.logger_.info("MAIN", "Switch initialization complete. Management interface getting ready.");
    sw.logger_.set_min_log_level(netflow::LogLevel::DEBUG); // Set to DEBUG for more verbose output during setup
    sw.logger_.debug("MAIN", "Logger level set to DEBUG for detailed setup logs.");


    // --- ConfigManager Example Usage ---
    std::cout << "\n--- ConfigManager Examples ---" << std::endl;
    sw.logger_.info("CONFIG_MAIN", "Demonstrating ConfigManager parameter setting...");
    sw.config_manager_.set_parameter("port.1.admin_up", true);
    sw.config_manager_.set_parameter("port.1.speed_mbps", static_cast<uint32_t>(10000)); // Set speed for port 1 again via config
    sw.config_manager_.set_parameter("vlan.20.name", std::string("Engineering")); // Example of a VLAN name
    sw.config_manager_.set_parameter("global.hostname", std::string("MyCoreSwitch"));

    // Apply these manually set parameters
    sw.logger_.info("CONFIG_MAIN", "Applying manually set parameters to the switch...");
    sw.config_manager_.apply_config(sw.config_manager_.get_current_config_data(), sw); // Old signature was correct

    // Verify if admin_up for port 1 was applied (optional check)
    auto port1_cfg_after_apply = sw.interface_manager_.get_port_config(1);
    if (port1_cfg_after_apply && port1_cfg_after_apply.value().admin_up) {
        sw.logger_.info("CONFIG_VERIFY", "Port 1 is now admin_up after apply_config.");
        // If port 1 was previously link_down due to admin_down, and now admin_up, simulate link going up
        if(!sw.interface_manager_.is_port_link_up(1)) {
            sw.interface_manager_.simulate_port_link_up(1);
        }
    } else {
        sw.logger_.warning("CONFIG_VERIFY", "Port 1 admin_up status not correctly applied or port not found.");
    }

    // Placeholder save
    if (sw.config_manager_.save_config("current_config_output.json")) {
        sw.logger_.info("CONFIG_MAIN", "Configuration saved (placeholder) to current_config_output.json");
    } else {
        sw.logger_.error("CONFIG_MAIN", "Failed to save configuration (placeholder).");
    }


    // --- ManagementInterface Example Usage ---
    std::cout << "\n--- ManagementInterface Examples ---" << std::endl;
    sw.logger_.info("MGMT_IF_MAIN", "Registering sample CLI commands and OID handlers...");

    // CLI Command
    sw.management_interface_.register_command("show_version",
        [&](const std::vector<std::string>& args) -> std::string {
            // Accessing logger from Switch instance captured by lambda (if needed, or use global)
            // sw.logger_.debug("CLI_HANDLER", "'show_version' command executed.");
            return "NetFlow++ Switch Version 1.0.1-alpha";
        }
    );
    std::string version_output = sw.management_interface_.handle_cli_command("show_version");
    sw.logger_.info("CLI_TEST", "Output of 'show_version': " + version_output);
    std::string help_output = sw.management_interface_.handle_cli_command("help"); // Test unknown command
    sw.logger_.info("CLI_TEST", "Output of 'help': " + help_output);

    // OID Handler
    sw.management_interface_.register_oid_handler(
        "1.3.6.1.2.1.1.1.0", // sysDescr OID
        [](){ return std::string("NetFlow++ Switch - High Performance Software Defined Networking"); }
    );
    auto oid_val = sw.management_interface_.handle_oid_get("1.3.6.1.2.1.1.1.0");
    if(oid_val) {
        sw.logger_.info("OID_TEST", "Value of OID '1.3.6.1.2.1.1.1.0' (sysDescr): " + oid_val.value());
    } else {
        sw.logger_.warning("OID_TEST", "Could not get value for OID '1.3.6.1.2.1.1.1.0'.");
    }
    bool oid_set_result = sw.management_interface_.handle_oid_set("1.3.6.1.2.1.1.1.0", "New Description"); // Try to set a read-only OID
    sw.logger_.info("OID_TEST", std::string("Attempt to set read-only OID '1.3.6.1.2.1.1.1.0': ") + (oid_set_result ? "Succeeded (unexpected)" : "Failed (expected)"));


    // --- Start the switch ---
    sw.start(); // Calls the placeholder start method

    // --- Interface Manager Example Usage (Original examples, can be kept or modified) ---
    std::cout << "\n--- Interface Manager Examples ---" << std::endl;
    netflow::InterfaceManager::PortConfig port1_config;
    port1_config.admin_up = true;
    port1_config.speed_mbps = 10000; // 10 Gbps
    port1_config.mtu = 9000;        // Jumbo frame
    sw.interface_manager_.configure_port(1, port1_config);
    std::cout << "Port 1 configured: admin_up=" << std::boolalpha << port1_config.admin_up
              << ", speed=" << port1_config.speed_mbps << " Mbps, MTU=" << port1_config.mtu << std::endl;

    sw.interface_manager_.on_link_up([](uint32_t port_id){
        std::cout << "[Callback] Port " << port_id << " link is UP." << std::endl;
    });
    sw.interface_manager_.on_link_down([](uint32_t port_id){
        std::cout << "[Callback] Port " << port_id << " link is DOWN." << std::endl;
    });

    sw.interface_manager_.simulate_port_link_down(1); // Should call link_down_callbacks
    sw.interface_manager_.simulate_port_link_up(1);   // Should call link_up_callbacks
    std::cout << "Port 1 link status (simulated): " << std::boolalpha
              << sw.interface_manager_.is_port_link_up(1) << std::endl;


    // --- Packet Classifier and Flow Table Example Usage ---
    std::cout << "\n--- Packet Classifier & Flow Table Examples ---" << std::endl;
    netflow::PacketClassifier::FlowKey rule_key_template;
    rule_key_template.src_ip = ntohl(0xC0A80101); // 192.168.1.1
    rule_key_template.dst_ip = ntohl(0xC0A8010A); // 192.168.1.10
    rule_key_template.protocol = 6; // TCP
    rule_key_template.dst_port = ntohs(80); // Port 80 (HTTP)

    netflow::PacketClassifier::FlowKey rule_mask; // Mask for specific fields
    // For IP and port matching, typically use all 1s in mask for fields to match
    rule_mask.src_ip = 0xFFFFFFFF;
    rule_mask.dst_ip = 0xFFFFFFFF;
    rule_mask.protocol = 0xFF;
    rule_mask.dst_port = 0xFFFF;
    // Other fields in mask are 0 (wildcard) by default in FlowKey constructor

    uint32_t rule_action_id = 1001; // Custom action ID for this rule
    netflow::PacketClassifier::ClassificationRule http_rule(rule_key_template, rule_mask, rule_action_id, 100); // Priority 100
    sw.packet_classifier_.add_rule(http_rule);
    std::cout << "Added HTTP classification rule for 192.168.1.1 -> 192.168.1.10:80, action_id=" << rule_action_id << std::endl;

    // Example FlowKey for table insertion (can be extracted from a packet or created manually)
    netflow::Switch::FlowKey flow_key_example = rule_key_template; // Use the same key for simplicity
    uint32_t flow_action_id = 2002;
    if (sw.flow_table_.insert(flow_key_example, flow_action_id)) {
        std::cout << "Inserted flow into FlowTable. Key (src_ip=" << std::hex << flow_key_example.src_ip
                  << ", dst_port=" << std::dec << ntohs(flow_key_example.dst_port) // Display in host order for readability
                  << "), action_id=" << flow_action_id << std::endl;
    }
    auto looked_up_action = sw.flow_table_.lookup(flow_key_example);
    if (looked_up_action) {
        std::cout << "Lookup in FlowTable successful. Action ID: " << *looked_up_action << std::endl;
    }


    // --- Simulate Packet Processing (Example) ---
    std::cout << "\n--- Simulating Packet Processing ---" << std::endl;
    // Ensure port 0 (ingress for first test packet) is also link up for packet to pass
    netflow::InterfaceManager::PortConfig main_port0_config; // Renamed to avoid conflict
    main_port0_config.admin_up = true;
    sw.interface_manager_.configure_port(0, main_port0_config);
    sw.interface_manager_.simulate_port_link_up(0);
    std::cout << "Port 0 link status (simulated): " << std::boolalpha
              << sw.interface_manager_.is_port_link_up(0) << std::endl;

    // Ensure port 2 is up for ACL redirect test
    netflow::InterfaceManager::PortConfig main_port2_config;
    main_port2_config.admin_up = true;
    sw.interface_manager_.configure_port(2, main_port2_config);
    sw.interface_manager_.simulate_port_link_up(2);
    std::cout << "Port 2 link status (simulated): " << std::boolalpha
              << sw.interface_manager_.is_port_link_up(2) << std::endl;


    // --- QoS Example Configuration ---
    std::cout << "\n--- QoS Configuration Example ---" << std::endl;
    netflow::QosConfig qos_cfg_p1;
    qos_cfg_p1.num_queues = 2;
    qos_cfg_p1.scheduler = netflow::SchedulerType::STRICT_PRIORITY;
    // queue_weights and rate_limits_kbps will be default sized by validate_and_prepare
    sw.qos_manager_.configure_port_qos(1, qos_cfg_p1); // Configure QoS for port 1

    netflow::QosConfig qos_cfg_p2; // For ACL redirect port
    qos_cfg_p2.num_queues = 4;
    sw.qos_manager_.configure_port_qos(2, qos_cfg_p2);


    // --- ACL Example Configuration ---
    std::cout << "\n--- ACL Configuration Example ---" << std::endl;
    netflow::AclRule acl_deny_rule;
    acl_deny_rule.rule_id = 1;
    acl_deny_rule.priority = 200; // High priority
    // Deny traffic from 192.168.1.1 to any, if it's TCP
    acl_deny_rule.src_ip = ntohl(0xC0A80101); // 192.168.1.1
    acl_deny_rule.protocol = 6; // TCP
    acl_deny_rule.action = netflow::AclActionType::DENY;
    sw.acl_manager_.add_rule(acl_deny_rule);
    std::cout << "Added ACL DENY rule for TCP from 192.168.1.1 (ID:1, Prio:200)." << std::endl;

    netflow::AclRule acl_redirect_rule;
    acl_redirect_rule.rule_id = 2;
    acl_redirect_rule.priority = 150;
    // Redirect UDP traffic from 192.168.1.2 to port 2
    acl_redirect_rule.src_ip = ntohl(0xC0A80102); // 192.168.1.2
    acl_redirect_rule.protocol = 17; // UDP
    acl_redirect_rule.action = netflow::AclActionType::REDIRECT;
    acl_redirect_rule.redirect_port_id = 2;
    sw.acl_manager_.add_rule(acl_redirect_rule);
    std::cout << "Added ACL REDIRECT rule for UDP from 192.168.1.2 to port 2 (ID:2, Prio:150)." << std::endl;


    // --- LACP Example Configuration ---
    std::cout << "\n--- LACP Configuration Example ---" << std::endl;
    netflow::LagConfig lag1_config;
    lag1_config.lag_id = 101; // LAG ID must not be a physical port ID if physical ports are 0-indexed
    lag1_config.member_ports = {3, 4}; // Assuming ports 3 and 4 exist
    lag1_config.active_mode = true;
    lag1_config.hash_mode = netflow::LacpHashMode::SRC_DST_IP;
    if (sw.lacp_manager_.create_lag(lag1_config)) {
        std::cout << "LAG " << lag1_config.lag_id << " created with member ports 3, 4." << std::endl;
        // Ensure member ports are up for LACP selection to be meaningful
        netflow::InterfaceManager::PortConfig lag_member_cfg;
        lag_member_cfg.admin_up = true;
        sw.interface_manager_.configure_port(3, lag_member_cfg);
        sw.interface_manager_.simulate_port_link_up(3);
        sw.interface_manager_.configure_port(4, lag_member_cfg);
        sw.interface_manager_.simulate_port_link_up(4);
    } else {
        std::cout << "Failed to create LAG " << lag1_config.lag_id << "." << std::endl;
    }
    // To test LACP, we would need an FDB entry pointing to lag_id 101.


    // Create a dummy packet buffer (normally from NIC driver or another source)
    // This packet is untagged, destined for a MAC address.
    size_t buffer_size = 128; // Increased for potential headers
    netflow::PacketBuffer* pb1 = sw.buffer_pool.allocate_buffer(buffer_size);
    if (pb1) {
        // Fill with some dummy Ethernet frame data
        // Dst MAC: 00:00:00:00:00:AA, Src MAC: 00:00:00:00:00:BB
        // EtherType: IPv4 (0x0800)
        // IP: 192.168.1.1 -> 192.168.1.10
        // Protocol: TCP (6)
        // TCP Ports: 12345 -> 80 (HTTP)
        uint8_t dummy_frame[] = {
            // Ethernet Header
            0x00, 0x00, 0x00, 0x00, 0x00, 0xAA, // Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xBB, // Src MAC
            0x08, 0x00,                         // EtherType (IPv4)
            // IPv4 Header (20 bytes)
            0x45, 0x00,                         // Version (4) IHL (5), DSCP/ECN
            0x00, 0x28,                         // Total Length (40 bytes: 20 IP + 20 TCP)
            0x12, 0x34, 0x00, 0x00,             // Identification, Flags/Fragment Offset
            0x40, 0x06,                         // TTL (64), Protocol (TCP=6)
            0x00, 0x00,                         // Header Checksum (placeholder)
            192, 168, 1, 1,                   // Src IP (192.168.1.1)
            192, 168, 1, 10,                  // Dst IP (192.168.1.10)
            // TCP Header (20 bytes)
            (12345 >> 8), (12345 & 0xFF),       // Src Port (12345)
            (80 >> 8), (80 & 0xFF),             // Dst Port (80)
            0x00, 0x00, 0x00, 0x00,             // Sequence Number
            0x00, 0x00, 0x00, 0x00,             // Ack Number
            0x50, 0x00,                         // Data Offset (5), Reserved, Flags
            0x00, 0x00,                         // Window Size (placeholder)
            0x00, 0x00,                         // Checksum (placeholder)
            0x00, 0x00                          // Urgent Pointer
        };
        memcpy(pb1->data, dummy_frame, sizeof(dummy_frame));
        pb1->size = sizeof(dummy_frame); // Actual data size

        std::cout << "\nSimulating packet (matching HTTP rule) ingress on Port 0 (Access VLAN 10):" << std::endl;
        sw.process_received_packet(0, pb1); // Ingress on port 0
        // pb1's ref_count will be handled by Packet and BufferPool within process_received_packet lifecycle
    }

    // Simulate another packet, this time one that might be a BPDU
    netflow::PacketBuffer* pb2 = sw.buffer_pool.allocate_buffer(buffer_size);
    if(pb2) {
        uint8_t bpdu_frame[] = {
            0x01, 0x80, 0xC2, 0x00, 0x00, 0x00, // BPDU Dst MAC
            0x00, 0x00, 0x00, 0x00, 0x00, 0xCC, // Src MAC
            0x00, 0x26, // Length field for LLC (example, actual BPDU is more complex)
            0x42, 0x42, 0x03, // LLC DSAP, SSAP, Control
            // ... Rest of BPDU data (highly simplified)
        };
        memcpy(pb2->data, bpdu_frame, sizeof(bpdu_frame));
        pb2->size = sizeof(bpdu_frame);
        std::cout << "\nSimulating BPDU packet ingress on Port 1 (Trunk, Link Up):" << std::endl;
        // Ensure port 1 is admin up for this test (already done by configure_port)
        // sw.interface_manager_.simulate_port_link_up(1); // Already done above
        sw.process_received_packet(1, pb2);
    }


    std::cout << "\n--- Simulation Finished ---" << std::endl;
    // Switch object sw goes out of scope here, its destructor will be called.

    return 0;
}
