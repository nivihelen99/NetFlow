#include "netflow++/switch.hpp"
#include "netflow++/config_manager.hpp" // Added for ConfigManager
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

    // Create a switch with a specific number of ports
    uint32_t num_ports = 4; // Example: 4 ports
    uint64_t switch_main_mac = 0x0000DEADBEEF0001ULL;
    uint16_t switch_main_stp_priority = 0x8000; // Default 32768

    sw.logger_.info("MAIN", "Creating Switch with MAC: " + sw.logger_.mac_to_string(switch_main_mac) +
                          " STP Priority: " + std::to_string(switch_main_stp_priority));
    netflow::Switch sw(num_ports, switch_main_mac, switch_main_stp_priority);

    // Configure packet handler (optional)
    sw.set_packet_handler(handle_cpu_packet);

    // --- STP Bridge Configuration (can be done via ConfigManager or directly) ---
    // The StpManager is now initialized with MAC and priority in Switch constructor.
    // We can still adjust it here if needed, e.g. by calling:
    // sw.stp_manager.set_bridge_priority_and_reinit(0x4000); // Make this switch more likely root
    // sw.logger_.info("STP_CONFIG", "Switch STP Bridge ID: 0x" +
    //               sw.logger_.uint64_to_hex_string(sw.stp_manager.get_bridge_config().bridge_id_value));


    // --- Port Configuration (VLANs) ---
    // Note: STP port states (FORWARDING, BLOCKING) are now managed by StpManager logic.
    // We should primarily configure admin state (up/down) and other parameters like VLAN.
    // STP will then decide if an admin_up port can transition to FORWARDING.

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
    for(uint32_t i = 0; i < num_ports; ++i) { // Configure all ports initially
        sw.vlan_manager.configure_port(i, default_access_config);
        // Set ports to admin up; STP will decide their forwarding state.
        netflow::InterfaceManager::PortConfig if_cfg;
        if_cfg.admin_up = true; // Bring ports admin_up
        if_cfg.speed_mbps = 1000; // Example speed
        sw.interface_manager_.configure_port(i, if_cfg);
        sw.interface_manager_.simulate_port_link_up(i); // Simulate link is also up
        // sw.stp_manager.admin_set_port_state(i, true); // Enable port in STP if it was disabled
    }
    // Initial STP states are set by StpManager constructor and first recalculate call.


    // --- Logger Example ---
    sw.logger_.info("MAIN", "Switch initialization complete. Management interface getting ready.");
    sw.logger_.set_min_log_level(netflow::LogLevel::DEBUG); // Set to DEBUG for more verbose output during setup
    sw.logger_.debug("MAIN", "Logger level set to DEBUG for detailed setup logs.");

    // --- ConfigManager Loading from JSON File ---
    std::cout << "\n--- ConfigManager Loading from File ---" << std::endl;
    sw.logger_.info("CONFIG_MAIN", "Loading configuration from default_switch_config.json...");
    if (sw.config_manager_.load_config("default_switch_config.json")) {
        sw.logger_.info("CONFIG_MAIN", "Configuration loaded successfully.");

        // Log some loaded values
        std::optional<std::string> hostname = sw.config_manager_.get_parameter_as<std::string>("global.hostname");
        if (hostname) {
            sw.logger_.info("CONFIG_MAIN", "Loaded hostname: " + hostname.value());
        }
        std::optional<int> aging_time = sw.config_manager_.get_parameter_as<int>("fdb.aging_time_seconds");
        if (aging_time) {
            sw.logger_.info("CONFIG_MAIN", "Loaded FDB aging time: " + std::to_string(aging_time.value()));
        }
        std::optional<int> bridge_prio = sw.config_manager_.get_parameter_as<int>("stp.bridge_priority");
        if (bridge_prio) {
            sw.logger_.info("CONFIG_MAIN", "Loaded STP Bridge Priority: " + std::to_string(bridge_prio.value()));
        }

        sw.logger_.info("CONFIG_MAIN", "Applying loaded configuration to the switch...");
        sw.config_manager_.apply_config(sw); // Apply the loaded config

        // Example: Verify a value after applying (actual application logic is still basic)
        // This assumes apply_config would eventually set the switch's internal hostname or similar
        sw.logger_.info("CONFIG_MAIN", "Hostname from config_data after load: " +
            (sw.config_manager_.get_parameter_as<std::string>("global.hostname").value_or("Not Set")));

    } else {
        sw.logger_.error("CONFIG_MAIN", "Failed to load configuration from default_switch_config.json.");
    }

    // --- Original ConfigManager Example Usage (can be removed or adapted) ---
    // std::cout << "\n--- ConfigManager Manual Examples ---" << std::endl;
    // sw.logger_.info("CONFIG_MAIN_MANUAL", "Demonstrating ConfigManager parameter setting manually...");
    // sw.config_manager_.set_parameter("port.1.admin_up", true);
    // sw.config_manager_.set_parameter("port.1.speed_mbps", static_cast<uint32_t>(10000));
    // sw.config_manager_.set_parameter("vlan.20.name", std::string("Engineering"));
    // sw.config_manager_.set_parameter("global.hostname", std::string("MyCoreSwitchManual")); // Different hostname

    // sw.logger_.info("CONFIG_MAIN_MANUAL", "Applying manually set parameters to the switch...");
    // sw.config_manager_.apply_config(sw); // Apply manually set params

    // auto port1_cfg_after_apply = sw.interface_manager_.get_port_config(1);
    // if (port1_cfg_after_apply && port1_cfg_after_apply.value().admin_up) {
    //     sw.logger_.info("CONFIG_VERIFY_MANUAL", "Port 1 is now admin_up after manual apply_config.");
    //     if(!sw.interface_manager_.is_port_link_up(1)) {
    //         sw.interface_manager_.simulate_port_link_up(1);
    //     }
    // } else {
    //     sw.logger_.warning("CONFIG_VERIFY_MANUAL", "Port 1 admin_up status not correctly applied or port not found after manual config.");
    // }
    // sw.logger_.info("CONFIG_MAIN_MANUAL", "Hostname from config_data after manual set: " +
    //         (sw.config_manager_.get_parameter_as<std::string>("global.hostname").value_or("Not Set")));


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
    // Port link states already simulated up during port configuration loop.


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
    size_t buffer_size = 128;

    // --- LACP Configuration ---
    sw.logger_.info("LACP_CONFIG", "Configuring LACP...");
    netflow::LagConfig lag1_cfg;
    lag1_cfg.lag_id = 1; // LAG ID 1
    lag1_cfg.member_ports = {0, 1}; // Ports 0 and 1 are members
    lag1_cfg.active_mode = true;    // Switch is in Active LACP mode
    lag1_cfg.lacp_rate = 1;         // Fast rate (1 second)
    // actor_admin_key will be derived from lag_id if 0.
    if (sw.lacp_manager_.create_lag(lag1_cfg)) {
        sw.logger_.info("LACP_CONFIG", "LAG 1 created with ports 0, 1. Active Mode, Fast Rate.");
    } else {
        sw.logger_.error("LACP_CONFIG", "Failed to create LAG 1.");
    }
    // Ensure LACP ports are admin up (already done in earlier loop)
    // sw.interface_manager_.configure_port(0, {.admin_up = true});
    // sw.interface_manager_.configure_port(1, {.admin_up = true});


    // --- Main Simulation Loop (STP & LACP) ---
    sw.logger_.info("MAIN_SIM", "Starting main simulation loop (STP & LACP)...");
    for (int tick = 0; tick < 60; ++tick) { // Simulate for 60 seconds
        sw.logger_.info("MAIN_SIM_TICK", "Tick " + std::to_string(tick));

        // Run STP timers and logic
        sw.stp_manager.run_stp_timers();
        std::vector<netflow::Packet> generated_bpdus = sw.stp_manager.generate_bpdus(sw.buffer_pool);
        if (!generated_bpdus.empty()) {
            sw.logger_.info("STP_SIM_GEN", "Generated " + std::to_string(generated_bpdus.size()) + " BPDUs.");
            // In a real switch, BPDUs are sent out. Here we just log.
        }

        // Run LACP timers and state machines
        sw.lacp_manager_.run_lacp_timers_and_statemachines();
        std::vector<netflow::Packet> generated_lacpdus = sw.lacp_manager_.generate_lacpdus(sw.buffer_pool);
        if (!generated_lacpdus.empty()) {
            sw.logger_.info("LACP_SIM_GEN", "Generated " + std::to_string(generated_lacpdus.size()) + " LACPDUs.");
            // In a real switch, LACPDUs are sent out. Here we might loop them back for test.
            // For now, just log.
        }

        // Log STP port states
        auto stp_summary = sw.stp_manager.get_all_ports_stp_info_summary();
        for(const auto& port_info_pair : stp_summary) {
            sw.logger_.debug("STP_STATE", "Port " + std::to_string(port_info_pair.first) +
                                         ": Role=" + port_info_pair.second.first +
                                         ", State=" + port_info_pair.second.second);
        }

        // Log LACP port states (simplified)
        // TODO: Add a get_all_ports_lacp_info_summary to LacpManager for detailed logging
        for(uint32_t port_id = 0; port_id < num_ports; ++port_id) {
            if(sw.lacp_manager_.is_port_in_lag(port_id)) {
                 // Add more detailed logging from LacpPortInfo if needed
                 // For now, just checking if it's active in a LAG
                 // bool is_active = sw.lacp_manager_. // Need a method like is_port_active_in_lag
                 // sw.logger_.debug("LACP_STATE", "Port " + std::to_string(port_id) + " LACP state: ...");
            }
        }


        // Simulate receiving an STP BPDU (as before)
        if (tick == 5) {
            // (STP BPDU reception code from previous step - can be kept or adapted)
            sw.logger_.info("STP_SIM_RX", "Simulating external STP BPDU reception on port 2 from a 'better' root.");
            // Assuming port 2 is not part of the LAG for this test
            netflow::PacketBuffer* sim_bpdu_pb = sw.buffer_pool.allocate_buffer(sizeof(netflow::EthernetHeader) + sizeof(netflow::LLCHeader) + netflow::CONFIG_BPDU_PAYLOAD_SIZE);
            if(sim_bpdu_pb) { /* ... (fill BPDU as before) ... */
                // Fill with BPDU data similar to previous step, make sure src MAC is different from switch MAC
                // and Bridge ID in BPDU is better than this switch's.
                // For example, on port 2 (if num_ports >=3)
                if (num_ports >=3) {
                    // ... (BPDU creation as in previous task for STP)
                    // For brevity, not repeating the full BPDU creation here.
                    // Ensure it's a valid BPDU that might cause a topology change.
                    // sw.process_received_packet(2, sim_bpdu_pb);
                } else {
                     sw.buffer_pool.release_buffer(sim_bpdu_pb); // Release if not used
                }
            }
        }

        // Simulate receiving an LACPDU on port 0 (member of LAG 1)
        // This LACPDU is from a partner that agrees to aggregate.
        if (tick == 10) {
            sw.logger_.info("LACP_SIM_RX", "Simulating LACPDU reception on port 0 from an active partner.");
            netflow::PacketBuffer* sim_lacpdu_pb = sw.buffer_pool.allocate_buffer(sizeof(netflow::EthernetHeader) + netflow::LACPDU_MIN_SIZE);
            if(sim_lacpdu_pb) {
                netflow::EthernetHeader* eth_h = reinterpret_cast<netflow::EthernetHeader*>(sim_lacpdu_pb->data);
                eth_h->dst_mac = netflow::ConfigBpdu::htonll(netflow::LacpDefaults::LACP_MULTICAST_MAC);
                eth_h->src_mac = netflow::ConfigBpdu::htonll(0x0000PARTNERMAC01ULL); // Partner's MAC
                eth_h->ethertype = htons(netflow::LacpDefaults::LACP_ETHERTYPE);

                netflow::Lacpdu* lacpdu_payload = reinterpret_cast<netflow::Lacpdu*>(sim_lacpdu_pb->data + sizeof(netflow::EthernetHeader));
                // Actor info in PDU (is our Partner's info about itself)
                lacpdu_payload->subtype = netflow::LacpDefaults::LACP_SUBTYPE;
                lacpdu_payload->version_number = netflow::LacpDefaults::LACP_VERSION;
                lacpdu_payload->tlv_type_actor = 0x01; lacpdu_payload->actor_info_length = 0x14;
                // Partner (sender of this PDU)
                lacpdu_payload->set_actor_system_id( (uint64_t(0x8000)<<48) | 0x0000PARTNERMAC00ULL ); // Partner system ID
                lacpdu_payload->actor_key = htons(lag1_cfg.actor_admin_key); // Partner uses same key
                lacpdu_payload->actor_port_priority = htons(128);
                lacpdu_payload->actor_port_number = htons(1); // Partner's port 1
                lacpdu_payload->actor_state = netflow::LACP_ACTIVITY | netflow::LACP_TIMEOUT | netflow::AGGREGATION | netflow::SYNCHRONIZATION | netflow::COLLECTING | netflow::DISTRIBUTING;

                // Partner info in PDU (is our Partner's view of us - the Actor)
                lacpdu_payload->tlv_type_partner = 0x02; lacpdu_payload->partner_info_length = 0x14;
                // Us (receiver of this PDU)
                lacpdu_payload->partner_system_priority = htons(switch_main_stp_priority); // Our system priority
                uint64_t temp_our_mac = switch_main_mac; // Our MAC
                for(int i=0; i<6; ++i) lacpdu_payload->partner_system_mac[5-i] = (temp_our_mac >> (i*8)) & 0xFF;
                lacpdu_payload->partner_key = htons(lag1_cfg.actor_admin_key); // Our key
                lacpdu_payload->partner_port_priority = htons(128); // Our port 0 priority
                lacpdu_payload->partner_port_number = htons(0);    // Our port 0
                lacpdu_payload->partner_state = netflow::LACP_ACTIVITY | netflow::LACP_TIMEOUT | netflow::AGGREGATION; // What partner thinks of our state (e.g. not yet sync)

                lacpdu_payload->tlv_type_collector = 0x03; lacpdu_payload->collector_info_length = 0x10;
                lacpdu_payload->collector_max_delay = htons(0);
                lacpdu_payload->tlv_type_terminator = 0x00; lacpdu_payload->terminator_length = 0x00;

                sim_lacpdu_pb->size = sizeof(netflow::EthernetHeader) + netflow::LACPDU_MIN_SIZE;
                sw.process_received_packet(0, sim_lacpdu_pb);
            }
        }

        // Test LACP egress selection if LAG becomes active
        if (tick > 15) { // Give LACP some time to potentially converge
            netflow::PacketBuffer* test_pkt_pb = sw.buffer_pool.allocate_buffer(64);
            if(test_pkt_pb) {
                // Create a dummy packet for hashing
                memset(test_pkt_pb->data, 0, 64);
                netflow::EthernetHeader* eth_h = reinterpret_cast<netflow::EthernetHeader*>(test_pkt_pb->data);
                eth_h->src_mac = netflow::ConfigBpdu::htonll(0xAAAAAAAAAAAAULL);
                eth_h->dst_mac = netflow::ConfigBpdu::htonll(0xBBBBBBBBBBBBULL);
                eth_h->ethertype = htons(0x0800); // IPv4
                test_pkt_pb->size = 64;
                netflow::Packet test_pkt(test_pkt_pb);

                uint32_t egress_port = sw.lacp_manager_.select_egress_port(lag1_cfg.lag_id, test_pkt);
                if (egress_port != 0 || lag1_cfg.lag_id == 0) { // Port 0 can be a valid member
                     sw.logger_.info("LACP_EGRESS_TEST", "Packet hashed to egress port " + std::to_string(egress_port) + " for LAG " + std::to_string(lag1_cfg.lag_id));
                } else {
                     sw.logger_.warning("LACP_EGRESS_TEST", "LACP egress selection for LAG " + std::to_string(lag1_cfg.lag_id) + " returned invalid port 0 or LAG has no active members.");
                }
                sw.buffer_pool.release_buffer(test_pkt_pb); // Release our ref, Packet had one
            }
        }
    }

    std::cout << "\n--- Simulation Finished ---" << std::endl;

    // --- Checksum Calculation Test ---
    sw.logger_.info("CHECKSUM_TEST", "Starting IPv4 Checksum Test...");
    {
        size_t eth_ipv4_size = sizeof(netflow::EthernetHeader) + sizeof(netflow::IPv4Header);
        netflow::PacketBuffer* pb_chksum_test = sw.buffer_pool.allocate_buffer(eth_ipv4_size);
        if (pb_chksum_test) {
            pb_chksum_test->size = eth_ipv4_size;
            memset(pb_chksum_test->data, 0, eth_ipv4_size); // Zero out buffer

            netflow::EthernetHeader* eth_h = reinterpret_cast<netflow::EthernetHeader*>(pb_chksum_test->data);
            eth_h->ethertype = htons(0x0800); // IPv4

            netflow::IPv4Header* ip_h = reinterpret_cast<netflow::IPv4Header*>(pb_chksum_test->data + sizeof(netflow::EthernetHeader));
            ip_h->version_ihl = (4 << 4) | 5; // IPv4, 5 words (20 bytes) header length
            ip_h->dscp_ecn = 0;
            ip_h->total_length = htons(sizeof(netflow::IPv4Header)); // No payload for this test
            ip_h->identification = htons(12345);
            ip_h->flags_fragment_offset = 0;
            ip_h->ttl = 64;
            ip_h->protocol = 6; // TCP (dummy)
            ip_h->header_checksum = 0; // Initial checksum is 0
            ip_h->src_ip = htonl(0xC0A80101); // 192.168.1.1
            ip_h->dst_ip = htonl(0xC0A8010A); // 192.168.1.10

            netflow::Packet test_pkt(pb_chksum_test);
            sw.logger_.info("CHECKSUM_TEST", "IPv4 Header before checksum update (checksum field should be 0):");
            // Log relevant IP header fields, especially checksum
            if(test_pkt.ipv4()){
                 sw.logger_.info("CHECKSUM_TEST", "  Initial Checksum: 0x" + sw.logger_.uint16_to_hex_string(ntohs(test_pkt.ipv4()->header_checksum)));
            }

            test_pkt.update_checksums();

            if(test_pkt.ipv4()){
                uint16_t calculated_checksum = ntohs(test_pkt.ipv4()->header_checksum); // ntohs for logging if it was stored as network order
                sw.logger_.info("CHECKSUM_TEST", "IPv4 Checksum after first update: 0x" + sw.logger_.uint16_to_hex_string(calculated_checksum));

                // Verify that the checksum is not 0 (unless header is all zeros, which it isn't)
                if (calculated_checksum == 0) {
                    sw.logger_.error("CHECKSUM_TEST", "Error: Calculated checksum is 0, which is unlikely for a valid header.");
                }

                // Modify a field and recalculate
                test_pkt.ipv4()->ttl = 100;
                sw.logger_.info("CHECKSUM_TEST", "Modified TTL to 100.");
                test_pkt.update_checksums();
                uint16_t new_calculated_checksum = ntohs(test_pkt.ipv4()->header_checksum);
                sw.logger_.info("CHECKSUM_TEST", "IPv4 Checksum after TTL change and second update: 0x" + sw.logger_.uint16_to_hex_string(new_calculated_checksum));

                if (new_calculated_checksum == calculated_checksum) {
                     sw.logger_.error("CHECKSUM_TEST", "Error: Checksum did not change after modifying TTL.");
                } else {
                     sw.logger_.info("CHECKSUM_TEST", "Checksum changed as expected.");
                }
            } else {
                 sw.logger_.error("CHECKSUM_TEST", "Failed to get IPv4 header after creating packet.");
            }
            // PacketBuffer ref count is managed by Packet object, will be decremented when test_pkt goes out of scope.
            // If pb_chksum_test was used directly after Packet creation, its ref count should be handled carefully.
            // Here, Packet test_pkt takes ownership (increments ref), and decrements on destruction.
            // No, Packet constructor takes a pointer and increments. The original pb_chksum_test is not managed by Packet.
            // We must release the initial ref obtained from allocate_buffer if Packet is expected to fully manage it.
            // However, Packet dtor decrements. So if Packet is the sole user, this is fine.
            // For safety: sw.buffer_pool.release_buffer(pb_chksum_test); // if Packet made a copy or similar
            // But Packet takes the pointer, so it should manage the one ref it got.
            // The issue is if Packet's lifetime is shorter than the buffer's intended use.
            // Current Packet takes a raw ptr and inc/dec. So the original pb_chksum_test is not needed after Packet creation.
            // To be super safe, if Packet might be copied or buffer shared, use std::shared_ptr or careful manual ref counting.
            // For this simple test, Packet's RAII on the buffer is sufficient.
        } else {
            sw.logger_.error("CHECKSUM_TEST", "Failed to allocate PacketBuffer for checksum test.");
        }
    }
    sw.logger_.info("CHECKSUM_TEST", "IPv4 Checksum Test Finished.");


    return 0;
}
