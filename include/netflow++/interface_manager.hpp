#ifndef NETFLOW_INTERFACE_MANAGER_HPP
#define NETFLOW_INTERFACE_MANAGER_HPP

#include "netflow++/packet.hpp" // For IpAddress and MacAddress
#include <cstdint>
#include <vector>   // Required for std::vector
#include <map>
#include <functional> // For std::function
#include <string>     // Potentially for port names in the future
#include <algorithm>  // For std::fill (if needed, though direct initialization is used)
#include <optional>   // For std::optional

namespace netflow {

// Structure to hold IP configuration for an interface
struct InterfaceIpConfig {
    IpAddress address;      // The IP address itself (network byte order)
    IpAddress subnet_mask;  // The subnet mask (network byte order)

    InterfaceIpConfig(IpAddress addr, IpAddress mask) : address(addr), subnet_mask(mask) {}
    // Default constructor might be useful for std::vector or std::optional initialization
    InterfaceIpConfig() : address(0), subnet_mask(0) {}
};

class InterfaceManager {
public:
    struct PortStats {
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
        uint64_t rx_drops = 0;
        uint64_t tx_drops = 0;

        PortStats() = default; // All members initialized by default member initializers
    };

    struct PortConfig {
        bool admin_up = false;          // Administrative status (true = enabled, false = disabled)
        uint32_t speed_mbps = 1000;     // Speed in Megabits per second (e.g., 10, 100, 1000, 10000)
        bool full_duplex = true;        // True for full-duplex, false for half-duplex
        bool auto_negotiation = true;   // True if auto-negotiation is enabled
        uint32_t mtu = 1500;            // Maximum Transmission Unit in bytes (excluding L2 header for IP MTU)
        MacAddress mac_address;         // MAC address of the interface
        // IP configurations for this interface (L3 properties)
        std::vector<InterfaceIpConfig> ip_configurations;

        PortConfig() : mac_address() {} // Initialize MAC address (e.g. to all zeros)
    };

    InterfaceManager();

    // IP Configuration Methods
    void add_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask);
    void remove_ip_address(uint32_t interface_id, const IpAddress& address, const IpAddress& subnet_mask);
    std::vector<InterfaceIpConfig> get_interface_ip_configs(uint32_t interface_id) const;
    bool is_my_ip(const IpAddress& ip) const; // Checks if IP belongs to any interface
    std::optional<uint32_t> find_interface_for_ip(const IpAddress& ip) const; // Finds interface ID for a given local IP
    std::optional<MacAddress> get_mac_for_ip(const IpAddress& ip) const; // Gets MAC for a local IP

    // Stubs to be replaced or properly implemented
    bool is_ip_local_to_interface(uint32_t interface_id, const IpAddress& ip) const;
    std::optional<MacAddress> get_interface_mac(uint32_t interface_id) const;
    std::optional<IpAddress> get_interface_ip(uint32_t interface_id) const; // Gets the primary IP of an interface


    // Configures a port with the given settings.
    // If the port doesn't exist, it will be created.
    void configure_port(uint32_t port_id, const PortConfig& config);

    // Retrieves the configuration for a given port.
    // Returns std::optional<PortConfig> to handle cases where port might not be configured.
    std::optional<PortConfig> get_port_config(uint32_t port_id) const;

    // Retrieves statistics for a given port.
    // Returns default (all zero) stats if the port is not found or has no stats yet.
    PortStats get_port_stats(uint32_t port_id) const;

    // Clears (resets to zero) statistics for a specific port.
    // If the port doesn't exist, this operation has no effect.
    void clear_port_stats(uint32_t port_id);

    // Checks if a port is administratively up (enabled).
    // This does not necessarily mean the link is operationally up.
    bool is_port_admin_up(uint32_t port_id) const;

    // Placeholder for actual operational link status (would involve hardware interaction)
    bool is_port_link_up(uint32_t port_id) const;

    // Registers a callback function to be invoked when a port's link goes up.
    void on_link_up(std::function<void(uint32_t port_id)> callback);

    // Registers a callback function to be invoked when a port's link goes down.
    void on_link_down(std::function<void(uint32_t port_id)> callback);

    // Simulates a port's link coming up and invokes registered callbacks.
    void simulate_port_link_up(uint32_t port_id);

    // Simulates a port's link going down and invokes registered callbacks.
    void simulate_port_link_down(uint32_t port_id);

    // Method to get all configured port/interface IDs
    std::vector<uint32_t> get_all_interface_ids() const {
        std::vector<uint32_t> ids;
        for(const auto& pair : port_configs_) {
            ids.push_back(pair.first);
        }
        return ids;
    }

    // Method to check if a port ID is valid/configured
    bool is_port_valid(uint32_t port_id) const {
        return port_configs_.count(port_id) > 0;
    }

    // Placeholder for L3 interface identification - can be refined
    std::vector<uint32_t> get_all_l3_interface_ids() const {
        std::vector<uint32_t> l3_ids;
        for(const auto& pair : port_configs_) {
            // Assuming an interface is L3 if it has any IP configuration
            if(!pair.second.ip_configurations.empty()) {
                l3_ids.push_back(pair.first);
            }
        }
        return l3_ids;
    }


public: // Changed from protected to public
    // Helper to update RX stats (example, would be called by data plane)
    void _increment_rx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);

    // Helper to update TX stats (example)
    void _increment_tx_stats(uint32_t port_id, uint64_t bytes, bool is_error = false, bool is_drop = false);

private:
    std::map<uint32_t, PortConfig> port_configs_;
    std::map<uint32_t, PortStats> port_stats_;
    std::map<uint32_t, bool> simulated_link_state_; // For is_port_link_up simulation

    std::vector<std::function<void(uint32_t port_id)>> link_up_callbacks_;
    std::vector<std::function<void(uint32_t port_id)>> link_down_callbacks_;
};

} // namespace netflow

#endif // NETFLOW_INTERFACE_MANAGER_HPP
