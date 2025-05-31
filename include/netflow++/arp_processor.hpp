#ifndef NETFLOW_ARP_PROCESSOR_HPP
#define NETFLOW_ARP_PROCESSOR_HPP

#include "packet.hpp"
#include "interface_manager.hpp" // Assumed to exist
#include "forwarding_database.hpp" // Assumed to exist
#include <map>
#include <chrono>
#include <mutex>
#include <optional>
#include <cstdint> // For uint32_t

namespace netflow {

// Forward declaration if Switch or a similar packet sending entity is used
class Switch; // Or a more specific delegate/interface for sending packets

class ArpProcessor {
public:
    // Constructor
    ArpProcessor(InterfaceManager& if_manager, ForwardingDatabase& fwd_db, Switch& packet_sender); // Added Switch& for sending

    // Process an incoming ARP packet
    void process_arp_packet(Packet& packet, uint32_t ingress_port);

    // Lookup MAC address for a given IP address in the ARP cache
    std::optional<MacAddress> lookup_mac(IpAddress ip_address);

    // Send an ARP request for a target IP address
    // egress_port_if_known can be used to determine source IP/MAC if applicable,
    // or if the system has multiple interfaces, a source interface IP might be needed.
    void send_arp_request(IpAddress target_ip, uint32_t egress_port_hint);


    // ARP Cache Entry
    struct ArpCacheEntry {
        MacAddress mac_address;
        std::chrono::steady_clock::time_point last_seen;
        bool is_static; // For static ARP entries if needed in future

        // Default constructor
        ArpCacheEntry() : mac_address(), last_seen(std::chrono::steady_clock::now()), is_static(false) {}

        ArpCacheEntry(MacAddress mac, bool static_entry = false)
            : mac_address(mac), last_seen(std::chrono::steady_clock::now()), is_static(static_entry) {}
    };


private:
    // ARP Cache: Maps IP Address to MAC Address and timestamp
    std::map<IpAddress, ArpCacheEntry> arp_cache_;
    std::mutex cache_mutex_; // Mutex to protect the ARP cache

    // References to other components
    InterfaceManager& interface_manager_;
    ForwardingDatabase& forwarding_database_; // May be used for FDB updates or other interactions
    Switch& switch_ref_; // Reference to the main switch logic for sending packets

    // ARP constants
    static constexpr uint16_t ARP_OPCODE_REQUEST = 1;
    static constexpr uint16_t ARP_OPCODE_REPLY = 2;
    static constexpr std::chrono::seconds ARP_CACHE_TIMEOUT = std::chrono::minutes(5); // Example timeout

    // Helper to construct and send an ARP reply
    void send_arp_reply( IpAddress target_ip, MacAddress target_mac,
                         IpAddress sender_ip, MacAddress sender_mac,
                         uint32_t egress_port);

    // Helper to construct and send an ARP request packet (internal use by send_arp_request)
    void construct_and_send_arp_request(IpAddress source_ip, MacAddress source_mac,
                                        IpAddress target_ip, uint32_t egress_port);

    void update_arp_cache(IpAddress ip, MacAddress mac);
    void age_arp_cache(); // Placeholder for cache aging logic
};

} // namespace netflow

#endif // NETFLOW_ARP_PROCESSOR_HPP
