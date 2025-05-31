#ifndef NETFLOW_ICMP_PROCESSOR_HPP
#define NETFLOW_ICMP_PROCESSOR_HPP

#include "packet.hpp"
#include "interface_manager.hpp" // Assumed to exist
// #include "logger.hpp" // Placeholder if a dedicated logger is available
#include <cstdint> // For uint32_t

namespace netflow {

// Forward declaration for Switch or packet sending delegate
class Switch;

class IcmpProcessor {
public:
    // Constructor
    IcmpProcessor(InterfaceManager& if_manager, Switch& packet_sender);

    // Process an incoming ICMP packet
    void process_icmp_packet(Packet& packet, uint32_t ingress_port);

    // Methods to send ICMP error messages
    void send_time_exceeded(Packet& original_packet, uint32_t original_ingress_port);
    void send_destination_unreachable(Packet& original_packet, uint32_t original_ingress_port, uint8_t code = 0 /* Network Unreachable */);

private:
    // References to other components
    InterfaceManager& interface_manager_;
    Switch& switch_ref_; // Reference to the main switch logic for sending packets
    // Assuming logger_ref_ is added if LOG_ macros are to be used, or pass logger from switch_ref_
    // SwitchLogger& logger_ref_;

    // Helper function to construct and send an ICMP Echo Reply
    void send_icmp_echo_reply(Packet& original_request_packet,
                              uint32_t egress_port,
                              IpAddress new_src_ip, MacAddress new_src_mac,
                              IpAddress new_dst_ip, MacAddress new_dst_mac);

    // Private helper for common ICMP error packet construction
    void send_icmp_error_packet_base(
        Packet& original_packet,       // The packet that caused the error
        uint8_t icmp_type,
        uint8_t icmp_code);
};

} // namespace netflow

#endif // NETFLOW_ICMP_PROCESSOR_HPP
