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

private:
    // References to other components
    InterfaceManager& interface_manager_;
    Switch& switch_ref_; // Reference to the main switch logic for sending packets

    // Helper function to construct and send an ICMP Echo Reply
    void send_icmp_echo_reply(Packet& original_request_packet,
                              uint32_t egress_port,
                              IpAddress new_src_ip, MacAddress new_src_mac,
                              IpAddress new_dst_ip, MacAddress new_dst_mac);
};

} // namespace netflow

#endif // NETFLOW_ICMP_PROCESSOR_HPP
