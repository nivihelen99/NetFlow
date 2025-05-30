#ifndef NETFLOW_PLUS_PLUS_PROTO_PLACEHOLDERS_HPP
#define NETFLOW_PLUS_PLUS_PROTO_PLACEHOLDERS_HPP

namespace netflow_plus_plus {
namespace proto {

// Dummy placeholder for IPv4 header
struct IPv4Header {
    unsigned char version_ihl;
    unsigned char dscp_ecn;
    unsigned short total_length;
    // ... other common IPv4 fields
};

// Dummy placeholder for IPv6 header
struct IPv6Header {
    unsigned int version_tc_flowlabel;
    unsigned short payload_length;
    unsigned char next_header;
    unsigned char hop_limit;
    // ... other common IPv6 fields
};

// Dummy placeholder for TCP header
struct TcpHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned int seq_num;
    // ... other common TCP fields
};

// Dummy placeholder for UDP header
struct UdpHeader {
    unsigned short src_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
};

} // namespace proto
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_PROTO_PLACEHOLDERS_HPP
