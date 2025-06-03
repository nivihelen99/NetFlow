#ifndef NETFLOW_ISIS_PDU_SERIALIZATION_HPP
#define NETFLOW_ISIS_PDU_SERIALIZATION_HPP

#include "netflow++/isis/isis_common.hpp"
#include "netflow++/isis/isis_pdu.hpp"     // For PDU struct definitions (LanHelloPdu, etc.) and TLV value structs
#include "netflow++/packet.hpp"          // For IpAddress
#include <vector>
#include <string>

namespace netflow {
namespace isis {

// PDU serialization function declarations
std::vector<uint8_t> serialize_lan_hello_pdu(const LanHelloPdu& pdu);
std::vector<uint8_t> serialize_point_to_point_hello_pdu(const PointToPointHelloPdu& pdu);
std::vector<uint8_t> serialize_link_state_pdu(const LinkStatePdu& pdu); // Note: may modify PDU (checksum, length)
std::vector<uint8_t> serialize_complete_sequence_numbers_pdu(const CompleteSequenceNumbersPdu& pdu);
std::vector<uint8_t> serialize_partial_sequence_numbers_pdu(const PartialSequenceNumbersPdu& pdu);

// TLV value serialization function declarations
std::vector<uint8_t> serialize_area_addresses_tlv_value(const AreaAddressesTlvValue& value);
std::vector<uint8_t> serialize_protocols_supported_tlv_value(const std::vector<uint8_t>& nlpids);
std::vector<uint8_t> serialize_ip_interface_address_tlv_value(const IpAddress& ip_address);
// Add more TLV serializers as needed e.g. for IS Reachability, Ext IS Reach, Ext IP Reach etc.
std::vector<uint8_t> serialize_is_reach_tlv_value(/* params */);
std::vector<uint8_t> serialize_ext_is_reach_tlv_value(/* params */);
std::vector<uint8_t> serialize_ext_ip_reach_tlv_value(/* params */);


std::vector<uint8_t> serialize_multicast_capability_tlv_value(const MulticastCapabilityTlvValue& value);
std::vector<uint8_t> serialize_multicast_group_membership_tlv_value(const MulticastGroupMembershipTlvValue& value);

} // namespace isis
} // namespace netflow
#endif // NETFLOW_ISIS_PDU_SERIALIZATION_HPP
