#ifndef NETFLOW_ISIS_PDU_PARSING_HPP
#define NETFLOW_ISIS_PDU_PARSING_HPP

#include "netflow++/isis/isis_common.hpp" // For CommonPduHeader, etc.
#include "netflow++/isis/isis_pdu.hpp"     // For PDU struct definitions (LanHelloPdu, LinkStatePdu, etc.)
// #include "netflow++/isis/isis_utils.hpp" // Removed to break circular dependency.
                                         // BufferReader is used in function signatures; it's defined in isis_utils.hpp,
                                         // which includes this header. This implies files using these parse functions
                                         // should include isis_utils.hpp to get both BufferReader and these declarations.
#include <vector>
#include <cstdint>

// Forward declare BufferReader if it's used in function signatures here
// and primarily defined in isis_utils.hpp.
// However, isis_utils.hpp includes this file, so the definitions in isis_utils.cpp
// should see BufferReader from isis_utils.hpp.
// The files including *this* header (isis_pdu_parsing.hpp) might need BufferReader.
// Let's assume for now that isis_utils.hpp (which includes this) will be included by any file needing these + BufferReader.
// struct BufferReader; // Consider forward declaration if direct includes of this header need it without isis_utils.hpp

namespace netflow {
namespace isis {

// PDU-specific parsing function declarations
bool parse_lan_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LanHelloPdu& pdu);
bool parse_point_to_point_hello_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PointToPointHelloPdu& pdu);
bool parse_link_state_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, LinkStatePdu& pdu);
bool parse_complete_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, CompleteSequenceNumbersPdu& pdu);
bool parse_partial_sequence_numbers_pdu(const std::vector<uint8_t>& pdu_data, CommonPduHeader& common_header, PartialSequenceNumbersPdu& pdu);

} // namespace isis
} // namespace netflow
#endif // NETFLOW_ISIS_PDU_PARSING_HPP
