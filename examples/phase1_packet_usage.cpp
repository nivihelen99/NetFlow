#include "netflow++/packet.hpp"       // Updated include for Packet and MacAddress
#include "netflow++/packet_buffer.hpp" // Updated include for PacketBuffer
#include <iostream>
#include <vector> // Required for std::vector
#include <cstring> // For memcpy

// Note: This example was based on an older version of PacketBuffer and Packet.
// It has been updated to reflect current class definitions.

int main() {
    std::cout << "--- Phase 1: Packet and PacketBuffer Usage Example (Updated) ---" << std::endl;

    size_t buffer_len = 128;
    // Create a PacketBuffer - it now allocates its own memory.
    netflow::PacketBuffer* pb = new netflow::PacketBuffer(buffer_len);

    // Fill with some dummy data if needed for later examples (e.g. Ethernet header)
    // For this phase, just checking creation is enough.
    // Example:
    // unsigned char sample_data[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x00};
    // if (buffer_len >= sizeof(sample_data)) {
    //    std::memcpy(pb->data, sample_data, sizeof(sample_data));
    //    pb->size = sizeof(sample_data); // Update actual data size if only partially filled
    // } else {
    //    pb->set_data_len(buffer_len); // Default if not specifically filling
    // }
    // To make the buffer conceptually "full" with data up to its capacity:
    pb->set_data_len(buffer_len);


    // Create a Packet object using the PacketBuffer pointer.
    // The Packet constructor will call increment_ref() on pb.
    netflow::Packet packet(pb);
    std::cout << "Packet object created." << std::endl;

    // Attempt to get an Ethernet header
    std::cout << "Attempting to get Ethernet header..." << std::endl;
    // Packet methods are const, so this is fine.
    if (packet.ethernet() == nullptr) {
        // This might happen if the dummy_data doesn't represent a valid Ethernet frame
        // or if buffer size is too small for a full header.
        std::cout << "Ethernet header is nullptr (e.g. data not initialized or too short)." << std::endl;
    } else {
        std::cout << "Ethernet header was accessible (though data might be all zeros)." << std::endl;
    }

    // Demonstrate PacketBuffer usage via Packet
    netflow::PacketBuffer* retrieved_buffer = packet.get_buffer();
    if (retrieved_buffer) {
        std::cout << "Packet buffer data length: " << retrieved_buffer->get_data_length() << " bytes." << std::endl;
        std::cout << "Packet buffer capacity: " << retrieved_buffer->get_capacity() << " bytes." << std::endl;
        std::cout << "Packet buffer ref_count: " << retrieved_buffer->ref_count.load() << std::endl;
    }

    // When 'packet' goes out of scope, its destructor will call decrement_ref() on pb.
    // Since pb was also new'd here, and its initial ref_count was 1, then incremented by Packet to 2,
    // then decremented by Packet's destructor to 1, we need one more decrement_ref()
    // to ensure it's deleted.
    // This highlights the manual nature of ref counting if not using smart pointers for PacketBuffer itself.
    // In the main switch logic, PacketBuffer is typically managed by BufferPool.
    pb->decrement_ref();
    // If Packet was the sole owner after this point, the above decrement would delete pb.
    // If pb->ref_count is not 0 here, it indicates an issue or other references exist.

    std::cout << "--- Example Complete ---" << std::endl;

    return 0;
}
