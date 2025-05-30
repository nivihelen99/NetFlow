#include "netflow_plus_plus/core/packet.hpp"
#include <iostream>
#include <vector> // Required for std::vector

int main() {
    // Create a dummy data buffer for the PacketBuffer
    // In a real application, this would come from a network interface or a file
    std::vector<unsigned char> dummy_data(128, 0); // 128 bytes of zeros

    // Create a PacketBuffer
    // The PacketBuffer takes ownership (or would, in a full implementation with manual ref counting)
    // or participates in shared ownership of the data.
    // For std::shared_ptr<PacketBuffer> in Packet, we need to make_shared.
    auto packet_buffer = std::make_shared<netflow_plus_plus::core::PacketBuffer>(dummy_data.data(), dummy_data.size());

    // Create a Packet object
    netflow_plus_plus::core::Packet packet(packet_buffer);
    std::cout << "Packet object created." << std::endl;

    // Attempt to get an Ethernet header (placeholder)
    std::cout << "Attempting to get Ethernet header..." << std::endl;
    if (packet.ethernet() == nullptr) {
        std::cout << "Ethernet header is nullptr (as expected in this phase)." << std::endl;
    } else {
        std::cout << "Ethernet header was not nullptr (unexpected)." << std::endl;
    }

    // Demonstrate PacketBuffer usage (optional)
    if (packet.get_buffer()) {
        std::cout << "Packet buffer size: " << packet.get_buffer()->get_size() << " bytes." << std::endl;
        // packet.get_buffer()->retain(); // Example of manual ref counting if not using shared_ptr
        // packet.get_buffer()->release();
    }


    // The Packet and PacketBuffer will be automatically cleaned up due to RAII / shared_ptr.

    return 0;
}
