#ifndef NETFLOW_PACKET_BUFFER_HPP
#define NETFLOW_PACKET_BUFFER_HPP

#include <cstddef>
#include <atomic>

namespace netflow {

struct PacketBuffer {
    unsigned char* data;
    size_t size;
    std::atomic<int> ref_count;

    // Placeholder for scatter-gather support
    // PacketBuffer* next_fragment; // For linked list of fragments
    // std::vector<PacketBuffer*> fragments; // For list of fragments

    PacketBuffer(size_t len) : data(new unsigned char[len]), size(len), ref_count(1) {}

    ~PacketBuffer() {
        delete[] data;
    }

    void increment_ref() {
        ref_count.fetch_add(1, std::memory_order_relaxed);
    }

    void decrement_ref() {
        if (ref_count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete this;
        }
    }
};

} // namespace netflow

#endif // NETFLOW_PACKET_BUFFER_HPP
