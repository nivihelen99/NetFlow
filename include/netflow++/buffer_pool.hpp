#ifndef NETFLOW_BUFFER_POOL_HPP
#define NETFLOW_BUFFER_POOL_HPP

#include "packet_buffer.hpp"
#include <vector>
#include <mutex>
#include <memory> // For std::unique_ptr
#include <list>     // For std::list
#include <algorithm> // For std::find

namespace netflow {

class BufferPool {
public:
    // Constructor
    BufferPool() {
        // TODO: Initialize with pre-allocated buffers or based on configuration
    }

    // Destructor
    ~BufferPool() {
        std::lock_guard<std::mutex> lock(mutex_); // Ensure thread safety during destruction
        for (PacketBuffer* buf : available_buffers_) {
            delete buf; // Delete all buffers currently in the pool
        }
        available_buffers_.clear();

        // Regarding allocated_buffers_debug_:
        // If this list is supposed to track all buffers *ever* created for leak detection,
        // then it should not be cleared or deleted here, as some might be legitimately in use.
        // However, if it tracks buffers currently "leased out", then at shutdown,
        // any remaining buffers in allocated_buffers_debug_ that are NOT in available_buffers_
        // (which we just cleared and deleted) could be considered leaks.
        // For simplicity, this destructor will only clean available_buffers_.
        // A more robust leak detection would require careful management of allocated_buffers_debug_
        // throughout the lifecycle, ensuring buffers are removed when truly deleted (not just returned to pool).
        // If a buffer from allocated_buffers_debug_ was already returned and deleted via available_buffers_,
        // double deletion must be avoided.
        // For now, let's assume allocated_buffers_debug_ might hold raw pointers that were
        // also in available_buffers_. Since we deleted from available_buffers_,
        // we should not delete them again from allocated_buffers_debug_ without careful checking.
        // A simple approach: If a buffer is deleted, it should ideally be removed from ALL lists.
        // Given PacketBuffer's new decrement_ref, the pool is the sole deleter of returned-to-pool buffers.

        // Clear the debug list too, assuming its purpose is to track buffers that *were* allocated.
        // If they are in available_buffers_, they are deleted. If they are still "out",
        // then deleting them here would be incorrect as they might still be in use.
        // This debug list needs a clearer ownership definition.
        // For now, we assume that buffers in available_buffers_ are the only ones the pool owns and should delete.
        // If allocated_buffers_debug_ is for external leak tracking, it should not delete.
        // Let's remove deletion from allocated_buffers_debug_ in the destructor to be safe,
        // as its items might be active or already deleted if they were in available_buffers_.
        allocated_buffers_debug_.clear(); // Just clear the list, actual deletion handled for available_buffers_
    }

    // Allocates a PacketBuffer from the pool.
    PacketBuffer* allocate_buffer(size_t required_data_payload_size, size_t required_headroom = 32) {
        std::lock_guard<std::mutex> lock(mutex_);

        size_t required_total_capacity = required_data_payload_size + required_headroom;

        // Try to find a suitable buffer in the available list
        for (auto it = available_buffers_.begin(); it != available_buffers_.end(); ++it) {
            PacketBuffer* buf = *it;
            if (buf->get_capacity() >= required_total_capacity) {
                available_buffers_.erase(it); // Remove from pool

                // Reset buffer for reuse
                buf->ref_count.store(1, std::memory_order_relaxed); // Reset ref count
                // buf->reset_offsets_and_len(required_headroom, 0); // Set headroom, data length to 0
                // Or, if data_len should be payload size:
                buf->reset_offsets_and_len(required_headroom, required_data_payload_size);
                 // Let's set data_len to 0, user will set actual data length via Packet or directly.
                buf->reset_offsets_and_len(required_headroom, 0);


                // Track leased buffer.
                // Add to allocated_buffers_debug_ if not already present (it shouldn't be if logic is correct).
                // This list tracks buffers currently "leased out".
                auto alloc_it = std::find(allocated_buffers_debug_.begin(), allocated_buffers_debug_.end(), buf);
                if (alloc_it == allocated_buffers_debug_.end()) {
                    allocated_buffers_debug_.push_back(buf);
                }
                return buf;
            }
        }

        // If no suitable buffer is found, allocate a new one.
        // The capacity should be sufficient for payload and headroom.
        PacketBuffer* new_buffer = new PacketBuffer(required_total_capacity, required_headroom, 0);
        // ref_count is already 1 from PacketBuffer constructor.
        allocated_buffers_debug_.push_back(new_buffer); // Track newly allocated buffer
        return new_buffer;
    }

    // Returns a PacketBuffer to the pool.
    void free_buffer(PacketBuffer* buffer) {
        if (!buffer) {
            return;
        }

        // This function is called when a user/owner of a PacketBuffer reference
        // is done with it. It decrements the buffer's reference count.
        // If the reference count drops to zero, the buffer is considered no longer
        // in use externally and can be returned to the pool's available list.
        // The PacketBuffer's decrement_ref() method returns true if the count reached zero.

        if (buffer->decrement_ref()) { // If ref_count becomes 0 after decrement
            std::lock_guard<std::mutex> lock(mutex_);
            available_buffers_.push_back(buffer);

            // Remove from allocated_buffers_debug_ as it's no longer leased out.
            // This list tracks buffers currently "leased out".
            auto it_alloc = std::find(allocated_buffers_debug_.begin(), allocated_buffers_debug_.end(), buffer);
            if (it_alloc != allocated_buffers_debug_.end()) {
                allocated_buffers_debug_.erase(it_alloc);
            }
        }
        // If decrement_ref() returned false, it means other references to this buffer
        // still exist. The buffer remains in the allocated_buffers_debug_ list (if it was there)
        // and is not added to available_buffers_ yet. It will be fully returned to the pool
        // only when the last reference holder calls free_buffer(), causing the count to drop to zero.
    }


private:
    std::mutex mutex_;
    // Use std::list for available_buffers_ for efficient addition/removal.
    std::list<PacketBuffer*> available_buffers_;

    // For debugging purposes, to track allocated buffers by the pool.
    // This list could track all buffers currently "leased out" by the pool.
    std::list<PacketBuffer*> allocated_buffers_debug_;


    // TODO: NUMA-specific pools
    // std::vector<std::vector<PacketBuffer*>> numa_pools_[MAX_NUMA_NODES];

    // TODO: Configuration for buffer sizes and counts
    // size_t default_buffer_size_;
    // size_t max_pool_size_;
};

} // namespace netflow

#endif // NETFLOW_BUFFER_POOL_HPP
