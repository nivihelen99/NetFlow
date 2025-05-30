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
        // TODO: Release all buffers in the pool
        for (auto& buffer_ptr_vec : available_buffers_) {
            for (PacketBuffer* buf : buffer_ptr_vec) {
                 delete buf; // This might be problematic if decrement_ref is supposed to handle deletion
            }
        }
         for (PacketBuffer* buf : allocated_buffers_debug_) { // For debugging leaks
            delete buf;
        }
    }

    // Allocates a PacketBuffer from the pool.
    // For now, a simple allocation, but placeholders for more advanced features.
    PacketBuffer* allocate_buffer(size_t size) {
        std::lock_guard<std::mutex> lock(mutex_);

        // TODO: NUMA awareness - allocate from a pool associated with the current NUMA node.
        // TODO: Configurable buffer sizes - find a pool that matches the requested size or can accommodate it.
        // TODO: Huge page integration - allocate using huge pages if enabled and beneficial.

        // Simple strategy: if a buffer of suitable size is available, use it. Otherwise, allocate new.
        // This is a very basic implementation. A real pool would likely have fixed-size blocks
        // or more sophisticated management.
        for (auto& buffer_ptr_vec : available_buffers_) {
            for (auto it = buffer_ptr_vec.begin(); it != buffer_ptr_vec.end(); ++it) {
                if ((*it)->size >= size) { // Found a suitable buffer
                    PacketBuffer* buf = *it;
                    buffer_ptr_vec.erase(it);
                    buf->increment_ref(); // Should be 1 after allocation from pool
                    allocated_buffers_debug_.push_back(buf); // For debugging
                    return buf;
                }
            }
        }

        // If no suitable buffer is found, allocate a new one.
        PacketBuffer* new_buffer = new PacketBuffer(size);
        // new_buffer->ref_count should already be 1 from its constructor
        allocated_buffers_debug_.push_back(new_buffer); // For debugging
        return new_buffer;
    }

    // Returns a PacketBuffer to the pool.
    void free_buffer(PacketBuffer* buffer) {
        if (!buffer) {
            return;
        }

        // The buffer's ref_count should be decremented by the user before calling free_buffer.
        // If ref_count reaches 0, it will delete itself.
        // If we want the pool to manage deletion, then decrement_ref should not delete.
        // For now, assume decrement_ref handles deletion if ref_count is 0.
        // If the buffer is not deleted (i.e., ref_count > 0 after decrement),
        // it means it's still in use elsewhere, which is an error if called via free_buffer.
        // Or, if the pool is to take ownership back for reuse:

        bool should_return_to_pool = true;
        // If decrement_ref deletes the buffer when count reaches 0,
        // then we should not add it back to the pool.
        // Let's adjust PacketBuffer's decrement_ref or BufferPool's logic.
        // For this subtask, let's assume PacketBuffer's decrement_ref will delete.
        // So, free_buffer is more of a hint that the user is done,
        // and the buffer will self-delete when ref_count is 0.

        // If we want the pool to reclaim and reuse:
        // buffer->ref_count = 0; // Or some internal pool state
        // std::lock_guard<std::mutex> lock(mutex_);
        // available_buffers_.push_back(buffer); // Add to appropriate list based on size etc.
        // allocated_buffers_debug_.remove(buffer); // For debugging

        // Current approach: User calls decrement_ref. If it hits 0, PacketBuffer deletes itself.
        // This function might be used to signal the pool that a buffer *might* be available soon,
        // or to handle cases where the buffer should explicitly be returned to the pool
        // even if its ref_count isn't 0 (which would be unusual).

        // For this iteration, let's simplify: free_buffer just ensures ref_count is decremented.
        // The user should call this when they are done with their reference.
        // If the buffer is part of a pool and its ref_count becomes 0, it means no one else
        // is using it and it *could* be returned to a list of available buffers.

        // Let's assume the user calls decrement_ref on the buffer.
        // This function is then responsible for taking it back if it's still alive.
        // This is a bit tricky with the current PacketBuffer design where decrement_ref deletes.

        // Option 1: PacketBuffer::decrement_ref does NOT delete. BufferPool::free_buffer does.
        // Option 2: PacketBuffer::decrement_ref DOES delete. BufferPool::free_buffer is more of a no-op or for stats.
        // Let's stick to the provided PacketBuffer for now, so it self-deletes.
        // This means free_buffer in the pool might not do much other than potentially some tracking.

        // If PacketBuffer's decrement_ref handles deletion, this function's role changes.
        // It might be called to indicate the user is done, and the pool can do internal bookkeeping.
        // Or, the pool's "free_buffer" should be the one that calls "decrement_ref" and then
        // if the buffer is not deleted, adds it to its internal free list.

        std::lock_guard<std::mutex> lock(mutex_);
        // Attempt to remove from debug list
        auto it_alloc = std::find(allocated_buffers_debug_.begin(), allocated_buffers_debug_.end(), buffer);
        if (it_alloc != allocated_buffers_debug_.end()) {
            allocated_buffers_debug_.erase(it_alloc);
        }

        // If PacketBuffer's decrement_ref doesn't delete, but returns true if ref_count is 0:
        // if (buffer->decrement_ref_and_check_if_zero()) {
        //      // Now add to a specific free list in available_buffers_
        //      // For simplicity, just one list for now
        //      bool found_list = false;
        //      for(auto& buffer_vec : available_buffers_){
        //          // Potentially check size to return to correct internal pool
        //          buffer_vec.push_back(buffer);
        //          found_list = true;
        //          break;
        //      }
        //      if(!found_list){ // e.g. create a new vector for this size
        //          available_buffers_.push_back({buffer});
        //      }
        // }
        // Given current PacketBuffer, if decrement_ref() made ref_count 0, it's deleted.
        // So, we cannot add it to available_buffers_.
        // This function is more like "I am done with this buffer, pool, you may take note".
        // The current PacketBuffer deletes itself, which is fine for non-pooled scenarios.
        // For a pool, we'd typically want the pool to manage the lifecycle.

        // Let's adjust so free_buffer is the one triggering potential deletion or reuse.
        // We will call decrement_ref here. If it's still alive, we pool it.
        // This requires PacketBuffer::decrement_ref to NOT delete itself.
        // I will assume for now I cannot change packet_buffer.hpp in this step.
        // So this free_buffer will be a bit conceptual.
        // The user calls buffer->decrement_ref(). If it's 0, it's gone.
        // If they call pool.free_buffer(buffer) afterwards, the buffer pointer is dangling.
        // This design needs refinement if the pool is to actively manage reuse.

        // For now, this function will assume the buffer is *not* yet deleted by a ref_count drop to zero.
        // And the pool will take ownership if ref_count becomes 1 (owned only by pool).
        // This is a common model for intrusive ref counting with a pool.
        // However, PacketBuffer's decrement_ref already deletes.
        // This means the BufferPool cannot easily reclaim it.

        // Sticking to the current PacketBuffer: the pool cannot truly "free" and "reuse"
        // in the traditional sense unless PacketBuffer's behavior changes.
        // The pool can only allocate new ones or hand out ones it held onto without giving out.

        // Given the constraints, this free_buffer might just be a placeholder or for debug.
        // A true pool would require PacketBuffer.decrement_ref to not self-delete,
        // or the pool to be the sole owner that hands out refs.
    }


private:
    std::mutex mutex_;
    // Placeholder for actual pool storage.
    // Could be a list of free PacketBuffer pointers, perhaps segregated by size.
    // std::vector<PacketBuffer*> available_buffers_;
    std::vector<std::vector<PacketBuffer*>> available_buffers_; // Vector of vectors for different sizes perhaps

    // For debugging purposes, to track allocated buffers by the pool
    std::list<PacketBuffer*> allocated_buffers_debug_;


    // TODO: NUMA-specific pools
    // std::vector<std::vector<PacketBuffer*>> numa_pools_[MAX_NUMA_NODES];

    // TODO: Configuration for buffer sizes and counts
    // size_t default_buffer_size_;
    // size_t max_pool_size_;
};

} // namespace netflow

#endif // NETFLOW_BUFFER_POOL_HPP
