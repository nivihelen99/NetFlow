#include "netflow/core/PacketBuffer.h"
#include <stdexcept> // For std::runtime_error
#include <iostream>  // For basic error messages (consider a logger later)
#include <cstring>   // For memcpy, memset

// --- PacketBuffer Implementation ---

PacketBuffer::PacketBuffer(size_t buffer_size, int numa_node_id)
    : buffer_data_(nullptr),
      buffer_size_(0),
      data_length_(0),
      ref_counter_(0), // Initial ref count is 0 until acquired from a pool or explicitly reffed
      numa_node_id_(numa_node_id) {
    if (buffer_size == 0 || buffer_size > 16384) { // Max size sanity check (e.g. 16KB)
        // In a real system, use a proper logging mechanism
        std::cerr << "Warning: Invalid buffer_size requested: " << buffer_size << ". Using default 2048." << std::endl;
        buffer_size = 2048; // Default or fallback size
    }
    allocate_buffer(buffer_size, numa_node_id);
    // Initially, a buffer might be considered "empty" and not referenced.
    // A pool would typically call ref() when handing it out.
}

PacketBuffer::~PacketBuffer() {
    deallocate_buffer();
}

void PacketBuffer::allocate_buffer(size_t size, int numa_node) {
    // Basic allocation. NUMA-aware allocation (e.g., using numactl lib or similar)
    // and memory-mapped huge pages would be implemented here.
    // For now, simple allocation:
    if (numa_node != -1) {
        // Placeholder for NUMA-specific allocation
        // std::cout << "Info: Allocating buffer on NUMA node " << numa_node << std::endl;
    }
    buffer_data_ = std::make_unique<unsigned char[]>(size);
    if (!buffer_data_) {
        throw std::runtime_error("Failed to allocate packet buffer memory");
    }
    buffer_size_ = size;
    // std::cout << "Info: Allocated buffer of size " << size << std::endl;
}

void PacketBuffer::deallocate_buffer() {
    // buffer_data_ unique_ptr handles deallocation
    buffer_size_ = 0;
    // std::cout << "Info: Deallocated buffer" << std::endl;
}

void* PacketBuffer::data() const {
    return buffer_data_.get();
}

size_t PacketBuffer::size() const {
    return buffer_size_;
}

size_t PacketBuffer::data_len() const {
    return data_length_;
}

void PacketBuffer::set_data_len(size_t len) {
    if (len > buffer_size_) {
        // Potentially throw an error or log a warning
        // std::cerr << "Warning: Attempting to set data_len (" << len
        //           << ") greater than buffer_size_ (" << buffer_size_ << ")" << std::endl;
        data_length_ = buffer_size_;
    } else {
        data_length_ = len;
    }
}

void PacketBuffer::ref() {
    ref_counter_++;
}

bool PacketBuffer::unref() {
    if (ref_counter_ == 0) {
        // This case should ideally not happen if ref/unref is managed correctly
        // std::cerr << "Warning: unref() called on PacketBuffer with zero ref_count." << std::endl;
        return true; // Or handle as an error
    }
    --ref_counter_;
    return ref_counter_ == 0;
}

unsigned int PacketBuffer::ref_count() const {
    return ref_counter_.load();
}

const std::vector<PacketBuffer::sg_entry>& PacketBuffer::get_sg_list() const {
    return sg_list_;
}

void PacketBuffer::add_sg_entry(void* sg_data, size_t sg_len) {
    // In a more complex system, sg_entry might point to other PacketBuffers
    // or parts of this PacketBuffer. This is a simplified version.
    sg_list_.push_back({sg_data, sg_len});
}

void PacketBuffer::reset() {
    data_length_ = 0;
    sg_list_.clear();
    // ref_counter_ should be managed by the pool or owner.
    // Resetting ref_counter_ here might be incorrect depending on usage.
    // If reset means "prepare for reuse by pool", then ref_counter_ might be reset to 0 or 1.
    // For now, let's assume reset prepares it for new data, ref count is external.
}


// --- PacketBufferPool Implementation (Simplified) ---

PacketBufferPool::PacketBufferPool(size_t buf_size, size_t p_size, int numa_node)
    : buffer_size_(buf_size), numa_node_id_(numa_node) {
    if (p_size == 0) {
        throw std::runtime_error("PacketBufferPool size cannot be zero.");
    }
    pool_.reserve(p_size);
    for (size_t i = 0; i < p_size; ++i) {
        try {
            PacketBuffer* pb = new PacketBuffer(buffer_size_, numa_node_id_);
            // Buffers in the pool initially have a ref count of 1 (held by the pool)
            // or 0 if they are considered fully "available" and ref is only for external use.
            // Let's assume they are ready for acquisition, so ref_count is 0.
            // pb->ref(); // If pool holds a reference
            pool_.push_back(pb);
        } catch (const std::exception& e) {
            // Cleanup already allocated buffers if pool construction fails mid-way
            for (PacketBuffer* allocated_pb : pool_) {
                delete allocated_pb;
            }
            pool_.clear();
            throw std::runtime_error(std::string("Failed to allocate all buffers for pool: ") + e.what());
        }
    }
    // std::cout << "Info: PacketBufferPool created with " << p_size << " buffers of size " << buf_size << std::endl;
}

PacketBufferPool::~PacketBufferPool() {
    for (PacketBuffer* pb : pool_) {
        // Ensure ref_count is appropriate before deleting.
        // If buffers were acquired and not released, this might indicate a leak.
        // if (pb->ref_count() > 0) { // Assuming 0 means it's safe to delete from pool's perspective
        //     std::cerr << "Warning: Deleting PacketBuffer from pool with ref_count " << pb->ref_count() << std::endl;
        // }
        delete pb;
    }
    pool_.clear();
    // std::cout << "Info: PacketBufferPool destroyed." << std::endl;
}

PacketBuffer* PacketBufferPool::acquire_buffer() {
    // Basic non-thread-safe example. A real pool needs synchronization.
    if (pool_.empty()) {
        // std::cerr << "Warning: PacketBufferPool is empty. Cannot acquire buffer." << std::endl;
        // Optionally, try to dynamically allocate a new one if allowed, or return nullptr.
        return nullptr; 
    }
    PacketBuffer* pb = pool_.back();
    pool_.pop_back();
    pb->reset(); // Prepare buffer for new use
    pb->ref();   // Acquired buffer gets one reference
    return pb;
}

void PacketBufferPool::release_buffer(PacketBuffer* buffer) {
    if (!buffer) return;

    // if (buffer->unref()) { // Decrement ref count, if it becomes 0, it's truly released
        // Optional: Check if buffer actually belongs to this pool based on size/numa_node
        // if (buffer->size() != buffer_size_) {
        //     std::cerr << "Error: Releasing buffer with incorrect size to the pool." << std::endl;
        //     delete buffer; // Or handle error appropriately
        //     return;
        // }
        // pool_.push_back(buffer); // Add back to the pool
    // } else {
        // Buffer is still referenced elsewhere, should not be added back to the pool yet.
        // This indicates a shared PacketBuffer scenario. The last unref() will make it 0.
        // std::cout << "Info: PacketBuffer unreffed but still has " << buffer->ref_count() << " references. Not returning to pool yet." << std::endl;
    // }
    // Simplified release: directly attempt to return to pool if ref count becomes 0.
    // A more robust pool would handle cases where unref doesn't mean it's immediately pool-ready.
    if (buffer->unref()) { // If unref() returns true, ref_count is 0
        pool_.push_back(buffer);
    } else {
        // This means someone else still holds a reference. The current design of unref()
        // and acquire() implies that when acquire() is called, the ref_count becomes 1.
        // When release_buffer is called, it calls unref(). If it's not 0, it means
        // there's an imbalance or shared ownership not fully captured by this simple pool.
        // For a simple pool, we expect ref_count to be 1 when release_buffer is called by the owner.
        std::cerr << "Warning: Released buffer still has ref_count > 0 (" << buffer->ref_count() 
                  << "). Potential ref_count mismatch or shared ownership issue." << std::endl;
        // Depending on policy, either force it back or flag error. Forcing back:
        // pool_.push_back(buffer);
        // Or, if this is an error state, potentially don't add it back or log more severely.
    }
}

size_t PacketBufferPool::available_buffers() const {
    return pool_.size();
}

size_t PacketBufferPool::total_buffers() const {
    // In a dynamic pool, this might differ from pool_.capacity() or initial size.
    // For this simple version, it's the current number of buffers in the vector.
    // A better measure would be initial_pool_size or similar.
    // For now, let's assume it's how many it *can* hold if it were full to its initial capacity.
    // This is not well-defined in current simple impl if buffers are created outside.
    // Let's return current available + those in use (which is hard to track without more state).
    // So, for simplicity, just return current size.
    return pool_.size(); // This shows how many are *currently in the pool*, not total created/managed.
}
