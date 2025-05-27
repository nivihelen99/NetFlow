#ifndef NETFLOW_CORE_PACKET_BUFFER_H
#define NETFLOW_CORE_PACKET_BUFFER_H

#include <cstddef> // For size_t
#include <atomic>  // For std::atomic
#include <vector>  // For scatter-gather
#include <memory>  // For std::unique_ptr

// Forward declaration for NumaNode if used for NUMA awareness
// struct NumaNode; 

class PacketBuffer {
public:
    // Structure for scatter-gather elements
    struct sg_entry {
        void* data;
        size_t len;
    };

    // Constructor: Pass NUMA node info if applicable, buffer size
    // For now, NUMA awareness logic can be minimal or placeholder
    PacketBuffer(size_t buffer_size, int numa_node_id = -1);

    // Destructor
    ~PacketBuffer();

    // Get a pointer to the raw buffer data
    void* data() const;

    // Get the size of the buffer
    size_t size() const;

    // Get the current data length in the buffer
    size_t data_len() const;

    // Set the current data length in the buffer
    void set_data_len(size_t len);

    // Increment reference count
    void ref();

    // Decrement reference count. If count reaches zero, buffer might be returned to a pool.
    // Returns true if the buffer should be deallocated/returned to pool.
    bool unref();

    // Get current reference count
    unsigned int ref_count() const;

    // Scatter-gather I/O support (conceptual)
    // These methods might be more complex in a full implementation,
    // involving interaction with a buffer pool that manages sg lists.
    const std::vector<sg_entry>& get_sg_list() const;
    void add_sg_entry(void* data, size_t len); // Simplified for now

    // Methods for memory-mapped buffer properties (conceptual)
    // bool is_mmapped() const;
    // int huge_page_size() const; // Returns 0 if not using huge pages

    // Reset buffer (clear data_len, potentially other metadata)
    void reset();

private:
    std::unique_ptr<unsigned char[]> buffer_data_; // Owns the memory if not mmapped/externally managed
    size_t buffer_size_;
    size_t data_length_;
    std::atomic<unsigned int> ref_counter_;
    int numa_node_id_; // For NUMA awareness

    std::vector<sg_entry> sg_list_; // For scatter-gather

    // Private helper to allocate memory, potentially NUMA-aware or mmapped
    // For now, a simple new unsigned char[] is fine.
    void allocate_buffer(size_t size, int numa_node); 
    void deallocate_buffer();

    // Flag to indicate if memory is externally managed (e.g. mmap)
    // bool externally_managed_memory_; 
};

// Basic Packet Buffer Pool (Simplified for now)
// A real pool would be more complex, managing multiple PacketBuffer instances.
class PacketBufferPool {
public:
    PacketBufferPool(size_t buffer_size, size_t pool_size, int numa_node_id = -1);
    ~PacketBufferPool();

    PacketBuffer* acquire_buffer();
    void release_buffer(PacketBuffer* buffer);

    size_t available_buffers() const;
    size_t total_buffers() const;

private:
    size_t buffer_size_;
    int numa_node_id_;
    std::vector<PacketBuffer*> pool_;
    // Mutex or lock-free mechanism would be needed for thread-safe acquire/release
    // std::mutex pool_mutex_; 
};

#endif // NETFLOW_CORE_PACKET_BUFFER_H
