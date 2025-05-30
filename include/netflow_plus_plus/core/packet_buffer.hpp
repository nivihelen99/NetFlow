#ifndef NETFLOW_PLUS_PLUS_CORE_PACKET_BUFFER_HPP
#define NETFLOW_PLUS_PLUS_CORE_PACKET_BUFFER_HPP

#include <atomic>
#include <cstring> // For std::memcpy

namespace netflow_plus_plus {
namespace core {

// Forward declaration
class PacketBuffer;

/**
 * @brief Manages the underlying memory buffer for network packets.
 *
 * This class is responsible for allocating, deallocating, and providing access
 * to the raw packet data. Future enhancements will include support for
 * zero-copy mechanisms and NUMA-aware allocations.
 */
class PacketBuffer {
public:
    /**
     * @brief Constructs a PacketBuffer.
     *
     * @param data Pointer to the raw packet data.
     * @param size Size of the packet data in bytes.
     */
    PacketBuffer(unsigned char* data, std::size_t size, bool take_ownership = false)
        : data_(data), size_(size), ref_count_(1), owns_data_(take_ownership) {
        // If take_ownership is true, this class is responsible for deleting data_
    }

    /**
     * @brief Constructs a PacketBuffer by copying data from a source.
     * This buffer will own its data.
     * @param data Pointer to the raw data to copy.
     * @param size Size of the data to copy.
     */
    PacketBuffer(const unsigned char* data_to_copy, std::size_t size)
        : size_(size), ref_count_(1), owns_data_(true) {
        if (data_to_copy && size > 0) {
            data_ = new unsigned char[size_];
            std::memcpy(data_, data_to_copy, size_);
        } else {
            data_ = nullptr;
            size_ = 0; // Ensure size is 0 if data is null
        }
    }


    /**
     * @brief Destructor.
     *
     * Deallocates data if this PacketBuffer owns it.
     */
    ~PacketBuffer() {
        if (owns_data_ && data_) {
            delete[] data_;
            data_ = nullptr;
        }
    }

    // Delete copy constructor and assignment operator to prevent shallow copies.
    // If copying is needed, a deep copy mechanism should be implemented (e.g., a clone method).
    PacketBuffer(const PacketBuffer&) = delete;
    PacketBuffer& operator=(const PacketBuffer&) = delete;

    /**
     * @brief Increments the reference count.
     */
    void retain() {
        ref_count_.fetch_add(1, std::memory_order_relaxed);
    }

    /**
     * @brief Decrements the reference count.
     *
     * If the reference count reaches zero, this method would typically
     * trigger the deallocation of the buffer.
     */
    void release() {
        if (ref_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            if (owns_data_ && data_) {
                delete[] data_;
                data_ = nullptr;
            }
            // If not owning data, the creator is responsible.
            // In a system with memory pools, this is where buffer would be returned to pool.
            // For self-destruction in ref counting context:
            // delete this; // This is tricky and requires careful design.
            // Generally, PacketBuffer itself might be managed by shared_ptr or similar.
        }
    }

    /**
     * @brief Gets a pointer to the raw packet data.
     * @return Pointer to the data.
     */
    unsigned char* get_data() const {
        return data_;
    }

    /**
     * @brief Gets the size of the packet data.
     * @return Size in bytes.
     */
    std::size_t get_size() const {
        return size_;
    }

private:
    unsigned char* data_;         // Pointer to the packet data
    std::size_t size_;            // Size of the packet data
    std::atomic<long> ref_count_; // Atomic reference counter
    bool owns_data_;              // True if this buffer allocated and owns data_

    // Placeholder for future memory management enhancements:
    // - Zero-copy buffer management (e.g., from DPDK rings, network card direct buffers)
    // - NUMA-aware allocations
    // - Integration with memory pools
};

} // namespace core
} // namespace netflow_plus_plus

#endif // NETFLOW_PLUS_PLUS_CORE_PACKET_BUFFER_HPP
