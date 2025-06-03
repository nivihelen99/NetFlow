#ifndef NETFLOW_PACKET_BUFFER_HPP
#define NETFLOW_PACKET_BUFFER_HPP

#include <cstddef>
#include <atomic>
#include <stdexcept> // For std::invalid_argument if needed for stricter checks

namespace netflow {

struct PacketBuffer {
    unsigned char* raw_data_ptr_; // Pointer to the start of allocated memory
    size_t capacity_;             // Total allocated size
    size_t data_offset_;          // Offset from raw_data_ptr_ to the start of actual packet data
    size_t data_len_;             // Length of the actual packet data
    std::atomic<int> ref_count;

    // Placeholder for scatter-gather support
    // PacketBuffer* next_fragment; // For linked list of fragments
    // std::vector<PacketBuffer*> fragments; // For list of fragments

    PacketBuffer(size_t capacity, size_t initial_headroom = 0, size_t initial_data_len = 0)
        : raw_data_ptr_(new unsigned char[capacity]),
          capacity_(capacity),
          data_offset_(initial_headroom),
          data_len_(initial_data_len),
          ref_count(1) {
        if (initial_headroom + initial_data_len > capacity) {
            delete[] raw_data_ptr_; // Avoid memory leak
            throw std::invalid_argument("Initial headroom + data length exceeds capacity");
        }
    }

    ~PacketBuffer() {
        delete[] raw_data_ptr_;
    }

    void increment_ref() {
        ref_count.fetch_add(1, std::memory_order_relaxed);
    }

    // Returns true if ref_count becomes 0, false otherwise.
    // The caller (BufferPool) is responsible for delete or reuse.
    bool decrement_ref() {
        if (ref_count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            return true; // Ref count was 1 and is now 0
        }
        return false; // Ref count was greater than 1
    }

    // Accessor methods
    unsigned char* get_data_start_ptr() const { return raw_data_ptr_ + data_offset_; }
    size_t get_data_length() const { return data_len_; }
    size_t get_capacity() const { return capacity_; }
    size_t get_headroom() const { return data_offset_; }
    size_t get_tailroom() const { return capacity_ - (data_offset_ + data_len_); }

    // Manipulation methods
    bool set_data_len(size_t new_len) {
        if (data_offset_ + new_len <= capacity_) {
            data_len_ = new_len;
            return true;
        }
        return false;
    }

    bool prepend_data(size_t len_to_prepend) {
        if (get_headroom() >= len_to_prepend) {
            data_offset_ -= len_to_prepend;
            data_len_ += len_to_prepend;
            return true;
        }
        return false;
    }

    bool append_data(size_t len_to_append) {
        if (get_tailroom() >= len_to_append) {
            data_len_ += len_to_append;
            return true;
        }
        return false;
    }

    bool consume_data_front(size_t len_to_consume) {
        if (data_len_ >= len_to_consume) {
            data_offset_ += len_to_consume;
            data_len_ -= len_to_consume;
            return true;
        }
        return false;
    }

    bool consume_data_end(size_t len_to_consume) {
        if (data_len_ >= len_to_consume) {
            data_len_ -= len_to_consume;
            return true;
        }
        return false;
    }

    void reset_offsets_and_len(size_t new_offset, size_t new_len) {
        // Basic check, could be more robust depending on expected use
        if (new_offset + new_len <= capacity_) {
            data_offset_ = new_offset;
            data_len_ = new_len;
        } else {
            // Or throw an exception, or handle error appropriately
            // For now, let's throw to indicate misuse clearly.
            throw std::out_of_range("New offset and length exceed buffer capacity in reset_offsets_and_len");
        }
    }
};

} // namespace netflow

#endif // NETFLOW_PACKET_BUFFER_HPP
