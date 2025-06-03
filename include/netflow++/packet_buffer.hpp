#ifndef NETFLOW_PACKET_BUFFER_HPP
#define NETFLOW_PACKET_BUFFER_HPP

#include <cstddef>   // For std::size_t
#include <atomic>    // For std::atomic, std::memory_order
#include <stdexcept> // For std::invalid_argument, std::out_of_range
// #include <vector> // Not strictly needed for current active code, but if fragments were used

namespace netflow {

struct PacketBuffer {
    unsigned char* raw_data_ptr_;
    std::size_t capacity_;
    std::size_t data_offset_;
    std::size_t data_len_;
    std::atomic<int> ref_count;

    // PacketBuffer* next_fragment; // For linked list of fragments
    // std::vector<PacketBuffer*> fragments; // For list of fragments

    PacketBuffer(std::size_t capacity, std::size_t initial_headroom = 0, std::size_t initial_data_len = 0)
        : raw_data_ptr_(new unsigned char[capacity]),
          capacity_(capacity),
          data_offset_(initial_headroom),
          data_len_(initial_data_len),
          ref_count(1) {
        if (initial_headroom + initial_data_len > capacity) {
            delete[] raw_data_ptr_;
            throw std::invalid_argument("Initial headroom + data length exceeds capacity");
        }
    }

    ~PacketBuffer() {
        delete[] raw_data_ptr_;
    }

    void increment_ref() {
        ref_count.fetch_add(1, std::memory_order_relaxed);
    }

    bool decrement_ref() {
        if (ref_count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            return true;
        }
        return false;
    }

    unsigned char* get_data_start_ptr() const { return raw_data_ptr_ + data_offset_; }
    std::size_t get_data_length() const { return data_len_; }
    std::size_t get_capacity() const { return capacity_; }
    std::size_t get_headroom() const { return data_offset_; }
    std::size_t get_tailroom() const { return capacity_ - (data_offset_ + data_len_); }

    bool set_data_len(std::size_t new_len) {
        if (data_offset_ + new_len <= capacity_) {
            data_len_ = new_len;
            return true;
        }
        return false;
    }

    bool prepend_data(std::size_t len_to_prepend) {
        if (get_headroom() >= len_to_prepend) {
            data_offset_ -= len_to_prepend;
            data_len_ += len_to_prepend;
            return true;
        }
        return false;
    }

    bool append_data(std::size_t len_to_append) {
        if (get_tailroom() >= len_to_append) {
            data_len_ += len_to_append;
            return true;
        }
        return false;
    }

    bool consume_data_front(std::size_t len_to_consume) {
        if (data_len_ >= len_to_consume) {
            data_offset_ += len_to_consume;
            data_len_ -= len_to_consume;
            return true;
        }
        return false;
    }

    bool consume_data_end(std::size_t len_to_consume) {
        if (data_len_ >= len_to_consume) {
            data_len_ -= len_to_consume;
            return true;
        }
        return false;
    }

    void reset_offsets_and_len(std::size_t new_offset, std::size_t new_len) {
        if (new_offset + new_len <= capacity_) {
            data_offset_ = new_offset;
            data_len_ = new_len;
        } else {
            throw std::out_of_range("New offset and length exceed buffer capacity in reset_offsets_and_len");
        }
    }
};

} // namespace netflow

#endif // NETFLOW_PACKET_BUFFER_HPP
