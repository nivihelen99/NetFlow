#include "gtest/gtest.h"
#include "netflow++/buffer_pool.hpp"
#include "netflow++/packet_buffer.hpp"
#include <vector> // For std::vector if needed for any test logic
#include <set>    // For std::set to track unique buffer pointers

// Test Fixture for BufferPool
class BufferPoolTest : public ::testing::Test {
protected:
    netflow::BufferPool pool_; // Default constructor is fine

    // Optional: Helper to check buffer properties
    void CheckBufferProperties(netflow::PacketBuffer* buf, size_t expected_capacity_min, size_t expected_headroom, size_t expected_data_len, int expected_ref_count) {
        ASSERT_NE(buf, nullptr);
        EXPECT_GE(buf->get_capacity(), expected_capacity_min); // Pool might give a larger buffer
        EXPECT_EQ(buf->get_headroom(), expected_headroom);
        EXPECT_EQ(buf->get_data_length(), expected_data_len);
        EXPECT_EQ(buf->ref_count.load(), expected_ref_count);
    }
};

TEST_F(BufferPoolTest, AllocateFromEmptyPool) {
    size_t requested_capacity = 1000;
    size_t requested_headroom = 32;
    netflow::PacketBuffer* buf = pool_.allocate_buffer(requested_capacity, requested_headroom);

    ASSERT_NE(buf, nullptr);
    // The pool allocates capacity + headroom, so capacity check is on total size.
    // PacketBuffer constructor takes capacity, initial_headroom.
    // BufferPool::allocate_buffer(min_payload_capacity, initial_headroom)
    // So, the actual capacity of the PacketBuffer should be at least min_payload_capacity + initial_headroom.
    CheckBufferProperties(buf, requested_capacity + requested_headroom, requested_headroom, 0, 1);

    pool_.free_buffer(buf);
}

TEST_F(BufferPoolTest, FreeAndReallocate) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100, 10);
    ASSERT_NE(buf1, nullptr);
    pool_.free_buffer(buf1);

    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(80, 5); // Requesting smaller capacity and headroom
    ASSERT_NE(buf2, nullptr);
    // The pool should reuse buf1 if it's suitable (capacity >= 80+5 and headroom can be adjusted)
    // BufferPool logic: finds buffer with capacity >= (min_payload_capacity + initial_headroom)
    // buf1 capacity was >= 100+10 = 110.
    // buf2 needs capacity >= 80+5 = 85. buf1 is suitable.
    EXPECT_EQ(buf1, buf2); // Buffer is reused
    CheckBufferProperties(buf2, 80 + 5, 5, 0, 1);

    pool_.free_buffer(buf2);
}

TEST_F(BufferPoolTest, AllocateDifferentSizes) {
    netflow::PacketBuffer* buf_large = pool_.allocate_buffer(2000);
    ASSERT_NE(buf_large, nullptr);
    netflow::PacketBuffer* buf_small = pool_.allocate_buffer(500);
    ASSERT_NE(buf_small, nullptr);
    ASSERT_NE(buf_large, buf_small);

    pool_.free_buffer(buf_large);
    pool_.free_buffer(buf_small);

    // Pool now has a 2000-cap and a 500-cap buffer (approx sizes)
    // Request 1000. Should reuse the 2000-cap buffer.
    netflow::PacketBuffer* buf_medium = pool_.allocate_buffer(1000);
    ASSERT_NE(buf_medium, nullptr);
    EXPECT_EQ(buf_medium, buf_large); // Reuses the larger one

    pool_.free_buffer(buf_medium);
}

TEST_F(BufferPoolTest, NoSuitableBufferInPool) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100);
    ASSERT_NE(buf1, nullptr);
    pool_.free_buffer(buf1);

    // Pool has a buffer of capacity ~100. Request a larger one.
    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(200);
    ASSERT_NE(buf2, nullptr);
    EXPECT_NE(buf1, buf2); // New buffer should be created
    CheckBufferProperties(buf2, 200, 0, 0, 1);

    pool_.free_buffer(buf2);
}

TEST_F(BufferPoolTest, RefCountPreventsPrematureReclaim) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100); // pool gives buf with ref_count = 1
    ASSERT_NE(buf1, nullptr);

    buf1->increment_ref(); // User increments ref_count to 2, indicating another user

    // First user is done with buf1
    pool_.free_buffer(buf1); // Inside free_buffer, decrement_ref makes ref_count = 1. Not added to pool.

    // Try to allocate another buffer. Since buf1 is not in the pool (still ref_count=1),
    // a new buffer (buf2) should be allocated or an existing different one reused.
    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(100);
    ASSERT_NE(buf2, nullptr);
    EXPECT_NE(buf1, buf2); // buf1 should still be "in use" by the second user

    // Second user is done with buf1
    pool_.free_buffer(buf1); // Inside free_buffer, decrement_ref makes ref_count = 0. Now added to pool.

    // Try to allocate another buffer. Now buf1 should be available and reused.
    netflow::PacketBuffer* buf3 = pool_.allocate_buffer(100);
    ASSERT_NE(buf3, nullptr);
    EXPECT_EQ(buf1, buf3); // buf1 is now reused

    pool_.free_buffer(buf2); // Cleanup buf2
    pool_.free_buffer(buf3); // Cleanup buf3 (which is buf1)
}

TEST_F(BufferPoolTest, FreeNullBuffer) {
    ASSERT_NO_THROW(pool_.free_buffer(nullptr)); // Should not crash or throw
}

TEST_F(BufferPoolTest, PoolMaintainsMultipleBuffers) {
    std::set<netflow::PacketBuffer*> allocated_buffers;
    for (int i = 0; i < 5; ++i) {
        netflow::PacketBuffer* buf = pool_.allocate_buffer(100 + i * 10); // Different sizes
        ASSERT_NE(buf, nullptr);
        allocated_buffers.insert(buf);
    }
    EXPECT_EQ(allocated_buffers.size(), 5); // All 5 should be distinct

    for (netflow::PacketBuffer* buf : allocated_buffers) {
        pool_.free_buffer(buf);
    }
    allocated_buffers.clear();

    // Allocate again, some should be reused
    // The exact reuse pattern depends on the pool's internal logic (e.g., how it sorts free lists)
    // but we expect to get valid buffers.
    std::set<netflow::PacketBuffer*> reallocated_buffers;
    for (int i = 0; i < 5; ++i) {
        netflow::PacketBuffer* buf = pool_.allocate_buffer(100 + i * 10);
        ASSERT_NE(buf, nullptr);
        reallocated_buffers.insert(buf);
    }
    EXPECT_EQ(reallocated_buffers.size(), 5);

    for (netflow::PacketBuffer* buf : reallocated_buffers) {
       pool_.free_buffer(buf);
    }
}
