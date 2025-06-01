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

    // Manually free for this test, assuming ref_count becomes 0.
    // If decrement_ref returns true (was 1, now 0), then free_buffer.
    if (buf->decrement_ref()) {
        pool_.free_buffer(buf);
    } else {
        // This case should not happen if allocate_buffer sets ref_count to 1
        // and nothing else incremented it.
        FAIL() << "Buffer ref_count was not 1 after allocation and single decrement.";
    }
}

TEST_F(BufferPoolTest, FreeAndReallocate) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100, 10);
    ASSERT_NE(buf1, nullptr);
    if (buf1->decrement_ref()) { // ref_count becomes 0
        pool_.free_buffer(buf1);
    } else {
        FAIL() << "buf1 ref_count error before freeing.";
    }

    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(80, 5); // Requesting smaller capacity and headroom
    ASSERT_NE(buf2, nullptr);
    // The pool should reuse buf1 if it's suitable (capacity >= 80+5 and headroom can be adjusted)
    // BufferPool logic: finds buffer with capacity >= (min_payload_capacity + initial_headroom)
    // buf1 capacity was >= 100+10 = 110.
    // buf2 needs capacity >= 80+5 = 85. buf1 is suitable.
    EXPECT_EQ(buf1, buf2); // Buffer is reused
    CheckBufferProperties(buf2, 80 + 5, 5, 0, 1);

    if (buf2->decrement_ref()) {
        pool_.free_buffer(buf2);
    }
}

TEST_F(BufferPoolTest, AllocateDifferentSizes) {
    netflow::PacketBuffer* buf_large = pool_.allocate_buffer(2000);
    ASSERT_NE(buf_large, nullptr);
    netflow::PacketBuffer* buf_small = pool_.allocate_buffer(500);
    ASSERT_NE(buf_small, nullptr);
    ASSERT_NE(buf_large, buf_small);

    if (buf_large->decrement_ref()) pool_.free_buffer(buf_large); else FAIL();
    if (buf_small->decrement_ref()) pool_.free_buffer(buf_small); else FAIL();

    // Pool now has a 2000-cap and a 500-cap buffer (approx sizes)
    // Request 1000. Should reuse the 2000-cap buffer.
    netflow::PacketBuffer* buf_medium = pool_.allocate_buffer(1000);
    ASSERT_NE(buf_medium, nullptr);
    EXPECT_EQ(buf_medium, buf_large); // Reuses the larger one

    if (buf_medium->decrement_ref()) pool_.free_buffer(buf_medium); else FAIL();
}

TEST_F(BufferPoolTest, NoSuitableBufferInPool) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100);
    ASSERT_NE(buf1, nullptr);
    if (buf1->decrement_ref()) pool_.free_buffer(buf1); else FAIL();

    // Pool has a buffer of capacity ~100. Request a larger one.
    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(200);
    ASSERT_NE(buf2, nullptr);
    EXPECT_NE(buf1, buf2); // New buffer should be created
    CheckBufferProperties(buf2, 200, 0, 0, 1);

    if (buf2->decrement_ref()) pool_.free_buffer(buf2); else FAIL();
}

TEST_F(BufferPoolTest, RefCountPreventsPrematureReclaim) {
    netflow::PacketBuffer* buf1 = pool_.allocate_buffer(100);
    ASSERT_NE(buf1, nullptr);

    buf1->increment_ref(); // ref_count is now 2

    // This call to free_buffer will decrement ref_count to 1, but not add to available list
    // because free_buffer is only called if decrement_ref() returned true (meaning it reached 0)
    // The test logic should be:
    // bool was_last_ref = buf1->decrement_ref(); // ref_count becomes 1
    // if (was_last_ref) { pool_.free_buffer(buf1); }
    // ASSERT_FALSE(was_last_ref); // It wasn't the last reference
    // So, to test this, we call decrement_ref and check its return.

    ASSERT_FALSE(buf1->decrement_ref()); // ref_count becomes 1, does not return true

    netflow::PacketBuffer* buf2 = pool_.allocate_buffer(100);
    ASSERT_NE(buf2, nullptr);
    EXPECT_NE(buf1, buf2); // buf1 should still be "in use" (not in pool's available list)

    ASSERT_TRUE(buf1->decrement_ref()); // ref_count becomes 0, returns true
    pool_.free_buffer(buf1); // Now it should be returned to available list

    netflow::PacketBuffer* buf3 = pool_.allocate_buffer(100);
    ASSERT_NE(buf3, nullptr);
    EXPECT_EQ(buf1, buf3); // buf1 is now reused

    if (buf2->decrement_ref()) pool_.free_buffer(buf2); else FAIL();
    if (buf3->decrement_ref()) pool_.free_buffer(buf3); else FAIL();
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
        if (buf->decrement_ref()) {
            pool_.free_buffer(buf);
        } else {
            FAIL() << "Buffer ref_count error during cleanup.";
        }
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
       if (buf->decrement_ref()) {
            pool_.free_buffer(buf);
        } else {
            FAIL() << "Buffer ref_count error during cleanup (reallocated).";
        }
    }
}
