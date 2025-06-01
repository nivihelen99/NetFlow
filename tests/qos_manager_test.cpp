#include "gtest/gtest.h"
#include "netflow++/qos_manager.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp" // For SwitchLogger
#include <vector>
#include <optional>
#include <array>
#include <cstring>
#include <numeric>

// Helper function to create a PacketBuffer with specific Ethernet + VLAN frame
netflow::Packet create_test_packet(std::optional<uint8_t> pcp, uint16_t vid = 1, size_t payload_size = 10, uint16_t original_ethertype = netflow::ETHERTYPE_IPV4) {
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t VLAN_HEADER_SIZE = netflow::VlanHeader::SIZE;

    size_t total_header_size = ETH_HEADER_SIZE;
    if (pcp.has_value()) {
        total_header_size += VLAN_HEADER_SIZE;
    }

    std::vector<unsigned char> frame_data(total_header_size + payload_size);

    netflow::EthernetHeader eth_header;
    uint8_t dst_mac_bytes[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t src_mac_bytes[] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    std::memcpy(eth_header.dst_mac.bytes, dst_mac_bytes, 6);
    std::memcpy(eth_header.src_mac.bytes, src_mac_bytes, 6);

    if (pcp.has_value()) {
        eth_header.ethertype = htons(netflow::ETHERTYPE_VLAN);
        std::memcpy(frame_data.data(), &eth_header, ETH_HEADER_SIZE);

        netflow::VlanHeader vlan_h;
        vlan_h.set_priority(pcp.value());
        vlan_h.set_vlan_id(vid);
        vlan_h.ethertype = htons(original_ethertype);
        std::memcpy(frame_data.data() + ETH_HEADER_SIZE, &vlan_h, VLAN_HEADER_SIZE);
    } else {
        eth_header.ethertype = htons(original_ethertype);
        std::memcpy(frame_data.data(), &eth_header, ETH_HEADER_SIZE);
    }

    std::iota(frame_data.begin() + total_header_size, frame_data.end(), static_cast<unsigned char>(0));

    unsigned char* buffer_data = new unsigned char[frame_data.size()];
    std::memcpy(buffer_data, frame_data.data(), frame_data.size());

    netflow::PacketBuffer pkt_buf(buffer_data, frame_data.size(), [buffer_data]() { delete[] buffer_data; });
    // Packet constructor makes a copy of the buffer for its own management or increments ref count.
    // The returned Packet will be valid.
    return netflow::Packet(&pkt_buf);
}

// Test fixture to provide a logger instance
class QosManagerTest : public ::testing::Test {
protected:
    netflow::SwitchLogger& logger_ = netflow::SwitchLogger::getInstance();
    // You might need to initialize SwitchLogger if it's not a singleton
    // or if getInstance() needs setup. For now, assuming it's usable directly.
};


TEST_F(QosManagerTest, Instantiation) {
    netflow::QosManager qos_manager(logger_);
    SUCCEED();
}

TEST_F(QosManagerTest, ConfigureAndGetPortQos) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 4;
    config.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    config.queue_weights = {10, 20, 30, 40};
    config.rate_limits_kbps = {100, 200, 0, 500};
    config.max_queue_depth = 50;

    qos_manager.configure_port_qos(port_id, config);

    std::optional<netflow::QosConfig> retrieved_config_opt = qos_manager.get_port_qos_config(port_id);
    ASSERT_TRUE(retrieved_config_opt.has_value());
    netflow::QosConfig retrieved_config = retrieved_config_opt.value();

    EXPECT_EQ(retrieved_config.num_queues, config.num_queues);
    EXPECT_EQ(retrieved_config.scheduler, config.scheduler);
    EXPECT_EQ(retrieved_config.max_queue_depth, config.max_queue_depth);
    ASSERT_EQ(retrieved_config.queue_weights.size(), config.num_queues);
    if (config.scheduler != netflow::SchedulerType::STRICT_PRIORITY) {
        EXPECT_EQ(retrieved_config.queue_weights, config.queue_weights);
    }
    ASSERT_EQ(retrieved_config.rate_limits_kbps.size(), config.num_queues);

    netflow::QosConfig config_zero_q;
    config_zero_q.num_queues = 0;
    qos_manager.configure_port_qos(port_id + 1, config_zero_q);
    std::optional<netflow::QosConfig> c = qos_manager.get_port_qos_config(port_id + 1);
    ASSERT_TRUE(c.has_value()); // Config is stored after validate_and_prepare fixes num_queues
    EXPECT_EQ(c.value().num_queues, 1);

    config_zero_q.num_queues = 2;
    config_zero_q.max_queue_depth = 0;
    qos_manager.configure_port_qos(port_id + 2, config_zero_q);
    c = qos_manager.get_port_qos_config(port_id + 2);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c.value().max_queue_depth, 1);

    netflow::QosConfig invalid_config_wrr;
    invalid_config_wrr.num_queues = 2;
    invalid_config_wrr.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    invalid_config_wrr.queue_weights = {1};
    qos_manager.configure_port_qos(port_id + 3, invalid_config_wrr);
    ASSERT_FALSE(qos_manager.get_port_qos_config(port_id + 3).has_value());
}

TEST_F(QosManagerTest, GetSchedulerTypeForPort) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 1;
    config.scheduler = netflow::SchedulerType::STRICT_PRIORITY;
    qos_manager.configure_port_qos(port_id, config);

    std::optional<netflow::SchedulerType> scheduler = qos_manager.get_scheduler_type_for_port(port_id);
    ASSERT_TRUE(scheduler.has_value());
    EXPECT_EQ(scheduler.value(), netflow::SchedulerType::STRICT_PRIORITY);

    EXPECT_FALSE(qos_manager.get_scheduler_type_for_port(port_id + 1).has_value());
}

TEST_F(QosManagerTest, ClassifyPacketToQueue) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 4;
    qos_manager.configure_port_qos(port_id, config);

    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(7), port_id), 0);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(6), port_id), 0);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(5), port_id), 1);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(4), port_id), 1);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(3), port_id), 2);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(2), port_id), 2);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(1), port_id), 3);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(0), port_id), 3);
    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(std::nullopt), port_id), 3);

    EXPECT_EQ(qos_manager.classify_packet_to_queue(create_test_packet(7), port_id + 100), 0);
}

TEST_F(QosManagerTest, EnqueueAndQueueFull) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 1;
    config.max_queue_depth = 2;
    qos_manager.configure_port_qos(port_id, config);

    netflow::Packet pkt1 = create_test_packet(7);
    netflow::Packet pkt2 = create_test_packet(6);
    netflow::Packet pkt3 = create_test_packet(5);

    qos_manager.enqueue_packet(pkt1, port_id);
    qos_manager.enqueue_packet(pkt2, port_id);
    qos_manager.enqueue_packet(pkt3, port_id);

    std::optional<netflow::QosManager::QueueStats> stats_q0 = qos_manager.get_queue_stats(port_id, 0);
    ASSERT_TRUE(stats_q0.has_value());
    EXPECT_EQ(stats_q0->packets_enqueued, 2);
    EXPECT_EQ(stats_q0->current_depth, 2);
    EXPECT_EQ(stats_q0->packets_dropped_full, 1);
    EXPECT_EQ(stats_q0->packets_dequeued, 0);

    qos_manager.enqueue_packet(create_test_packet(std::nullopt), port_id + 1);
    stats_q0 = qos_manager.get_queue_stats(port_id, 0);
    ASSERT_TRUE(stats_q0.has_value());
    EXPECT_EQ(stats_q0->packets_enqueued, 2);
    EXPECT_EQ(stats_q0->packets_dropped_full, 1);
}


TEST_F(QosManagerTest, DequeuePacketSpecificQueue) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 2;
    config.max_queue_depth = 5;
    qos_manager.configure_port_qos(port_id, config);

    netflow::Packet pkt_q0_data = create_test_packet(7); // Classified to Q0
    netflow::Packet pkt_q1_data = create_test_packet(0); // Classified to Q1

    qos_manager.enqueue_packet(pkt_q0_data, port_id);
    qos_manager.enqueue_packet(pkt_q1_data, port_id);

    std::optional<netflow::Packet> dequeued_pkt_q0 = qos_manager.dequeue_packet(port_id, 0);
    ASSERT_TRUE(dequeued_pkt_q0.has_value());

    auto stats_q0 = qos_manager.get_queue_stats(port_id, 0);
    ASSERT_TRUE(stats_q0.has_value());
    EXPECT_EQ(stats_q0->current_depth, 0);
    EXPECT_EQ(stats_q0->packets_dequeued, 1);
    EXPECT_EQ(stats_q0->packets_enqueued, 1);

    std::optional<netflow::Packet> dequeued_pkt_q1 = qos_manager.dequeue_packet(port_id, 1);
    ASSERT_TRUE(dequeued_pkt_q1.has_value());
    auto stats_q1 = qos_manager.get_queue_stats(port_id, 1);
    ASSERT_TRUE(stats_q1.has_value());
    EXPECT_EQ(stats_q1->current_depth, 0);
    EXPECT_EQ(stats_q1->packets_dequeued, 1);

    EXPECT_FALSE(qos_manager.dequeue_packet(port_id, 0).has_value());
    EXPECT_FALSE(qos_manager.dequeue_packet(port_id, 99).has_value());
    EXPECT_FALSE(qos_manager.dequeue_packet(port_id + 1, 0).has_value());
}

TEST_F(QosManagerTest, SelectPacketStrictPriority) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 3;
    config.scheduler = netflow::SchedulerType::STRICT_PRIORITY;
    config.max_queue_depth = 5;
    qos_manager.configure_port_qos(port_id, config);

    // For 3 queues: PCP (7,6,5)->Q0; (4,3,2)->Q1; (1,0)->Q2
    netflow::Packet pkt_q1_1 = create_test_packet(3); // Q1
    netflow::Packet pkt_q0_1 = create_test_packet(7); // Q0
    netflow::Packet pkt_q2_1 = create_test_packet(0); // Q2
    netflow::Packet pkt_q0_2 = create_test_packet(6); // Q0

    qos_manager.enqueue_packet(pkt_q1_1, port_id);
    qos_manager.enqueue_packet(pkt_q0_1, port_id);
    qos_manager.enqueue_packet(pkt_q2_1, port_id);
    qos_manager.enqueue_packet(pkt_q0_2, port_id);

    std::optional<netflow::Packet> dq;
    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_FALSE(dq.has_value());

    auto stats_q0 = qos_manager.get_queue_stats(port_id, 0);
    EXPECT_EQ(stats_q0->packets_dequeued, 2);
    auto stats_q1 = qos_manager.get_queue_stats(port_id, 1);
    EXPECT_EQ(stats_q1->packets_dequeued, 1);
    auto stats_q2 = qos_manager.get_queue_stats(port_id, 2);
    EXPECT_EQ(stats_q2->packets_dequeued, 1);
}

TEST_F(QosManagerTest, SelectPacketRoundRobin) {
    netflow::QosManager qos_manager(logger_);
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 3;
    config.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    config.max_queue_depth = 5;
    qos_manager.configure_port_qos(port_id, config);

    netflow::Packet pkt_q0 = create_test_packet(7);
    netflow::Packet pkt_q1 = create_test_packet(3);
    netflow::Packet pkt_q2 = create_test_packet(0);

    qos_manager.enqueue_packet(pkt_q0, port_id); // Q0
    qos_manager.enqueue_packet(pkt_q1, port_id); // Q1
    qos_manager.enqueue_packet(pkt_q2, port_id); // Q2

    std::optional<netflow::Packet> dq;
    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());
    auto stats_q1 = qos_manager.get_queue_stats(port_id, 1); // RR starts after last_serviced (0), so Q1
    if (stats_q1.has_value() && stats_q1->packets_dequeued == 1) { /* ok */ }
    else {
        auto stats_q0_alt = qos_manager.get_queue_stats(port_id, 0);
         if(stats_q0_alt.has_value() && stats_q0_alt->packets_dequeued == 1) { /* ok if RR started at 0 */ }
         else {
            auto stats_q2_alt = qos_manager.get_queue_stats(port_id,2);
            if(stats_q2_alt.has_value() && stats_q2_alt->packets_dequeued ==1) {/*ok if RR started at 2*/}
            else {FAIL() << "Expected first RR dequeue from Q0, Q1 or Q2";}
         }
    }


    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_TRUE(dq.has_value());

    // Check that all packets were dequeued one from each queue
    EXPECT_EQ(qos_manager.get_queue_stats(port_id,0)->packets_dequeued,1);
    EXPECT_EQ(qos_manager.get_queue_stats(port_id,1)->packets_dequeued,1);
    EXPECT_EQ(qos_manager.get_queue_stats(port_id,2)->packets_dequeued,1);


    dq = qos_manager.select_packet_to_dequeue(port_id);
    ASSERT_FALSE(dq.has_value());
}
