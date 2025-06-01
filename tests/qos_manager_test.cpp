#include "gtest/gtest.h"
#include "netflow++/qos_manager.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp"
#include <vector>
#include <optional>
#include <array>
#include <cstring>
#include <numeric>
#include <arpa/inet.h> // For htons

// Helper function to create a PacketBuffer with specific Ethernet + VLAN frame
netflow::Packet create_test_packet_qos( // Renamed to avoid potential clashes if other files have same name
    std::optional<uint8_t> pcp, uint16_t vid = 1,
    size_t payload_size = 10, uint16_t original_ethertype = netflow::ETHERTYPE_IPV4)
{
    constexpr size_t ETH_HEADER_SIZE = netflow::EthernetHeader::SIZE;
    constexpr size_t VLAN_HEADER_SIZE = netflow::VlanHeader::SIZE;

    size_t current_header_size = ETH_HEADER_SIZE;
    if (pcp.has_value()) {
        current_header_size += VLAN_HEADER_SIZE;
    }
    size_t total_frame_size = current_header_size + payload_size;

    std::vector<unsigned char> frame_data_vec(total_frame_size); // Temporary vector to build frame

    netflow::EthernetHeader eth_header_data;
    uint8_t dst_mac_bytes[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t src_mac_bytes[] = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    std::memcpy(eth_header_data.dst_mac.bytes, dst_mac_bytes, 6);
    std::memcpy(eth_header_data.src_mac.bytes, src_mac_bytes, 6);

    size_t current_offset = 0;
    if (pcp.has_value()) {
        eth_header_data.ethertype = htons(netflow::ETHERTYPE_VLAN);
        std::memcpy(frame_data_vec.data() + current_offset, &eth_header_data, ETH_HEADER_SIZE);
        current_offset += ETH_HEADER_SIZE;

        netflow::VlanHeader vlan_h_data;
        vlan_h_data.set_priority(pcp.value());
        vlan_h_data.set_vlan_id(vid);
        vlan_h_data.ethertype = htons(original_ethertype);
        std::memcpy(frame_data_vec.data() + current_offset, &vlan_h_data, VLAN_HEADER_SIZE);
        current_offset += VLAN_HEADER_SIZE;
    } else {
        eth_header_data.ethertype = htons(original_ethertype);
        std::memcpy(frame_data_vec.data() + current_offset, &eth_header_data, ETH_HEADER_SIZE);
        current_offset += ETH_HEADER_SIZE;
    }

    std::iota(frame_data_vec.begin() + current_offset, frame_data_vec.end(), static_cast<unsigned char>(0));

    // Create PacketBuffer instance - it allocates memory
    netflow::PacketBuffer* pb = new netflow::PacketBuffer(total_frame_size);
    std::memcpy(pb->get_data_start_ptr(), frame_data_vec.data(), total_frame_size);
    pb->set_data_len(total_frame_size);

    netflow::Packet pkt(pb);
    pb->decrement_ref(); // Packet constructor increments ref_count, so balance it here.
    return pkt;
}


class QosManagerTest : public ::testing::Test {
protected:
    // Instantiate logger directly
    netflow::SwitchLogger logger_{netflow::LogLevel::DEBUG};
    netflow::QosManager qos_manager_{logger_}; // Initialize QosManager with the logger

    void SetUp() override {
       // qos_manager_.clear_all_port_configs(); // Assuming such a method exists for clean tests
    }
};


TEST_F(QosManagerTest, Instantiation) {
    // Already instantiated in fixture
    SUCCEED();
}

TEST_F(QosManagerTest, ConfigureAndGetPortQos) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 4;
    config.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    config.queue_weights = {10, 20, 30, 40};
    config.rate_limits_kbps = {100, 200, 0, 500};
    config.max_queue_depth = 50;

    qos_manager_.configure_port_qos(port_id, config);

    std::optional<netflow::QosConfig> retrieved_config_opt = qos_manager_.get_port_qos_config(port_id);
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
    config_zero_q.num_queues = 0; // validate_and_prepare in QosConfig will default this to 1
    qos_manager_.configure_port_qos(port_id + 1, config_zero_q);
    std::optional<netflow::QosConfig> c = qos_manager_.get_port_qos_config(port_id + 1);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c.value().num_queues, 1);

    config_zero_q.num_queues = 2;
    config_zero_q.max_queue_depth = 0; // validate_and_prepare will default this to 1
    qos_manager_.configure_port_qos(port_id + 2, config_zero_q);
    c = qos_manager_.get_port_qos_config(port_id + 2);
    ASSERT_TRUE(c.has_value());
    EXPECT_EQ(c.value().max_queue_depth, 1);

    netflow::QosConfig invalid_config_wrr;
    invalid_config_wrr.num_queues = 2;
    invalid_config_wrr.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    invalid_config_wrr.queue_weights = {1};
    qos_manager_.configure_port_qos(port_id + 3, invalid_config_wrr); // This should be rejected by QosManager
    ASSERT_FALSE(qos_manager_.get_port_qos_config(port_id + 3).has_value());
}

TEST_F(QosManagerTest, GetSchedulerTypeForPort) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 1;
    config.scheduler = netflow::SchedulerType::STRICT_PRIORITY;
    qos_manager_.configure_port_qos(port_id, config);

    std::optional<netflow::SchedulerType> scheduler = qos_manager_.get_scheduler_type_for_port(port_id);
    ASSERT_TRUE(scheduler.has_value());
    EXPECT_EQ(scheduler.value(), netflow::SchedulerType::STRICT_PRIORITY);

    EXPECT_FALSE(qos_manager_.get_scheduler_type_for_port(port_id + 1).has_value());
}

TEST_F(QosManagerTest, ClassifyPacketToQueue) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 4;
    qos_manager_.configure_port_qos(port_id, config);

    EXPECT_EQ(qos_manager_.classify_packet_to_queue(create_test_packet_qos(7), port_id), 0);
    EXPECT_EQ(qos_manager_.classify_packet_to_queue(create_test_packet_qos(1), port_id), 3);
    EXPECT_EQ(qos_manager_.classify_packet_to_queue(create_test_packet_qos(std::nullopt), port_id), 3);

    EXPECT_EQ(qos_manager_.classify_packet_to_queue(create_test_packet_qos(7), port_id + 100), 0);
}

TEST_F(QosManagerTest, EnqueueAndQueueFull) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 1;
    config.max_queue_depth = 2;
    qos_manager_.configure_port_qos(port_id, config);

    netflow::Packet pkt1 = create_test_packet_qos(7);
    netflow::Packet pkt2 = create_test_packet_qos(6);
    netflow::Packet pkt3 = create_test_packet_qos(5);

    qos_manager_.enqueue_packet(pkt1, port_id);
    qos_manager_.enqueue_packet(pkt2, port_id);
    qos_manager_.enqueue_packet(pkt3, port_id);

    std::optional<netflow::QosManager::QueueStats> stats_q0 = qos_manager_.get_queue_stats(port_id, 0);
    ASSERT_TRUE(stats_q0.has_value());
    EXPECT_EQ(stats_q0->packets_enqueued, 2);
    EXPECT_EQ(stats_q0->current_depth, 2);
    EXPECT_EQ(stats_q0->packets_dropped_full, 1);
    EXPECT_EQ(stats_q0->packets_dequeued, 0);
}


TEST_F(QosManagerTest, DequeuePacketSpecificQueue) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 2;
    config.max_queue_depth = 5;
    qos_manager_.configure_port_qos(port_id, config);

    netflow::Packet pkt_q0_data = create_test_packet_qos(7); // Classified to Q0 (for 2 queues: 7,6,5,4 -> Q0; 3,2,1,0 -> Q1)
    netflow::Packet pkt_q1_data = create_test_packet_qos(0); // Classified to Q1

    qos_manager_.enqueue_packet(pkt_q0_data, port_id);
    qos_manager_.enqueue_packet(pkt_q1_data, port_id);

    std::optional<netflow::Packet> dequeued_pkt_q0 = qos_manager_.dequeue_packet(port_id, 0);
    ASSERT_TRUE(dequeued_pkt_q0.has_value());

    auto stats_q0 = qos_manager_.get_queue_stats(port_id, 0);
    ASSERT_TRUE(stats_q0.has_value());
    EXPECT_EQ(stats_q0->current_depth, 0);
    EXPECT_EQ(stats_q0->packets_dequeued, 1);

    std::optional<netflow::Packet> dequeued_pkt_q1 = qos_manager_.dequeue_packet(port_id, 1);
    ASSERT_TRUE(dequeued_pkt_q1.has_value());
    auto stats_q1 = qos_manager_.get_queue_stats(port_id, 1);
    ASSERT_TRUE(stats_q1.has_value());
    EXPECT_EQ(stats_q1->current_depth, 0);
    EXPECT_EQ(stats_q1->packets_dequeued, 1);

    EXPECT_FALSE(qos_manager_.dequeue_packet(port_id, 0).has_value());
    EXPECT_FALSE(qos_manager_.dequeue_packet(port_id, 99).has_value());
    EXPECT_FALSE(qos_manager_.dequeue_packet(port_id + 1, 0).has_value());
}

TEST_F(QosManagerTest, SelectPacketStrictPriority) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 3;
    config.scheduler = netflow::SchedulerType::STRICT_PRIORITY;
    config.max_queue_depth = 5;
    qos_manager_.configure_port_qos(port_id, config);

    // For 3 queues: PCP (7,6,5)->Q0; (4,3,2)->Q1; (1,0)->Q2
    netflow::Packet pkt_q1_1 = create_test_packet_qos(3); // Q1
    netflow::Packet pkt_q0_1 = create_test_packet_qos(7); // Q0
    netflow::Packet pkt_q2_1 = create_test_packet_qos(0); // Q2
    netflow::Packet pkt_q0_2 = create_test_packet_qos(6); // Q0

    qos_manager_.enqueue_packet(pkt_q1_1, port_id);
    qos_manager_.enqueue_packet(pkt_q0_1, port_id);
    qos_manager_.enqueue_packet(pkt_q2_1, port_id);
    qos_manager_.enqueue_packet(pkt_q0_2, port_id);

    std::optional<netflow::Packet> dq;
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value()); // Q0 (pkt_q0_1)
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value()); // Q0 (pkt_q0_2)
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value()); // Q1 (pkt_q1_1)
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value()); // Q2 (pkt_q2_1)
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_FALSE(dq.has_value());

    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 0)->packets_dequeued, 2);
    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 1)->packets_dequeued, 1);
    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 2)->packets_dequeued, 1);
}

TEST_F(QosManagerTest, SelectPacketRoundRobin) {
    uint32_t port_id = 1;
    netflow::QosConfig config;
    config.num_queues = 3;
    config.scheduler = netflow::SchedulerType::WEIGHTED_ROUND_ROBIN;
    config.max_queue_depth = 5;
    qos_manager_.configure_port_qos(port_id, config);

    // For 3 queues: PCP (7,6,5)->Q0; (4,3,2)->Q1; (1,0)->Q2
    netflow::Packet pkt_q0 = create_test_packet_qos(7);
    netflow::Packet pkt_q1 = create_test_packet_qos(3);
    netflow::Packet pkt_q2 = create_test_packet_qos(0);

    qos_manager_.enqueue_packet(pkt_q0, port_id); // Q0
    qos_manager_.enqueue_packet(pkt_q1, port_id); // Q1
    qos_manager_.enqueue_packet(pkt_q2, port_id); // Q2

    std::optional<netflow::Packet> dq;
    // RR starts after last_serviced (0), so checks Q1, then Q2, then Q0.
    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value());
    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 1)->packets_dequeued, 1);

    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value());
    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 2)->packets_dequeued, 1);

    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_TRUE(dq.has_value());
    EXPECT_EQ(qos_manager_.get_queue_stats(port_id, 0)->packets_dequeued, 1);

    dq = qos_manager_.select_packet_to_dequeue(port_id); ASSERT_FALSE(dq.has_value());
}
