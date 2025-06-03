#ifndef NETFLOW_QOS_MANAGER_HPP
#define NETFLOW_QOS_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <deque>
#include <optional>
#include "packet.hpp"
#include "netflow++/logger.hpp" // Assuming logger is here

namespace netflow {

enum class SchedulerType {
    STRICT_PRIORITY,
    WEIGHTED_ROUND_ROBIN,
    DEFICIT_ROUND_ROBIN
};

struct QosConfig {
    uint8_t num_queues = 4;
    SchedulerType scheduler = SchedulerType::STRICT_PRIORITY;
    std::vector<uint32_t> queue_weights;
    std::vector<uint32_t> rate_limits_kbps;
    uint32_t max_queue_depth = 1000;        // Default max depth per queue. Min 1.

    QosConfig() {
        // Default constructor
    }

    void validate_and_prepare() {
        if (num_queues == 0) {
            // Consider logging an error if logger is available.
            // For now, ensures functionality by setting a minimum.
            num_queues = 1;
        }
        if (queue_weights.size() != num_queues) {
            queue_weights.resize(num_queues, 1);
        }
        if (rate_limits_kbps.size() != num_queues) {
            rate_limits_kbps.resize(num_queues, 0);
        }
        if (max_queue_depth == 0) {
            // Consider logging an error.
            max_queue_depth = 1;
        }
    }
};

class QosManager {
public:
    QosManager(SwitchLogger& logger);
    ~QosManager();

    void configure_port_qos(uint32_t port_id, QosConfig config);
    uint8_t classify_packet_to_queue(const Packet& pkt, uint32_t port_id) const;
    void enqueue_packet(const Packet& pkt, uint32_t port_id);

    // Dequeue methods returning a copy of the Packet
    std::optional<Packet> dequeue_packet(uint32_t port_id, uint8_t queue_id);
    std::optional<Packet> select_packet_to_dequeue(uint32_t port_id);

    bool should_transmit(uint32_t port_id, uint8_t queue_id) const;
    void update_token_buckets();

    // Information retrieval methods
    std::optional<QosConfig> get_port_qos_config(uint32_t port_id) const;
    std::optional<SchedulerType> get_scheduler_type_for_port(uint32_t port_id) const;

    struct QueueStats {
        uint64_t packets_enqueued = 0;
        uint64_t packets_dropped_full = 0;
        uint64_t packets_dropped_no_config = 0;
        uint64_t packets_dequeued = 0;
        size_t current_depth = 0;

        void update_depth(const std::deque<Packet>& queue) {
            current_depth = queue.size();
        }
    };
    std::optional<QueueStats> get_queue_stats(uint32_t port_id, uint8_t queue_id) const;

private:
    std::map<uint32_t, QosConfig> port_qos_configs_;
    std::map<uint32_t, std::vector<std::deque<Packet>>> port_queues_;
    std::map<uint32_t, std::vector<QueueStats>> port_queue_stats_;
    std::map<uint32_t, uint8_t> port_last_serviced_queue_;

    SwitchLogger& logger_;
};

} // namespace netflow

#endif // NETFLOW_QOS_MANAGER_HPP
