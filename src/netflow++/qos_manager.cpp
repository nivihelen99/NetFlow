#include "netflow++/qos_manager.hpp"
#include "netflow++/packet.hpp"
#include "netflow++/logger.hpp" // Assuming logger is here

// #include <iostream> // Placeholder for logging - REMOVE

namespace netflow {

// Constructor
QosManager::QosManager(SwitchLogger& logger) : logger_(logger) {
    logger_.log(LogLevel::DEBUG, "QosManager", "QosManager initialized.");
}

// Destructor
QosManager::~QosManager() {
    logger_.log(LogLevel::DEBUG, "QosManager", "QosManager destroyed.");
}

void QosManager::configure_port_qos(uint32_t port_id, QosConfig config) {
    config.validate_and_prepare();

    if ((config.scheduler == SchedulerType::WEIGHTED_ROUND_ROBIN || config.scheduler == SchedulerType::DEFICIT_ROUND_ROBIN) &&
        config.queue_weights.size() != config.num_queues) {
        logger_.log(LogLevel::ERROR, "QosManager", "configure_port_qos - Queue weights size (" +
                    std::to_string(config.queue_weights.size()) +
                    ") mismatch for scheduler type on port " + std::to_string(port_id) +
                    ". Expected " + std::to_string(static_cast<int>(config.num_queues)) + ".");
        return;
    }

    port_qos_configs_[port_id] = config;
    // Resize and let deques/stats be default-constructed (empty)
    port_queues_[port_id].resize(config.num_queues);
    port_queue_stats_[port_id].resize(config.num_queues);
    port_last_serviced_queue_[port_id] = 0;

    logger_.log(LogLevel::INFO, "QosManager", "configure_port_qos - QoS configured for port " + std::to_string(port_id) + " with " +
              std::to_string(static_cast<int>(config.num_queues)) + " queues, depth " + std::to_string(config.max_queue_depth) +
              ". Scheduler: " + std::to_string(static_cast<int>(config.scheduler)) + ". Structures initialized.");
}

std::optional<QosConfig> QosManager::get_port_qos_config(uint32_t port_id) const {
    auto it = port_qos_configs_.find(port_id);
    if (it != port_qos_configs_.end()) {
        return it->second;
    }
    // logger_.log(LogLevel::DEBUG, "QosManager", "get_port_qos_config - No QoS config found for port " + std::to_string(port_id));
    return std::nullopt;
}

std::optional<SchedulerType> QosManager::get_scheduler_type_for_port(uint32_t port_id) const {
    auto it = port_qos_configs_.find(port_id);
    if (it != port_qos_configs_.end()) {
        return it->second.scheduler;
    }
    // logger_.log(LogLevel::DEBUG, "QosManager", "get_scheduler_type_for_port - No scheduler type for port " + std::to_string(port_id));
    return std::nullopt;
}

uint8_t QosManager::classify_packet_to_queue(const Packet& pkt, uint32_t port_id) const {
    auto config_it = port_qos_configs_.find(port_id);
    uint8_t target_queue = 0;

    if (config_it != port_qos_configs_.end()) {
        const QosConfig& config = config_it->second;

        std::optional<uint8_t> pcp_opt = pkt.vlan_priority();
        if (pcp_opt.has_value()) {
            uint8_t pcp = pcp_opt.value();
            if (config.num_queues == 4) {
                 if (pcp >= 6) target_queue = 0;
                 else if (pcp >= 4) target_queue = 1;
                 else if (pcp >= 2) target_queue = 2;
                 else target_queue = 3;
            } else {
                target_queue = static_cast<uint8_t>(((7 - pcp) * config.num_queues) / 8.0);
            }
            if (target_queue >= config.num_queues) {
                target_queue = config.num_queues - 1;
            }
        } else {
            target_queue = config.num_queues - 1;
        }
        logger_.log(LogLevel::DEBUG, "QosManager", "classify_packet_to_queue - Packet classified to queue " + std::to_string(static_cast<int>(target_queue)) +
                  " on port " + std::to_string(port_id) + " (PCP: " + (pcp_opt.has_value() ? std::to_string(pcp_opt.value()) : "N/A") + ")");
    } else {
        logger_.log(LogLevel::WARNING, "QosManager", "classify_packet_to_queue - No QoS config for port " + std::to_string(port_id)
                  + ". Defaulting to queue 0.");
    }
    return target_queue;
}

void QosManager::enqueue_packet(const Packet& pkt, uint32_t port_id) {
    auto config_it = port_qos_configs_.find(port_id);
    if (config_it == port_qos_configs_.end()) {
        logger_.log(LogLevel::ERROR, "QosManager", "enqueue_packet - No QoS config for port " + std::to_string(port_id) + ". Packet dropped.");
        return;
    }

    const QosConfig& config = config_it->second;
    uint8_t queue_id = classify_packet_to_queue(pkt, port_id);

    auto queues_it = port_queues_.find(port_id);
    auto stats_it = port_queue_stats_.find(port_id);

    if (queues_it == port_queues_.end() || stats_it == port_queue_stats_.end()) {
        logger_.log(LogLevel::ERROR, "QosManager", "enqueue_packet - Internal error: Queue or stats structure missing for port " + std::to_string(port_id)
                  + ". Packet dropped.");
        return;
    }

    if (queue_id >= config.num_queues || queue_id >= queues_it->second.size() || queue_id >= stats_it->second.size()) {
        logger_.log(LogLevel::ERROR, "QosManager", "enqueue_packet - Invalid queue_id " + std::to_string(static_cast<int>(queue_id))
                  + " for port " + std::to_string(port_id) + ". Max queues: " + std::to_string(static_cast<int>(config.num_queues))
                  + ". Packet dropped.");
        if (stats_it != port_queue_stats_.end() && queue_id < stats_it->second.size()) {
             stats_it->second[queue_id].packets_dropped_full++;
        }
        return;
    }

    if (queues_it->second[queue_id].size() >= config.max_queue_depth) {
        logger_.log(LogLevel::WARNING, "QosManager", "enqueue_packet - Port " + std::to_string(port_id) + " Queue " + std::to_string(static_cast<int>(queue_id))
                  + " is full (max_depth: " + std::to_string(config.max_queue_depth) + "). Packet dropped (tail drop).");
        stats_it->second[queue_id].packets_dropped_full++;
    } else {
        // Create a new Packet in place using its constructor that takes a PacketBuffer*.
        // This shares the underlying buffer and increments its reference count.
        queues_it->second[queue_id].emplace_back(pkt.get_buffer());
        stats_it->second[queue_id].packets_enqueued++;
        logger_.log(LogLevel::DEBUG, "QosManager", "enqueue_packet - Enqueued packet on port " + std::to_string(port_id) + " queue " + std::to_string(static_cast<int>(queue_id))
                  + ". Queue depth: " + std::to_string(queues_it->second[queue_id].size()));
    }
    stats_it->second[queue_id].update_depth(queues_it->second[queue_id]);
}

std::optional<Packet> QosManager::dequeue_packet(uint32_t port_id, uint8_t queue_id) {
    auto config_it = port_qos_configs_.find(port_id);
    if (config_it == port_qos_configs_.end()) {
        logger_.log(LogLevel::WARNING, "QosManager", "dequeue_packet - No QoS config for port " + std::to_string(port_id) + ". Cannot dequeue.");
        return std::nullopt;
    }
    const QosConfig& config = config_it->second;
    if (queue_id >= config.num_queues) {
        logger_.log(LogLevel::ERROR, "QosManager", "dequeue_packet - Invalid queue_id " + std::to_string(static_cast<int>(queue_id)) +
                  " for port " + std::to_string(port_id) + ".");
        return std::nullopt;
    }

    auto queues_it = port_queues_.find(port_id);
    auto stats_it = port_queue_stats_.find(port_id);

    if (queues_it == port_queues_.end() || stats_it == port_queue_stats_.end() ||
        queue_id >= queues_it->second.size() || queue_id >= stats_it->second.size()) {
        logger_.log(LogLevel::ERROR, "QosManager", "dequeue_packet - Internal error: Queue/stats structure mismatch for port " +
                   std::to_string(port_id) + " queue " + std::to_string(static_cast<int>(queue_id)) + ".");
        return std::nullopt;
    }

    std::deque<Packet>& queue = queues_it->second[queue_id];
    QueueStats& stats = stats_it->second[queue_id];

    if (queue.empty()) {
        return std::nullopt;
    }

    // Move the packet out of the queue. This uses Packet's move constructor.
    Packet pkt_to_return = std::move(queue.front());
    queue.pop_front();

    stats.packets_dequeued++;
    stats.update_depth(queue);

    logger_.log(LogLevel::DEBUG, "QosManager", "dequeue_packet - Dequeued packet (moved) from port " + std::to_string(port_id) +
              " queue " + std::to_string(static_cast<int>(queue_id)) + ". New depth: " + std::to_string(stats.current_depth));
    return pkt_to_return;
}

std::optional<Packet> QosManager::select_packet_to_dequeue(uint32_t port_id) {
    auto config_it = port_qos_configs_.find(port_id);
    if (config_it == port_qos_configs_.end() || config_it->second.num_queues == 0) {
        return std::nullopt;
    }
    const QosConfig& config = config_it->second;

    auto queues_it = port_queues_.find(port_id);
    if (queues_it == port_queues_.end()) {
        logger_.log(LogLevel::ERROR, "QosManager", "select_packet_to_dequeue - Queue structure missing for port " + std::to_string(port_id));
        return std::nullopt;
    }

    if (config.scheduler == SchedulerType::STRICT_PRIORITY) {
        for (uint8_t i = 0; i < config.num_queues; ++i) {
            if (i < queues_it->second.size() && !queues_it->second[i].empty()) {
                if (should_transmit(port_id, i)) {
                    logger_.log(LogLevel::DEBUG, "QosManager", "select_packet_to_dequeue (StrictPriority) - Selected queue " + std::to_string(i) + " on port " + std::to_string(port_id));
                    return dequeue_packet(port_id, i);
                }
            }
        }
    } else if (config.scheduler == SchedulerType::WEIGHTED_ROUND_ROBIN ||
               config.scheduler == SchedulerType::DEFICIT_ROUND_ROBIN) {
        uint8_t num_queues = config.num_queues;
        uint8_t current_q_offset = port_last_serviced_queue_[port_id];

        for (uint8_t i = 0; i < num_queues; ++i) {
            uint8_t current_q_check_idx = (current_q_offset + 1 + i) % num_queues;

            if (current_q_check_idx < queues_it->second.size() && !queues_it->second[current_q_check_idx].empty()) {
                if (should_transmit(port_id, current_q_check_idx)) {
                    logger_.log(LogLevel::DEBUG, "QosManager", "select_packet_to_dequeue (RoundRobin) - Selected queue " + std::to_string(current_q_check_idx) + " on port " + std::to_string(port_id));
                    std::optional<Packet> pkt_opt = dequeue_packet(port_id, current_q_check_idx);
                    if (pkt_opt) {
                        port_last_serviced_queue_[port_id] = current_q_check_idx;
                        return pkt_opt;
                    }
                }
            }
        }
    }
    return std::nullopt;
}


bool QosManager::should_transmit(uint32_t port_id, uint8_t queue_id) const {
    auto config_it = port_qos_configs_.find(port_id);
    if (config_it == port_qos_configs_.end()) return false;
    const QosConfig& config = config_it->second;
    if (queue_id >= config.num_queues) return false;

    auto queues_it = port_queues_.find(port_id);
    if (queues_it != port_queues_.end() && queue_id < queues_it->second.size() && !queues_it->second[queue_id].empty()) {
        // TODO: Add actual token bucket logic here if rate_limits_kbps[queue_id] > 0
        return true;
    }
    return false;
}

void QosManager::update_token_buckets() {
    // logger_.log(LogLevel::DEBUG, "QosManager", "update_token_buckets - Placeholder called.");
}

std::optional<QosManager::QueueStats> QosManager::get_queue_stats(uint32_t port_id, uint8_t queue_id) const {
    auto stats_it = port_queue_stats_.find(port_id);
    if (stats_it != port_queue_stats_.end()) {
        if (queue_id < stats_it->second.size()) {
            return stats_it->second[queue_id];
        }
    }
    return std::nullopt;
}

} // namespace netflow
