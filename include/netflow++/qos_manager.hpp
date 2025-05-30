#ifndef NETFLOW_QOS_MANAGER_HPP
#define NETFLOW_QOS_MANAGER_HPP

#include <cstdint>
#include <vector>
#include <map>
#include <string>    // Potentially for logging or more complex config
#include <iostream>  // For placeholder logging in enqueue_packet (if uncommented)
#include <deque>     // For std::deque
#include "packet.hpp" // For Packet class

namespace netflow {

enum class SchedulerType {
    STRICT_PRIORITY,
    WEIGHTED_ROUND_ROBIN,
    DEFICIT_ROUND_ROBIN
    // Potentially others like WFQ (Weighted Fair Queuing)
};

struct QosConfig {
    uint8_t num_queues = 4; // Default to 4 queues
    SchedulerType scheduler = SchedulerType::STRICT_PRIORITY;
    std::vector<uint32_t> queue_weights;    // For WRR, DRR (size should match num_queues)
    std::vector<uint32_t> rate_limits_kbps; // Per-queue rate limits in Kbps (0 = no limit)
                                            // (size should match num_queues)

    QosConfig() {
        // Ensure vectors are sized according to num_queues by default, if needed.
        // However, it's better to do this when num_queues is known or set.
        // For now, default constructor is fine. User should ensure consistency.
    }

    // Helper to validate and adjust config, e.g., resize vectors
    void validate_and_prepare() {
        if (queue_weights.size() != num_queues) {
            queue_weights.resize(num_queues, 1); // Default weight 1 if not matching
        }
        if (rate_limits_kbps.size() != num_queues) {
            rate_limits_kbps.resize(num_queues, 0); // Default 0 (no limit)
        }
    }
};

class QosManager {
public:
    QosManager() = default;

    void configure_port_qos(uint32_t port_id, QosConfig config) { // Pass by value to modify
        config.validate_and_prepare(); // Ensure weights/rates vectors match num_queues
        port_qos_configs_[port_id] = config;

        // Initialize/resize queue structures for the port
        // .assign will create or replace with new deques.
        port_queues_[port_id].assign(config.num_queues, std::deque<const Packet*>());
        // Also, if using port_queue_stats_, resize it here too.
        // port_queue_stats_[port_id].assign(config.num_queues, QueueStats());

        std::cout << "QoS configured for port " << port_id << " with "
                  << static_cast<int>(config.num_queues) << " queues. Queue structure initialized." << std::endl;
    }

    // Placeholder: Actual classification can be based on DSCP, PCP, ACL results etc.
    // This method determines which queue a packet should go into.
    uint8_t classify_packet_to_queue(const Packet& pkt, uint32_t port_id) const {
        // If port has specific config, use it, else default.
        auto it = port_qos_configs_.find(port_id);
        if (it != port_qos_configs_.end()) {
            const QosConfig& config = it->second;
            if (config.num_queues == 0) {
                return 0; // Or a special "no_qos_queue" identifier
            }
            // --- Placeholder Classification Logic ---
            // Example: Use packet's VLAN priority (PCP bits) if available
            // PCP values are 0-7. We need to map this to available queues.
            // Higher PCP often means higher priority queue.
            std::optional<uint8_t> pcp_opt = pkt.vlan_priority();
            if (pcp_opt.has_value()) {
                uint8_t pcp = pcp_opt.value(); // 0-7
                // Example mapping: map 7,6 to queue 0 (highest), 5,4 to queue 1, etc.
                // This depends on how queues are indexed (0 = highest or lowest).
                // Assuming queue 0 is highest priority for STRICT_PRIORITY:
                if (config.scheduler == SchedulerType::STRICT_PRIORITY) {
                    if (pcp >= 6) return 0 % config.num_queues; // Highest
                    if (pcp >= 4) return 1 % config.num_queues; // Medium-High
                    if (pcp >= 2) return 2 % config.num_queues; // Medium-Low
                    return 3 % config.num_queues;               // Lowest
                }
            }

            // Fallback: simple round-robin for demonstration if no PCP or other scheduler.
            // This is not a good general classification but fills the placeholder.
            // A real classifier would use DSCP, ACL results, etc.
            // For now, just return queue 0 if configured, or a default queue.
            return 0;
            // A very simple hash-based distribution if not strict priority based on PCP:
            // PacketClassifier::FlowKey flow_key = some_classifier_instance.extract_flow_key(pkt);
            // uint32_t hash = some_classifier_instance.hash_flow(flow_key);
            // return static_cast<uint8_t>(hash % config.num_queues);
        }
        return 0; // Default queue if no config or no queues
    }

    // Placeholder: Actual enqueuing needs queue structures and scheduling logic for dequeuing.
    // This method would place the packet (or a pointer/descriptor) into the specified queue.
    void enqueue_packet(const Packet& pkt, uint32_t port_id, uint8_t queue_id) {
        auto config_it = port_qos_configs_.find(port_id);
        if (config_it == port_qos_configs_.end()) {
            // std::cerr << "Warning: No QoS config for port " << port_id << ". Packet not enqueued." << std::endl;
            return;
        }

        auto queues_it = port_queues_.find(port_id);
        if (queues_it == port_queues_.end()) {
            // std::cerr << "Warning: No queue structure for port " << port_id << ". Packet not enqueued." << std::endl;
            return;
        }

        if (queue_id >= config_it->second.num_queues || queue_id >= queues_it->second.size()) {
            // std::cerr << "Warning: Invalid queue_id " << static_cast<int>(queue_id)
            //           << " for port " << port_id << ". Packet not enqueued." << std::endl;
            return;
        }

        // Placeholder: Queue size limit check (Tail Drop)
        if (queues_it->second[queue_id].size() >= MAX_QUEUE_DEPTH_PLACEHOLDER) {
            // std::cout << "Port " << port_id << " Queue " << static_cast<int>(queue_id)
            //           << " is full. Packet dropped (tail drop)." << std::endl;
            // port_queue_stats_[port_id][queue_id].dropped_packets++; // Example stat update
            return;
        }

        queues_it->second[queue_id].push_back(&pkt);
        // std::cout << "Enqueued packet on port " << port_id << " queue " << static_cast<int>(queue_id)
        //           << ". Queue depth: " << queues_it->second[queue_id].size() << std::endl;
        // port_queue_stats_[port_id][queue_id].enqueued_packets++;
        // port_queue_stats_[port_id][queue_id].enqueued_bytes += pkt.get_buffer()->size;
    }

    // Dequeues a packet from the highest priority non-empty queue for a given port.
    // Returns a pointer to the Packet, or nullptr if all queues are empty.
    // The caller is responsible for the packet after dequeue (e.g., sending it).
    // Note: Returns Packet* which might require const_cast from const Packet* if stored that way.
    Packet* dequeue_packet(uint32_t port_id) {
        auto config_it = port_qos_configs_.find(port_id);
        if (config_it == port_qos_configs_.end() || config_it->second.num_queues == 0) {
            return nullptr; // No QoS config or no queues for this port
        }

        auto queues_it = port_queues_.find(port_id);
        if (queues_it == port_queues_.end()) {
            return nullptr; // No queue structure for this port
        }

        const QosConfig& config = config_it->second;
        std::vector<std::deque<const Packet*>>& queues = queues_it->second;

        // Implement scheduler logic based on config.scheduler
        // For now, implementing Strict Priority (queue 0 is highest priority)
        if (config.scheduler == SchedulerType::STRICT_PRIORITY) {
            for (uint8_t i = 0; i < config.num_queues; ++i) {
                if (i < queues.size() && !queues[i].empty()) {
                    const Packet* packet_ptr = queues[i].front();
                    queues[i].pop_front();
                    // std::cout << "Dequeued packet from port " << port_id << " queue " << static_cast<int>(i)
                    //           << ". Queue depth: " << queues[i].size() << std::endl;
                    // port_queue_stats_[port_id][i].dequeued_packets++;
                    // port_queue_stats_[port_id][i].dequeued_bytes += packet_ptr->get_buffer()->size;

                    // Packet pointers are stored as const Packet*. If the receiver needs non-const,
                    // const_cast is needed here. This implies a trust contract that the receiver
                    // (e.g., a data plane transmit function) might need to modify it for transmission
                    // (e.g., internal tagging, TTL decrement if it were a router).
                    // However, modifying a truly const object is UB.
                    // This points to a design consideration: if Packet needs modification after dequeue,
                    // perhaps it shouldn't be const* in queues, or a copy is made.
                    // For now, using const_cast as a pragmatic placeholder.
                    return const_cast<Packet*>(packet_ptr);
                }
            }
        }
        // TODO: Implement WRR, DRR scheduling logic here
        // else if (config.scheduler == SchedulerType::WEIGHTED_ROUND_ROBIN) { ... }
        // else if (config.scheduler == SchedulerType::DEFICIT_ROUND_ROBIN) { ... }

        return nullptr; // All queues are empty or scheduler type not handled yet
    }

    // Placeholder: Determines if a packet should be transmitted from a specific queue.
    // Real implementation would involve token buckets for rate limiting.
    bool should_transmit(uint32_t port_id, uint8_t queue_id) const {
        auto queues_it = port_queues_.find(port_id);
        if (queues_it != port_queues_.end()) {
            if (queue_id < queues_it->second.size() && !queues_it->second[queue_id].empty()) {
                // Basic check: if queue is not empty, allow transmission.
                // TODO: Add rate limiting logic here.
                // If rate_limits_kbps[queue_id] > 0, check token bucket.
                return true;
            }
        }
        return false;
    }

    // Placeholder: Method to update token buckets for rate limiting.
    // This would be called periodically (e.g., by a timer thread).
    void update_token_buckets() {
        // For each port, for each queue:
        //   If rate_limits_kbps[queue_id] > 0:
        //     Replenish tokens in the bucket based on elapsed time and rate.
        //     Ensure tokens do not exceed a maximum bucket size.
        // std::cout << "Placeholder: update_token_buckets() called." << std::endl;
    }

private:
    // Note: The first erroneous private section and duplicate port_qos_configs_ declaration were removed.
    // All private members are now correctly declared below.

    std::map<uint32_t, QosConfig> port_qos_configs_;

    // Placeholder for actual per-port, per-queue packet storage (e.g., deques of Packet pointers or buffers)
    // Example: std::map<uint32_t, std::vector<std::deque<PacketBuffer*>>> port_queues_;
    // This would also require managing PacketBuffer ref_counts carefully.

    // Placeholder for stats per queue (e.g., enqueued/dequeued packets/bytes, drops)
    // struct QueueStats { uint64_t enqueued_packets=0; uint64_t enqueued_bytes=0; ... };
    // std::map<uint32_t, std::vector<QueueStats>> port_queue_stats_;

    // Actual queue structures. Maps port ID to a vector of deques.
    // Each deque represents a queue for that port.
    // Stores non-owning pointers to Packets. Lifetime management of Packet objects
    // (and their underlying PacketBuffers) is external. Typically, Packet objects
    // are managed by the Switch or BufferPool, and QoS manager just references them
    // while they are enqueued.
    std::map<uint32_t, std::vector<std::deque<const Packet*>>> port_queues_;

    const size_t MAX_QUEUE_DEPTH_PLACEHOLDER = 1000; // Example max packets per queue
};

} // namespace netflow

#endif // NETFLOW_QOS_MANAGER_HPP
