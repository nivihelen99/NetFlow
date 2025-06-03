#ifndef NETFLOW_LOGGER_HPP
#define NETFLOW_LOGGER_HPP

#include "packet.hpp" // For MacAddress, IpAddress, Packet, ntohl

#include <string>    // For std::string, std::to_string
#include <iostream>  // For std::cout, std::cerr, std::endl, std::ostream
#include <vector>    // For std::vector (general utility, not strictly needed by declarations)
#include <ctime>     // For std::time_t, std::time, std::localtime, std::strftime, struct std::tm
#include <cstdio>    // For std::snprintf
#include <sstream>   // For std::ostringstream
#include <iomanip>   // For std::hex, std::setw, std::setfill
#include <cstdint>   // For uint64_t, uint32_t, uint16_t

namespace netflow {

struct PerformanceCounters {
    uint64_t packets_processed = 0;
    uint64_t bytes_processed = 0;
    uint64_t errors_encountered = 0;
    uint64_t flow_lookups = 0;
};

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class SwitchLogger {
public:
    explicit SwitchLogger(LogLevel min_level = LogLevel::INFO) : min_log_level_(min_level) {}

    void set_min_log_level(LogLevel level) {
        min_log_level_ = level;
    }

    LogLevel get_min_log_level() const {
        return min_log_level_;
    }

    void log(LogLevel level, const std::string& component, const std::string& message) const {
        if (level < min_log_level_) {
            return;
        }

        std::time_t t = std::time(nullptr);
        char time_buf[100];
        // Using struct tm explicitly for clarity with std::localtime
        struct std::tm* local_tm = std::localtime(&t);

        if (local_tm && std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", local_tm)) {
            // Successfully formatted time
        } else {
            // Fallback in case strftime fails or local_tm is null
            std::snprintf(time_buf, sizeof(time_buf), "YYYY-MM-DD HH:MM:SS");
        }

        std::ostream& output_stream = (level >= LogLevel::ERROR) ? std::cerr : std::cout;

        output_stream << "[" << time_buf << "] "
                      << "[" << level_to_string(level) << "] "
                      << "[" << component << "] "
                      << message << std::endl;
    }

    void debug(const std::string& component, const std::string& message) const {
        log(LogLevel::DEBUG, component, message);
    }
    void info(const std::string& component, const std::string& message) const {
        log(LogLevel::INFO, component, message);
    }
    void warning(const std::string& component, const std::string& message) const {
        log(LogLevel::WARNING, component, message);
    }
    void error(const std::string& component, const std::string& message) const {
        log(LogLevel::ERROR, component, message);
    }
    void critical(const std::string& component, const std::string& message) const {
        log(LogLevel::CRITICAL, component, message);
    }

    std::string mac_to_string(const MacAddress& mac) const {
        char buf[18]; // XX:XX:XX:XX:XX:XX + null terminator
        // mac.bytes is std::array<uint8_t, 6>
        std::snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                      mac.bytes[0], mac.bytes[1], mac.bytes[2],
                      mac.bytes[3], mac.bytes[4], mac.bytes[5]);
        return std::string(buf);
    }

    std::string ip_to_string(const IpAddress& ip_addr_net_order) const {
        // IpAddress is uint32_t in network byte order
        uint32_t ip_host_order = ntohl(ip_addr_net_order); // ntohl is from network headers via packet.hpp
        std::ostringstream oss;
        oss << ((ip_host_order >> 24) & 0xFF) << "."
            << ((ip_host_order >> 16) & 0xFF) << "."
            << ((ip_host_order >> 8) & 0xFF) << "."
            << (ip_host_order & 0xFF);
        return oss.str();
    }

    std::string to_hex_string(uint16_t val) const {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << val;
        return oss.str();
    }

public: 
    void log_packet_drop(const Packet& pkt, uint32_t port_id, const std::string& reason) const {
        if (min_log_level_ > LogLevel::INFO) return;

        std::string src_mac_str = "N/A", dst_mac_str = "N/A";
        // Check if ethernet header exists before trying to get MACs
        if (pkt.ethernet()) { // Assuming ethernet() returns nullptr if not an Ethernet packet
             if(auto smac = pkt.src_mac()) src_mac_str = mac_to_string(smac.value());
             if(auto dmac = pkt.dst_mac()) dst_mac_str = mac_to_string(dmac.value());
        }

        std::string message = "Packet dropped on port " + std::to_string(port_id) +
                              ". Reason: " + reason +
                              ". SrcMAC: " + src_mac_str + ", DstMAC: " + dst_mac_str;
        log(LogLevel::INFO, "PACKET_DROP", message);
    }

    void log_mac_learning(const MacAddress& mac, uint32_t port_id, uint16_t vlan_id) const {
        if (min_log_level_ > LogLevel::DEBUG) return;
        std::string message = "MAC " + mac_to_string(mac) +
                              " learned on port " + std::to_string(port_id) +
                              ", VLAN " + std::to_string(vlan_id);
        log(LogLevel::DEBUG, "FDB", message);
    }

    void log_stp_event(uint32_t port_id, const std::string& event_details) const {
        if (min_log_level_ > LogLevel::INFO) return;
        std::string message = "STP event on port " + std::to_string(port_id) + ": " + event_details;
        log(LogLevel::INFO, "STP", message);
    }

    void log_performance_stats(const PerformanceCounters& counters) const {
        if (min_log_level_ > LogLevel::INFO) return;
        std::string message = "Performance Stats: PacketsProcessed=" + std::to_string(counters.packets_processed) +
                              ", BytesProcessed=" + std::to_string(counters.bytes_processed) +
                              ", ErrorsEncountered=" + std::to_string(counters.errors_encountered) +
                              ", FlowLookups=" + std::to_string(counters.flow_lookups);
        log(LogLevel::INFO, "STATS", message);
    }

private:
    LogLevel min_log_level_;

    std::string level_to_string(LogLevel level) const {
        switch (level) {
            case LogLevel::DEBUG:    return "DEBUG   ";
            case LogLevel::INFO:     return "INFO    ";
            case LogLevel::WARNING:  return "WARNING ";
            case LogLevel::ERROR:    return "ERROR   ";
            case LogLevel::CRITICAL: return "CRITICAL";
            default:                 return "UNKNOWN ";
        }
    }
};

} // namespace netflow

#endif // NETFLOW_LOGGER_HPP
