#ifndef BYTE_SWAP_HPP
#define BYTE_SWAP_HPP

#include <cstdint>



// Platform detection
#ifdef _WIN32
    #include <winsock2.h>
    #pragma comment(lib, "ws2_32.lib")
#elif defined(__linux__) || defined(__APPLE__) || defined(__unix__)
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

// Endianness detection
#ifndef __BYTE_ORDER__
    #if defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) || defined(__THUMBEL__) || \
        defined(__AARCH64EL__) || defined(_MIPSEL) || defined(__MIPSEL) || \
        defined(__MIPSEL__) || defined(_WIN32) || defined(__i386__) || defined(__x86_64__)
        #define IS_LITTLE_ENDIAN 1
        #define IS_BIG_ENDIAN 0
    #elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) || defined(__THUMBEB__) || \
          defined(__AARCH64EB__) || defined(_MIPSEB) || defined(__MIPSEB) || \
          defined(__MIPSEB__)
        #define IS_LITTLE_ENDIAN 0
        #define IS_BIG_ENDIAN 1
    #else
        // Runtime detection fallback
        #define IS_LITTLE_ENDIAN (*(uint16_t*)"\0\xff" < 0x100)
        #define IS_BIG_ENDIAN (!IS_LITTLE_ENDIAN)
    #endif
#else
    #define IS_LITTLE_ENDIAN (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    #define IS_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#endif

namespace netflow {
namespace byte_swap {

// Compiler-specific byte swap intrinsics
#if defined(_MSC_VER)
    #include <intrin.h>
    #define BSWAP16(x) _byteswap_ushort(x)
    #define BSWAP32(x) _byteswap_ulong(x)
    #define BSWAP64(x) _byteswap_uint64(x)
#elif defined(__GNUC__) || defined(__clang__)
    #define BSWAP16(x) __builtin_bswap16(x)
    #define BSWAP32(x) __builtin_bswap32(x)
    #define BSWAP64(x) __builtin_bswap64(x)
#else
    // Fallback implementations
    #define BSWAP16(x) ((uint16_t)(((x) >> 8) | ((x) << 8)))
    #define BSWAP32(x) ((uint32_t)(((x) >> 24) | (((x) & 0x00FF0000) >> 8) | \
                                   (((x) & 0x0000FF00) << 8) | ((x) << 24)))
    #define BSWAP64(x) ((uint64_t)(((x) >> 56) | \
                                   (((x) & 0x00FF000000000000ULL) >> 40) | \
                                   (((x) & 0x0000FF0000000000ULL) >> 24) | \
                                   (((x) & 0x000000FF00000000ULL) >> 8) | \
                                   (((x) & 0x00000000FF000000ULL) << 8) | \
                                   (((x) & 0x0000000000FF0000ULL) << 24) | \
                                   (((x) & 0x000000000000FF00ULL) << 40) | \
                                   ((x) << 56)))
#endif

// Inline byte swap functions
constexpr uint16_t swap16(uint16_t value) noexcept {
    return BSWAP16(value);
}

constexpr uint32_t swap32(uint32_t value) noexcept {
    return BSWAP32(value);
}

constexpr uint64_t swap64(uint64_t value) noexcept {
    return BSWAP64(value);
}

// Network to host byte order conversion (16-bit)
inline uint16_t ntohs(uint16_t network_value) noexcept {
#if defined(_WIN32) || (defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    return ::ntohs(network_value);
#else
    return IS_LITTLE_ENDIAN ? swap16(network_value) : network_value;
#endif
}

// Host to network byte order conversion (16-bit)
inline uint16_t htons(uint16_t host_value) noexcept {
#if defined(_WIN32) || (defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    return ::htons(host_value);
#else
    return IS_LITTLE_ENDIAN ? swap16(host_value) : host_value;
#endif
}

// Network to host byte order conversion (32-bit)
inline uint32_t ntohl(uint32_t network_value) noexcept {
#if defined(_WIN32) || (defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    return ::ntohl(network_value);
#else
    return IS_LITTLE_ENDIAN ? swap32(network_value) : network_value;
#endif
}

// Host to network byte order conversion (32-bit)
inline uint32_t htonl(uint32_t host_value) noexcept {
#if defined(_WIN32) || (defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    return ::htonl(host_value);
#else
    return IS_LITTLE_ENDIAN ? swap32(host_value) : host_value;
#endif
}

// Network to host byte order conversion (64-bit)
inline uint64_t ntohll(uint64_t network_value) noexcept {
    return IS_LITTLE_ENDIAN ? swap64(network_value) : network_value;
}

// Host to network byte order conversion (64-bit)
inline uint64_t htonll(uint64_t host_value) noexcept {
    return IS_LITTLE_ENDIAN ? swap64(host_value) : host_value;
}

// Template-based generic conversion functions
template<typename T>
T network_to_host(T network_value) noexcept {
    static_assert(std::is_integral_v<T>, "Type must be integral");
    
    if constexpr (sizeof(T) == 1) {
        return network_value;
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(ntohs(static_cast<uint16_t>(network_value)));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(ntohl(static_cast<uint32_t>(network_value)));
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(ntohll(static_cast<uint64_t>(network_value)));
    } else {
        static_assert(sizeof(T) <= 8, "Unsupported type size");
        return network_value;
    }
}

template<typename T>
T host_to_network(T host_value) noexcept {
    static_assert(std::is_integral_v<T>, "Type must be integral");
    
    if constexpr (sizeof(T) == 1) {
        return host_value;
    } else if constexpr (sizeof(T) == 2) {
        return static_cast<T>(htons(static_cast<uint16_t>(host_value)));
    } else if constexpr (sizeof(T) == 4) {
        return static_cast<T>(htonl(static_cast<uint32_t>(host_value)));
    } else if constexpr (sizeof(T) == 8) {
        return static_cast<T>(htonll(static_cast<uint64_t>(host_value)));
    } else {
        static_assert(sizeof(T) <= 8, "Unsupported type size");
        return host_value;
    }
}

// Utility functions for reading/writing multi-byte values from/to byte arrays
inline uint16_t read_be16(const uint8_t* buffer) noexcept {
    return static_cast<uint16_t>((buffer[0] << 8) | buffer[1]);
}

inline uint32_t read_be32(const uint8_t* buffer) noexcept {
    return static_cast<uint32_t>((buffer[0] << 24) | (buffer[1] << 16) | 
                                 (buffer[2] << 8) | buffer[3]);
}

inline uint64_t read_be64(const uint8_t* buffer) noexcept {
    return (static_cast<uint64_t>(read_be32(buffer)) << 32) | read_be32(buffer + 4);
}

inline void write_be16(uint8_t* buffer, uint16_t value) noexcept {
    buffer[0] = static_cast<uint8_t>(value >> 8);
    buffer[1] = static_cast<uint8_t>(value & 0xFF);
}

inline void write_be32(uint8_t* buffer, uint32_t value) noexcept {
    buffer[0] = static_cast<uint8_t>(value >> 24);
    buffer[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[3] = static_cast<uint8_t>(value & 0xFF);
}

inline void write_be64(uint8_t* buffer, uint64_t value) noexcept {
    write_be32(buffer, static_cast<uint32_t>(value >> 32));
    write_be32(buffer + 4, static_cast<uint32_t>(value & 0xFFFFFFFF));
}

// Little endian versions
inline uint16_t read_le16(const uint8_t* buffer) noexcept {
    return static_cast<uint16_t>(buffer[0] | (buffer[1] << 8));
}

inline uint32_t read_le32(const uint8_t* buffer) noexcept {
    return static_cast<uint32_t>(buffer[0] | (buffer[1] << 8) | 
                                 (buffer[2] << 16) | (buffer[3] << 24));
}

inline void write_le16(uint8_t* buffer, uint16_t value) noexcept {
    buffer[0] = static_cast<uint8_t>(value & 0xFF);
    buffer[1] = static_cast<uint8_t>(value >> 8);
}

inline void write_le32(uint8_t* buffer, uint32_t value) noexcept {
    buffer[0] = static_cast<uint8_t>(value & 0xFF);
    buffer[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
    buffer[2] = static_cast<uint8_t>((value >> 16) & 0xFF);
    buffer[3] = static_cast<uint8_t>(value >> 24);
}

} // namespace byte_swap
} // namespace netflow

// Convenience macros for common operations
#define ISIS_NTOHS(x) isis::byte_swap::ntohs(x)
#define ISIS_HTONS(x) isis::byte_swap::htons(x)
#define ISIS_NTOHL(x) isis::byte_swap::ntohl(x)
#define ISIS_HTONL(x) isis::byte_swap::htonl(x)
#define ISIS_NTOHLL(x) isis::byte_swap::ntohll(x)
#define ISIS_HTONLL(x) isis::byte_swap::htonll(x)


#endif // BYTE_SWAP_HPP
