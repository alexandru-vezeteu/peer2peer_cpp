#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// RAII wrapper for a TCP connection with length-prefixed message framing.
// Frame format: [4-byte big-endian length][payload bytes]
class tcp_connection {
public:
    tcp_connection() = default;
    explicit tcp_connection(int fd, std::string peer_ip);
    tcp_connection(tcp_connection&&) noexcept;
    tcp_connection& operator=(tcp_connection&&) noexcept;
    ~tcp_connection();

    tcp_connection(const tcp_connection&) = delete;
    tcp_connection& operator=(const tcp_connection&) = delete;

    bool send_frame(std::span<const uint8_t> data);
    std::optional<std::vector<uint8_t>> recv_frame();

    [[nodiscard]] const std::string& peer_ip() const noexcept { return peer_ip_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int         fd_{-1};
    std::string peer_ip_;
};

// TCP server: bind, listen, accept.
class tcp_server {
public:
    explicit tcp_server(uint16_t port);
    ~tcp_server();

    tcp_server(const tcp_server&) = delete;
    tcp_server& operator=(const tcp_server&) = delete;

    std::optional<tcp_connection> accept_one();

private:
    int fd_{-1};
};

// Connect to host:port; throws std::runtime_error on failure.
tcp_connection tcp_connect(std::string_view host, uint16_t port);
