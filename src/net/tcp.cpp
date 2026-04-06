#include "net/tcp.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <stdexcept>
#include <string>

namespace {

bool send_all(int fd, const void* buf, size_t len)
{
    const auto* p = static_cast<const uint8_t*>(buf);
    while (len > 0) {
        ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n <= 0) return false;
        p   += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

bool recv_all(int fd, void* buf, size_t len)
{
    auto* p = static_cast<uint8_t*>(buf);
    while (len > 0) {
        ssize_t n = ::recv(fd, p, len, 0);
        if (n <= 0) return false;
        p   += static_cast<size_t>(n);
        len -= static_cast<size_t>(n);
    }
    return true;
}

} // namespace

tcp_connection::tcp_connection(int fd, std::string peer_ip)
    : fd_(fd), peer_ip_(std::move(peer_ip)) {}

tcp_connection::tcp_connection(tcp_connection&& o) noexcept
    : fd_(o.fd_), peer_ip_(std::move(o.peer_ip_))
{
    o.fd_ = -1;
}

tcp_connection& tcp_connection::operator=(tcp_connection&& o) noexcept
{
    if (this != &o) {
        if (fd_ >= 0) ::close(fd_);
        fd_      = o.fd_;
        peer_ip_ = std::move(o.peer_ip_);
        o.fd_    = -1;
    }
    return *this;
}

tcp_connection::~tcp_connection()
{
    if (fd_ >= 0) ::close(fd_);
}

bool tcp_connection::send_frame(std::span<const uint8_t> data)
{
    uint32_t len_net = htonl(static_cast<uint32_t>(data.size()));
    return send_all(fd_, &len_net, 4)
        && send_all(fd_, data.data(), data.size());
}

std::optional<std::vector<uint8_t>> tcp_connection::recv_frame()
{
    uint32_t len_net{};
    if (!recv_all(fd_, &len_net, 4)) return std::nullopt;
    uint32_t len = ntohl(len_net);
    if (len > (1u << 20)) return std::nullopt; // 1 MiB sanity cap
    std::vector<uint8_t> buf(len);
    if (!recv_all(fd_, buf.data(), len)) return std::nullopt;
    return buf;
}

// ── tcp_server ──────────────────────────────────────────────────────────────

tcp_server::tcp_server(uint16_t port)
{
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) throw std::runtime_error("socket() failed");

    int opt = 1;
    ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);

    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed on port " + std::to_string(port));

    if (::listen(fd_, 16) < 0)
        throw std::runtime_error("listen() failed");
}

tcp_server::~tcp_server()
{
    if (fd_ >= 0) ::close(fd_);
}

std::optional<tcp_connection> tcp_server::accept_one()
{
    sockaddr_in client{};
    socklen_t   len = sizeof(client);
    int cfd = ::accept(fd_, reinterpret_cast<sockaddr*>(&client), &len);
    if (cfd < 0) return std::nullopt;

    char ip_buf[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, &client.sin_addr, ip_buf, sizeof(ip_buf));
    return tcp_connection{cfd, std::string(ip_buf)};
}

// ── tcp_connect ──────────────────────────────────────────────────────────────

tcp_connection tcp_connect(std::string_view host, uint16_t port)
{
    addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res{};
    std::string host_str(host);
    std::string port_str = std::to_string(port);

    if (::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &res) != 0)
        throw std::runtime_error("getaddrinfo failed for " + host_str);

    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        ::freeaddrinfo(res);
        throw std::runtime_error("socket() failed");
    }

    if (::connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        ::close(fd);
        ::freeaddrinfo(res);
        throw std::runtime_error("connect() failed to " + host_str + ":" + port_str);
    }

    char ip_buf[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET,
                &reinterpret_cast<const sockaddr_in*>(res->ai_addr)->sin_addr,
                ip_buf, sizeof(ip_buf));
    ::freeaddrinfo(res);
    return tcp_connection{fd, std::string(ip_buf)};
}
