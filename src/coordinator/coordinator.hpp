#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "protocol/wire.hpp"

// Coordinator node: accepts registrations from peers and hands out peer lists.
// Each incoming connection is served in a detached thread.
// Nodes may re-register to refresh their entry.
class coordinator {
public:
    explicit coordinator(uint16_t port);
    void run(); // blocks forever

private:
    void serve(int client_fd, std::string peer_ip);

    uint16_t               port_;
    std::mutex             mu_;
    std::vector<peer_info> peers_;
};
