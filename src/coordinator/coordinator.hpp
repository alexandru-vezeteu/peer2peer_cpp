#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "protocol/wire.hpp"

// Coordinator node: accepts registrations from peers and hands out peer lists.
// Each incoming connection is served in a detached thread.
// Nodes may re-register to refresh their entry.
// Entries older than PEER_TTL are excluded from GET_PEERS responses, so crashed
// or force-killed nodes fall out of the list automatically.
class coordinator {
public:
    explicit coordinator(uint16_t port);
    void run(); // blocks forever

    static constexpr std::chrono::seconds PEER_TTL{30};

private:
    struct timed_peer {
        peer_info                                pi;
        std::chrono::steady_clock::time_point    last_seen;
    };

    uint16_t                  port_;
    std::mutex                mu_;
    std::vector<timed_peer>   peers_;
};
