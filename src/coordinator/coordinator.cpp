#include "coordinator/coordinator.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <thread>

#include "net/tcp.hpp"
#include "protocol/wire.hpp"

coordinator::coordinator(uint16_t port) : port_(port) {}

void coordinator::run()
{
    tcp_server server(port_);
    std::cout << "[coordinator] listening on port " << port_ << "\n";

    while (true) {
        auto conn_opt = server.accept_one();
        if (!conn_opt) continue;

        std::string ip = conn_opt->peer_ip();

        // Move the connection into the thread closure
        std::thread([this, conn = std::move(*conn_opt), ip = std::move(ip)]() mutable {
            std::cout << "[coordinator] connection from " << ip << "\n";

            while (true) {
                auto frame = conn.recv_frame();
                if (!frame) break;

                auto type = get_type(*frame);

                if (type == msg_type::register_node) {
                    auto r = parse_register(*frame);
                    if (!r) break;

                    peer_info pi{};
                    // Use the TCP source IP for the peer's address
                    if (::inet_pton(AF_INET, ip.c_str(), pi.ip.data()) != 1) break;
                    pi.port   = r->port;
                    pi.pubkey = r->pubkey;

                    {
                        std::lock_guard lock(mu_);
                        auto now = std::chrono::steady_clock::now();
                        auto it = std::find_if(peers_.begin(), peers_.end(),
                            [&](const timed_peer& tp) { return tp.pi.pubkey == pi.pubkey; });
                        if (it != peers_.end()) { it->pi = pi; it->last_seen = now; }
                        else peers_.push_back({pi, now});
                    }
                    std::cout << "[coordinator] registered " << ip << ":" << r->port << "\n";
                    conn.send_frame(build_ok());

                } else if (type == msg_type::get_peers) {
                    auto now = std::chrono::steady_clock::now();
                    std::vector<peer_info> snapshot;
                    {
                        std::lock_guard lock(mu_);
                        for (const auto& tp : peers_)
                            if (now - tp.last_seen <= PEER_TTL)
                                snapshot.push_back(tp.pi);
                    }
                    conn.send_frame(build_peer_list(snapshot));

                } else {
                    std::cerr << "[coordinator] unexpected message type\n";
                    break;
                }
            }
            std::cout << "[coordinator] " << ip << " disconnected\n";
        }).detach();
    }
}
