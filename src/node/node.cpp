#include "node/node.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "net/tcp.hpp"

// ── Coordinator helpers ───────────────────────────────────────────────────────

namespace {

// Register with coordinator and return the full peer list (including ourselves).
std::vector<peer_info> coordinator_register_and_get(
    const node_config&           cfg,
    std::span<const uint8_t, 32> identity_pk)
{
    try {
        auto conn = tcp_connect(cfg.coordinator_host, cfg.coordinator_port);

        // Register
        std::array<uint8_t, 32> pk_arr;
        std::memcpy(pk_arr.data(), identity_pk.data(), 32);
        conn.send_frame(build_register(cfg.listen_port, pk_arr));

        auto ok_frame = conn.recv_frame();
        if (!ok_frame || get_type(*ok_frame) != msg_type::ok) {
            std::cerr << "[node] registration rejected by coordinator\n";
            return {};
        }

        // Get peers
        conn.send_frame(build_get_peers());
        auto list_frame = conn.recv_frame();
        if (!list_frame) return {};

        auto peers = parse_peer_list(*list_frame);
        return peers ? *peers : std::vector<peer_info>{};

    } catch (const std::exception& e) {
        std::cerr << "[node] coordinator error: " << e.what() << "\n";
        return {};
    }
}

} // namespace

// ── node ─────────────────────────────────────────────────────────────────────

node::node(node_config cfg,
           std::array<uint8_t, 32> identity_sk,
           std::array<uint8_t, 32> identity_pk)
    : cfg_(std::move(cfg))
    , isk_(identity_sk)
    , ipk_(identity_pk)
{}

void node::run()
{
    // 1. Register and fetch peer list
    auto peers = coordinator_register_and_get(cfg_, ipk_);
    std::cout << "[node] coordinator returned " << peers.size() << " peer(s)\n";

    // 2. Start accept loop — keep a handle so we can join it later
    std::thread accept_thread(&node::accept_loop, this);

    // 3. Connect outward to every peer whose pubkey differs from ours
    for (const auto& pi : peers) {
        if (pi.pubkey == ipk_) continue; // skip ourselves
        std::thread(&node::connect_to, this, pi).detach();
    }

    // 4. Interactive stdin → broadcast loop
    // If stdin is a terminal, this blocks for user input.
    // If stdin is /dev/null or a pipe, it returns immediately; we keep running
    // so that the accept loop and existing peer connections stay alive.
    std::cout << "[node] type messages and press Enter to broadcast (Ctrl-D to quit)\n";
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(line.data()), line.size());
        broadcast(msg);
    }
    std::cout << "[node] stdin closed — still accepting connections\n";

    // Block on the accept thread so the process doesn't exit
    accept_thread.join();
}

void node::accept_loop()
{
    try {
        tcp_server server(cfg_.listen_port);
        std::cout << "[node] listening on port " << cfg_.listen_port << "\n";
        while (true) {
            auto conn_opt = server.accept_one();
            if (!conn_opt) continue;
            std::cout << "[node] incoming connection from " << conn_opt->peer_ip() << "\n";
            std::thread([this, conn = std::move(*conn_opt)]() mutable {
                setup_peer(std::move(conn), false /*responder*/);
            }).detach();
        }
    } catch (const std::exception& e) {
        std::cerr << "[node] accept_loop error: " << e.what() << "\n";
    }
}

void node::connect_to(peer_info pi)
{
    char ip_str[INET_ADDRSTRLEN]{};
    ::inet_ntop(AF_INET, pi.ip.data(), ip_str, sizeof(ip_str));
    try {
        std::cout << "[node] connecting to " << ip_str << ":" << pi.port << "\n";
        auto conn = tcp_connect(ip_str, pi.port);
        setup_peer(std::move(conn), true /*initiator*/);
    } catch (const std::exception& e) {
        std::cerr << "[node] connect_to " << ip_str << ":" << pi.port
                  << " failed: " << e.what() << "\n";
    }
}

void node::setup_peer(tcp_connection conn, bool as_initiator)
{
    std::optional<session> sess_opt;
    if (as_initiator)
        sess_opt = handshake_as_initiator(conn, isk_, ipk_);
    else
        sess_opt = handshake_as_responder(conn, isk_, ipk_);

    if (!sess_opt) {
        std::cerr << "[node] handshake failed with " << conn.peer_ip() << "\n";
        return;
    }

    char pk_hex[9]{}; // show first 4 bytes as hex for identification
    for (int i = 0; i < 4; ++i)
        std::snprintf(pk_hex + i * 2, 3, "%02x", sess_opt->peer_identity_pk[i]);
    std::cout << "[node] handshake OK — peer id prefix: " << pk_hex << "\n";

    auto pc = std::make_shared<peer_conn>(std::move(*sess_opt), std::move(conn));
    add_peer(pc);
    recv_loop(pc); // blocks until peer disconnects
    remove_peer(pc.get());
    std::cout << "[node] peer " << pk_hex << " disconnected\n";
}

void node::recv_loop(std::shared_ptr<peer_conn> pc)
{
    char pk_hex[9]{};
    for (int i = 0; i < 4; ++i)
        std::snprintf(pk_hex + i * 2, 3, "%02x", pc->sess.peer_identity_pk[i]);

    while (true) {
        auto msg = pc->recv_msg();
        if (!msg) break;
        std::string text(msg->begin(), msg->end());
        std::cout << "[" << pk_hex << "] " << text << "\n";
    }
}

void node::add_peer(std::shared_ptr<peer_conn> pc)
{
    std::lock_guard lock(peers_mu_);
    peers_.push_back(std::move(pc));
}

void node::remove_peer(peer_conn* raw)
{
    std::lock_guard lock(peers_mu_);
    peers_.erase(
        std::remove_if(peers_.begin(), peers_.end(),
            [raw](const auto& p) { return p.get() == raw; }),
        peers_.end());
}

void node::broadcast(std::span<const uint8_t> msg)
{
    std::vector<std::shared_ptr<peer_conn>> snapshot;
    {
        std::lock_guard lock(peers_mu_);
        snapshot = peers_;
    }
    if (snapshot.empty()) {
        std::cout << "[node] no peers connected yet\n";
        return;
    }
    for (auto& pc : snapshot) {
        if (!pc->send_msg(msg))
            std::cerr << "[node] send failed to a peer\n";
    }
}
