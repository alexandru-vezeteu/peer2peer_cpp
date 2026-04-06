#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "net/tcp.hpp"
#include "protocol/wire.hpp"
#include "session/session.hpp"

struct node_config {
    uint16_t    listen_port;
    std::string coordinator_host;
    uint16_t    coordinator_port;
};

// A peer_conn bundles a live session with its underlying TCP connection.
// send() is protected by a mutex so the main thread and background threads
// can call it safely; recv() is called only from one dedicated recv thread.
struct peer_conn {
    session        sess;
    tcp_connection conn;
    std::mutex     send_mu;

    peer_conn(session s, tcp_connection c)
        : sess(std::move(s)), conn(std::move(c)) {}

    bool send_msg(std::span<const uint8_t> data)
    {
        std::lock_guard lock(send_mu);
        return sess.send(conn, data);
    }

    std::optional<std::vector<uint8_t>> recv_msg()
    {
        return sess.recv(conn);
    }
};

class node {
public:
    node(node_config cfg,
         std::array<uint8_t, 32> identity_sk,
         std::array<uint8_t, 32> identity_pk);

    // Registers with coordinator, connects to known peers, then runs the
    // interactive stdin→broadcast loop. Blocks until stdin is closed.
    void run();

private:
    void accept_loop();
    void connect_to(peer_info pi);
    void setup_peer(tcp_connection conn, bool as_initiator);
    void recv_loop(std::shared_ptr<peer_conn> pc);
    void add_peer(std::shared_ptr<peer_conn> pc);
    void remove_peer(peer_conn* raw);
    void broadcast(std::span<const uint8_t> msg);

    node_config             cfg_;
    std::array<uint8_t, 32> isk_, ipk_;

    std::mutex                              peers_mu_;
    std::vector<std::shared_ptr<peer_conn>> peers_;
};
