#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "net/tcp.hpp"
#include "protocol/wire.hpp"
#include "session/session.hpp"
#include "transfer/chunker.hpp"

struct node_config {
    uint16_t    listen_port;
    std::string coordinator_host;
    uint16_t    coordinator_port;
};

// Bundles a live session with its TCP connection.
// send_msg() / send_chunked_msg() are mutex-protected so the main thread and
// recv threads coexist.  recv_msg() must be called from exactly one thread.
struct peer_conn {
    session          sess;
    tcp_connection   conn;
    std::mutex       send_mu;
    uint16_t         listen_port{0}; // peer's declared listen port (0 = unknown / inbound)
    transfer_registry chunks;        // per-peer chunk reassembly state (recv thread only)

    peer_conn(session s, tcp_connection c, uint16_t lport = 0)
        : sess(std::move(s)), conn(std::move(c)), listen_port(lport) {}

    bool send_msg(std::span<const uint8_t> data)
    {
        std::lock_guard lock(send_mu);
        return sess.send(conn, data);
    }

    // Splits data into ≤chunk_size chunks and sends each as an encrypted session
    // message.  Returns true when all chunks were sent successfully.
    bool send_chunked_msg(std::span<const uint8_t> data,
                          size_t chunk_size = CHUNK_PAYLOAD_SIZE)
    {
        std::lock_guard lock(send_mu);
        return ::send_chunked(sess, conn, data, chunk_size) > 0;
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

    // Interactive mode: register, connect to peers, then read stdin and
    // broadcast each line.  Blocks until stdin is closed.
    void run();

    // Daemon mode: register, connect, run control server at socket_path.
    // Periodically refreshes the peer list from the coordinator.
    // Blocks until the process is killed.
    void run_daemon(const std::string& socket_path);

private:
    // Networking
    void accept_loop();
    void connect_to(peer_info pi);
    void setup_peer(tcp_connection conn, bool as_initiator, uint16_t peer_listen_port = 0);
    void recv_loop(std::shared_ptr<peer_conn> pc);
    void add_peer(std::shared_ptr<peer_conn> pc);
    void remove_peer(peer_conn* raw);
    void broadcast(std::span<const uint8_t> msg);

    // Daemon control server
    void control_server_loop(const std::string& socket_path);
    void handle_control_client(int fd);
    void ctl_list(int fd);
    void ctl_send(int fd, const std::string& args);
    void ctl_send_file(int fd, const std::string& args);
    void ctl_broadcast(int fd, const std::string& msg_text);
    void ctl_recv(int fd);

    node_config             cfg_;
    std::array<uint8_t, 32> isk_, ipk_;

    std::mutex                              peers_mu_;
    std::vector<std::shared_ptr<peer_conn>> peers_;

    // Ring buffer of received messages for the control shell to poll
    std::mutex                                        msgs_mu_;
    std::deque<std::pair<std::string, std::string>>   received_msgs_; // {pk_hex8, text}
};
