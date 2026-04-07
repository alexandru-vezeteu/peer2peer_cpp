#include "node/node.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "control/control.hpp"
#include "net/tcp.hpp"

// ── Coordinator helpers ───────────────────────────────────────────────────────

namespace {

std::vector<peer_info> coordinator_register_and_get(
    const node_config&           cfg,
    std::span<const uint8_t, 32> identity_pk)
{
    try {
        auto conn = tcp_connect(cfg.coordinator_host, cfg.coordinator_port);

        std::array<uint8_t, 32> pk_arr;
        std::memcpy(pk_arr.data(), identity_pk.data(), 32);
        conn.send_frame(build_register(cfg.listen_port, pk_arr));

        auto ok_frame = conn.recv_frame();
        if (!ok_frame || get_type(*ok_frame) != msg_type::ok) {
            std::cerr << "[node] registration rejected by coordinator\n";
            return {};
        }

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

// Query peer list without re-registering — used to resolve inbound peer ports.
// The coordinator accepts GET_PEERS on any connection without requiring registration.
std::vector<peer_info> coordinator_get_peers(const node_config& cfg)
{
    try {
        auto conn = tcp_connect(cfg.coordinator_host, cfg.coordinator_port);
        conn.send_frame(build_get_peers());
        auto list_frame = conn.recv_frame();
        if (!list_frame) return {};
        auto peers = parse_peer_list(*list_frame);
        return peers ? *peers : std::vector<peer_info>{};
    } catch (const std::exception& e) {
        std::cerr << "[node] coordinator get_peers error: " << e.what() << "\n";
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

// ── Interactive mode ──────────────────────────────────────────────────────────

void node::run()
{
    auto peers = coordinator_register_and_get(cfg_, ipk_);
    std::cout << "[node] coordinator returned " << peers.size() << " peer(s)\n";

    std::thread accept_thread(&node::accept_loop, this);

    for (const auto& pi : peers) {
        if (pi.pubkey == ipk_) continue;
        std::thread(&node::connect_to, this, pi).detach();
    }

    std::cout << "[node] type messages and press Enter to broadcast (Ctrl-D to quit)\n";
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty()) continue;
        broadcast(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(line.data()), line.size()));
    }
    std::cout << "[node] stdin closed — still accepting connections\n";
    accept_thread.join();
}

// ── Daemon mode ───────────────────────────────────────────────────────────────

void node::run_daemon(const std::string& socket_path)
{
    auto peers = coordinator_register_and_get(cfg_, ipk_);
    std::cout << "[daemon] registered; " << peers.size() << " peer(s) known\n";

    std::thread(&node::accept_loop, this).detach();

    for (const auto& pi : peers) {
        if (pi.pubkey == ipk_) continue;
        std::thread(&node::connect_to, this, pi).detach();
    }

    // Periodic peer refresh — discovers nodes that registered after us
    std::thread([this]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(10));
            auto fresh = coordinator_register_and_get(cfg_, ipk_);
            for (const auto& pi : fresh) {
                if (pi.pubkey == ipk_) continue;
                bool already = false;
                {
                    std::lock_guard lock(peers_mu_);
                    for (const auto& pc : peers_) {
                        if (pc->sess.peer_identity_pk == pi.pubkey) {
                            already = true;
                            break;
                        }
                    }
                }
                if (!already)
                    std::thread(&node::connect_to, this, pi).detach();
            }
        }
    }).detach();

    // Blocks here serving the control socket
    control_server_loop(socket_path);
}

// ── Networking helpers ────────────────────────────────────────────────────────

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
                setup_peer(std::move(conn), false);
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
        setup_peer(std::move(conn), true, pi.port);
    } catch (const std::exception& e) {
        std::cerr << "[node] connect_to " << ip_str << ":" << pi.port
                  << " failed: " << e.what() << "\n";
    }
}

void node::setup_peer(tcp_connection conn, bool as_initiator, uint16_t peer_listen_port)
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

    char pk_hex[9]{};
    for (int i = 0; i < 4; ++i)
        std::snprintf(pk_hex + i * 2, 3, "%02x", sess_opt->peer_identity_pk[i]);
    std::cout << "[node] handshake OK — peer id prefix: " << pk_hex << "\n";

    // For inbound connections we don't know the peer's listen port a priori.
    // Resolve it by querying the coordinator (GET_PEERS only — no re-registration).
    if (peer_listen_port == 0) {
        auto fresh = coordinator_get_peers(cfg_);
        for (const auto& pi : fresh) {
            if (pi.pubkey == sess_opt->peer_identity_pk) {
                peer_listen_port = pi.port;
                break;
            }
        }
    }

    auto pc = std::make_shared<peer_conn>(std::move(*sess_opt), std::move(conn), peer_listen_port);
    add_peer(pc);
    recv_loop(pc);
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

        std::lock_guard lock(msgs_mu_);
        if (received_msgs_.size() >= 200) received_msgs_.pop_front();
        received_msgs_.push_back({std::string(pk_hex), text});
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
    std::vector<std::shared_ptr<peer_conn>> snap;
    { std::lock_guard lock(peers_mu_); snap = peers_; }
    if (snap.empty()) { std::cout << "[node] no peers connected yet\n"; return; }
    for (auto& pc : snap)
        if (!pc->send_msg(msg)) std::cerr << "[node] send failed to a peer\n";
}

// ── Control server ────────────────────────────────────────────────────────────

void node::control_server_loop(const std::string& path)
{
    ::unlink(path.c_str()); // remove stale socket from a previous run

    int srv = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv < 0) { std::cerr << "[daemon] socket() failed\n"; return; }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "[daemon] bind() failed on " << path << "\n";
        ::close(srv);
        return;
    }
    ::listen(srv, 4);
    std::cout << "[daemon] control socket ready at " << path << "\n";

    while (true) {
        int client = ::accept(srv, nullptr, nullptr);
        if (client < 0) continue;
        std::thread([this, client]() {
            handle_control_client(client);
            ::close(client);
        }).detach();
    }
}

void node::handle_control_client(int fd)
{
    line_reader reader(fd);
    while (true) {
        auto line_opt = reader.read_line();
        if (!line_opt) break;
        const std::string& cmd = *line_opt;

        if (cmd == "LIST")
            ctl_list(fd);
        else if (cmd.size() > 5 && cmd.substr(0, 5) == "SEND ")
            ctl_send(fd, cmd.substr(5));
        else if (cmd.size() > 10 && cmd.substr(0, 10) == "BROADCAST ")
            ctl_broadcast(fd, cmd.substr(10));
        else if (cmd == "RECV")
            ctl_recv(fd);
        else if (cmd == "QUIT")
            break;
    }
}

void node::ctl_list(int fd)
{
    struct entry { std::string pk; std::string ip; uint16_t port; };
    std::vector<entry> entries;
    {
        std::lock_guard lock(peers_mu_);
        for (const auto& pc : peers_) {
            char pk[9]{};
            for (int i = 0; i < 4; ++i)
                std::snprintf(pk + i * 2, 3, "%02x", pc->sess.peer_identity_pk[i]);
            entries.push_back({pk, pc->conn.peer_ip(), pc->listen_port});
        }
    }
    std::string resp = "PEERS " + std::to_string(entries.size()) + "\n";
    for (size_t i = 0; i < entries.size(); ++i) {
        std::string port = entries[i].port ? std::to_string(entries[i].port) : "?";
        resp += std::to_string(i + 1) + " " + entries[i].pk
             + " " + entries[i].ip + ":" + port + "\n";
    }
    ctl_write_raw(fd, resp);
}

void node::ctl_send(int fd, const std::string& args)
{
    auto sp = args.find(' ');
    if (sp == std::string::npos) { ctl_write(fd, "ERR usage: SEND <idx> <message>"); return; }

    int idx = 0;
    try { idx = std::stoi(args.substr(0, sp)); }
    catch (...) { ctl_write(fd, "ERR invalid index"); return; }

    const std::string text = args.substr(sp + 1);

    std::shared_ptr<peer_conn> target;
    {
        std::lock_guard lock(peers_mu_);
        if (idx < 1 || static_cast<size_t>(idx) > peers_.size()) {
            ctl_write(fd, "ERR peer index out of range");
            return;
        }
        target = peers_[static_cast<size_t>(idx - 1)];
    }

    bool ok = target->send_msg(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size()));
    ctl_write(fd, ok ? "OK" : "ERR send failed");
}

void node::ctl_broadcast(int fd, const std::string& text)
{
    std::vector<std::shared_ptr<peer_conn>> snap;
    { std::lock_guard lock(peers_mu_); snap = peers_; }

    int count = 0;
    auto bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size());
    for (auto& pc : snap)
        if (pc->send_msg(bytes)) ++count;

    ctl_write(fd, "OK " + std::to_string(count));
}

void node::ctl_recv(int fd)
{
    std::vector<std::pair<std::string, std::string>> msgs;
    {
        std::lock_guard lock(msgs_mu_);
        msgs.assign(received_msgs_.begin(), received_msgs_.end());
        received_msgs_.clear();
    }
    std::string resp = "MSGS " + std::to_string(msgs.size()) + "\n";
    for (const auto& [pk, text] : msgs)
        resp += pk + " " + text + "\n";
    ctl_write_raw(fd, resp);
}
