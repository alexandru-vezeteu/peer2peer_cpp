#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sodium.h>
#include <unistd.h>

#include "control/control.hpp"
#include "coordinator/coordinator.hpp"
#include "impl/crypto/hash/sha_512.hpp"
#include "impl/crypto/signing/eddsa.hpp"
#include "node/node.hpp"

using eddsa_t = crypto::eddsa<crypto::sha_512>;

// ── Helpers ───────────────────────────────────────────────────────────────────

static void print_usage(const char* argv0)
{
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " coordinator --port <port>\n"
        << "  " << argv0 << " node   --port <listen-port> --coordinator <host:port>\n"
        << "  " << argv0 << " daemon --port <listen-port> --coordinator <host:port>"
                              " [--socket <path>]\n"
        << "  " << argv0 << " shell  [--socket <path>]\n";
}

static bool parse_host_port(const std::string& s, std::string& host, uint16_t& port)
{
    auto colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    host = s.substr(0, colon);
    try {
        int p = std::stoi(s.substr(colon + 1));
        if (p <= 0 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) { return false; }
    return true;
}

// ── Shell mode ────────────────────────────────────────────────────────────────

static void run_shell(const std::string& socket_path)
{
    int fd = unix_connect(socket_path);
    if (fd < 0) {
        std::cerr << "Cannot reach daemon at " << socket_path << "\n"
                  << "Make sure the daemon is running: p2p daemon --port <N> --coordinator <host:port>\n";
        return;
    }

    line_reader reader(fd);

    // ── helpers ──────────────────────────────────────────────────────────────

    auto send_cmd = [&](const std::string& cmd) {
        ctl_write(fd, cmd);
    };

    auto do_list = [&]() {
        send_cmd("LIST");
        auto hdr = reader.read_line();
        if (!hdr) return;
        int count = 0;
        try { count = std::stoi(hdr->substr(6)); } catch (...) { return; }
        if (count == 0) { std::cout << "  (no peers connected yet)\n"; return; }
        std::cout << "  #  id       address\n";
        std::cout << "  ─  ──────── ─────────────────\n";
        for (int i = 0; i < count; ++i) {
            auto line = reader.read_line();
            if (!line) break;
            std::cout << "  " << *line << "\n";
        }
    };

    auto do_recv = [&]() {
        send_cmd("RECV");
        auto hdr = reader.read_line();
        if (!hdr) return;
        int count = 0;
        try { count = std::stoi(hdr->substr(5)); } catch (...) { return; }
        for (int i = 0; i < count; ++i) {
            auto line = reader.read_line();
            if (!line) break;
            auto sp = line->find(' ');
            if (sp != std::string::npos)
                std::cout << "  \033[32m[" << line->substr(0, sp) << "]\033[0m "
                          << line->substr(sp + 1) << "\n";
        }
    };

    // ── banner ───────────────────────────────────────────────────────────────

    std::cout << "\033[1m";
    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║          P2P Node Interactive Shell          ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";
    std::cout << "\033[0m";
    std::cout << "  /peers           — list connected peers\n";
    std::cout << "  /msg <n> <text>  — send encrypted message to peer n\n";
    std::cout << "  /all <text>      — broadcast to all peers\n";
    std::cout << "  /msgs            — show received messages\n";
    std::cout << "  /quit            — exit shell\n\n";

    std::cout << "Peers at startup:\n";
    do_list();

    // ── main loop ────────────────────────────────────────────────────────────

    std::string line;
    while (true) {
        // Drain received messages before every prompt
        do_recv();

        std::cout << "\n\033[1m>\033[0m ";
        std::cout.flush();

        if (!std::getline(std::cin, line)) break;
        if (line.empty()) continue;

        if (line == "/quit" || line == "/exit") {
            send_cmd("QUIT");
            break;

        } else if (line == "/peers") {
            do_list();

        } else if (line == "/msgs") {
            do_recv();

        } else if (line.size() > 5 && line.substr(0, 5) == "/msg ") {
            send_cmd("SEND " + line.substr(5));
            auto resp = reader.read_line();
            if (resp) std::cout << "  " << *resp << "\n";

        } else if (line.size() > 5 && line.substr(0, 5) == "/all ") {
            send_cmd("BROADCAST " + line.substr(5));
            auto resp = reader.read_line();
            if (resp) std::cout << "  " << *resp << "\n";

        } else {
            std::cout << "  Unknown command. "
                         "Try /peers, /msg <n> <text>, /all <text>, /msgs, /quit\n";
        }
    }

    ::close(fd);
}

// ── main ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) { std::cerr << "libsodium init failed\n"; return 1; }
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) { print_usage(argv[0]); return 1; }
    std::string mode(argv[1]);

    // ── coordinator ──────────────────────────────────────────────────────────
    if (mode == "coordinator") {
        uint16_t port = 9000;
        for (int i = 2; i < argc - 1; ++i)
            if (std::string(argv[i]) == "--port")
                port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
        coordinator c(port);
        c.run();
        return 0;
    }

    // ── node (interactive) / daemon ──────────────────────────────────────────
    if (mode == "node" || mode == "daemon") {
        uint16_t    listen_port = 0;
        std::string coord_addr, socket_path = DEFAULT_SOCKET_PATH;

        for (int i = 2; i < argc - 1; ++i) {
            std::string f(argv[i]);
            if (f == "--port")        listen_port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
            else if (f == "--coordinator") coord_addr  = argv[i + 1];
            else if (f == "--socket")      socket_path = argv[i + 1];
        }
        if (listen_port == 0 || coord_addr.empty()) { print_usage(argv[0]); return 1; }

        std::string coord_host; uint16_t coord_port{};
        if (!parse_host_port(coord_addr, coord_host, coord_port)) {
            std::cerr << "Invalid coordinator address: " << coord_addr << "\n";
            return 1;
        }

        auto identity_sk = eddsa_t::generate_private();
        auto identity_pk = eddsa_t::derive_public(identity_sk);

        std::cout << "[node] identity (first 4 bytes): ";
        for (int i = 0; i < 4; ++i)
            std::cout << std::hex << static_cast<int>(identity_pk[i]);
        std::cout << std::dec << "\n";

        node_config cfg{ listen_port, coord_host, coord_port };
        node n(cfg, identity_sk, identity_pk);

        if (mode == "daemon") n.run_daemon(socket_path);
        else                  n.run();
        return 0;
    }

    // ── shell ────────────────────────────────────────────────────────────────
    if (mode == "shell") {
        std::string socket_path = DEFAULT_SOCKET_PATH;
        for (int i = 2; i < argc - 1; ++i)
            if (std::string(argv[i]) == "--socket")
                socket_path = argv[i + 1];
        run_shell(socket_path);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
