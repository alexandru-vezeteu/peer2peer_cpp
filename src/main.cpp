#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>

#include <sodium.h>

#include "coordinator/coordinator.hpp"
#include "impl/crypto/key_exchange/x25519.hpp"
#include "impl/crypto/signing/eddsa.hpp"
#include "impl/crypto/hash/sha_512.hpp"
#include "node/node.hpp"

using eddsa_t = crypto::eddsa<crypto::sha_512>;

static void print_usage(const char* argv0)
{
    std::cerr << "Usage:\n"
              << "  " << argv0 << " coordinator --port <port>\n"
              << "  " << argv0 << " node --port <listen-port> "
                                   "--coordinator <host:port>\n";
}

// Parse "host:port" into its components
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

int main(int argc, char* argv[])
{
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    // Flush every write so output isn't lost when killed or piped
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) { print_usage(argv[0]); return 1; }

    std::string mode(argv[1]);

    // ── Coordinator mode ─────────────────────────────────────────────────────
    if (mode == "coordinator") {
        uint16_t port = 9000;
        for (int i = 2; i < argc - 1; ++i) {
            if (std::string(argv[i]) == "--port")
                port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
        }
        coordinator c(port);
        c.run();
        return 0;
    }

    // ── Node mode ────────────────────────────────────────────────────────────
    if (mode == "node") {
        uint16_t    listen_port       = 0;
        std::string coordinator_addr;

        for (int i = 2; i < argc - 1; ++i) {
            std::string flag(argv[i]);
            if (flag == "--port")
                listen_port = static_cast<uint16_t>(std::stoi(argv[i + 1]));
            else if (flag == "--coordinator")
                coordinator_addr = argv[i + 1];
        }

        if (listen_port == 0 || coordinator_addr.empty()) {
            print_usage(argv[0]);
            return 1;
        }

        std::string coord_host;
        uint16_t    coord_port{};
        if (!parse_host_port(coordinator_addr, coord_host, coord_port)) {
            std::cerr << "Invalid coordinator address: " << coordinator_addr << "\n";
            return 1;
        }

        // Generate a fresh Ed25519 identity key pair for this session
        auto identity_sk = eddsa_t::generate_private();
        auto identity_pk = eddsa_t::derive_public(identity_sk);

        std::cout << "[node] generated identity key (first 4 bytes): ";
        for (int i = 0; i < 4; ++i)
            std::cout << std::hex << static_cast<int>(identity_pk[i]);
        std::cout << std::dec << "\n";

        node_config cfg{ listen_port, coord_host, coord_port };
        node n(cfg, identity_sk, identity_pk);
        n.run();
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
