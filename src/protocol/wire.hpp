#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

enum class msg_type : uint8_t {
    // Coordinator
    register_node = 0x01,
    get_peers     = 0x02,
    peer_list     = 0x03,
    ok            = 0x04,
    // Handshake
    hs_init       = 0x10,
    hs_resp       = 0x11,
    hs_finish     = 0x12,
    // Encrypted payload
    encrypted     = 0x20,
};

struct peer_info {
    std::array<uint8_t, 4>  ip;     // network byte order
    uint16_t                port;   // host byte order
    std::array<uint8_t, 32> pubkey; // Ed25519 identity public key
};

// ── Builders ────────────────────────────────────────────────────────────────

std::vector<uint8_t> build_register(uint16_t port,
                                    std::span<const uint8_t, 32> pubkey);
std::vector<uint8_t> build_get_peers();
std::vector<uint8_t> build_peer_list(std::span<const peer_info> peers);
std::vector<uint8_t> build_ok();

std::vector<uint8_t> build_hs_init(std::span<const uint8_t, 32> eph_pk);
std::vector<uint8_t> build_hs_resp(std::span<const uint8_t, 32> eph_pk,
                                   std::span<const uint8_t, 32> identity_pk,
                                   std::span<const uint8_t, 64> sig);
std::vector<uint8_t> build_hs_finish(std::span<const uint8_t, 32> identity_pk,
                                     std::span<const uint8_t, 64> sig);
std::vector<uint8_t> build_encrypted(std::span<const uint8_t, 12> nonce,
                                     std::span<const uint8_t>     blob);

// ── Type peek ───────────────────────────────────────────────────────────────

[[nodiscard]] msg_type get_type(std::span<const uint8_t> frame);

// ── Parsers ─────────────────────────────────────────────────────────────────

struct parsed_register  { uint16_t port; std::array<uint8_t, 32> pubkey; };
struct parsed_hs_init   { std::array<uint8_t, 32> eph_pk; };
struct parsed_hs_resp   {
    std::array<uint8_t, 32> eph_pk;
    std::array<uint8_t, 32> identity_pk;
    std::array<uint8_t, 64> sig;
};
struct parsed_hs_finish {
    std::array<uint8_t, 32> identity_pk;
    std::array<uint8_t, 64> sig;
};
struct parsed_encrypted {
    std::array<uint8_t, 12> nonce;
    std::vector<uint8_t>    blob; // ciphertext + tag
};

std::optional<parsed_register>             parse_register (std::span<const uint8_t> f);
std::optional<std::vector<peer_info>>      parse_peer_list(std::span<const uint8_t> f);
std::optional<parsed_hs_init>              parse_hs_init  (std::span<const uint8_t> f);
std::optional<parsed_hs_resp>              parse_hs_resp  (std::span<const uint8_t> f);
std::optional<parsed_hs_finish>            parse_hs_finish(std::span<const uint8_t> f);
std::optional<parsed_encrypted>            parse_encrypted(std::span<const uint8_t> f);
