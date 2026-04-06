#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "net/tcp.hpp"

// An encrypted, authenticated session established after a successful handshake.
// k_send / k_recv are ChaCha20-Poly1305 keys derived from the X25519 shared secret.
// Nonces are implicit monotonic counters encoded in the ENCRYPTED wire frame.
struct session {
    std::array<uint8_t, 32> peer_identity_pk{};

    bool send(tcp_connection& conn, std::span<const uint8_t> plaintext);
    std::optional<std::vector<uint8_t>> recv(tcp_connection& conn);

private:
    std::array<uint8_t, 32> k_send_{};
    std::array<uint8_t, 32> k_recv_{};
    uint64_t                send_ctr_{0};

    friend std::optional<session> handshake_as_initiator(
        tcp_connection&,
        const std::array<uint8_t, 32>&,
        const std::array<uint8_t, 32>&);
    friend std::optional<session> handshake_as_responder(
        tcp_connection&,
        const std::array<uint8_t, 32>&,
        const std::array<uint8_t, 32>&);
};

// Handshake protocol (simplified Noise-like, mutual authentication via Ed25519):
//
//   Initiator → Responder : HS_INIT  { eph_pk }
//   Responder → Initiator : HS_RESP  { eph_pk, identity_pk, sig(init_eph||resp_eph) }
//   Initiator → Responder : HS_FINISH{ identity_pk, sig(init_eph||resp_eph) }
//
// Session keys derived from X25519(my_eph_sk, peer_eph_pk):
//   k_i2r = SHA256(0x00 || shared)
//   k_r2i = SHA256(0x01 || shared)

std::optional<session> handshake_as_initiator(
    tcp_connection& conn,
    const std::array<uint8_t, 32>& identity_sk,
    const std::array<uint8_t, 32>& identity_pk);

std::optional<session> handshake_as_responder(
    tcp_connection& conn,
    const std::array<uint8_t, 32>& identity_sk,
    const std::array<uint8_t, 32>& identity_pk);
