#include "session/session.hpp"

#include <cstring>
#include <iostream>

#include "impl/crypto/aead/chacha20_poly1305.hpp"
#include "impl/crypto/hash/sha_256.hpp"
#include "impl/crypto/hash/sha_512.hpp"
#include "impl/crypto/key_exchange/x25519.hpp"
#include "impl/crypto/signing/eddsa.hpp"
#include "protocol/wire.hpp"

using sign_t = crypto::eddsa<crypto::sha_512>;
using kex_t  = crypto::x25519;
using aead_t = crypto::chacha20_poly1305;
using sha256 = crypto::sha_256;

// ── Internal helpers ─────────────────────────────────────────────────────────

namespace {

// Data signed during the handshake: init_eph_pk || resp_eph_pk (64 bytes)
std::array<uint8_t, 64> make_signed_data(
    std::span<const uint8_t, 32> init_eph,
    std::span<const uint8_t, 32> resp_eph)
{
    std::array<uint8_t, 64> d;
    std::memcpy(d.data(),      init_eph.data(), 32);
    std::memcpy(d.data() + 32, resp_eph.data(), 32);
    return d;
}

// Derive two directional ChaCha20-Poly1305 keys from the X25519 shared secret.
//   k_i2r = SHA256(0x00 || shared)
//   k_r2i = SHA256(0x01 || shared)
void derive_keys(std::span<const uint8_t, 32> shared,
                 std::array<uint8_t, 32>& k_i2r,
                 std::array<uint8_t, 32>& k_r2i)
{
    std::array<uint8_t, 33> buf;
    std::memcpy(buf.data() + 1, shared.data(), 32);

    buf[0] = 0x00;
    k_i2r  = sha256::hash(std::span<const uint8_t>(buf.data(), 33));

    buf[0] = 0x01;
    k_r2i  = sha256::hash(std::span<const uint8_t>(buf.data(), 33));
}

// 12-byte nonce from a 64-bit counter (big-endian in bytes 4-11, bytes 0-3 zero)
std::array<uint8_t, 12> counter_nonce(uint64_t ctr)
{
    std::array<uint8_t, 12> n{};
    for (int i = 7; i >= 0; --i) {
        n[static_cast<size_t>(4 + i)] = static_cast<uint8_t>(ctr & 0xFF);
        ctr >>= 8;
    }
    return n;
}

} // namespace

// ── session ───────────────────────────────────────────────────────────────────

bool session::send(tcp_connection& conn, std::span<const uint8_t> plaintext)
{
    auto nonce = counter_nonce(send_ctr_++);
    // aead_t::seal mutates the plaintext span (XOR in place), so copy first
    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());
    auto blob  = aead_t::seal(k_send_, nonce, pt, {});
    auto frame = build_encrypted(nonce, blob);
    return conn.send_frame(frame);
}

std::optional<std::vector<uint8_t>> session::recv(tcp_connection& conn)
{
    auto raw = conn.recv_frame();
    if (!raw) return std::nullopt;

    auto enc = parse_encrypted(*raw);
    if (!enc) return std::nullopt;

    auto plaintext = aead_t::open(k_recv_, enc->nonce, enc->blob, {});
    if (plaintext.empty()) return std::nullopt; // authentication failed

    return plaintext;
}

// ── Handshake: initiator ──────────────────────────────────────────────────────

std::optional<session> handshake_as_initiator(
    tcp_connection& conn,
    const std::array<uint8_t, 32>& identity_sk,
    const std::array<uint8_t, 32>& identity_pk)
{
    // 1. Generate ephemeral X25519 key pair
    auto eph_sk = kex_t::generate();
    auto eph_pk = kex_t::derive_public(eph_sk);

    // 2. Send HS_INIT
    if (!conn.send_frame(build_hs_init(eph_pk))) {
        std::cerr << "[handshake] send HS_INIT failed\n";
        return std::nullopt;
    }

    // 3. Receive HS_RESP
    auto resp_raw = conn.recv_frame();
    if (!resp_raw) { std::cerr << "[handshake] no HS_RESP\n"; return std::nullopt; }
    auto resp = parse_hs_resp(*resp_raw);
    if (!resp) { std::cerr << "[handshake] bad HS_RESP\n"; return std::nullopt; }

    // 4. Verify responder's signature over (init_eph_pk || resp_eph_pk)
    auto signed_data = make_signed_data(eph_pk, resp->eph_pk);
    if (!sign_t::verify(resp->identity_pk,
                        std::span<const uint8_t>(signed_data.data(), 64),
                        resp->sig).unwrap_public())
    {
        std::cerr << "[handshake] responder signature invalid\n";
        return std::nullopt;
    }

    // 5. Compute shared secret
    auto shared_opt = kex_t::exchange(eph_sk, resp->eph_pk);
    if (!shared_opt.is_some_public()) {
        std::cerr << "[handshake] X25519 exchange failed\n";
        return std::nullopt;
    }
    auto shared = shared_opt.value_or({});

    // 6. Sign and send HS_FINISH
    auto my_sig = sign_t::sign(identity_sk,
                               std::span<const uint8_t>(signed_data.data(), 64));
    if (!conn.send_frame(build_hs_finish(identity_pk, my_sig))) {
        std::cerr << "[handshake] send HS_FINISH failed\n";
        return std::nullopt;
    }

    // 7. Wait for responder's OK — confirms it accepted our identity.
    //    If verification failed on their side they close the connection; recv returns nullopt.
    auto ack = conn.recv_frame();
    if (!ack || get_type(*ack) != msg_type::ok) {
        std::cerr << "[handshake] no OK from responder (identity rejected?)\n";
        return std::nullopt;
    }

    // 8. Build session (initiator sends on k_i2r, receives on k_r2i)
    session s;
    s.peer_identity_pk = resp->identity_pk;
    std::array<uint8_t, 32> k_i2r, k_r2i;
    derive_keys(shared, k_i2r, k_r2i);
    s.k_send_ = k_i2r;
    s.k_recv_ = k_r2i;
    return s;
}

// ── Handshake: responder ──────────────────────────────────────────────────────

std::optional<session> handshake_as_responder(
    tcp_connection& conn,
    const std::array<uint8_t, 32>& identity_sk,
    const std::array<uint8_t, 32>& identity_pk)
{
    // 1. Receive HS_INIT
    auto init_raw = conn.recv_frame();
    if (!init_raw) { std::cerr << "[handshake] no HS_INIT\n"; return std::nullopt; }
    auto init = parse_hs_init(*init_raw);
    if (!init) { std::cerr << "[handshake] bad HS_INIT\n"; return std::nullopt; }

    // 2. Generate ephemeral X25519 key pair
    auto eph_sk = kex_t::generate();
    auto eph_pk = kex_t::derive_public(eph_sk);

    // 3. Compute shared secret
    auto shared_opt = kex_t::exchange(eph_sk, init->eph_pk);
    if (!shared_opt.is_some_public()) {
        std::cerr << "[handshake] X25519 exchange failed\n";
        return std::nullopt;
    }
    auto shared = shared_opt.value_or({});

    // 4. Sign (init_eph_pk || resp_eph_pk) with our identity key
    auto signed_data = make_signed_data(init->eph_pk, eph_pk);
    auto my_sig = sign_t::sign(identity_sk,
                               std::span<const uint8_t>(signed_data.data(), 64));

    // 5. Send HS_RESP
    if (!conn.send_frame(build_hs_resp(eph_pk, identity_pk, my_sig))) {
        std::cerr << "[handshake] send HS_RESP failed\n";
        return std::nullopt;
    }

    // 6. Receive HS_FINISH
    auto finish_raw = conn.recv_frame();
    if (!finish_raw) { std::cerr << "[handshake] no HS_FINISH\n"; return std::nullopt; }
    auto finish = parse_hs_finish(*finish_raw);
    if (!finish) { std::cerr << "[handshake] bad HS_FINISH\n"; return std::nullopt; }

    // 7. Verify initiator's signature
    if (!sign_t::verify(finish->identity_pk,
                        std::span<const uint8_t>(signed_data.data(), 64),
                        finish->sig).unwrap_public())
    {
        std::cerr << "[handshake] initiator signature invalid\n";
        // Do NOT send OK — closing the connection signals rejection to initiator
        return std::nullopt;
    }

    // 8. Acknowledge: tell initiator we accepted their identity
    if (!conn.send_frame(build_ok())) {
        std::cerr << "[handshake] send OK failed\n";
        return std::nullopt;
    }

    // 9. Build session (responder sends on k_r2i, receives on k_i2r)
    session s;
    s.peer_identity_pk = finish->identity_pk;
    std::array<uint8_t, 32> k_i2r, k_r2i;
    derive_keys(shared, k_i2r, k_r2i);
    s.k_send_ = k_r2i;
    s.k_recv_ = k_i2r;
    return s;
}
