// End-to-end integration tests for the session layer.
// Each test creates two OS threads connected via loopback TCP, runs
// the full handshake, and validates the encrypted messaging.

#include <array>
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#include "impl/crypto/aead/chacha20_poly1305.hpp"
#include "impl/crypto/hash/sha_256.hpp"
#include "impl/crypto/hash/sha_512.hpp"
#include "impl/crypto/key_exchange/x25519.hpp"
#include "impl/crypto/signing/eddsa.hpp"
#include "net/tcp.hpp"
#include "session/session.hpp"

using eddsa_t  = crypto::eddsa<crypto::sha_512>;
using aead_t   = crypto::chacha20_poly1305;
using kex_t    = crypto::x25519;

// ── Minimal test harness ──────────────────────────────────────────────────────

static int g_run  = 0;
static int g_pass = 0;

#define CHECK(cond, label)                                          \
    do {                                                            \
        ++g_run;                                                    \
        if (cond) { ++g_pass; std::cout << "  PASS  " label "\n"; }\
        else             std::cout << "  FAIL  " label "\n";       \
    } while (0)

// Convenience: cast string to byte span
static std::span<const uint8_t> as_bytes(const std::string& s)
{
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

// ── Test 1: basic handshake + one message ────────────────────────────────────

void test_basic_handshake_and_message()
{
    std::cout << "\n[1] Basic handshake + message delivery\n";

    constexpr uint16_t PORT = 19101;

    auto sk_a = eddsa_t::generate_private();
    auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private();
    auto pk_b = eddsa_t::derive_public(sk_b);

    bool   hs_responder_ok = false;
    bool   hs_initiator_ok = false;
    std::string received;
    std::array<uint8_t, 32> recv_peer_pk{};

    // Responder (A) — starts server, waits for one connection
    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        hs_responder_ok  = true;
        recv_peer_pk     = sess->peer_identity_pk;
        auto msg = sess->recv(*conn);
        if (msg) received = std::string(msg->begin(), msg->end());
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // Initiator (B)
    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        hs_initiator_ok = true;
        sess->send(conn, as_bytes("hello from B"));
    }

    fut.wait();

    CHECK(hs_initiator_ok,         "Initiator handshake completes");
    CHECK(hs_responder_ok,         "Responder handshake completes");
    CHECK(received == "hello from B", "Message decrypted correctly");
    CHECK(recv_peer_pk == pk_b,    "Peer authenticated via Ed25519");
}

// ── Test 2: multi-message stream, both directions ────────────────────────────

void test_bidirectional_multi_message()
{
    std::cout << "\n[2] Bidirectional multi-message exchange\n";

    constexpr uint16_t PORT = 19102;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    const std::vector<std::string> b_to_a = {"alpha", "beta", "gamma delta"};
    const std::vector<std::string> a_to_b = {"response 1", "response 2"};

    std::vector<std::string> got_by_a, got_by_b;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        // Receive b_to_a messages
        for (size_t i = 0; i < b_to_a.size(); ++i) {
            auto m = sess->recv(*conn);
            if (m) got_by_a.emplace_back(m->begin(), m->end());
        }
        // Send a_to_b messages
        for (const auto& m : a_to_b)
            sess->send(*conn, as_bytes(m));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        for (const auto& m : b_to_a)
            sess->send(conn, as_bytes(m));
        for (size_t i = 0; i < a_to_b.size(); ++i) {
            auto m = sess->recv(conn);
            if (m) got_by_b.emplace_back(m->begin(), m->end());
        }
    }

    fut.wait();

    CHECK(got_by_a == b_to_a, "A received all messages from B in order");
    CHECK(got_by_b == a_to_b, "B received all messages from A in order");
}

// ── Test 3: tampered ciphertext is rejected ───────────────────────────────────

void test_aead_tamper_detection()
{
    std::cout << "\n[3] AEAD tamper detection\n";

    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i + 1);

    const std::string msg = "top secret payload";
    std::vector<uint8_t> pt(msg.begin(), msg.end());

    auto blob = aead_t::seal(key, nonce, pt, {});

    // Tamper with the first ciphertext byte
    auto tampered = blob;
    tampered[0] ^= 0xAA;
    auto res_tampered = aead_t::open(key, nonce, tampered, {});
    CHECK(res_tampered.empty(), "Tampered ciphertext body rejected");

    // Tamper with the authentication tag (last 16 bytes)
    auto tag_tampered = blob;
    tag_tampered[tag_tampered.size() - 1] ^= 0x01;
    auto res_tag = aead_t::open(key, nonce, tag_tampered, {});
    CHECK(res_tag.empty(), "Tampered auth tag rejected");

    // Correct blob decrypts cleanly
    auto res_ok = aead_t::open(key, nonce, blob, {});
    CHECK(!res_ok.empty(), "Untampered blob accepted");
    std::string decrypted(res_ok.begin(), res_ok.end());
    CHECK(decrypted == msg, "Decrypted content matches original plaintext");

    // Wrong key
    auto key2 = key; key2[0] ^= 0xFF;
    auto res_wrong_key = aead_t::open(key2, nonce, blob, {});
    CHECK(res_wrong_key.empty(), "Wrong key rejected");
}

// ── Test 4: mismatched identity key is rejected ───────────────────────────────

void test_identity_mismatch_rejected()
{
    std::cout << "\n[4] Mismatched Ed25519 identity key rejected at handshake\n";

    constexpr uint16_t PORT = 19104;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    // B claims pk_b_legit but signs with sk_evil — simulates a MITM claiming
    // a different identity.
    auto sk_evil = eddsa_t::generate_private();
    auto sk_b    = eddsa_t::generate_private();
    auto pk_b    = eddsa_t::derive_public(sk_b); // pk_b != derive(sk_evil)

    bool responder_rejected = false;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        responder_rejected = !sess.has_value();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // Initiator claims pk_b but signs the handshake with sk_evil → Ed25519 verify fails
    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_evil /*signing key*/, pk_b /*claimed pk*/);

    fut.wait();

    CHECK(responder_rejected, "Responder rejects mismatched identity key");
    CHECK(!sess.has_value(),  "Initiator does not get a session from forged handshake");
}

// ── Test 5: nonce counters advance — different messages produce different ciphertext

void test_nonce_counter_advance()
{
    std::cout << "\n[5] Nonce counter advances (no ciphertext reuse)\n";

    constexpr uint16_t PORT = 19105;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    // Capture the raw wire frames so we can compare ciphertexts
    std::vector<std::vector<uint8_t>> raw_frames;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        for (int i = 0; i < 3; ++i) {
            auto f = conn->recv_frame();
            if (f) raw_frames.push_back(*f);
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        const std::string same = "identical plaintext";
        sess->send(conn, as_bytes(same));
        sess->send(conn, as_bytes(same));
        sess->send(conn, as_bytes(same));
    }

    fut.wait();

    bool all_different = false;
    if (raw_frames.size() == 3)
        all_different = (raw_frames[0] != raw_frames[1]) && (raw_frames[1] != raw_frames[2]);

    CHECK(all_different,
          "Identical plaintexts produce different ciphertexts (nonce advances)");
}

// ── Test 6: wrong session key cannot decrypt ──────────────────────────────────

void test_session_key_isolation()
{
    std::cout << "\n[6] Session key isolation between independent sessions\n";

    // Derive two independent session key pairs from different X25519 exchanges
    auto sk1 = kex_t::generate(); auto pk1 = kex_t::derive_public(sk1);
    auto sk2 = kex_t::generate(); auto pk2 = kex_t::derive_public(sk2);

    auto shared1 = kex_t::exchange(sk1, pk2).value_or({});
    auto shared2 = kex_t::exchange(sk2, pk1).value_or({});

    // Both should give the same ECDH output (Diffie-Hellman property)
    CHECK(shared1 == shared2, "X25519 shared secrets match (DH correctness)");

    // Derive keys for session 1
    std::array<uint8_t, 33> buf{};
    std::memcpy(buf.data() + 1, shared1.data(), 32);
    buf[0] = 0x00;
    auto k_s1 = crypto::sha_256::hash(std::span<const uint8_t>(buf.data(), 33));

    // Derive different keys for a completely separate exchange
    auto sk3 = kex_t::generate();
    auto sk4 = kex_t::generate(); auto pk4 = kex_t::derive_public(sk4);
    auto shared3 = kex_t::exchange(sk3, pk4).value_or({});
    std::memcpy(buf.data() + 1, shared3.data(), 32);
    buf[0] = 0x00;
    auto k_s2 = crypto::sha_256::hash(std::span<const uint8_t>(buf.data(), 33));

    std::array<uint8_t, 12> nonce{};
    const std::string secret = "session-private";
    std::vector<uint8_t> pt(secret.begin(), secret.end());

    // Encrypt with k_s1, try to decrypt with k_s2 (different session)
    auto blob = aead_t::seal(k_s1, nonce, pt, {});
    auto res  = aead_t::open(k_s2, nonce, blob, {});
    CHECK(res.empty(), "Session 2 key cannot decrypt session 1 message");

    // Decrypt with correct k_s1
    std::vector<uint8_t> pt2(secret.begin(), secret.end());
    auto blob2 = aead_t::seal(k_s1, nonce, pt2, {});
    auto res2  = aead_t::open(k_s1, nonce, blob2, {});
    CHECK(!res2.empty() && std::string(res2.begin(), res2.end()) == secret,
          "Correct session key decrypts successfully");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main()
{
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    std::cout << "╔══════════════════════════════════════════════╗\n";
    std::cout << "║        P2P Session Integration Tests         ║\n";
    std::cout << "╚══════════════════════════════════════════════╝\n";

    test_basic_handshake_and_message();
    test_bidirectional_multi_message();
    test_aead_tamper_detection();
    test_identity_mismatch_rejected();
    test_nonce_counter_advance();
    test_session_key_isolation();

    std::cout << "\n══════════════════════════════════════════════\n";
    std::cout << "Results: " << g_pass << "/" << g_run << " passed\n";

    if (g_pass != g_run) {
        std::cout << "OVERALL: FAIL\n";
        return 1;
    }
    std::cout << "OVERALL: PASS\n";
    return 0;
}
