// Integration tests for encrypted node communication and message chunking.
//
// Each network test connects two sessions over loopback TCP, performs the full
// handshake (mutual Ed25519 authentication + X25519 key agreement), then
// exercises the chunking layer.  The reassembler unit tests run without any
// network I/O.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <future>
#include <iostream>
#include <numeric>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#include "impl/crypto/hash/sha_256.hpp"
#include "impl/crypto/hash/sha_512.hpp"
#include "impl/crypto/signing/eddsa.hpp"
#include "net/tcp.hpp"
#include "session/session.hpp"
#include "transfer/chunker.hpp"

using eddsa_t = crypto::eddsa<crypto::sha_512>;

// ── Minimal test harness ──────────────────────────────────────────────────────

static int g_run  = 0;
static int g_pass = 0;

#define CHECK(cond, label)                                            \
    do {                                                              \
        ++g_run;                                                      \
        if (cond) { ++g_pass; std::cout << "  PASS  " label "\n"; }  \
        else             std::cout << "  FAIL  " label "\n";         \
    } while (0)

static std::span<const uint8_t> as_bytes(const std::string& s)
{
    return {reinterpret_cast<const uint8_t*>(s.data()), s.size()};
}

static std::span<const uint8_t> as_bytes(const std::vector<uint8_t>& v)
{
    return {v.data(), v.size()};
}

// Receive all chunks from sess/conn until EOF, return assembled messages.
static std::vector<std::vector<uint8_t>> recv_all_chunked(session& sess, tcp_connection& conn)
{
    transfer_registry registry;
    std::vector<std::vector<uint8_t>> results;
    while (true) {
        auto msg = sess.recv(conn);
        if (!msg) break;
        auto span = std::span<const uint8_t>(*msg);
        if (auto ci = parse_chunk_frame(span)) {
            auto assembled = registry.ingest(ci->transfer_id, ci->index, ci->total, ci->data);
            if (assembled) results.push_back(std::move(*assembled));
        } else {
            // Regular (non-chunked) message — deliver as-is.
            results.push_back(std::move(*msg));
        }
    }
    return results;
}

// ── Test 1: single-chunk round-trip ──────────────────────────────────────────

void test_single_chunk_roundtrip()
{
    std::cout << "\n[1] Single-chunk encrypted round-trip\n";

    constexpr uint16_t PORT = 19201;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    const std::string payload = "Hello, encrypted world!";
    std::vector<uint8_t> received;

    // A is sender (responder side of the handshake)
    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        send_chunked(*sess, *conn, as_bytes(payload), CHUNK_PAYLOAD_SIZE);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        auto msgs = recv_all_chunked(*sess, conn);
        if (!msgs.empty()) received = msgs[0];
    }
    fut.wait();

    std::string got(received.begin(), received.end());
    CHECK(got == payload, "Small payload transmitted and reassembled via encrypted session");
}

// ── Test 2: multi-chunk round-trip ───────────────────────────────────────────

void test_multi_chunk_roundtrip()
{
    std::cout << "\n[2] Multi-chunk encrypted round-trip (3 chunks)\n";

    constexpr uint16_t PORT        = 19202;
    constexpr size_t   CHUNK_SZ    = 1024; // deliberately small to force splitting
    constexpr size_t   PAYLOAD_SZ  = 2500; // > 2×CHUNK_SZ → 3 chunks

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    // Build a recognisable payload: bytes 0, 1, 2, … (mod 256)
    std::vector<uint8_t> payload(PAYLOAD_SZ);
    std::iota(payload.begin(), payload.end(), uint8_t{0});

    std::vector<uint8_t> received;
    uint16_t             chunks_sent = 0;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        chunks_sent = send_chunked(*sess, *conn, as_bytes(payload), CHUNK_SZ);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        auto msgs = recv_all_chunked(*sess, conn);
        if (!msgs.empty()) received = msgs[0];
    }
    fut.wait();

    CHECK(chunks_sent == 3,           "Sender split 2500 bytes into 3 chunks of ≤1024");
    CHECK(received == payload,        "Receiver reassembled all 3 chunks in order");
}

// ── Test 3: large payload integrity ──────────────────────────────────────────

void test_large_payload_integrity()
{
    std::cout << "\n[3] Large payload integrity (64 KiB, SHA-256 hash check)\n";

    constexpr uint16_t PORT       = 19203;
    constexpr size_t   PAYLOAD_SZ = 64 * 1024;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    std::vector<uint8_t> payload(PAYLOAD_SZ);
    ::randombytes_buf(payload.data(), payload.size());

    auto hash_before = crypto::sha_256::hash(as_bytes(payload));

    std::vector<uint8_t> received;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        send_chunked(*sess, *conn, as_bytes(payload));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        auto msgs = recv_all_chunked(*sess, conn);
        if (!msgs.empty()) received = msgs[0];
    }
    fut.wait();

    auto hash_after = crypto::sha_256::hash(as_bytes(received));
    CHECK(received.size() == PAYLOAD_SZ, "Received byte count matches original");
    CHECK(hash_before == hash_after,     "SHA-256 hash matches — no bit flips in transit");
}

// ── Test 4: two sequential transfers on the same session ─────────────────────

void test_two_sequential_transfers()
{
    std::cout << "\n[4] Two sequential chunked transfers on the same encrypted session\n";

    constexpr uint16_t PORT     = 19204;
    constexpr size_t   CHUNK_SZ = 512;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    const std::string msg1(1500, 'A'); // 3 chunks at 512 B each
    const std::string msg2(700,  'B'); // 2 chunks

    std::vector<std::vector<uint8_t>> received;

    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        send_chunked(*sess, *conn, as_bytes(msg1), CHUNK_SZ);
        send_chunked(*sess, *conn, as_bytes(msg2), CHUNK_SZ);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) received = recv_all_chunked(*sess, conn);
    fut.wait();

    CHECK(received.size() == 2, "Both transfers were reassembled");
    if (received.size() == 2) {
        std::string r1(received[0].begin(), received[0].end());
        std::string r2(received[1].begin(), received[1].end());
        CHECK(r1 == msg1, "First transfer content matches");
        CHECK(r2 == msg2, "Second transfer content matches");
    }
}

// Receive exactly one reassembled chunked message from sess/conn.
static std::vector<uint8_t> recv_one_chunked(session& sess, tcp_connection& conn)
{
    transfer_registry reg;
    while (true) {
        auto msg = sess.recv(conn);
        if (!msg) return {};
        if (auto ci = parse_chunk_frame(std::span<const uint8_t>(*msg))) {
            auto assembled = reg.ingest(ci->transfer_id, ci->index, ci->total, ci->data);
            if (assembled) return std::move(*assembled);
        }
    }
}

// ── Test 5: bidirectional chunked communication ───────────────────────────────

void test_bidirectional_chunked()
{
    std::cout << "\n[5] Bidirectional chunked communication between two peers\n";

    constexpr uint16_t PORT     = 19205;
    constexpr size_t   CHUNK_SZ = 256;

    auto sk_a = eddsa_t::generate_private(); auto pk_a = eddsa_t::derive_public(sk_a);
    auto sk_b = eddsa_t::generate_private(); auto pk_b = eddsa_t::derive_public(sk_b);

    const std::string a_to_b(800, 'X');  // ceil(800/256) = 4 chunks
    const std::string b_to_a(600, 'Y');  // ceil(600/256) = 3 chunks

    std::vector<uint8_t> got_by_b, got_by_a;

    // A: send, then receive exactly one message back
    auto fut = std::async(std::launch::async, [&] {
        tcp_server srv(PORT);
        auto conn = srv.accept_one();
        if (!conn) return;
        auto sess = handshake_as_responder(*conn, sk_a, pk_a);
        if (!sess) return;
        send_chunked(*sess, *conn, as_bytes(a_to_b), CHUNK_SZ);
        got_by_a = recv_one_chunked(*sess, *conn);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    // B: receive one message from A, then send back
    auto conn = tcp_connect("127.0.0.1", PORT);
    auto sess = handshake_as_initiator(conn, sk_b, pk_b);
    if (sess) {
        got_by_b = recv_one_chunked(*sess, conn);
        send_chunked(*sess, conn, as_bytes(b_to_a), CHUNK_SZ);
    }
    fut.wait();

    std::string rb(got_by_b.begin(), got_by_b.end());
    std::string ra(got_by_a.begin(), got_by_a.end());
    CHECK(rb == a_to_b, "B received A's chunked message correctly");
    CHECK(ra == b_to_a, "A received B's chunked message correctly");
}

// ── Test 6: reassembler — out-of-order chunk arrival ────────────────────────

void test_reassembler_out_of_order()
{
    std::cout << "\n[6] Reassembler handles out-of-order chunk arrival\n";

    chunk_reassembler ra(3);

    const std::vector<uint8_t> c0 = {0x01, 0x02, 0x03};
    const std::vector<uint8_t> c1 = {0x04, 0x05};
    const std::vector<uint8_t> c2 = {0x06, 0x07, 0x08, 0x09};

    auto r2 = ra.add(2, c2); // arrives first
    CHECK(!r2.has_value(), "Transfer incomplete after chunk 2 (out of order)");

    auto r0 = ra.add(0, c0);
    CHECK(!r0.has_value(), "Transfer incomplete after chunk 0");

    auto r1 = ra.add(1, c1); // last one
    CHECK(r1.has_value(),  "Transfer complete after final chunk 1");

    const std::vector<uint8_t> expected = {0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09};
    CHECK(r1 == expected, "Assembled data is in logical order (0, 1, 2) regardless of arrival");
}

// ── Test 7: duplicate chunk is silently ignored ───────────────────────────────

void test_reassembler_duplicate_chunk()
{
    std::cout << "\n[7] Reassembler ignores duplicate chunks\n";

    chunk_reassembler ra(2);

    const std::vector<uint8_t> c0 = {0xAA};
    const std::vector<uint8_t> c1 = {0xBB};

    ra.add(0, c0);
    auto dup = ra.add(0, c0); // duplicate slot 0
    CHECK(!dup.has_value(), "Duplicate chunk does not trigger spurious completion");

    auto result = ra.add(1, c1);
    CHECK(result.has_value(), "Transfer still completes after the duplicate");
    const std::vector<uint8_t> expected = {0xAA, 0xBB};
    CHECK(result == expected, "Assembled content is correct (duplicate ignored)");
}

// ── Test 8: make/parse chunk frame round-trip ────────────────────────────────

void test_chunk_frame_codec()
{
    std::cout << "\n[8] Chunk frame encode / decode round-trip\n";

    const std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    auto frame = make_chunk_frame(0xDEADBEEF, 2, 7, as_bytes(data));

    CHECK(frame.size() == CHUNK_HEADER_SIZE + data.size(), "Frame has correct length");
    CHECK(frame[0] == CHUNK_MAGIC, "First byte is CHUNK_MAGIC");

    auto ci = parse_chunk_frame(frame);
    CHECK(ci.has_value(),          "Frame parsed successfully");
    if (ci) {
        CHECK(ci->transfer_id == 0xDEADBEEF, "transfer_id round-trips correctly");
        CHECK(ci->index == 2,               "chunk_index round-trips correctly");
        CHECK(ci->total == 7,               "total_chunks round-trips correctly");
        std::vector<uint8_t> got(ci->data.begin(), ci->data.end());
        CHECK(got == data,                  "Payload round-trips correctly");
    }

    // Sanity-check invalid frames
    CHECK(!parse_chunk_frame({}).has_value(),              "Empty buffer rejected");
    CHECK(!parse_chunk_frame(std::span<const uint8_t>(frame).subspan(0, 3)).has_value(),
          "Truncated header rejected");

    auto bad = frame;
    bad[0] = 0x00; // wrong magic
    CHECK(!parse_chunk_frame(bad).has_value(), "Wrong magic byte rejected");
}

// ── main ──────────────────────────────────────────────────────────────────────

int main()
{
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    std::cout << "╔══════════════════════════════════════════════════════╗\n";
    std::cout << "║   Encrypted Node Communication & Chunking Tests      ║\n";
    std::cout << "╚══════════════════════════════════════════════════════╝\n";

    test_single_chunk_roundtrip();
    test_multi_chunk_roundtrip();
    test_large_payload_integrity();
    test_two_sequential_transfers();
    test_bidirectional_chunked();
    test_reassembler_out_of_order();
    test_reassembler_duplicate_chunk();
    test_chunk_frame_codec();

    std::cout << "\n══════════════════════════════════════════════════════\n";
    std::cout << "Results: " << g_pass << "/" << g_run << " passed\n";

    if (g_pass != g_run) {
        std::cout << "OVERALL: FAIL\n";
        return 1;
    }
    std::cout << "OVERALL: PASS\n";
    return 0;
}
