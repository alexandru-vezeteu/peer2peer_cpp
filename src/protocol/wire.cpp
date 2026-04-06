#include "protocol/wire.hpp"

#include <arpa/inet.h>
#include <cstring>

// ── Internal helpers ─────────────────────────────────────────────────────────

namespace {

void append_bytes(std::vector<uint8_t>& v, const void* data, size_t n)
{
    const auto* p = static_cast<const uint8_t*>(data);
    v.insert(v.end(), p, p + n);
}

void append_u16be(std::vector<uint8_t>& v, uint16_t x)
{
    uint16_t n = htons(x);
    append_bytes(v, &n, 2);
}

uint16_t read_u16be(const uint8_t* p)
{
    uint16_t n;
    std::memcpy(&n, p, 2);
    return ntohs(n);
}

} // namespace

// ── Builders ─────────────────────────────────────────────────────────────────

std::vector<uint8_t> build_register(uint16_t port,
                                    std::span<const uint8_t, 32> pubkey)
{
    // [type:1][port:2][pubkey:32]
    std::vector<uint8_t> v;
    v.reserve(35);
    v.push_back(static_cast<uint8_t>(msg_type::register_node));
    append_u16be(v, port);
    append_bytes(v, pubkey.data(), 32);
    return v;
}

std::vector<uint8_t> build_get_peers()
{
    return {static_cast<uint8_t>(msg_type::get_peers)};
}

std::vector<uint8_t> build_peer_list(std::span<const peer_info> peers)
{
    // [type:1][count:2][(ip:4, port:2, pubkey:32) * count]
    std::vector<uint8_t> v;
    v.reserve(3 + peers.size() * 38);
    v.push_back(static_cast<uint8_t>(msg_type::peer_list));
    append_u16be(v, static_cast<uint16_t>(peers.size()));
    for (const auto& p : peers) {
        append_bytes(v, p.ip.data(), 4);
        append_u16be(v, p.port);
        append_bytes(v, p.pubkey.data(), 32);
    }
    return v;
}

std::vector<uint8_t> build_ok()
{
    return {static_cast<uint8_t>(msg_type::ok)};
}

std::vector<uint8_t> build_hs_init(std::span<const uint8_t, 32> eph_pk)
{
    // [type:1][eph_pk:32]
    std::vector<uint8_t> v;
    v.reserve(33);
    v.push_back(static_cast<uint8_t>(msg_type::hs_init));
    append_bytes(v, eph_pk.data(), 32);
    return v;
}

std::vector<uint8_t> build_hs_resp(std::span<const uint8_t, 32> eph_pk,
                                   std::span<const uint8_t, 32> identity_pk,
                                   std::span<const uint8_t, 64> sig)
{
    // [type:1][eph_pk:32][identity_pk:32][sig:64]
    std::vector<uint8_t> v;
    v.reserve(129);
    v.push_back(static_cast<uint8_t>(msg_type::hs_resp));
    append_bytes(v, eph_pk.data(), 32);
    append_bytes(v, identity_pk.data(), 32);
    append_bytes(v, sig.data(), 64);
    return v;
}

std::vector<uint8_t> build_hs_finish(std::span<const uint8_t, 32> identity_pk,
                                     std::span<const uint8_t, 64> sig)
{
    // [type:1][identity_pk:32][sig:64]
    std::vector<uint8_t> v;
    v.reserve(97);
    v.push_back(static_cast<uint8_t>(msg_type::hs_finish));
    append_bytes(v, identity_pk.data(), 32);
    append_bytes(v, sig.data(), 64);
    return v;
}

std::vector<uint8_t> build_encrypted(std::span<const uint8_t, 12> nonce,
                                     std::span<const uint8_t>     blob)
{
    // [type:1][nonce:12][ciphertext+tag]
    std::vector<uint8_t> v;
    v.reserve(13 + blob.size());
    v.push_back(static_cast<uint8_t>(msg_type::encrypted));
    append_bytes(v, nonce.data(), 12);
    append_bytes(v, blob.data(), blob.size());
    return v;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

msg_type get_type(std::span<const uint8_t> frame)
{
    if (frame.empty()) return static_cast<msg_type>(0x00);
    return static_cast<msg_type>(frame[0]);
}

// ── Parsers ──────────────────────────────────────────────────────────────────

std::optional<parsed_register> parse_register(std::span<const uint8_t> f)
{
    if (f.size() < 35) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::register_node)) return std::nullopt;
    parsed_register r;
    r.port = read_u16be(f.data() + 1);
    std::memcpy(r.pubkey.data(), f.data() + 3, 32);
    return r;
}

std::optional<std::vector<peer_info>> parse_peer_list(std::span<const uint8_t> f)
{
    if (f.size() < 3) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::peer_list)) return std::nullopt;
    uint16_t count = read_u16be(f.data() + 1);
    if (f.size() < 3u + static_cast<size_t>(count) * 38u) return std::nullopt;
    std::vector<peer_info> peers;
    peers.reserve(count);
    const uint8_t* p = f.data() + 3;
    for (uint16_t i = 0; i < count; ++i) {
        peer_info pi;
        std::memcpy(pi.ip.data(), p, 4);       p += 4;
        pi.port = read_u16be(p);                p += 2;
        std::memcpy(pi.pubkey.data(), p, 32);   p += 32;
        peers.push_back(pi);
    }
    return peers;
}

std::optional<parsed_hs_init> parse_hs_init(std::span<const uint8_t> f)
{
    if (f.size() < 33) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::hs_init)) return std::nullopt;
    parsed_hs_init r;
    std::memcpy(r.eph_pk.data(), f.data() + 1, 32);
    return r;
}

std::optional<parsed_hs_resp> parse_hs_resp(std::span<const uint8_t> f)
{
    // [type:1][eph_pk:32][identity_pk:32][sig:64] = 129 bytes
    if (f.size() < 129) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::hs_resp)) return std::nullopt;
    parsed_hs_resp r;
    std::memcpy(r.eph_pk.data(),      f.data() +  1, 32);
    std::memcpy(r.identity_pk.data(), f.data() + 33, 32);
    std::memcpy(r.sig.data(),         f.data() + 65, 64);
    return r;
}

std::optional<parsed_hs_finish> parse_hs_finish(std::span<const uint8_t> f)
{
    // [type:1][identity_pk:32][sig:64] = 97 bytes
    if (f.size() < 97) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::hs_finish)) return std::nullopt;
    parsed_hs_finish r;
    std::memcpy(r.identity_pk.data(), f.data() +  1, 32);
    std::memcpy(r.sig.data(),         f.data() + 33, 64);
    return r;
}

std::optional<parsed_encrypted> parse_encrypted(std::span<const uint8_t> f)
{
    // [type:1][nonce:12][blob...]  minimum 13 bytes + tag (16) = 29
    if (f.size() < 29) return std::nullopt;
    if (f[0] != static_cast<uint8_t>(msg_type::encrypted)) return std::nullopt;
    parsed_encrypted r;
    std::memcpy(r.nonce.data(), f.data() + 1, 12);
    r.blob.assign(f.begin() + 13, f.end());
    return r;
}
