#include "poly1305.hpp"

#include <algorithm>

std::array<uint8_t, 16> Poly1305::generate(
    std::span<const uint8_t> key,
    std::span<const uint8_t> msg)
{
    // ── Load and clamp r (first 16 bytes of key) ──────────────────────────────
    // Clamping clears specific bits per RFC 8439 §2.5.1 to ensure r is in the
    // subgroup that makes the polynomial evaluation efficient and secure.
    std::array<uint8_t, 17> r_bytes{};
    for (size_t i = 0; i < 16; ++i) r_bytes[i] = key[i];
    // r_bytes[16] stays 0 (no high bit for the key)

    r_bytes[3]  &= 0x0F;
    r_bytes[7]  &= 0x0F;
    r_bytes[11] &= 0x0F;
    r_bytes[15] &= 0x0F;
    r_bytes[4]  &= 0xFC;
    r_bytes[8]  &= 0xFC;
    r_bytes[12] &= 0xFC;

    field_130 r   = field_130::from_bytes(r_bytes);
    field_130 acc = field_130::zero();

    // ── Process message blocks ────────────────────────────────────────────────
    // Each block is treated as a 130-bit integer: the raw bytes as a
    // little-endian number, with a 1-bit appended right after the last byte.
    // This ensures distinct representations for full and partial final blocks.
    size_t offset = 0;
    while (offset < msg.size()) {
        size_t block_len = std::min(msg.size() - offset, size_t(16));

        std::array<uint8_t, 17> block{};
        for (size_t i = 0; i < block_len; ++i)
            block[i] = msg[offset + i];
        block[block_len] = 0x01; // append bit at position 8*block_len

        field_130 n = field_130::from_bytes(block);
        acc = (acc + n) * r;
        offset += block_len;
    }

    // ── Finalise: tag = (acc mod p) + s  mod 2^128 ───────────────────────────
    acc.reduce_inplace();
    auto acc_bytes = acc.to_bytes(); // 17 bytes, canonical, little-endian

    // s is key[16..31] interpreted as a 128-bit little-endian integer.
    // We add s to the lower 128 bits of acc and discard any carry (mod 2^128).
    std::array<uint8_t, 16> tag{};
    uint32_t carry = 0;
    for (size_t i = 0; i < 16; ++i) {
        uint32_t sum = uint32_t(acc_bytes[i]) + uint32_t(key[16 + i]) + carry;
        tag[i] = uint8_t(sum);
        carry  = sum >> 8;
    }
    return tag;
}

bool Poly1305::verify(
    std::span<const uint8_t> key,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> provided_tag)
{
    auto computed = generate(key, msg);

    // Constant-time comparison: accumulate XOR differences.
    uint8_t diff = 0;
    for (size_t i = 0; i < 16; ++i)
        diff |= computed[i] ^ provided_tag[i];
    return diff == 0;
}
