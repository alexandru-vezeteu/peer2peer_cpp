#include "sha256.hpp"
#include "Hasher.hpp"
static_assert(Hasher<SHA256>);

static uint32_t rotr(uint32_t x, uint32_t n) 
{
    return (x >> n) | (x << (32 - n));
}
static uint32_t choice(uint32_t x, uint32_t y, uint32_t z) 
{
    return (x & y) ^ (~x & z);
}
static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) 
{
    return (x & y) ^ (x & z) ^ (y & z);
}
static uint32_t sig0(uint32_t x) 
{ 
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); 
}
static uint32_t sig1(uint32_t x) 
{
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}
static uint32_t SIG0(uint32_t x) 
{
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
static uint32_t SIG1(uint32_t x) 
{
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

// partea fractionara a radacinilor cubice ale primelor 64 de numere prime
static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

SHA256::SHA256() : buffer_len(0), bit_len(0) 
{
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

void SHA256::transform(const uint8_t *block) 
{
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) 
    {
        w[i] =  (static_cast<uint32_t>(block[i * 4]) << 24)     |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8)  |
                (static_cast<uint32_t>(block[i * 4 + 3]));
    }

    for (int i = 16; i < 64; ++i) 
    {
        w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; ++i) 
    {
        uint32_t t1 = h + SIG1(e) + choice(e, f, g) + K256[i] + w[i];
        uint32_t t2 = SIG0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256::update(std::span<const uint8_t> data) {
    for (uint8_t b : data) 
    {
        buffer[buffer_len++] = b;
        if (buffer_len == 64) 
        {
            transform(buffer);
            bit_len += 512;
            buffer_len = 0;
        }
    }
}

std::array<uint8_t, 32> SHA256::finalize() {
    uint64_t total_bits = bit_len + (static_cast<uint64_t>(buffer_len) * 8);

    buffer[buffer_len++] = 0x80;

    if (buffer_len > 56) 
    {
        while (buffer_len < 64) 
        {
            buffer[buffer_len++] = 0x00;
        }
        transform(buffer);
        buffer_len = 0;
    }

    while (buffer_len < 56) 
    {
        buffer[buffer_len++] = 0x00;
    }

    for (int i = 0; i < 8; ++i) 
    {
        buffer[63 - i] = static_cast<uint8_t>(total_bits >> (i * 8));
    }

    transform(buffer);

    std::array<uint8_t, 32> digest;
    for (int i = 0; i < 8; ++i) 
    {
        digest[i * 4] = static_cast<uint8_t>(state[i] >> 24);
        digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 16);
        digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 8);
        digest[i * 4 + 3] = static_cast<uint8_t>(state[i]);
    }

    //reset
    this->buffer_len = 0;
    this->bit_len = 0;
    this->state[0] = 0x6a09e667;
    this->state[1] = 0xbb67ae85;
    this->state[2] = 0x3c6ef372;
    this->state[3] = 0xa54ff53a;
    this->state[4] = 0x510e527f;
    this->state[5] = 0x9b05688c;
    this->state[6] = 0x1f83d9ab;
    this->state[7] = 0x5be0cd19;

    return digest;
}
std::array<uint8_t, 32> SHA256::hash(std::span<const uint8_t> data)
 {
    SHA256 h;
    h.update(data);
    return h.finalize();
}
