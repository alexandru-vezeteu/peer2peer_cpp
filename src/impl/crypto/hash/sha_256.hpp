#pragma once
#include <array>
#include <cstdint>
#include <span>

#include "domain/crypto/hash.hpp"
using std::span;
using std::size_t;
using std::array;

namespace crypto {


class sha_256
{
public:
    static constexpr size_t digest_size = 32;

    sha_256();
    void update(span<const uint8_t> data);
    array<uint8_t, digest_size> finalize();
    static array<uint8_t, digest_size> hash(span<const uint8_t> data);

private:
    void transform(const uint8_t* block);
    uint32_t state[8];
    uint8_t  buffer[64];
    size_t   buffer_len;
    uint64_t bit_len;
};

static_assert(hasher<sha_256>);

} // namespace crypto
