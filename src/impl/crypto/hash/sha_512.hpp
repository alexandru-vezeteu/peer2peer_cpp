#pragma once
#include <array>
#include <cstdint>
#include <span>

#include "domain/crypto/hash.hpp"

using std::span;
using std::size_t;
using std::array;

namespace crypto {

class sha_512
{
public:
    static constexpr size_t digest_size = 64;

    sha_512();
    void update(span<const uint8_t> data);
    array<uint8_t, digest_size> finalize();
    static array<uint8_t, digest_size> hash(span<const uint8_t> data);

private:
    void transform(const uint8_t* block);
    uint64_t state[8];
    uint8_t  buffer[128];
    size_t   buffer_len;
    uint64_t bit_len_low;
    uint64_t bit_len_high;
};

static_assert(hasher<sha_512>);

} // namespace crypto
