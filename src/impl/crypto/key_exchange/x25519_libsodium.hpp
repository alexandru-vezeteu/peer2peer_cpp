#pragma once

#include <array>
#include <cstdint>
#include <sodium.h>

#include "domain/crypto/key_exchange.hpp"
#include "impl/crypto/util/ct_optional.hpp"
#include "impl/crypto/util/ct_array.hpp"


using std::size_t;
using std::array;

namespace crypto {

class x25519_libsodium
{
public:

    using private_key   = array<uint8_t, crypto_scalarmult_SCALARBYTES>;
    using public_key    = array<uint8_t, crypto_scalarmult_BYTES>;
    using shared_secret = array<uint8_t, crypto_scalarmult_BYTES>;

    static constexpr size_t public_key_size    = crypto_scalarmult_BYTES;
    static constexpr size_t shared_secret_size = crypto_scalarmult_BYTES;

    static bool init_random();

    static private_key generate();

    static public_key derive_public(const private_key &sk);

    static ct_optional<shared_secret> exchange(const private_key &sk, const public_key &pk);
};

static_assert(key_exchange<x25519_libsodium>);

} // namespace crypto
