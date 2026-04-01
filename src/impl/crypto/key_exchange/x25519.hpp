#pragma once

#include <array>
#include <cstdint>
#include <sodium.h>

#include "domain/crypto/key_exchange.hpp"
#include "impl/crypto/util/ct_array.hpp"
#include "impl/crypto/util/ct_optional.hpp"
#include "impl/crypto/util/math/group/montgomery_point.hpp"

using std::size_t;
using std::array;

namespace crypto {


class x25519
{
public:
    static constexpr size_t public_key_size    = 32;
    static constexpr size_t shared_secret_size = 32;
    
    using private_key   = array<uint8_t, 32>;
    using public_key    = array<uint8_t, public_key_size>;
    using shared_secret = array<uint8_t, shared_secret_size>;

   

    static bool init_random();

    static private_key generate();

    static public_key derive_public(const private_key &sk);

    static ct_optional<shared_secret> exchange(const private_key &sk, const public_key &pk);
    
};

static_assert(key_exchange<x25519>);

} // namespace crypto
