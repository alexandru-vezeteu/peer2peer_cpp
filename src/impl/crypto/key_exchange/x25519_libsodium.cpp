#include "x25519_libsodium.hpp"

namespace crypto {

using private_key = x25519_libsodium::private_key;
using public_key = x25519_libsodium::public_key;
using shared_secret = x25519_libsodium::shared_secret;

bool x25519_libsodium::init_random()
{
    return sodium_init() != -1; 
}

private_key x25519_libsodium::generate()
{
    private_key sk;
    randombytes_buf(sk.data(), sk.size());
    return sk;
}

public_key x25519_libsodium::derive_public(const private_key &sk)
{
    public_key pk;
    crypto_scalarmult_base(pk.data(), sk.data());
    return pk;
}

ct_optional<shared_secret> x25519_libsodium::exchange(const private_key &sk, const public_key &pk)
{
    shared_secret ss{};
    [[maybe_unused]] int r = crypto_scalarmult(ss.data(), sk.data(), pk.data());
    uint64_t acc = 0;
    for (auto b : ss) acc |= b;
    return ct_optional<shared_secret>::from_choice(ss, choice::from_nonzero(acc));
}

} // namespace crypto
