#include "x25519.hpp"

namespace crypto {

using private_key = x25519::private_key;
using public_key = x25519::public_key;
using shared_secret = x25519::shared_secret;

bool x25519::init_random() 
{
    return sodium_init() != -1; 
}

private_key x25519::generate()
{
    private_key sk;
    randombytes_buf(sk.data(), sk.size());
    return sk;
}

public_key x25519::derive_public(const private_key &sk)
{
    field_q s = field_q::from_bytes(sk);
    s.clamp();
    return (montgomery_point::base_point() * s).to_affine().to_bytes();
}

ct_optional<shared_secret> x25519::exchange(const private_key &sk, const public_key &pk)
{
    auto point  = montgomery_point::from_affine(field_25519::from_bytes(pk));
    field_q s = field_q::from_bytes(sk);
    s.clamp();
    auto result = (point * s).to_affine();
    return ct_optional<shared_secret>::from_choice(result.to_bytes(), !result.is_zero());
}

} // namespace crypto
