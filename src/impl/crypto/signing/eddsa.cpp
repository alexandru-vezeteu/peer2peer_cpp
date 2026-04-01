#include "eddsa.hpp"
#include "impl/crypto/util/math/group/edwards_point.hpp"

namespace crypto {

template<hasher H>
bool eddsa<H>::init_random()
{
    return sodium_init() != -1;
}

template<hasher H>
typename eddsa<H>::public_key eddsa<H>::derive_public(typename eddsa<H>::private_key priv)
{
    auto h = H::hash(priv);
    array<uint8_t, 32> h_a;
    for (size_t i = 0; i < 32; ++i) 
    {
        h_a[i] = h[i];
    }
    
    field_q a = field_q::from_bytes(h_a);
    a.clamp();

    edwards_point A = edwards_point::base_point() * a;
    return A.to_bytes();
}

template<hasher H>
typename eddsa<H>::signature eddsa<H>::sign(typename eddsa<H>::private_key priv, span<const uint8_t> msg)
{
    auto h = H::hash(priv);
    array<uint8_t, 32> h_a;
    for (size_t i = 0; i < 32; ++i) 
    {
        h_a[i] = h[i];
    }
    
    field_q a = field_q::from_bytes(h_a);
    a.clamp();

    edwards_point A_pt = edwards_point::base_point() * a;
    typename eddsa<H>::public_key A = A_pt.to_bytes();

    H h_r;
    h_r.update(span<const uint8_t>(h.data() + 32, 32));
    h_r.update(msg);
    auto r_hash = h_r.finalize();
    field_q r = field_q::reduce_512(r_hash);

    edwards_point R_pt = edwards_point::base_point() * r;
    auto R = R_pt.to_bytes();

    H h_S;
    h_S.update(R);
    h_S.update(A);
    h_S.update(msg);
    auto S_hash = h_S.finalize();
    field_q S = field_q::reduce_512(S_hash);

    field_q a_mod_l = field_q::from_bytes_mod_l(a.to_bytes()); 

    field_q S_sig = r + (S * a_mod_l);

    typename eddsa<H>::signature sig;
    for (size_t i = 0; i < 32; ++i) 
    {
        sig[i] = R[i];
    }
    auto S_sig_bytes = S_sig.to_bytes();
    for (size_t i = 0; i < 32; ++i) 
    {
        sig[i + 32] = S_sig_bytes[i];
    }
    
    return sig;
}

template<hasher H>
choice eddsa<H>::verify(typename eddsa<H>::public_key pub, span<const uint8_t> msg, typename eddsa<H>::signature sig)
{
    auto A_opt = edwards_point::from_bytes(pub);
    if (!A_opt.is_some_public()) {
        return choice::false_choice();
    }
    edwards_point A = A_opt.value_or(edwards_point::base_point());

    array<uint8_t, 32> R_bytes;
    array<uint8_t, 32> S_sig_bytes;
    for (size_t i = 0; i < 32; ++i) 
    {
        R_bytes[i] = sig[i];
        S_sig_bytes[i] = sig[i + 32];
    }
    
    auto R_opt = edwards_point::from_bytes(R_bytes);
    if (!R_opt.is_some_public()) 
    {
        return choice::false_choice();
    }
    edwards_point R = R_opt.value_or(edwards_point::base_point());

    field_q S_sig = field_q::from_bytes_mod_l(S_sig_bytes);
    auto S_sig_check = S_sig.to_bytes();
    bool is_reduced = true;
    for(int i=0; i<32; ++i) 
    {
        if(S_sig_check[i] != S_sig_bytes[i]) is_reduced = false;
    }
    
    if (!is_reduced) 
    {
        return choice::false_choice();
    }

    H h_S;
    h_S.update(R_bytes);
    h_S.update(pub);
    h_S.update(msg);
    auto S_hash = h_S.finalize();
    field_q S = field_q::reduce_512(S_hash);

    edwards_point SB = edwards_point::base_point() * S_sig;
    edwards_point SA = A * S;
    edwards_point R_SA = R + SA;

    // avoid small-subgroup attacks
    edwards_point SB8 = SB.dbl().dbl().dbl();
    edwards_point R_SA8 = R_SA.dbl().dbl().dbl();

    return SB8 == R_SA8;
}

template<hasher H>
typename eddsa<H>::private_key eddsa<H>::generate_private()
{
    eddsa<H>::private_key seed;
    randombytes_buf(seed.data(), seed.size());
    return seed;
}

template class eddsa<sha_512>;

} // namespace crypto
