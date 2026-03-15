#include "field_25519.hpp"


choice field_25519::is_one() const
{
    auto reduced = this->reduce();
    uint64_t diff = reduced.limbs[0] ^ 0x1; 
    // 1->0
    // fac asta pt ca daca al doilea limb are 1 pe primul bit in al doilea limb OR ul e orb..
    for(size_t i=1;i<reduced.limbs.size();++i)
    {
        diff |= reduced.limbs[i];
    }
    return choice::choice_from_equal(diff, 0);
}

choice field_25519::is_zero() const
{
    auto reduced = this->reduce();
    uint64_t diff = 0;
    for(size_t i=0;i<reduced.limbs.size();++i)
    {
        diff |= reduced.limbs[i];
    }
    return choice::choice_from_equal(diff, 0);
}
    


field_25519 field_25519::operator+(const field_25519 other) const
{
    field_25519 ret = other;
    for(size_t i=0;i<this->limbs.size();++i)
    {
        ret.limbs[i] += this->limbs[i];
    }
    return ret;
}
field_25519 field_25519::operator-(const field_25519 other) const
{
    return other;
}
field_25519 field_25519::operator*(const field_25519 other) const
{
    return other;
}
field_25519 field_25519::operator-() const
{
    return {};
}
field_25519 field_25519::square() const
{
    return {};
}
field_25519 field_25519::invert() const
{
    return {};
}

choice field_25519::operator==(const field_25519 other) const
{
    return choice(other.limbs[0]);
}
choice field_25519::operator!=(const field_25519 other) const
{
    return choice(other.limbs[0]);
}





const std::array<uint8_t, field_25519::byte_size> field_25519::to_bytes() const
{
    return {};
}