#include "edwards_point.hpp"

using std::array;
//twisted edwards form:
//ax^2 + y^2 = 1+dx^2y^2
//a = -1
//d = -121665/121666 
static field_25519 get_d() 
{
    static field_25519 d_val = 
        (field_25519::zero() - (field_25519::zero() + 121665)) * (field_25519::zero() + 121666).invert();
    return d_val;
}

static field_25519 get_2d() {
    static field_25519 d2_val = get_d() + get_d();
    return d2_val;
}

edwards_point edwards_point::base_point() {
    // Base point y = 4/5 
    static field_25519 y = (field_25519::zero() + 4) * (field_25519::zero() + 5).invert();
    // Calculate x
    static field_25519 u = y.square() - field_25519::one();
    static field_25519 v = get_d() * y.square() + field_25519::one();
    static field_25519 x2 = u * v.invert();
    static field_25519 x = sqrt(x2).value_or(field_25519::zero());
    
    // x must be positive (lowest bit 0)
    if ((x.to_bytes()[0] & 1) == 1) {
        x = -x;
    }

    return edwards_point(x, y, field_25519::one(), x * y);
}

template<typename T>
ct_optional<T> edwards_point::from_bytes(const array<uint8_t, 32>& b) {
    uint8_t sign_bit = (b[31] >> 7) & 1;

    array<uint8_t, 32> y_bytes = b;
    y_bytes[31] &= 0x7F; // clear highest bit

    field_25519 y = field_25519::from_bytes(y_bytes);
    auto y_canonical = y.to_bytes();
    bool y_is_canonical = true;
    for (size_t i = 0; i < 32; ++i) {
        if (y_canonical[i] != y_bytes[i]) {
            y_is_canonical = false;
        }
    }
    if (!y_is_canonical) {
        return ct_optional<T>::none();
    }
    
    field_25519 u = y.square() - field_25519::one();
    field_25519 v = get_d() * y.square() + field_25519::one();
    field_25519 x2 = u * v.invert();
    
    auto x_opt = sqrt(x2);
    if (!x_opt.is_some_public()) {
        return ct_optional<edwards_point>::none();
    }
    
    field_25519 x = x_opt.value_or(field_25519::zero());
    
    if (x.is_zero().unwrap_public() && sign_bit == 1) {
        return ct_optional<T>::none();
    }
    
    choice is_correct_sign = choice::from_equal((uint8_t)(x.to_bytes()[0] & 1), sign_bit);
    x = ct_select(x, -x, is_correct_sign);
    
    return ct_optional<T>::some(edwards_point(x, y, field_25519::one(), x * y));
}

template ct_optional<edwards_point> edwards_point::from_bytes(const array<uint8_t, 32>& b);

array<uint8_t, 32> edwards_point::to_bytes() const {
    field_25519 z_inv = z.invert();
    field_25519 affine_x = x * z_inv;
    field_25519 affine_y = y * z_inv;
    
    array<uint8_t, 32> res = affine_y.to_bytes();
    uint8_t sign_bit = affine_x.to_bytes()[0] & 1;
    res[31] |= (sign_bit << 7);
    
    return res;
}

edwards_point edwards_point::operator+(const edwards_point& other) const {
    /*
      Hisil et al. 2008
      A = (Y1-X1)*(Y2-X2)
      B = (Y1+X1)*(Y2+X2)
      C = T1*2d*T2
      D = Z1*2*Z2
      E = B-A
      F = D-C
      G = D+C
      H = B+A
      X3 = E*F
      Y3 = G*H
      T3 = E*H
      Z3 = F*G
    */
    field_25519 A = (y - x) * (other.y - other.x);
    field_25519 B = (y + x) * (other.y + other.x);
    field_25519 C = t * get_2d() * other.t;
    field_25519 D = z * (other.z + other.z);
    
    field_25519 E = B - A;
    field_25519 F = D - C;
    field_25519 G = D + C;
    field_25519 H = B + A;
    
    return edwards_point(E * F, G * H, F * G, E * H);
}

edwards_point edwards_point::dbl() const {
    /*
      A = X1^2
      B = Y1^2
      C = 2*Z1^2
      H = A+B
      E = H - (X1+Y1)^2
      G = A-B
      F = C+G
      X3 = E*F
      Y3 = G*H
      T3 = E*H
      Z3 = F*G
    */
    field_25519 A = x.square();
    field_25519 B = y.square();
    field_25519 C = z.square() + z.square();
    field_25519 H = A + B;
    field_25519 E = H - (x + y).square();
    field_25519 G = A - B;
    field_25519 F = C + G;
    
    return edwards_point(E * F, G * H, F * G, E * H);
}

edwards_point edwards_point::operator*(const field_q& s) const {
    edwards_point res = edwards_point::identity();
    for (int i = 255; i >= 0; --i) {
        res = res.dbl();
        choice bit = s.get_bit_i(i);
        edwards_point sum = res + *this;
        res = ct_select(sum, res, bit);
    }
    return res;
}

choice edwards_point::operator==(const edwards_point& other) const {
    // Both points must be equivalent in projective scale
    // X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1
    field_25519 X1Z2 = x * other.z;
    field_25519 X2Z1 = other.x * z;
    field_25519 Y1Z2 = y * other.z;
    field_25519 Y2Z1 = other.y * z;
    return (X1Z2 == X2Z1) && (Y1Z2 == Y2Z1);
}

edwards_point ct_select(edwards_point a, edwards_point b, choice c) {
    return edwards_point(
        ct_select(a.x, b.x, c),
        ct_select(a.y, b.y, c),
        ct_select(a.z, b.z, c),
        ct_select(a.t, b.t, c)
    );
}
