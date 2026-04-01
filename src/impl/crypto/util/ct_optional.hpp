#pragma once
#include <concepts>
#include <utility>
#include "choice.hpp"
#include "impl/crypto/util/ct_selectable.hpp"
#include "domain/crypto/optional.hpp"


using std::default_initializable;

template<typename T>
requires default_initializable<T> && ct_selectable<T, choice>
struct ct_optional
{
    static ct_optional some(T v)              noexcept { return ct_optional( std::move(v), choice::true_choice()  ); }
    static ct_optional none()                 noexcept { return ct_optional( T{},          choice::false_choice() ); }
    static ct_optional from_choice(T v, choice c) noexcept { return ct_optional( std::move(v), c ); }

    [[nodiscard]] T value_or(T fallback) const noexcept
    {
        return ct_select(value, fallback, valid);
    }

    [[nodiscard]] bool is_some_public() const noexcept { return valid.unwrap_public(); }

    using value_type = T;
    
private:
    explicit ct_optional(T v, choice c) noexcept : value(std::move(v)), valid(c) {}
    T      value;
    choice valid;
};

template<typename T>
inline constexpr bool is_optional_type<ct_optional<T>, T> = true;
