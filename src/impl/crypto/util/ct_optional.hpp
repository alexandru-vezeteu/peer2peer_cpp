#pragma once
#include <concepts>
#include <utility>
#include "choice.hpp"
#include "domain/crypto/ct/ct_selectable.hpp"
#include "domain/crypto/ct/optional.hpp"

template<typename T>
requires std::default_initializable<T> && ct_selectable<T, choice>
struct ct_optional
{
    static ct_optional some(T v) noexcept { return { std::move(v), choice::true_choice()  }; }
    static ct_optional none()    noexcept { return { T{},          choice::false_choice() }; }

    [[nodiscard]] T value_or(T fallback) const noexcept
    {
        return T::ct_select(value, fallback, valid);
    }

    [[nodiscard]] bool is_some_public() const noexcept { return valid.unwrap_public(); }

    using value_type = T;

private:
    ct_optional(T v, choice c) noexcept : value(std::move(v)), valid(c) {}
    T      value;
    choice valid;
};

template<typename T>
inline constexpr bool is_optional_type<ct_optional<T>, T> = true;
