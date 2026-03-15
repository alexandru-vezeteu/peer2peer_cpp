#pragma once
#include <concepts>
#include <utility>
#include "Choice.hpp"

#include "CtSelectable.hpp"

template<typename T>
requires std::default_initializable<T> && CtSelectable<T>
struct CtOptional
{
    static CtOptional some(T v) noexcept { return { std::move(v), Choice{true}  }; }
    static CtOptional none()    noexcept { return { T{},          Choice{false} }; }

    [[nodiscard]] T value_or(T fallback) const noexcept
    {
        return T::ct_select(value, fallback, valid);
    }

    [[nodiscard]] Choice is_some_public() const noexcept { return valid; }

private:
    T      value;
    Choice valid;
};