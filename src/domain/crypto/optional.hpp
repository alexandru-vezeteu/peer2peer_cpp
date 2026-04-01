#pragma once
#include <optional>

using std::remove_cvref_t;
template<typename O, typename T>
inline constexpr bool is_optional_type = false;

template<typename T>
inline constexpr bool is_optional_type<std::optional<T>, T> = true;


template<typename O, typename T>
concept optional_of = is_optional_type<remove_cvref_t<O>, T>;


template<typename O>
concept optional = requires { requires is_optional_type<remove_cvref_t<O>, typename remove_cvref_t<O>::value_type>; };
