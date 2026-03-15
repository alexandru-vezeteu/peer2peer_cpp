#pragma once

#include <concepts>

template<typename T>
inline constexpr bool is_condition_type = false;

template<> inline constexpr bool is_condition_type<bool>   = true;


template<typename T>
concept condition = is_condition_type<std::remove_cvref_t<T>>;
