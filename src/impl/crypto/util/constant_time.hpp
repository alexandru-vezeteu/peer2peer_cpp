#pragma once
#include "impl/crypto/util/ct_comparable.hpp"
#include "impl/crypto/util/ct_selectable.hpp"
#include "impl/crypto/util/ct_swappable.hpp"

template<typename T, typename C>
concept constant_time = ct_comparable<T> && ct_selectable<T, C> && ct_swappable<T, C>;
