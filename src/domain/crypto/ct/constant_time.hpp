#pragma once

#include "ct_comparable.hpp"
#include "ct_selectable.hpp"
#include "ct_swappable.hpp"

template<typename T, typename C>
concept constant_time = ct_comparable<T> && ct_selectable<T, C> && ct_swappable<T, C>;
