project('peer2peer', 'cpp',
  version : '0.1.0',
  default_options : ['cpp_std=c++23', 'warning_level=3', 'werror=true']
)

crypto_sources = [
  'src/impl/crypto/hash/sha256.cpp',
  'src/impl/crypto/hash/sha512.cpp',
  'src/impl/crypto/util/math/field/field_25519.cpp',
]

inc = include_directories('src')

executable('p2p',
  sources : ['src/main.cpp'] + crypto_sources,
  include_directories : inc,
)

openssl = dependency('openssl')

test_hasher = executable('THasher',
  sources : ['src/tests/crypto/hash_test.cpp'] + crypto_sources,
  include_directories : inc,
  dependencies : openssl,
)

test('hasher', test_hasher)

sodium_dep = dependency('libsodium')

test_field = executable('TField',
  sources : ['src/tests/crypto/field_25519_test.cpp'] + crypto_sources,
  include_directories : inc,
  dependencies : sodium_dep,
)

test('field_25519', test_field)

test_field_stress = executable('TFieldStress',
  sources : ['src/tests/crypto/field_25519_stress.cpp'] + crypto_sources,
  include_directories : inc,
  dependencies : sodium_dep,
)

test('field_25519_stress', test_field_stress)

montgomery_sources = crypto_sources + [
  'src/impl/crypto/util/math/group/montgomery_point.cpp',
]

test_x25519 = executable('TX25519',
  sources : ['src/tests/crypto/x25519_test.cpp'] + montgomery_sources,
  include_directories : inc,
  dependencies : sodium_dep,
)

test('x25519', test_x25519)
