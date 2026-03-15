project('peer2peer', 'cpp',
  version : '0.1.0',
  default_options : ['cpp_std=c++23', 'warning_level=3', 'werror=true']
)

crypto_sources = [
  'src/impl/crypto/hash/sha256.cpp',
  'src/impl/crypto/hash/sha512.cpp',
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
