project('peer2peer', 'cpp',
  version : '0.1.0',
  default_options : ['cpp_std=c++23', 'warning_level=3', 'werror=true']
)

crypto_sources = [
  'src/Crypto/Hasher/sha256.cpp',
  'src/Crypto/Hasher/sha512.cpp',
]

crypto_inc = include_directories('src', 'src/Crypto')

executable('p2p',
  sources : ['src/main.cpp'] + crypto_sources,
  include_directories : crypto_inc,
)

openssl = dependency('openssl')

test_hasher = executable('THasher',
  sources : ['src/Tests/THasher.cpp'] + crypto_sources,
  include_directories : crypto_inc,
  dependencies : openssl,
)

test('hasher', test_hasher)
