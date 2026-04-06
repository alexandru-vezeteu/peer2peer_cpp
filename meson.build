project('peer2peer', 'cpp',
  version : '0.1.0',
  default_options : ['cpp_std=c++23', 'warning_level=3', 'werror=true']
)

# ── Dependencies ──────────────────────────────────────────────────────────────

openssl    = dependency('openssl')
sodium_dep = dependency('libsodium')
threads    = dependency('threads')

# ── Source groups ─────────────────────────────────────────────────────────────

crypto_sources = [
  'src/impl/crypto/hash/sha_256.cpp',
  'src/impl/crypto/hash/sha_512.cpp',
  'src/impl/crypto/util/math/field/field_25519.cpp',
  'src/impl/crypto/util/math/field/field_1305.cpp',
  'src/impl/crypto/stream_cipher/chacha_20.cpp',
  'src/impl/crypto/mac/poly_1305.cpp',
  'src/impl/crypto/aead/chacha20_poly1305.cpp',
  'src/impl/crypto/util/math/field/field_q.cpp',
]

montgomery_sources = crypto_sources + [
  'src/impl/crypto/util/math/group/montgomery_point.cpp',
  'src/impl/crypto/key_exchange/x25519.cpp',
]

eddsa_sources = crypto_sources + [
  'src/impl/crypto/util/math/group/edwards_point.cpp',
  'src/impl/crypto/signing/eddsa.cpp',
]

p2p_sources = crypto_sources + [
  'src/impl/crypto/util/math/group/montgomery_point.cpp',
  'src/impl/crypto/key_exchange/x25519.cpp',
  'src/impl/crypto/util/math/group/edwards_point.cpp',
  'src/impl/crypto/signing/eddsa.cpp',
  'src/net/tcp.cpp',
  'src/protocol/wire.cpp',
  'src/session/session.cpp',
  'src/coordinator/coordinator.cpp',
  'src/node/node.cpp',
]

inc = include_directories('src')

# ── Main executable ───────────────────────────────────────────────────────────

executable('p2p',
  sources              : ['src/main.cpp'] + p2p_sources,
  include_directories  : inc,
  dependencies         : [sodium_dep, threads],
)

# ── Crypto tests ──────────────────────────────────────────────────────────────

test_hasher = executable('THasher',
  sources             : ['src/tests/crypto/hash_test.cpp'] + crypto_sources,
  include_directories : inc,
  dependencies        : openssl,
)
test('hasher', test_hasher)

test_x25519 = executable('TX25519',
  sources             : ['src/tests/crypto/x25519_test.cpp']
                        + montgomery_sources
                        + ['src/impl/crypto/key_exchange/x25519_libsodium.cpp'],
  include_directories : inc,
  dependencies        : sodium_dep,
)
test('x25519', test_x25519)

test_eddsa = executable('TEdDSA',
  sources             : ['src/tests/crypto/eddsa_test.cpp'] + eddsa_sources,
  include_directories : inc,
  dependencies        : sodium_dep,
)
test('eddsa', test_eddsa)

test_chacha20 = executable('TChaCha20',
  sources             : ['src/tests/crypto/chacha20_test.cpp'] + crypto_sources,
  include_directories : inc,
)
test('chacha20', test_chacha20)

test_poly1305 = executable('TPoly1305',
  sources             : ['src/tests/crypto/poly1305_test.cpp'] + crypto_sources,
  include_directories : inc,
)
test('poly1305', test_poly1305)

test_chacha20_poly1305 = executable('TChaCha20Poly1305',
  sources             : ['src/tests/crypto/chacha20_poly1305_test.cpp'] + crypto_sources,
  include_directories : inc,
)
test('chacha20_poly1305', test_chacha20_poly1305)

# ── Integration test (full session stack over loopback TCP) ───────────────────

integration_sources = p2p_sources

integration_test = executable('integration_test',
  sources             : ['src/tests/integration/integration_test.cpp']
                        + integration_sources,
  include_directories : inc,
  dependencies        : [sodium_dep, threads],
)

test('integration', integration_test, timeout : 30)
