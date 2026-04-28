#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

#include "net/tcp.hpp"
#include "session/session.hpp"

// Chunk frame layout (session plaintext, inside ChaCha20-Poly1305 encryption):
//   [0x01]          1 byte  — CHUNK_MAGIC
//   [transfer_id]   4 bytes — little-endian uint32, unique per transfer
//   [chunk_index]   2 bytes — little-endian uint16, 0-based
//   [total_chunks]  2 bytes — little-endian uint16
//   [data]          rest
inline constexpr uint8_t CHUNK_MAGIC        = 0x01;
inline constexpr size_t  CHUNK_HEADER_SIZE  = 9;        // 1+4+2+2
inline constexpr size_t  CHUNK_PAYLOAD_SIZE = 8 * 1024; // default payload bytes per chunk

struct chunk_info {
    uint32_t                 transfer_id;
    uint16_t                 index;
    uint16_t                 total;
    std::span<const uint8_t> data; // view into the source buffer
};

// Build the plaintext session payload for one chunk.
std::vector<uint8_t> make_chunk_frame(uint32_t                 transfer_id,
                                       uint16_t                 index,
                                       uint16_t                 total,
                                       std::span<const uint8_t> data);

// Parse a chunk frame.  Returns nullopt if the bytes don't look like a chunk.
std::optional<chunk_info> parse_chunk_frame(std::span<const uint8_t> bytes);

// Send data split across multiple encrypted session messages.
// A random transfer_id is generated per call so concurrent transfers don't collide.
// Returns the number of chunks sent (0 if data is empty or the first send fails).
uint16_t send_chunked(session&                  sess,
                      tcp_connection&           conn,
                      std::span<const uint8_t>  data,
                      size_t                    chunk_size = CHUNK_PAYLOAD_SIZE);

// Accumulates chunks for one in-flight transfer until all arrive.
class chunk_reassembler {
public:
    explicit chunk_reassembler(uint16_t total)
        : slots_(total), total_(total) {}

    // Add one chunk.  Returns the assembled payload when the last chunk arrives;
    // returns nullopt if the transfer is still incomplete or the slot was already filled.
    std::optional<std::vector<uint8_t>> add(uint16_t                 index,
                                            std::span<const uint8_t> data);

private:
    std::vector<std::optional<std::vector<uint8_t>>> slots_;
    uint16_t total_;
    uint16_t received_ = 0;
};

// Manages multiple concurrent in-flight transfers keyed by transfer_id.
// Not thread-safe — call from a single recv thread per peer.
class transfer_registry {
public:
    // Ingest one chunk.  Returns the assembled payload when the last chunk of a
    // transfer arrives; erases the entry and returns nullopt otherwise.
    std::optional<std::vector<uint8_t>> ingest(uint32_t                 transfer_id,
                                                uint16_t                 index,
                                                uint16_t                 total,
                                                std::span<const uint8_t> data);

    // Remove transfers that have been open for longer than ttl (default 60 s).
    void prune(std::chrono::seconds ttl = std::chrono::seconds(60));

private:
    struct entry {
        chunk_reassembler                     asm_;
        std::chrono::steady_clock::time_point created;
        explicit entry(uint16_t total)
            : asm_(total), created(std::chrono::steady_clock::now()) {}
    };
    std::unordered_map<uint32_t, entry> map_;
};
