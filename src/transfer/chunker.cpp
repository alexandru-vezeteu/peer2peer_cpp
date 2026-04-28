#include "transfer/chunker.hpp"

#include <algorithm>
#include <cstring>

#include <sodium.h>

// ── Frame serialisation ───────────────────────────────────────────────────────

std::vector<uint8_t> make_chunk_frame(uint32_t                 transfer_id,
                                       uint16_t                 index,
                                       uint16_t                 total,
                                       std::span<const uint8_t> data)
{
    std::vector<uint8_t> frame(CHUNK_HEADER_SIZE + data.size());
    frame[0] = CHUNK_MAGIC;
    frame[1] = static_cast<uint8_t>(transfer_id);
    frame[2] = static_cast<uint8_t>(transfer_id >> 8);
    frame[3] = static_cast<uint8_t>(transfer_id >> 16);
    frame[4] = static_cast<uint8_t>(transfer_id >> 24);
    frame[5] = static_cast<uint8_t>(index);
    frame[6] = static_cast<uint8_t>(index >> 8);
    frame[7] = static_cast<uint8_t>(total);
    frame[8] = static_cast<uint8_t>(total >> 8);
    std::memcpy(frame.data() + CHUNK_HEADER_SIZE, data.data(), data.size());
    return frame;
}

std::optional<chunk_info> parse_chunk_frame(std::span<const uint8_t> bytes)
{
    if (bytes.size() < CHUNK_HEADER_SIZE) return std::nullopt;
    if (bytes[0] != CHUNK_MAGIC)          return std::nullopt;

    chunk_info ci;
    ci.transfer_id = static_cast<uint32_t>(bytes[1])
                   | static_cast<uint32_t>(bytes[2]) << 8
                   | static_cast<uint32_t>(bytes[3]) << 16
                   | static_cast<uint32_t>(bytes[4]) << 24;
    ci.index = static_cast<uint16_t>(bytes[5])
             | static_cast<uint16_t>(bytes[6]) << 8;
    ci.total = static_cast<uint16_t>(bytes[7])
             | static_cast<uint16_t>(bytes[8]) << 8;
    ci.data  = bytes.subspan(CHUNK_HEADER_SIZE);

    if (ci.total == 0 || ci.index >= ci.total) return std::nullopt;
    return ci;
}

// ── send_chunked ──────────────────────────────────────────────────────────────

uint16_t send_chunked(session&                 sess,
                      tcp_connection&          conn,
                      std::span<const uint8_t> data,
                      size_t                   chunk_size)
{
    if (data.empty()) return 0;
    if (chunk_size == 0) chunk_size = CHUNK_PAYLOAD_SIZE;

    uint32_t transfer_id;
    ::randombytes_buf(&transfer_id, sizeof(transfer_id));

    const auto total = static_cast<uint16_t>((data.size() + chunk_size - 1) / chunk_size);

    for (uint16_t i = 0; i < total; ++i) {
        const size_t offset = static_cast<size_t>(i) * chunk_size;
        const size_t len    = std::min(chunk_size, data.size() - offset);
        auto frame = make_chunk_frame(transfer_id, i, total, data.subspan(offset, len));
        if (!sess.send(conn, frame)) return i; // partial send — return how many succeeded
    }
    return total;
}

// ── chunk_reassembler ─────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> chunk_reassembler::add(uint16_t                 index,
                                                            std::span<const uint8_t> data)
{
    if (index >= total_ || slots_[index].has_value()) return std::nullopt;
    slots_[index].emplace(data.begin(), data.end());
    ++received_;
    if (received_ < total_) return std::nullopt;

    std::vector<uint8_t> out;
    for (const auto& s : slots_)
        out.insert(out.end(), s->begin(), s->end());
    return out;
}

// ── transfer_registry ─────────────────────────────────────────────────────────

std::optional<std::vector<uint8_t>> transfer_registry::ingest(uint32_t                 transfer_id,
                                                               uint16_t                 index,
                                                               uint16_t                 total,
                                                               std::span<const uint8_t> data)
{
    auto [it, _] = map_.emplace(std::piecewise_construct,
                                std::forward_as_tuple(transfer_id),
                                std::forward_as_tuple(total));
    auto result = it->second.asm_.add(index, data);
    if (result) map_.erase(it);
    return result;
}

void transfer_registry::prune(std::chrono::seconds ttl)
{
    const auto now = std::chrono::steady_clock::now();
    for (auto it = map_.begin(); it != map_.end(); ) {
        if (now - it->second.created > ttl)
            it = map_.erase(it);
        else
            ++it;
    }
}
