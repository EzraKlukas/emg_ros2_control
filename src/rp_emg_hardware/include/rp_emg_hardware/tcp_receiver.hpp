#pragma once

#include <arpa/inet.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <type_traits>
#include <vector>

namespace tcp {
constexpr std::size_t kPacketBytes = 24576;
constexpr std::size_t kNumIntan = 8;
constexpr std::size_t kNumICM = 4;
constexpr std::size_t kIntanSamplingRatio = 2;
constexpr std::size_t kMagicBytes = 4;
constexpr std::size_t kBytesPerWord = 8;
constexpr std::size_t kPacketTrailerIntanOffsetCount = 48; // Way overkill

// offsets
constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kPacketNumOffset = 8;
constexpr std::size_t kPacketTrailerBytesOffset = 12;
constexpr std::size_t kPacketBytesOffset = 16;
constexpr std::size_t kPacketValidDataBytesOffset = 20;
constexpr std::size_t kPacketIntanCountOffset = 24;
constexpr std::size_t kPacketMaxIntanCountOffset = 28;
constexpr std::size_t kPacketICMCountOffset = 32;
constexpr std::size_t kPacketICMOffsetOffset = 36;
constexpr std::size_t kPacketTrailerStartOffset = 40;
constexpr std::size_t kPacketFlagsOffset = 44;
constexpr std::size_t kPacketDroppedIntanOffset = 48;
constexpr std::size_t kPacketDroppedICMOffset = 52;
constexpr std::size_t kPacketIntanOffsetOffset = 56;

constexpr std::size_t kBufferSize = 24600;

struct PacketTrailer {
  std::uint64_t magic;
  std::uint32_t packet_num, trailer_bytes, packet_bytes, valid_data_bytes,
      intan_frame_count, max_intan_frame_count, icm_frame_count, icm_offset,
      trailer_offset, flags, dropped_intan_frames, dropped_icm_frames;
  std::array<std::uint32_t, kPacketTrailerIntanOffsetCount> intan_offsets;
};

template <typename T> T get_at_offset(const char *data, std::size_t offset) {
  T ret{};
  std::memcpy(&ret, data + offset, sizeof(T));
  return ret;
}

int open_client(std::string host, unsigned port);

PacketTrailer decode_packet_trailer(const char *data);
} // namespace tcp
