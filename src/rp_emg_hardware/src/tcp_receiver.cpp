#include "rp_emg_hardware/tcp_receiver.hpp"
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <fstream> // Required for std::ofstream
#include <iomanip>
#include <iostream>
#include <numeric>
#include <string>
#include <unistd.h>
#include <vector>

static void usage(const char *program) {
  fprintf(stderr,
          "Usage: %s [--count N] "
          "[--host HOST ] "
          "[--port PORT ]"
          "\n",
          program);
}

tcp::PacketTrailer tcp::decode_packet_trailer(const char *data) {
  tcp::PacketTrailer trailer;

  trailer.magic = get_at_offset<uint64_t>(data, kMagicOffset);
  trailer.packet_num = get_at_offset<uint32_t>(data, kPacketNumOffset);
  trailer.trailer_bytes =
      get_at_offset<uint32_t>(data, kPacketTrailerBytesOffset);
  trailer.packet_bytes = get_at_offset<uint32_t>(data, kPacketBytesOffset);
  trailer.valid_data_bytes =
      get_at_offset<uint32_t>(data, kPacketValidDataBytesOffset);
  trailer.intan_frame_count =
      get_at_offset<uint32_t>(data, kPacketIntanCountOffset);
  trailer.max_intan_frame_count =
      get_at_offset<uint32_t>(data, kPacketMaxIntanCountOffset);
  trailer.icm_frame_count =
      get_at_offset<uint32_t>(data, kPacketICMCountOffset);
  trailer.icm_offset = get_at_offset<uint32_t>(data, kPacketICMOffsetOffset);
  trailer.trailer_offset =
      get_at_offset<uint32_t>(data, kPacketTrailerStartOffset);
  trailer.flags = get_at_offset<uint32_t>(data, kPacketFlagsOffset);
  trailer.dropped_intan_frames =
      get_at_offset<uint32_t>(data, kPacketDroppedIntanOffset);
  trailer.dropped_icm_frames =
      get_at_offset<uint32_t>(data, kPacketDroppedICMOffset);

  for (std::size_t index = 0; index < kPacketTrailerIntanOffsetCount; ++index) {
    trailer.intan_offsets[index] = get_at_offset<uint32_t>(
        data, kPacketIntanOffsetOffset + index * sizeof(uint32_t));
  }

  return trailer;
}

int tcp::open_client(std::string host, unsigned int port) {
  int sock = 0;
  struct sockaddr_in serv_addr;

  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    std::cerr << "Socket creation error" << std::endl;
    return EXIT_FAILURE;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
    std::cerr << "Invalid address/ Address not supported" << std::endl;
    return EXIT_FAILURE;
  }

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    std::cerr << "Connection Failed" << std::endl;
    return EXIT_FAILURE;
  }

  return sock;
}

static int parse_u64(const char *text, uint64_t *value) {
  char *end;

  if (!text || !*text)
    return -1;
  *value = strtoull(text, &end, 0);
  return *end == '\0' ? 0 : -1;
}

static int parse_unsigned(const char *text, unsigned *value) {
  uint64_t parsed;

  if (parse_u64(text, &parsed) != 0 || parsed > UINT32_MAX)
    return -1;
  *value = (unsigned)parsed;
  return 0;
}

long long elapsed_since(std::chrono::microseconds time_initial) {
  auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
  auto time_current =
      std::chrono::duration_cast<std::chrono::microseconds>(now);

  // Return the raw difference as an integer
  return (time_current - time_initial).count();
}

void export_packet_metrics_to_csv(
    const std::string &directory_path,
    const std::vector<long long> &first_recv_times,
    const std::vector<long long> &packet_ready_times,
    const std::vector<uint32_t> &recv_calls,
    const std::string &filename = "packet_metrics.csv") {

  size_t size = first_recv_times.size();
  if (packet_ready_times.size() != size || recv_calls.size() != size) {
    std::cerr << "Error: Vector sizes do not match!\n";
    return;
  }

  // Construct the full file path from the directory
  std::string full_path = directory_path;

  // Ensure the directory path ends with a directory separator
  if (!full_path.empty() && full_path.back() != '/' &&
      full_path.back() != '\\') {
    full_path += '/';
  }
  full_path += filename;

  // Open file stream for writing (this creates the file)
  std::ofstream csv_file(full_path);
  if (!csv_file.is_open()) {
    std::cerr << "Error: Could not create file at path: " << full_path << "\n";
    std::cerr
        << "Make sure the directory exists and you have write permissions.\n";
    return;
  }

  const double NOMINAL_PERIOD = 1000.0;

  // Find Optimal Phase Alignment Offset
  double phase_sum = 0.0;
  for (size_t i = 0; i < size; ++i) {
    phase_sum += (first_recv_times[i] - (i * NOMINAL_PERIOD));
  }
  double optimized_base_time = phase_sum / size;

  // Write CSV Headers
  csv_file << "Index,First Recv (us),Target Time (us),Recv Jitter (us),Ready "
              "Delta (us),Recv Calls\n";
  csv_file << std::fixed << std::setprecision(2);

  // Stream rows out to file
  for (size_t i = 0; i < size; ++i) {
    double target_time = optimized_base_time + (i * NOMINAL_PERIOD);
    double jitter = first_recv_times[i] - target_time;
    long long ready_delta = packet_ready_times[i] - first_recv_times[i];

    csv_file << i << "," << first_recv_times[i] << "," << target_time << ","
             << jitter << "," << ready_delta << "," << recv_calls[i] << "\n";
  }

  csv_file.close();
  std::cout << "Successfully created and saved file to: " << full_path << "\n";
}

int main(int argc, char *argv[]) {
  std::string host;
  std::uint32_t count;
  std::uint32_t packet_index = 0;
  unsigned int port;
  char buffer[tcp::kBufferSize] = {0};
  int sock;

  // parsing args
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
      host = argv[++i];
    } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &count) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
      }
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      if (parse_unsigned(argv[++i], &port) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
      }
    }
  }

  std::vector<long long> first_recv_times(count);
  std::vector<long long> packet_ready_times(count);
  std::vector<uint32_t> recv_calls(count);

  sock = tcp::open_client(host, port);

  std::uint32_t bytes_into_packet = 0;

  auto time_initial = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now().time_since_epoch());

  ssize_t bytes_read = 0;
  while ((bytes_read = read(sock, buffer, tcp::kBufferSize)) != 0) {
    if (++recv_calls[packet_index] == 1) {
      first_recv_times[packet_index] = elapsed_since(time_initial);
    }
    bytes_into_packet += bytes_read;
    if (bytes_into_packet >= tcp::kBufferSize) {
      bytes_into_packet -= tcp::kBufferSize;
      packet_ready_times[packet_index] = elapsed_since(time_initial);
      ++packet_index;
    }
  }

  export_packet_metrics_to_csv(
      "/home/ezraklukas/Documents/arbeit/ubckin/notes/ezra/resources/"
      "ros2_framework/emg_ws/data",
      first_recv_times, packet_ready_times, recv_calls);
}
