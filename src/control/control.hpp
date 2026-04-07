#pragma once

// Unix-domain socket helpers shared between the daemon control server and
// the interactive shell client.  Header-only; no corresponding .cpp needed.

#include <optional>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

inline constexpr const char* DEFAULT_SOCKET_PATH = "/tmp/p2p.sock";

// ── Buffered line reader over a raw fd ───────────────────────────────────────

class line_reader {
public:
    explicit line_reader(int fd) : fd_(fd) {}

    // Returns the next '\n'-terminated line (without the newline), or
    // nullopt on EOF / error.
    std::optional<std::string> read_line()
    {
        while (true) {
            auto nl = buf_.find('\n');
            if (nl != std::string::npos) {
                auto line = buf_.substr(0, nl);
                buf_.erase(0, nl + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return line;
            }
            char tmp[512];
            ssize_t n = ::read(fd_, tmp, sizeof(tmp));
            if (n <= 0) return std::nullopt;
            buf_.append(tmp, static_cast<size_t>(n));
        }
    }

private:
    int         fd_;
    std::string buf_;
};

// Write a string followed by '\n'; returns false on error.
inline bool ctl_write(int fd, const std::string& s)
{
    std::string line = s + "\n";
    ssize_t n = ::write(fd, line.data(), line.size());
    return n == static_cast<ssize_t>(line.size());
}

// Write a raw string (no added newline), consuming the return value correctly.
inline void ctl_write_raw(int fd, const std::string& s)
{
    const char* p   = s.data();
    size_t      rem = s.size();
    while (rem > 0) {
        ssize_t n = ::write(fd, p, rem);
        if (n <= 0) return;
        p   += static_cast<size_t>(n);
        rem -= static_cast<size_t>(n);
    }
}

// Connect to a Unix-domain socket.  Returns the fd, or -1 on error.
inline int unix_connect(const std::string& path)
{
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}
