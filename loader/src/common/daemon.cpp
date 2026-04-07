#include "daemon.hpp"

#include <fcntl.h>
#include <linux/un.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <algorithm>

#include "logging.hpp"
#include "socket_utils.hpp"

namespace zygiskd {
static std::string TMP_PATH;
namespace {
constexpr char kFailureCounterName[] = "/early_boot_handshake_failures";
constexpr char kEmergencyMarkerName[] = "/emergency_disable";
constexpr int kEarlyBootWindowSeconds = 300;
constexpr int kFailureThreshold = 3;
constexpr const char* kDisableCandidates[] = {
    "/data/adb/modules/zygisksu/disable",
    "/data/adb/modules/neozygisk/disable",
};

bool path_exists(const std::string& path) { return !path.empty() && access(path.c_str(), F_OK) == 0; }

std::string counter_path() { return TMP_PATH + kFailureCounterName; }

std::string marker_path() { return TMP_PATH + kEmergencyMarkerName; }

bool is_early_boot() {
    timespec ts{};
    if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
        PLOGE("clock_gettime(CLOCK_BOOTTIME)");
        return false;
    }
    return ts.tv_sec <= kEarlyBootWindowSeconds;
}

int read_failure_count() {
    auto path = counter_path();
    if (!path_exists(path)) return 0;

    char buf[16]{};
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (len <= 0) return 0;
    buf[len] = '\0';
    return std::max(0, atoi(buf));
}

void write_failure_count(int failures) {
    auto path = counter_path();
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        PLOGE("open(%s)", path.c_str());
        return;
    }

    char buf[16];
    int len = snprintf(buf, sizeof(buf), "%d\n", failures);
    if (len > 0 && write(fd, buf, static_cast<size_t>(len)) != len) {
        PLOGE("write(%s)", path.c_str());
    }
    close(fd);
}

void touch_file(const char* path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        if (errno != ENOENT) PLOGE("open(%s)", path);
        return;
    }
    close(fd);
}

void arm_emergency_disable(const char* stage, int failures) {
    auto marker = marker_path();
    if (!marker.empty()) {
        int fd = open(marker.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd >= 0) {
            char buf[128];
            int len = snprintf(buf, sizeof(buf),
                               "NeoZygisk disabled after %d early-boot handshake failures at %s\n",
                               failures, stage ? stage : "unknown");
            if (len > 0) write(fd, buf, static_cast<size_t>(len));
            close(fd);
        } else {
            PLOGE("open(%s)", marker.c_str());
        }
    }

    for (auto* path : kDisableCandidates) {
        touch_file(path);
    }

    LOGE("NeoZygisk emergency disable armed after %d early-boot handshake failures (stage=%s)",
         failures, stage ? stage : "unknown");
}
}  // namespace

void Init(const char *path) {
    if (path != nullptr) {
        TMP_PATH = path;
    }
}

std::string GetTmpPath() { return TMP_PATH; }

bool IsEmergencyDisabled() {
    if (path_exists(marker_path())) return true;
    for (auto* path : kDisableCandidates) {
        if (path_exists(path)) return true;
    }
    return false;
}

void NoteHandshakeFailure(const char* stage) {
    if (TMP_PATH.empty() || IsEmergencyDisabled()) return;
    if (!is_early_boot()) {
        ClearHandshakeFailures();
        return;
    }

    const int failures = read_failure_count() + 1;
    write_failure_count(failures);
    LOGW("NeoZygisk handshake failure #%d during early boot (stage=%s)", failures,
         stage ? stage : "unknown");
    if (failures >= kFailureThreshold) {
        arm_emergency_disable(stage, failures);
    }
}

void ClearHandshakeFailures() {
    if (TMP_PATH.empty()) return;
    auto path = counter_path();
    if (!path.empty()) unlink(path.c_str());
}

int Connect(uint8_t retry) {
    if (IsEmergencyDisabled()) {
        errno = ECANCELED;
        return -1;
    }

    int fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un addr{
        .sun_family = AF_UNIX,
        .sun_path = {0},
    };
    auto socket_path = TMP_PATH + kCPSocketName;
    strcpy(addr.sun_path, socket_path.c_str());
    socklen_t socklen = sizeof(addr);

    while (retry--) {
        int r = connect(fd, reinterpret_cast<struct sockaddr *>(&addr), socklen);
        if (r == 0) {
            ClearHandshakeFailures();
            return fd;
        }
        if (retry) {
            LOGW("retrying to connect to zygiskd, sleep 1s");
            sleep(1);
        }
    }

    NoteHandshakeFailure("connect");
    close(fd);
    return -1;
}

bool PingHeartbeat() {
    UniqueFd fd = Connect(5);
    if (fd == -1) {
        PLOGE("connecting to zygiskd");
        return false;
    }
    socket_utils::write_u8(fd, (uint8_t) SocketAction::PingHeartbeat);
    return true;
}

uint32_t GetProcessFlags(uid_t uid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetProcessFlags");
        return 0;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::GetProcessFlags) ||
        !socket_utils::write_u32(fd, uid)) {
        NoteHandshakeFailure("GetProcessFlags/write");
        return 0;
    }
    return socket_utils::read_u32(fd);
}

void CacheMountNamespace(pid_t pid) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("CacheMountNamespace");
        NoteHandshakeFailure("CacheMountNamespace/connect");
        return;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::CacheMountNamespace) ||
        !socket_utils::write_u32(fd, (uint32_t) pid)) {
        NoteHandshakeFailure("CacheMountNamespace/write");
    }
}

// Returns the file descriptor >= 0 on success, or -1 on failure.
int UpdateMountNamespace(MountNamespace type) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("UpdateMountNamespace");
        return -1;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::UpdateMountNamespace) ||
        !socket_utils::write_u8(fd, (uint8_t) type)) {
        NoteHandshakeFailure("UpdateMountNamespace/write");
        return -1;
    }

    // Read Status Byte
    uint8_t status = socket_utils::read_u8(fd);
    // Handle Failure Case (Not Cached)
    if (status == 0) {
        // Daemon explicitly told us it doesn't have it.
        return -1;
    }
    // Handle Success Case
    int namespace_fd = socket_utils::recv_fd(fd);
    if (namespace_fd < 0) {
        PLOGE("UpdateMountNamespace: failed to receive fd");
        return -1;
    }

    return namespace_fd;
}

std::vector<Module> ReadModules() {
    std::vector<Module> modules;
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("ReadModules");
        return modules;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ReadModules)) {
        NoteHandshakeFailure("ReadModules/write");
        return modules;
    }
    size_t len = socket_utils::read_usize(fd);
    for (size_t i = 0; i < len; i++) {
        std::string name = socket_utils::read_string(fd);
        int module_fd = socket_utils::recv_fd(fd);
        modules.emplace_back(name, module_fd);
    }
    return modules;
}

int ConnectCompanion(size_t index) {
    int fd = Connect(1);
    if (fd == -1) {
        PLOGE("ConnectCompanion");
        return -1;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::RequestCompanionSocket) ||
        !socket_utils::write_usize(fd, index)) {
        NoteHandshakeFailure("ConnectCompanion/write");
        return -1;
    }
    if (socket_utils::read_u8(fd) == 1) {
        return fd;
    } else {
        close(fd);
        return -1;
    }
}

int GetModuleDir(size_t index) {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("GetModuleDir");
        return -1;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::GetModuleDir) ||
        !socket_utils::write_usize(fd, index)) {
        NoteHandshakeFailure("GetModuleDir/write");
        return -1;
    }
    return socket_utils::recv_fd(fd);
}

void ZygoteRestart() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        if (errno == ENOENT) {
            LOGD("could not notify ZygoteRestart (maybe it hasn't been created)");
        } else {
            PLOGE("notify ZygoteRestart");
            NoteHandshakeFailure("ZygoteRestart/connect");
        }
        return;
    }
    if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::ZygoteRestart)) {
        PLOGE("request ZygoteRestart");
        NoteHandshakeFailure("ZygoteRestart/write");
    }
}

void SystemServerStarted() {
    UniqueFd fd = Connect(1);
    if (fd == -1) {
        PLOGE("report system server started");
    } else {
        if (!socket_utils::write_u8(fd, (uint8_t) SocketAction::SystemServerStarted)) {
            PLOGE("report system server started");
            NoteHandshakeFailure("SystemServerStarted/write");
        } else {
            ClearHandshakeFailures();
        }
    }
}
}  // namespace zygiskd
