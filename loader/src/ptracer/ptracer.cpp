#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android/dlext.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>

#include "daemon.hpp"
#include "logging.hpp"
#include "utils.hpp"

static uintptr_t push_bytes(int pid, struct user_regs_struct &regs, const void *buf, size_t len,
                            size_t align = 16) {
    regs.REG_SP -= len;
    regs.REG_SP &= ~(static_cast<uintptr_t>(align) - 1);
    uintptr_t remote_addr = regs.REG_SP;
    if (write_proc(pid, remote_addr, buf, len) != static_cast<ssize_t>(len)) {
        LOGE("failed to write %zu bytes to remote process", len);
        return 0;
    }
    return remote_addr;
}

static void write_inject_status(const char *status) {
    int fd = open("/data/adb/neozygisk/inject-status", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                  0644);
    if (fd < 0) {
        PLOGE("open inject-status");
        return;
    }
    write(fd, status, strlen(status));
    write(fd, "\n", 1);
    close(fd);
}

static uintptr_t remote_close_fd(int pid, struct user_regs_struct &regs, uintptr_t close_addr,
                                 uintptr_t return_addr, int fd) {
    std::vector<long> args;
    args.push_back(fd);
    return remote_call(pid, regs, close_addr, return_addr, args);
}

static uintptr_t dlopen_via_transferred_fd(int pid, const char *lib_path,
                                           const std::vector<MapInfo> &local_map,
                                           const std::vector<MapInfo> &remote_map,
                                           uintptr_t libc_return_addr,
                                           struct user_regs_struct &regs) {
    int local_fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (local_fd < 0) {
        PLOGE("open %s", lib_path);
        write_inject_status("fail:fd-open");
        return 0;
    }

    int local_sock = -1;
    uintptr_t remote_listener = 0;
    uintptr_t remote_conn = 0;
    auto cleanup = [&]() {
        if (local_sock >= 0) close(local_sock);
        if (local_fd >= 0) close(local_fd);
    };

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::string sock_name = "neozygisk-inj-" + std::to_string(pid) + "-" + std::to_string(getpid());
    if (sock_name.size() + 1 >= sizeof(addr.sun_path)) {
        LOGE("abstract socket name is too long");
        cleanup();
        write_inject_status("fail:socket-name");
        return 0;
    }
    addr.sun_path[0] = '\0';
    memcpy(addr.sun_path + 1, sock_name.data(), sock_name.size());
    socklen_t addr_len =
        static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + 1 + sock_name.size());

    auto socket_addr = find_func_addr(local_map, remote_map, "libc.so", "socket");
    auto bind_addr = find_func_addr(local_map, remote_map, "libc.so", "bind");
    auto listen_addr = find_func_addr(local_map, remote_map, "libc.so", "listen");
    auto accept_addr = find_func_addr(local_map, remote_map, "libc.so", "accept");
    auto recvmsg_addr = find_func_addr(local_map, remote_map, "libc.so", "recvmsg");
    auto close_addr = find_func_addr(local_map, remote_map, "libc.so", "close");
    auto android_dlopen_ext_addr =
        find_func_addr(local_map, remote_map, "libdl.so", "android_dlopen_ext");
    if (!socket_addr || !bind_addr || !listen_addr || !accept_addr || !recvmsg_addr ||
        !close_addr || !android_dlopen_ext_addr) {
        LOGE("failed to resolve one or more fd-loader remote functions");
        cleanup();
        write_inject_status("fail:resolve");
        return 0;
    }

    std::vector<long> args;
    args.push_back(AF_UNIX);
    args.push_back(SOCK_STREAM);
    args.push_back(0);
    remote_listener =
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(socket_addr), libc_return_addr, args);
    if (remote_listener == 0 || static_cast<long>(remote_listener) < 0) {
        LOGE("remote socket() failed: 0x%" PRIxPTR, remote_listener);
        cleanup();
        write_inject_status("fail:remote-socket");
        return 0;
    }

    uintptr_t remote_addr = push_bytes(pid, regs, &addr, addr_len);
    if (remote_addr == 0) {
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:push-sockaddr");
        return 0;
    }

    args.clear();
    args.push_back(remote_listener);
    args.push_back(remote_addr);
    args.push_back(addr_len);
    auto bind_ret =
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(bind_addr), libc_return_addr, args);
    if (static_cast<long>(bind_ret) < 0) {
        LOGE("remote bind() failed: 0x%" PRIxPTR, bind_ret);
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:remote-bind");
        return 0;
    }

    args.clear();
    args.push_back(remote_listener);
    args.push_back(1);
    auto listen_ret =
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(listen_addr), libc_return_addr, args);
    if (static_cast<long>(listen_ret) < 0) {
        LOGE("remote listen() failed: 0x%" PRIxPTR, listen_ret);
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:remote-listen");
        return 0;
    }

    local_sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (local_sock < 0) {
        PLOGE("local socket");
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:local-socket");
        return 0;
    }
    if (connect(local_sock, reinterpret_cast<sockaddr *>(&addr), addr_len) < 0) {
        PLOGE("local connect to remote listener");
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:local-connect");
        return 0;
    }

    args.clear();
    args.push_back(remote_listener);
    args.push_back(0);
    args.push_back(0);
    remote_conn =
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(accept_addr), libc_return_addr, args);
    if (remote_conn == 0 || static_cast<long>(remote_conn) < 0) {
        LOGE("remote accept() failed: 0x%" PRIxPTR, remote_conn);
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:remote-accept");
        return 0;
    }

    char dummy = 'Z';
    char control[CMSG_SPACE(sizeof(int))]{};
    iovec local_iov{.iov_base = &dummy, .iov_len = sizeof(dummy)};
    msghdr local_msg{.msg_iov = &local_iov,
                     .msg_iovlen = 1,
                     .msg_control = control,
                     .msg_controllen = sizeof(control)};
    cmsghdr *cmsg = CMSG_FIRSTHDR(&local_msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &local_fd, sizeof(local_fd));
    if (sendmsg(local_sock, &local_msg, 0) != 1) {
        PLOGE("sendmsg SCM_RIGHTS");
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:sendmsg");
        return 0;
    }

    char remote_dummy = 0;
    uintptr_t remote_dummy_addr = push_bytes(pid, regs, &remote_dummy, sizeof(remote_dummy));
    std::vector<char> remote_control(CMSG_SPACE(sizeof(int)), 0);
    uintptr_t remote_control_addr =
        push_bytes(pid, regs, remote_control.data(), remote_control.size());
    iovec remote_iov{.iov_base = reinterpret_cast<void *>(remote_dummy_addr), .iov_len = 1};
    uintptr_t remote_iov_addr = push_bytes(pid, regs, &remote_iov, sizeof(remote_iov));
    msghdr remote_msg{};
    remote_msg.msg_iov = reinterpret_cast<iovec *>(remote_iov_addr);
    remote_msg.msg_iovlen = 1;
    remote_msg.msg_control = reinterpret_cast<void *>(remote_control_addr);
    remote_msg.msg_controllen = remote_control.size();
    uintptr_t remote_msg_addr = push_bytes(pid, regs, &remote_msg, sizeof(remote_msg));
    if (!remote_dummy_addr || !remote_control_addr || !remote_iov_addr || !remote_msg_addr) {
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:push-recvmsg");
        return 0;
    }

    args.clear();
    args.push_back(remote_conn);
    args.push_back(remote_msg_addr);
    args.push_back(0);
    auto recv_ret =
        remote_call(pid, regs, reinterpret_cast<uintptr_t>(recvmsg_addr), libc_return_addr, args);
    if (recv_ret != 1) {
        LOGE("remote recvmsg() returned 0x%" PRIxPTR, recv_ret);
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:remote-recvmsg");
        return 0;
    }

    if (read_proc(pid, remote_control_addr, remote_control.data(), remote_control.size()) !=
        static_cast<ssize_t>(remote_control.size())) {
        LOGE("failed to read remote control message");
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:read-cmsg");
        return 0;
    }

    auto *remote_cmsg = reinterpret_cast<cmsghdr *>(remote_control.data());
    if (remote_cmsg->cmsg_level != SOL_SOCKET || remote_cmsg->cmsg_type != SCM_RIGHTS ||
        remote_cmsg->cmsg_len < CMSG_LEN(sizeof(int))) {
        LOGE("remote control message did not contain SCM_RIGHTS fd");
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:cmsg-parse");
        return 0;
    }
    int remote_lib_fd = -1;
    memcpy(&remote_lib_fd, CMSG_DATA(remote_cmsg), sizeof(remote_lib_fd));
    LOGI("received remote library fd %d in PID %d", remote_lib_fd, pid);

    android_dlextinfo extinfo{};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
    extinfo.library_fd = remote_lib_fd;
    uintptr_t remote_extinfo = push_bytes(pid, regs, &extinfo, sizeof(extinfo), alignof(android_dlextinfo));
    auto remote_lib_name = push_string(pid, regs, "libzygisk.so");
    if (!remote_extinfo || !remote_lib_name) {
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        remote_lib_fd);
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_conn));
        remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                        static_cast<int>(remote_listener));
        cleanup();
        write_inject_status("fail:push-dlext");
        return 0;
    }

    args.clear();
    args.push_back(remote_lib_name);
    args.push_back(RTLD_NOW);
    args.push_back(remote_extinfo);
    auto remote_handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(android_dlopen_ext_addr),
                                     libc_return_addr, args);

    remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                    remote_lib_fd);
    remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                    static_cast<int>(remote_conn));
    remote_close_fd(pid, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr,
                    static_cast<int>(remote_listener));
    cleanup();

    if (remote_handle == 0) {
        LOGE("android_dlopen_ext(USE_LIBRARY_FD) failed");
        write_inject_status("fail:fd-dlopen");
        return 0;
    }

    LOGI("successfully loaded library via transferred fd, handle: 0x%" PRIxPTR, remote_handle);
    write_inject_status("success:fd-loader");
    return remote_handle;
}

/**
 * @brief Injects a shared library into a running process at its main entry point.
 *
 * This function orchestrates the core injection logic. It attaches to the target process,
 * intercepts its execution just before the first instruction, and uses this opportunity
 * to load a shared library (`libzygisk.so`) into the process's address space.
 *
 * The strategy is as follows:
 * 1.  **Parse Kernel Argument Block**: Read the process's stack to find the location of program
 *     arguments, environment variables, and the ELF Auxiliary Vector (auxv).
 * 2.  **Find Entry Point**: From the auxv, extract the `AT_ENTRY` value, which is the memory
 *     address of the program's first executable instruction. The dynamic linker has already
 *     run at this stage, making libraries like `libdl.so` available.
 * 3.  **Hijack Execution**: Overwrite the `AT_ENTRY` value in the process's memory with a
 *     deliberately invalid address. When the process is resumed, it will immediately trigger a
 *     segmentation fault (`SIGSEGV`), which we, as the tracer, can catch. This is a reliable
 *     way to pause the process at the perfect moment.
 * 4.  **Remote Code Execution**: Once the process is paused, we restore the original entry point.
 *     We then use `ptrace` to execute functions within the target process's context.
 *     - Remotely call `dlopen()` to load our library.
 *     - Remotely call `dlsym()` to find the address of our library's `entry` function.
 *     - Remotely call our `entry` function to initialize NeoZygisk.
 * 5.  **Restore State**: After injection, restore all CPU registers, which allows the original
 *     entry point to be called when the process is fully resumed.
 *
 * @param pid The Process ID of the target (e.g., Zygote).
 * @param lib_path The absolute path to the shared library to be injected.
 * @return True on successful injection, false otherwise.
 */
bool inject_on_main(int pid, const char *lib_path) {
    LOGI("starting library injection for PID: %d, library: %s", pid, lib_path);

    // Backup of the target's registers, to be restored before detaching.
    struct user_regs_struct regs{}, backup{};
    auto map = MapInfo::Scan(std::to_string(pid));
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers for PID %d, injection aborted", pid);
        return false;
    }

    // --- Step 1 & 2: Parse Kernel Argument Block to Find Entry Point ---
    // The stack pointer (SP) at process startup points to the Kernel Argument Block.
    // We parse this structure to locate argc, argv, envp, and the auxiliary vector (auxv).
    // Ref:
    // https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/private/KernelArgumentBlock.h
    LOGV("reading kernel argument block from stack pointer: 0x%lx", (unsigned long) regs.REG_SP);
    auto sp = static_cast<uintptr_t>(regs.REG_SP);

    int argc;
    read_proc(pid, sp, &argc, sizeof(argc));

    auto argv = reinterpret_cast<char **>(sp + sizeof(uintptr_t));
    auto envp = argv + argc + 1;

    // Iterate past the environment variables to find the start of the auxiliary vector.
    // The end of envp is marked by a null pointer.
    auto p = envp;
    while (true) {
        uintptr_t val;
        read_proc(pid, (uintptr_t) p, &val, sizeof(val));
        if (val != 0) {
            p++;
        } else {
            break;
        }
    }
    p++;  // Skip the final null pointer to get to auxv.
    auto auxv = reinterpret_cast<ElfW(auxv_t) *>(p);
    LOGV("parsed process startup info: argc=%d, argv=%p, envp=%p, auxv=%p", argc, argv, envp, auxv);

    // Now, scan the auxiliary vector to find AT_ENTRY. This gives us the program's
    // entry address, which is where execution will begin.
    uintptr_t entry_addr = 0;
    uintptr_t addr_of_entry_addr = 0;
    auto v = auxv;
    while (true) {
        ElfW(auxv_t) buf;
        read_proc(pid, (uintptr_t) v, &buf, sizeof(buf));
        if (buf.a_type == AT_NULL) {
            break;  // End of auxiliary vector.
        }
        if (buf.a_type == AT_ENTRY) {
            entry_addr = (uintptr_t) buf.a_un.a_val;
            addr_of_entry_addr = (uintptr_t) v + offsetof(ElfW(auxv_t), a_un);
            break;
        }
        v++;
    }

    if (entry_addr == 0) {
        LOGE("failed to find AT_ENTRY in auxiliary vector for PID %d, cannot determine entry point",
             pid);
        return false;
    }
    LOGI("found program entry point at 0x%" PRIxPTR, entry_addr);

    // --- Step 3: Hijack Execution Flow ---
    // We replace the program's entry point with an invalid address. This causes a SIGSEGV
    // as soon as we resume the process, allowing us to regain control at the perfect time.
    LOGV("hijacking entry point to intercept execution");
    // For arm32 compatibility, we set the last bit to the same as the entry address.
    uintptr_t break_addr = (-0x05ec1cff & ~1) | (entry_addr & 1);  // An arbitrary invalid address.
    if (!write_proc(pid, addr_of_entry_addr, &break_addr, sizeof(break_addr))) {
        LOGE("failed to write hijack address to PID %d, injection aborted", pid);
        return false;
    }

    int status;

    while (true) {
        // Resume execution. We pass 0 to signal to suppress any pending SIGSTOPs.
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            PLOGE("ptrace(PTRACE_CONT) failed");
            return false;
        }

        wait_for_trace(pid, &status, __WALL);

        // 1. Handle Process Death
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            LOGE("process died unexpectedly: %s", parse_status(status).c_str());
            return false;
        }

        // 2. Handle Stops
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == SIGSEGV) {
                // SUCCESS: We hit our trap.
                break;
            } else if (sig == SIGSTOP) {
                // NOISE: Spurious stop from PTRACE_ATTACH. Ignore and continue.
                continue;
            } else {
                // ERROR: Unexpected signal (e.g., SIGILL, SIGBUS). Abort.
                LOGE("process stopped for unexpected signal: %d", sig);
                return false;
            }
        }
    }

    // Verify we are truly at the trap
    if (!get_regs(pid, regs)) {
        LOGE("failed to get registers after SIGSEGV for PID %d", pid);
        return false;
    }
    // Sanity check: ensure we stopped at our invalid address.
    if (static_cast<uintptr_t>(regs.REG_IP & ~1) != (break_addr & ~1)) {
        LOGE("process stopped at unexpected address 0x%lx, expected ~0x%" PRIxPTR, regs.REG_IP,
             break_addr);
        return false;
    }

    LOGI("successfully intercepted process %d at its entry point", pid);

    // --- Step 4: Remote Code Execution ---
    // First, restore the original entry point in memory.
    if (!write_proc(pid, addr_of_entry_addr, &entry_addr, sizeof(entry_addr))) {
        LOGE("FATAL: failed to restore original entry point, process %d will not recover", pid);
        return false;
    }

    // Backup the current registers before we start making remote calls.
    memcpy(&backup, &regs, sizeof(regs));
    map = MapInfo::Scan(std::to_string(pid));  // Re-scan maps as they may have changed.
    auto local_map = MapInfo::Scan();
    auto libc_return_addr = find_module_return_addr(map, "libc.so");

    // Remotely call dlopen(lib_path, RTLD_NOW)
    LOGV("executing remote call to dlopen(\"%s\")", lib_path);
    auto dlopen_addr = find_func_addr(local_map, map, "libdl.so", "dlopen");
    if (dlopen_addr == nullptr) {
        LOGE("could not find address of dlopen in the target process");
        return false;
    }
    std::vector<long> args;
    auto remote_lib_path = push_string(pid, regs, lib_path);
    args.push_back((long) remote_lib_path);
    args.push_back((long) RTLD_NOW);
    auto remote_handle =
        remote_call(pid, regs, (uintptr_t) dlopen_addr, (uintptr_t) libc_return_addr, args);

    if (remote_handle == 0) {
        LOGE("remote call to dlopen failed, retrieving error message with dlerror");
        auto dlerror_addr = find_func_addr(local_map, map, "libdl.so", "dlerror");
        if (dlerror_addr == nullptr) {
            LOGE("could not find address of dlerror; cannot retrieve error string");
        } else {
            args.clear();
            auto dlerror_str_addr = remote_call(pid, regs, (uintptr_t) dlerror_addr,
                                                (uintptr_t) libc_return_addr, args);
            if (dlerror_str_addr == 0) {
                LOGE("remote call to dlerror returned null");
            } else {
                auto strlen_addr = find_func_addr(local_map, map, "libc.so", "strlen");
                if (strlen_addr == nullptr) {
                    LOGE("could not find address of strlen; cannot measure error string length");
                } else {
                    args.clear();
                    args.push_back(dlerror_str_addr);
                    auto dlerror_len = remote_call(pid, regs, (uintptr_t) strlen_addr,
                                                   (uintptr_t) libc_return_addr, args);
                    if (dlerror_len <= 0) {
                        LOGE("dlerror string length is invalid (%" PRIuPTR ")", dlerror_len);
                    } else {
                        std::string err;
                        err.resize(dlerror_len + 1, 0);
                        read_proc(pid, (uintptr_t) dlerror_str_addr, err.data(), dlerror_len);
                        LOGE("dlopen error: %s", err.c_str());
                    }
                }
            }
        }

        LOGI("path dlopen failed; trying transferred-fd android_dlopen_ext fallback");
        remote_handle = dlopen_via_transferred_fd(pid, lib_path, local_map, map,
                                                  (uintptr_t) libc_return_addr, regs);
        if (remote_handle == 0) {
            LOGE("fd-loader fallback failed");
            return false;
        }
    }
    LOGI("successfully loaded library, handle: 0x%" PRIxPTR, remote_handle);

    // Remotely call dlsym(handle, "entry")
    LOGV("executing remote call to dlsym to find the 'entry' symbol");
    auto dlsym_addr = find_func_addr(local_map, map, "libdl.so", "dlsym");
    if (dlsym_addr == nullptr) {
        LOGE("could not find address of dlsym in the target process");
        return false;
    }
    args.clear();
    auto remote_entry_str = push_string(pid, regs, "entry");
    args.push_back(remote_handle);
    args.push_back((long) remote_entry_str);
    auto injector_entry =
        remote_call(pid, regs, (uintptr_t) dlsym_addr, (uintptr_t) libc_return_addr, args);

    if (injector_entry == 0) {
        LOGE("dlsym failed to find the 'entry' symbol in the injected library");
        return false;
    }
    LOGI("found injector entry point at address 0x%" PRIxPTR, injector_entry);

    // Find the address range of the injected library to pass to its entry function.
    map = MapInfo::Scan(std::to_string(pid));
    void *start_addr = nullptr;
    size_t block_size = 0;
    for (const auto &info : map) {
        if (info.path.find("libzygisk.so") != std::string::npos) {
            if (start_addr == nullptr) start_addr = (void *) info.start;
            block_size += (info.end - info.start);
        }
    }
    LOGV("found injected library mapped from %p with total size %zu", start_addr, block_size);

    // Remotely call our entry(start_addr, block_size, path) function
    LOGI("calling the injector's entry function to initialize NeoZygisk");
    args.clear();
    args.push_back((uintptr_t) start_addr);
    args.push_back(block_size);
    auto remote_tmp_path = push_string(pid, regs, zygiskd::GetTmpPath().c_str());
    args.push_back((long) remote_tmp_path);
    remote_call(pid, regs, injector_entry, (uintptr_t) libc_return_addr, args);

    // --- Step 5: Restore State ---
    // Set the instruction pointer back to the original entry address and restore all registers.
    backup.REG_IP = (long) entry_addr;
    LOGI("injection complete, restoring registers before resuming normal execution");
    if (!set_regs(pid, backup)) {
        LOGE("failed to restore original registers for PID %d", pid);
        return false;
    }

    return true;
}

// Macro helper to check for specific ptrace stop events.
#define STOPPED_WITH(sig, event)                                                                   \
    (WIFSTOPPED(status) && WSTOPSIG(status) == (sig) && (status >> 16) == (event))

// Common wait routine to avoid repetition.
// Returns false if wait failed or process died unexpectedly.
static bool wait_for_process(int pid, int *status) {
    if (waitpid(pid, status, __WALL) < 0) {
        PLOGE("waitpid on PID %d", pid);
        return false;
    }
    return true;
}

/**
 * @brief Injects the Zygisk library into the main thread.
 *
 * Shared logic between Seize and Attach methods.
 */
static bool perform_injection(int pid) {
    std::string lib_path = zygiskd::GetTmpPath();
    lib_path += "/lib" LP_SELECT("", "64") "/libzygisk.so";

    if (!inject_on_main(pid, lib_path.c_str())) {
        LOGE("failed to inject library into zygote (PID: %d)", pid);
        return false;
    }
    return true;
}

static bool detach_with_gki_workaround(int pid, int detach_signal);

static bool is_neozygisk_mapped(int pid) {
    auto maps = MapInfo::Scan(std::to_string(pid));
    for (const auto &info : maps) {
        if (info.path.find("libzygisk.so") != std::string::npos) {
            return true;
        }
    }
    return false;
}

static bool detach_and_resume_best_effort(int pid) {
    if (ptrace(PTRACE_DETACH, pid, 0, SIGCONT) == 0) {
        return true;
    }
    LOGW("ptrace(PTRACE_DETACH, SIGCONT) on PID %d failed with %d: %s", pid, errno,
         strerror(errno));
    return detach_with_gki_workaround(pid, SIGCONT);
}

/**
 * @brief Executes the GKI 2.0 Workaround and detaches.
 *
 * Advances the process by one syscall to clear internal kernel ptrace state
 * before finally detaching.
 */
static bool detach_with_gki_workaround(int pid, int detach_signal) {
    int status;
    LOGV("applying GKI 2.0 workaround (step syscall) before detach");

    // 1. Advance to next syscall entry/exit to clear signal-stop state
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_SYSCALL) on PID %d", pid);
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);  // Try to detach anyway
        return false;
    }

    // 2. Wait for the syscall stop
    if (!wait_for_process(pid, &status)) {
        // If wait fails, force detach
        ptrace(PTRACE_DETACH, pid, 0, detach_signal);
        return false;
    }

    // 3. Clean detach
    if (ptrace(PTRACE_DETACH, pid, 0, detach_signal) == -1) {
        PLOGE("ptrace(PTRACE_DETACH) on PID %d", pid);
        return false;
    }
    return true;
}

// --- Strategy 1: PTRACE_SEIZE (Preferred) ---

static bool trace_with_seize(int pid) {
    LOGI("attempting trace_seize on PID %d", pid);
    bool injected = false;

    // PTRACE_O_EXITKILL ensures Zygote dies if we crash, preventing a zombie state.
    if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_EXITKILL) == -1) {
        // We do not return false here immediately; we let the caller handle errno.
        return false;
    }

    int status;
// Helper macro for local flow control
#define BAIL_AND_DETACH                                                                            \
    ptrace(PTRACE_DETACH, pid, 0, 0);                                                              \
    return false;

    // Force an initial ptrace stop. Existing zygotes discovered via /proc are
    // already SIGSTOPed by the monitor hand-off, and some kernels do not emit a
    // usable initial stop for bare PTRACE_SEIZE on that state.
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_INTERRUPT) on PID %d", pid);
        BAIL_AND_DETACH
    }

    // Wait for the initial Seize stop
    if (!wait_for_process(pid, &status)) return false;

    // Depending on kernel behavior, SEIZE+INTERRUPT can surface as SIGTRAP or
    // SIGSTOP with PTRACE_EVENT_STOP.
    if (STOPPED_WITH(SIGSTOP, PTRACE_EVENT_STOP) || STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
        // 1. Inject Payload
        if (!perform_injection(pid)) {
            BAIL_AND_DETACH
        }
        injected = true;

        LOGV("injection complete, starting signal continuation sequence");

        // 2. Send SIGCONT to the process
        if (kill(pid, SIGCONT) == -1) {
            PLOGE("kill(SIGCONT) on PID %d", pid);
            BAIL_AND_DETACH
        }

        // 3. Resume (PTRACE_CONT)
        if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
            PLOGE("ptrace(PTRACE_CONT) failed");
            BAIL_AND_DETACH
        }
        if (!wait_for_process(pid, &status)) return false;

        // 4. Expect SIGTRAP (caused by the signal interruption in Seize mode)
        if (STOPPED_WITH(SIGTRAP, PTRACE_EVENT_STOP)) {
            if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
                BAIL_AND_DETACH
            }
            if (!wait_for_process(pid, &status)) return false;

            // 5. Expect the actual SIGCONT delivery
            if (STOPPED_WITH(SIGCONT, 0)) {
                LOGV("received expected SIGCONT");
                // 6. Workaround + Detach
                return detach_with_gki_workaround(pid, SIGCONT);
            } else {
                LOGW("unexpected state after SIGTRAP: %s", parse_status(status).c_str());
                return detach_and_resume_best_effort(pid);
            }
        } else {
            LOGW("expected SIGTRAP after CONT, got: %s", parse_status(status).c_str());
            return detach_and_resume_best_effort(pid);
        }
    } else {
        LOGE("seize attached, but unexpected initial state: %s", parse_status(status).c_str());
        if (injected) {
            return detach_and_resume_best_effort(pid);
        }
        BAIL_AND_DETACH
    }

#undef BAIL_AND_DETACH
    return true;
}

// --- Strategy 2: PTRACE_ATTACH (Fallback) ---

static bool trace_with_attach(int pid) {
    LOGI("falling back to trace_attach on PID %d", pid);

    // Classic attach. This sends SIGSTOP to the process immediately.
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        PLOGE("ptrace(PTRACE_ATTACH) on PID %d", pid);
        return false;
    }

    int status;
    if (!wait_for_process(pid, &status)) {
        // If wait fails, we must try to detach or the process hangs forever
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }

    // Classic ATTACH results in a STOPPED status with SIGSTOP.
    // It does NOT use PTRACE_EVENT_STOP in the status bits usually.
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        // Optional: Set EXITKILL for parity with SEIZE, though not strictly required for fallback.
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);

        // 1. Inject Payload
        if (!perform_injection(pid)) {
            ptrace(PTRACE_DETACH, pid, 0, 0);
            return false;
        }

        // 2. Detach
        // For classic attach, we don't need the SIGTRAP/SIGCONT dance because
        // we haven't manually sent a SIGCONT via kill().
        // The process is simply stopped by the attach.
        // We use the GKI workaround to ensure the detach is clean.
        // We pass SIGCONT to detach to ensure the process resumes.
        if (detach_with_gki_workaround(pid, SIGCONT)) {
            return true;
        }
        return detach_and_resume_best_effort(pid);

    } else {
        LOGE("attach succeeded but process state unexpected: %s", parse_status(status).c_str());
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return false;
    }
}

/**
 * @brief Attaches to the Zygote process and initiates the injection.
 *
 * Tries modern PTRACE_SEIZE first. If that fails with I/O error (EIO),
 * falls back to classic PTRACE_ATTACH.
 *
 * @param pid The Zygote process ID.
 * @return True on success, false on failure.
 */
bool trace_zygote(int pid) {
    LOGI("attaching to zygote (PID: %d) to begin injection", pid);

    // 1. Try SEIZE (Modern, robust handling of group stops)
    if (trace_with_seize(pid)) {
        LOGI("successfully detached from zygote (via SEIZE), NeoZygisk active");
        return true;
    }

    // 2. Check for fallback condition
    // PTRACE_SEIZE returns EIO if the process state prohibits seizing,
    // or sometimes if security modules interfere.
    if (errno == EIO) {
        LOGW("PTRACE_SEIZE failed with EIO, attempting fallback to PTRACE_ATTACH");

        if (trace_with_attach(pid)) {
            LOGI("successfully detached from zygote (via ATTACH), NeoZygisk active");
            return true;
        }
    } else {
        // If it wasn't EIO (e.g., EPERM, ESRCH), Attach will likely fail too,
        // or the error is fatal.
        PLOGE("PTRACE_SEIZE failed (errno: %d)", errno);
    }

    if (is_neozygisk_mapped(pid)) {
        LOGW("NeoZygisk is already mapped into PID %d despite tracer failure; treating as success",
             pid);
        return true;
    }

    return false;
}
