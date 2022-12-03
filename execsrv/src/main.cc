#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <libgen.h>
#include <cstring>
#include <sys/mman.h>
#include <semaphore.h>
#include <signal.h>
#include <wait.h>

static FILE *LOG_FILE = nullptr;

static void log(const char *fmt, ...) {
    if (!LOG_FILE) {
        LOG_FILE = stderr;
    }

    va_list list;
    va_start(list, fmt);
    vfprintf(LOG_FILE, fmt, list);
    va_end(list);
}

static void initlog(const char *path) {
    LOG_FILE = fopen(path, "a");

    if (!LOG_FILE) {
        log("Failed to open log file, outputting to stderr instead\n");
    }
}

static void afl_persistent(const char *path, int argc, char *argv[]);

int main(int argc, char *argv[]) {
    int opt;
    char *path = nullptr;
    char *log_path = nullptr;

    while ((opt = getopt(argc, argv, "p:l:")) != -1) {
        switch (opt) {
            case 'p': path = optarg; break;
            case 'l': path = optarg; break;
        }
    }

    int new_argc = argc - optind + 1;
    char **new_argv = (char **) calloc(new_argc + 1, sizeof(char *));
    new_argv[0] = basename(path);
    memcpy(&new_argv[1], &argv[optind], (argc - optind) * sizeof(char *));

    afl_persistent(path, new_argc, new_argv);

    free(new_argv);
}

// =============================== AFL =================================
constexpr int AFL_FORKSRV_FD = 198;
constexpr int RESTORE_EVENT_FD = 400;
constexpr int STATUS_FD = 399;

struct Status {
    sem_t sem;
    int value;
};

static int RESTORE_FD = -1;

static void handler(int signal) {
    if (signal == SIGUSR1) {
        log("Restore requested\n");

        std::uint64_t v = 1;
        if (write(RESTORE_FD, &v, sizeof(v)) != sizeof(v)) {
            log("Failed to sent restore request to QEMU: %s\n", strerror(errno));
            exit(-1);
        }

        log("Restore request sent to QEMU\n");
    }
}

static void afl_persistent(const char *path, int argc, char *argv[]) {
    signal(SIGUSR1, &handler);

    std::uint32_t options = 0;
    if (write(AFL_FORKSRV_FD + 1, &options, sizeof(options)) != sizeof(options)) {
        log("AFL does not want to talk, exiting\n");
        return;
    }

    std::uint32_t was_killed = 0;
    pid_t child_pid = 0;
    bool child_stopped = false;
    int status;

    int status_fd = memfd_create("QEMU_OS_State", 0);
    if (status_fd == -1) {
        log("Cannot create shared mem for receiving os state: %s\n", std::strerror(errno));
        return;
    }

    if (ftruncate(status_fd, sizeof(Status)) == 01) {
        log("Error setting shared mem size: %s\n", std::strerror(errno));
        return;
    }

    Status *st = reinterpret_cast<Status *>(mmap(nullptr, sizeof(Status), PROT_READ | PROT_WRITE, MAP_SHARED, status_fd, 0));
    if (!st) {
        log("Failed to mount shared mem: %s\n", std::strerror(errno));
        return;
    }

    st->value = 0;
    if (sem_init(&st->sem, 1, 0) == -1) {
        log("Failed to initialize semaphore: %s\n", std::strerror(errno));
        return;
    }

    RESTORE_FD = eventfd(0, 0);
    if (RESTORE_FD == -1) {
        log("Failed to create restore eventfd: %s\n", strerror(errno));
        return;
    }

    pid_t my_pid = getpid();

    int afl_kill_sig = -1;
    const char *afl_kill_signal = getenv("AFL_KILL_SIGNAL");
    if (afl_kill_signal) {
        afl_kill_sig = atoi(afl_kill_signal);
    }

    while (true) {
        if (read(AFL_FORKSRV_FD, &was_killed, sizeof(was_killed)) != sizeof(was_killed))
            exit(4);

        if (!child_stopped) {
            child_pid = fork();
            if (child_pid < 0) {
                log("Failed to fork: %s\n", std::strerror(errno));
                exit(4);
            }

            if (!child_pid) {
                dup2(status_fd, STATUS_FD);
                close(AFL_FORKSRV_FD);
                close(AFL_FORKSRV_FD + 1);

                if (execve(path, argv, environ) == -1) {
                    log("execve failed: %s\n", std::strerror(errno));
                    exit(4);
                }
            } else {
                log("Spawned child pid = %d\n", child_pid);
            }
        } else {
            kill(child_pid, SIGCONT);
            child_stopped = false;
            log("Sending SIGCONT to %d\n", child_pid);
            if (sem_post(&st->sem) == -1) {
                log("Failed to lift semaphore: %s\n", std::strerror(errno));
                exit(5);
            }
        }

        pid_t pid;
        if (afl_kill_sig == SIGUSR1) {
            pid = my_pid;
        } else {
            pid = child_pid;
        }

        if (write(AFL_FORKSRV_FD + 1, &pid, sizeof(pid)) != sizeof(pid))
            exit(5);

        if (waitpid(child_pid, &status, WUNTRACED) == -1)
            exit(5);

        log("QEMU state = %X\n", status);

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            child_stopped = true;
        } else if (WIFSIGNALED(status)) {
            child_stopped = false;
            was_killed = true;
            log("QEMU was killed by signal = %d\n", WTERMSIG(status));
        }

        if (!was_killed) {
            log("QEMU OS state = %d\n", st->value);

            if (write(AFL_FORKSRV_FD + 1, &st->value, sizeof(st->value)) != sizeof(st->value))
                exit(7);
        } else {
            if (write(AFL_FORKSRV_FD + 1, &status, sizeof(status)) != sizeof(status))
                exit(7);
        }

    }
}
