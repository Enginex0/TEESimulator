// Fork-based supervisor for instant daemon restart
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static volatile sig_atomic_t should_exit = 0;

static void signal_handler(int sig) {
    should_exit = 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <daemon> [args...]\n", argv[0]);
        return 1;
    }

    // Forward termination signals to exit cleanly
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    const char *daemon_path = argv[1];
    char **daemon_argv = &argv[1];

    while (!should_exit) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork failed");
            usleep(100000); // 100ms backoff on fork failure
            continue;
        }

        if (pid == 0) {
            // Child: become the daemon
            prctl(PR_SET_PDEATHSIG, SIGKILL); // Die if parent dies
            execv(daemon_path, daemon_argv);
            perror("execv failed");
            _exit(127);
        }

        // Parent: wait for child to exit
        int status;
        waitpid(pid, &status, 0);

        if (should_exit) break;

        // Instant restart - no delay
    }

    return 0;
}
