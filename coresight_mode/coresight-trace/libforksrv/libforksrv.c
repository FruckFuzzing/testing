#define _GNU_SOURCE /* for RTLD_NEXT */
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include <signal.h>
#include <asm/unistd.h>
#include <sys/prctl.h>

#define FORKSRV_FD 198
#define AFLCS_FORKSRV_FD (FORKSRV_FD - 3)

static void __cs_start_forkserver(void) {
    int status;
    pid_t child_pid;
 
    static char tmp[4] = {0, 0, 0, 0};
    prctl(PR_SET_PDEATHSIG, SIGTERM);
     
    if (write(AFLCS_FORKSRV_FD + 1, tmp, 4) != 4) { 
        _exit(-1);
    }
     
    while (1) {
        /* Whoops, parent dead? */
        if (read(AFLCS_FORKSRV_FD, tmp, 4) != 4) {
            _exit(1);
        }
        child_pid = fork();
        if (child_pid < 0) {
            _exit(4);
        }
        if (!child_pid) {
            prctl(PR_SET_PDEATHSIG, SIGCONT);
            /* Child process. Wait for parent start tracing */
            raise(SIGSTOP);
            /* Close descriptors and run free. */
            close(AFLCS_FORKSRV_FD);
            close(AFLCS_FORKSRV_FD + 1);
        
            return;
        }
        /* Parent. */
        if (write(AFLCS_FORKSRV_FD + 1, &child_pid, 4) != 4) {
            _exit(5);
        }
    
        /* Wait until SIGCONT is signaled. */
        if (waitpid(child_pid, &status, WCONTINUED) < 0) {
            _exit(6);
        }
        if (!WIFCONTINUED(status)) {
            /* Relay status to proxy. */
            if (write(AFLCS_FORKSRV_FD + 1, &status, 4) != 4) {
                _exit(7);
            }
            continue;
        }
        while (1) {
            /* Get status. */
            if (waitpid(child_pid, &status, WUNTRACED) < 0) {
                _exit(8);
            }
            /* Relay status to proxy. */
            if (write(AFLCS_FORKSRV_FD + 1, &status, 4) != 4) {
                _exit(9);
            }
            if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)) {
                /* The child process is exited. */
                break;
            }
        }
    }
}

int __libc_start_main(int (*main)(int, char **, char **), int argc, char **argv,
                      void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void *stack_end) {

    int (*orig)(int (*main)(int, char **, char **), int argc, char **argv,
                void (*init)(void), void (*fini)(void), void (*rtld_fini)(void),
                void *stack_end);

    (void)argc;
    (void)argv;
    orig = dlsym(RTLD_NEXT, __func__);
    if (!orig) {
        fprintf(stderr, "Did not find original %s: %s\n", __func__, dlerror());
        exit(EXIT_FAILURE);
    }
    printf("Hook main ok\n");
  
    if(getenv("CS_FORKSERVER") != NULL){
        /* AFL-CS-START */  
        do { __cs_start_forkserver(); } while(0);
    }else{
        /* CS-TRACE */  
        raise(SIGSTOP);
    }

  return orig(main, argc, argv, init, fini, rtld_fini, stack_end);
}
