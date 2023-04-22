#include <stdio.h>
#include <spawn.h>
#include <sys/wait.h>
#include <mach/mach.h>
#include <mach/port.h>

extern char **environ;

#ifdef ROOTLESS
#define PREFIX "/var/jb"
#else
#define PREFIX ""
#endif

int main(){
	mach_port_t taskPort = MACH_PORT_NULL;
	kern_return_t ret = task_for_pid(mach_task_self(), 1, &taskPort);

	if (ret != KERN_SUCCESS || !MACH_PORT_VALID(taskPort)) {
			printf("No tfp1, not running as root? Exiting.\n");
			return -1;
	}

	mach_port_deallocate(mach_task_self(), taskPort);

	printf("Starting libhooker\n");
	int status = 0;
	pid_t pid;
	char *argv[] = {"inject_criticald", "1", PREFIX "/usr/libexec/libhooker/pspawn_payload.dylib", NULL};
	posix_spawn(&pid, PREFIX "/usr/libexec/libhooker/inject_criticald", NULL, NULL, argv, environ);
	waitpid(pid, &status, 0);
	return status;
}
