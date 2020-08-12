// golden
// 6/12/2018
//

#ifndef _PTRACE_H
#define _PTRACE_H

#include <ps4.h>
#include "sparse.h"
#include "kdbg.h"

// taken from ptrace.h

#define	PT_TRACE_ME	0	/* child declares it's being traced */
#define	PT_READ_I	1	/* read word in child's I space */
#define	PT_READ_D	2	/* read word in child's D space */
/* was	PT_READ_U	3	 * read word in child's user structure */
#define	PT_WRITE_I	4	/* write word in child's I space */
#define	PT_WRITE_D	5	/* write word in child's D space */
/* was	PT_WRITE_U	6	 * write word in child's user structure */
#define	PT_CONTINUE	7	/* continue the child */
#define	PT_KILL		8	/* kill the child process */
#define	PT_STEP		9	/* single step the child */
#define	PT_ATTACH	10	/* trace some running process */
#define	PT_DETACH	11	/* stop tracing a process */
#define PT_IO		12	/* do I/O to/from stopped process. */
#define	PT_LWPINFO	13	/* Info about the LWP that stopped. */
#define PT_GETNUMLWPS	14	/* get total number of threads */
#define PT_GETLWPLIST	15	/* get thread list */
#define PT_CLEARSTEP	16	/* turn off single step */
#define PT_SETSTEP	17	/* turn on single step */
#define PT_SUSPEND	18	/* suspend a thread */
#define PT_RESUME	19	/* resume a thread */
#define	PT_TO_SCE	20
#define	PT_TO_SCX	21
#define	PT_SYSCALL	22
#define	PT_FOLLOW_FORK	23
#define PT_GETREGS      33	/* get general-purpose registers */
#define PT_SETREGS      34	/* set general-purpose registers */
#define PT_GETFPREGS    35	/* get floating-point registers */
#define PT_SETFPREGS    36	/* set floating-point registers */
#define PT_GETDBREGS    37	/* get debugging registers */
#define PT_SETDBREGS    38	/* set debugging registers */
#define	PT_VM_TIMESTAMP	40	/* Get VM version (timestamp) */
#define	PT_VM_ENTRY     41 	/* Get VM map (entry) */

#define __LOW(v)	((v) & 0377)
#define __HIGH(v)	(((v) >> 8) & 0377)

#define WNOHANG         1	/* do not wait for child to exit */
#define WUNTRACED       2	/* for job control; not implemented */

#define WIFEXITED(s)	(__LOW(s) == 0)		    /* normal exit */
#define WEXITSTATUS(s)	(__HIGH(s))			    /* exit status */
#define WTERMSIG(s)	(__LOW(s) & 0177)		    /* sig value */
#define WIFSIGNALED(s)	((((unsigned int)(s)-1) & 0xFFFF) < 0xFF) /* signaled */
#define WIFSTOPPED(s) (__LOW(s) == 0177)		    /* stopped */
#define WSTOPSIG(s)	(__HIGH(s) & 0377)		    /* stop signal */

// some signals
#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt */
#define	SIGQUIT	3	/* quit */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGABRT	6	/* abort() */
#define	SIGIOT	SIGABRT	/* compatibility */
#define	SIGEMT	7	/* EMT instruction */
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGSEGV	11	/* segmentation violation */
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#define	SIGURG	16	/* urgent condition on IO channel */
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	SIGIO	23	/* input/output possible signal */
#define	SIGXCPU	24	/* exceeded CPU time limit */
#define	SIGXFSZ	25	/* exceeded file size limit */
#define	SIGVTALRM 26	/* virtual time alarm */
#define	SIGPROF	27	/* profiling time alarm */
#define SIGWINCH 28	/* window size changes */
#define SIGINFO	29	/* information request */
#define SIGUSR1 30	/* user defined signal 1 */
#define SIGUSR2 31	/* user defined signal 2 */

TYPE_BEGIN(struct ptrace_lwpinfo, 0x98);
TYPE_FIELD(uint32_t pl_lwpid, 0);
TYPE_FIELD(char pl_tdname[24], 0x80);
TYPE_END();

int ptrace(int req, int pid, void *addr, int data);
int wait4(int wpid, int *status, int options, void *rusage);

#endif
