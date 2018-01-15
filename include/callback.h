/**
 * @file callback.h
 * Callbacks for each library call that is intercepted by ntrace
 */

#ifndef NTRACE_CALLBACK__H__
#define NTRACE_CALLBACK__H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <ntrace.h>

/*
 * In all cases (except where noted below) the original routine is allowed
 * to execute, the result is recorded and then sent to one of these callbacks
 */
void cb_pipe        (proc_t *, int, int fds[2]);
void cb_read        (proc_t *, ssize_t, int, void *, size_t);
void cb_write       (proc_t *, ssize_t, int, const void *, size_t);
void cb_recv        (proc_t *, ssize_t, int, void *, size_t, int);
void cb_send        (proc_t *, ssize_t, int, const void *, size_t, int);
void cb_sendto      (proc_t *, ssize_t, int, const void *, size_t, int,
                        const struct sockaddr *, socklen_t);
void cb_recvfrom    (proc_t *, ssize_t, int, void *, size_t, int,
                        struct sockaddr *, socklen_t *);
void cb_connect     (proc_t *, int, int,
                        const struct sockaddr *, socklen_t);
void cb_bind        (proc_t *, int, int,
                        const struct sockaddr *, socklen_t);
void cb_accept      (proc_t *, int, int,
                        struct sockaddr *, socklen_t *);
void cb_socket      (proc_t *, int, int, int, int);
void cb_sendmsg     (proc_t *, ssize_t,int, const struct msghdr *, int);
void cb_recvmsg     (proc_t *, ssize_t, int, struct msghdr *, int);
void cb_dup         (proc_t *, int, int);
void cb_dup2        (proc_t *, int, int, int);
void cb_socketpair  (proc_t *, int, int, int, int, int vec[2]);
void cb___read_chk  (proc_t *, ssize_t, int, void *, size_t, size_t);
void cb_sendfile64  (proc_t *, ssize_t, int, int, off_t, size_t);
void cb_sendfile    (proc_t *, ssize_t, int, int, off_t, size_t);
void cb_writev      (proc_t *, ssize_t, int, const struct iovec *, int);

void cb_shutdown    (proc_t *, int, int, int);

/*
 * ntrace does internal bookkeeping for some of the flows (most notably
 * the log files being maintained) so this function returns a modified 
 * result to the caller
 */
int cb_close        (proc_t *, int, int);


/*
 * _exit carries the __noreturn__ attribute which means there is no return
 * value to be processed here
 */
void cb__exit       (proc_t *, int);

#endif /*NTRACE_CALLBACK__H__*/
