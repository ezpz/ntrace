/**
 * @file ntrace.c
 * Wrapper function definitions 
 */

#include <dlfcn.h>

#include <ntrace.h>
#include <util.h>
#include <callback.h>

int fork () {
    typedef int (*libcall)();
    /*
     * There is no callback here as this is a safety procedure.
     * If the very first thing to get called (in this list) is a fork
     * call and we do not catch it, then we have two processes 
     * that will act as the parent. To avoid that, we attach to 
     * the parent process before the fork.
     */
    proc_t * p = attach_to_process ();
    TRACE (p, "fork () = ...\n");
    libcall fun = dlsym (RTLD_NEXT, "fork");
    return fun ();
}

int clone (int (*fn)(void *), void * stk, int flag, void * arg) {
    typedef int (*libcall)(int (*)(void *), void *, int, void *);
    /*
     * Much like fork, there is no callback provided here.
     * We are only interested in setting up valid state
     * before the process is able to duplicate itself
     * leaving stagnate copies of the state everywhere.
     */
    proc_t * p = attach_to_process ();
    TRACE (p, "clone (%p, %p, %x, %p) = ...\n", fn, stk, flag, arg);
    libcall fun = dlsym (RTLD_NEXT, "clone");
    return fun (fn, stk, flag, arg);
}

void _exit (int status) {
    typedef void (*libcall)(int);
    proc_t * p = attach_to_process ();
    cb__exit (p, status);
    libcall fun = dlsym (RTLD_NEXT, "_exit");
    fun (status);
}

ssize_t sendfile64 (int s, int fd, off_t offset, size_t size) {
    typedef ssize_t (*libcall)(int,int,off_t,size_t);
    ssize_t res = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "sendfile64");
    res = fun (s,fd,offset,size);
    cb_sendfile64 (p, res, s, fd, offset, size);
    return res;
}

ssize_t sendfile (int s, int fd, off_t offset, size_t size) {
    typedef ssize_t (*libcall)(int,int,off_t,size_t);
    ssize_t res = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "sendfile");
    res = fun (s,fd,offset,size);
    cb_sendfile (p, res, s, fd, offset, size);
    return res;
}

int pipe (int fds[2]) {
    typedef int (*libcall)(int f[2]);
    int res = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "pipe");
    res = fun (fds);
    cb_pipe (p, res,fds);
    return res;
}

int accept (int fd, struct sockaddr * addr, socklen_t * len) {
    typedef int (*libcall)(int,struct sockaddr *, socklen_t *);
    int new_fd = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "accept");
    new_fd =  fun (fd, addr, len);
    cb_accept (p, new_fd, fd, addr, len);
    return new_fd;
}

int dup (int fd) {
    typedef int (*libcall)(int);
    int new_fd = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "dup");
    new_fd = fun (fd);
    cb_dup (p, new_fd, fd);
    return new_fd;
}

int dup2 (int fd, int newfd) {
    typedef int (*libcall)(int,int);
    int res = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "dup2");
    res = fun (fd, newfd);
    cb_dup2 (p, res, fd, newfd);
    return res;
}

int socketpair (int domain, int type, int protocol, int vec[2]) {
    typedef int (*libcall)(int,int,int,int v[2]);
    int res = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "socketpair");
    res = fun (domain,type,protocol,vec);
    cb_socketpair (p, res,domain,type,protocol,vec);
    return res;
}

int socket (int domain, int type, int protocol) {
    typedef int (*libcall)(int,int,int);
    int new_fd = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "socket");
    new_fd = fun (domain, type, protocol);
    cb_socket (p, new_fd, domain, type, protocol);
    return new_fd;
}

int close (int fd) {
    typedef int (*libcall)(int);
    int ret = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "close");
    ret = fun (fd);
    /*
     * see cb_close for details on this reassignment 
     */
    ret = cb_close (p, ret, fd);
    return ret;
}

int connect (int fd, const struct sockaddr * addr, socklen_t len) {
    typedef int (*libcall)(int,const struct sockaddr *,socklen_t);
    int ret = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "connect");
    ret = fun (fd, addr, len);
    cb_connect (p, ret, fd, addr, len);
    return ret;
}

int bind (int fd, const struct sockaddr * addr, socklen_t len) {
    typedef int (*libcall)(int,const struct sockaddr *, socklen_t);
    int ret = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "bind");
    ret = fun (fd, addr, len);
    cb_bind (p, ret, fd, addr, len);
    return ret;
}

ssize_t sendto (int fd, const void * buf, size_t size, int flags, const struct sockaddr * addr, socklen_t len) {
    typedef ssize_t (*libcall)(int,const void *,size_t,int,const struct sockaddr *,socklen_t);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "sendto");
    amnt = fun (fd, buf, size, flags, addr, len);
    cb_sendto (p, amnt,fd,buf,size,flags,addr,len);
    return amnt;
}

ssize_t send (int fd, const void * buf, size_t size, int flags) {
    typedef ssize_t (*libcall)(int,const void *,size_t,int);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "send");
    amnt = fun (fd, buf, size, flags);
    cb_send (p, amnt, fd, buf, size, flags);
    return amnt;
}

ssize_t writev (int fd, const struct iovec * io, int iocnt) {
    typedef ssize_t (*libcall)(int,const struct iovec *,int);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "writev");
    amnt = fun (fd, io, iocnt);
    cb_writev (p, amnt, fd, io, iocnt);
    return amnt;
}

ssize_t write (int fd, const void * buf, size_t size) {
    typedef ssize_t (*libcall)(int,const void *,size_t);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "write");
    amnt = fun (fd, buf, size);
    cb_write (p, amnt,fd,buf,size);
    return amnt;
}

ssize_t sendmsg (int fd, const struct msghdr * msg, int flags) {
    typedef ssize_t (*libcall)(int,const struct msghdr *,int);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "sendmsg");
    amnt = fun (fd, msg, flags);
    cb_sendmsg (p, amnt,fd,msg,flags);
    return amnt;
}

ssize_t recvfrom (int fd, void * buf, size_t size, int flags, struct sockaddr * addr, socklen_t * len) {
    typedef ssize_t (*libcall)(int,void *,size_t,int,struct sockaddr *,socklen_t *);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "recvfrom");
    amnt = fun (fd, buf, size, flags, addr, len);
    cb_recvfrom (p, amnt,fd,buf,size,flags,addr,len);
    return amnt;
}

ssize_t recv (int fd, void * buf, size_t size, int flags) {
    typedef ssize_t (*libcall)(int,void *,size_t,int);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "recv");
    amnt = fun (fd, buf, size, flags);
    cb_recv (p, amnt, fd, buf, size, flags);
    return amnt;
}

#if __USE_HOOK_READ_CHK
ssize_t __read_chk (int fd, void * buf, size_t nbytes, size_t size) {
    typedef ssize_t (*libcall)(int,void *,size_t,size_t);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "__read_chk");
    amnt = fun (fd, buf, nbytes, size);
    cb___read_chk (p, amnt,fd,buf,nbytes,size);
    return amnt;
}
#endif /* __USE_HOOK_READ_CHK */

ssize_t read (int fd, void * buf, size_t size) {
    typedef ssize_t (*libcall)(int,void *,size_t);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "read");
    amnt = fun (fd, buf, size);
    cb_read (p, amnt, fd, buf, size);
    return amnt;
}

ssize_t recvmsg (int fd, struct msghdr * msg, int flags) {
    typedef ssize_t (*libcall)(int,struct msghdr *,int);
    ssize_t amnt = 0;
    proc_t * p = attach_to_process ();
    libcall fun = dlsym (RTLD_NEXT, "recvmsg");
    amnt = fun (fd, msg, flags);
    cb_recvmsg (p, amnt, fd, msg, flags);
    return amnt;
}

