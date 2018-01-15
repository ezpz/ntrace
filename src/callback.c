/**
 * @file callback.c
 * Callbacks implemented for any intercepted library calls
 */


#include <callback.h>
#include <util.h>

extern int fileno (FILE *);

/**
 * Log the activity for this action
 * @note If amnt is < 0 it is assumed that the call failed and no logging
 * takes place here
 * @note Only network related calls are processed here
 * @param p The process this action is related to 
 * @param fd The file descriptor that received the action
 * @param amnt The result of the call itself
 * @param call The actual call this represents
 */
static void log_call (proc_t * p, int fd, ssize_t amnt, call_t call) {

    struct timeval tv;

    if (amnt < 0 || p->flows[fd].type != FD_NET)
        return;

    gettimeofday (&tv, NULL);

    CALL_LOG (p, CALL_LOG_FMT, 
            call2str (call), fd, p->pid, tv.tv_sec, tv.tv_usec, amnt);
}


void cb_pipe (proc_t * p, int res, int fds[2]) {
    /*
     * pipes are tricky since they can be used for either net or disk 
     * traffic. For now, the fds are tagged with PIPE and it is assumed
     * that if an exclusively network oriented connection was needed
     * socketpair would be used.
     */
    TRACE (p, "pipe ([%d, %d]) = %d\n", fds[0], fds[1], res);

    if (res < 0)
        return;

    associate_fd (p, fds[0], FD_PIPE);
    associate_fd (p, fds[1], FD_PIPE);
}


void cb_read (proc_t * p, ssize_t amnt, int fd, void * buf, size_t sz) {

    TRACE (p, "[%4s] read (%d, %p, %zu) = %zd\n", flow2str (&p->flows[fd]),
            fd, buf, sz, amnt);

    log_call (p, fd, amnt, SC_READ);
}


void cb_write (proc_t * p, ssize_t amnt, int fd, const void * buf, size_t sz) {
    
    TRACE (p, "[%4s] write (%d, %p, %zu) = %zd\n", flow2str (&p->flows[fd]),
            fd, buf, sz, amnt);

    log_call (p, fd, amnt, SC_WRITE);
}


void cb_recv (proc_t * p, ssize_t amnt, int fd, void * buf, 
        size_t sz, int flags) {

    TRACE (p, "[%4s] recv (%d, %p, %zu, 0x%x) = %zd\n", 
            flow2str (&p->flows[fd]),
            fd, buf, sz, flags, amnt);

    log_call (p, fd, amnt, SC_RECV);
}


void cb_send (proc_t * p, ssize_t amnt, int fd, const void * buf, 
        size_t sz, int flags) {

    TRACE (p, "[%4s] send (%d, %p, %zu, 0x%x) = %zd\n", 
            flow2str (&p->flows[fd]),
            fd, buf, sz, flags, amnt);

    log_call (p, fd, amnt, SC_SEND);
}


void cb_sendto (proc_t * p, ssize_t amnt, int fd, const void * buf, size_t sz, 
        int flags, const struct sockaddr * addr, socklen_t len) {

    if (addr) {
        TRACE (p, "[%4s] sendto (%d, %p, %zu, 0x%x, [%s, ...], %d) = %zd\n",
            flow2str (&p->flows[fd]), fd, buf, sz, flags, 
            family2str (addr->sa_family), len, amnt);
    } else {
        TRACE (p, "[%4s] sendto (%d, %p, %zu, 0x%x, (nil), %d) = %zd\n",
            flow2str (&p->flows[fd]), fd, buf, sz, flags, len, amnt);
    }

    log_call (p, fd, amnt, SC_SENDTO);
}


void cb_recvfrom (proc_t * p, ssize_t amnt, int fd, void * buf, size_t sz, 
        int flags, struct sockaddr * addr, socklen_t * len) {

    if (addr) {
        TRACE (p, "[%4s] recvfrom (%d, %p, %zu, 0x%x, [%s, ...], %d) = %zd\n", 
            flow2str (&p->flows[fd]), fd, buf, sz, flags, 
            family2str (addr->sa_family), len ? *len : 0, amnt);
    } else {
        TRACE (p, "[%4s] recvfrom (%d, %p, %zu, 0x%x, (nil), %d) = %zd\n", 
            flow2str (&p->flows[fd]), fd, buf, sz, flags, 
            len ? *len : 0, amnt);
    }

    log_call (p, fd, amnt, SC_RECVFROM);
}


void cb_connect (proc_t * p, int res, int fd,
        const struct sockaddr * addr, socklen_t len) {
    if (addr) {
        TRACE (p, "connect (%d, [%s, ...], %d) = %d\n", 
            fd, family2str (addr->sa_family), len, res);
    } else {
        TRACE (p, "connect (%d, (nil), %d) = %d\n", fd, len, res);
    }
}


void cb_bind (proc_t * p, int res, int fd,
        const struct sockaddr * addr, socklen_t len) {
    if (addr) {
        TRACE (p, "bind (%d, [%s, ...], %d) = %d\n", 
            fd, family2str (addr->sa_family), len, res);
    } else {
        TRACE (p, "bind (%d, (nil), %d) = %d\n", fd, len, res);
    }
}


void cb_accept (proc_t * p, int res, int fd,
        struct sockaddr * addr, socklen_t * len) {
    if (addr) {
        TRACE (p, "accept (%d, [%s, ...], %d) = %d\n",
            fd, family2str (addr->sa_family), len ? *len : 0, res);
    } else {
        TRACE (p, "accept (%d, (nil), %d) = %d\n",
            fd, len ? *len : 0, res);
    }

    if (res < 0)
        return;

    associate_fd (p, res, FD_NET);
}


void cb_socket (proc_t * p, int new_fd, int domain, int type, int proto) {

    TRACE (p, "socket (%s, 0x%x, 0x%x) = %d\n", 
            family2str (domain), type, proto, new_fd);

    if (new_fd < 0)
        return;

    associate_fd (p, new_fd, FD_NET);
}


void cb_sendmsg (proc_t * p, ssize_t amnt, int fd, 
        const struct msghdr * msg, int flags) {

    TRACE (p, "[%4s] sendmsg (%d, %p, 0x%x) = %zd\n", flow2str (&p->flows[fd]),
            fd, msg, flags, amnt);

    log_call (p, fd, amnt, SC_SENDMSG);
}


void cb_recvmsg (proc_t * p, ssize_t amnt, int fd, struct msghdr * msg, 
        int flags) {

    TRACE (p, "[%4s] recvmsg (%d, %p, 0x%x) = %zd\n", flow2str (&p->flows[fd]),
            fd, msg, flags, amnt);
    
    log_call (p, fd, amnt, SC_RECVMSG);
}


void cb_dup (proc_t * p, int new_fd, int fd) {
   /*
    * On a dup, the method is to copy the association of the original fd
    */
    TRACE (p, "dup (%d [%s]) = %d\n", fd, flow2str (&p->flows[fd]), new_fd);

    if (new_fd < 0)
        return;

    associate_fd (p, new_fd, p->flows[fd].type);
}


void cb_dup2 (proc_t * p, int res, int fd, int new_fd) {
    /*
     * Behavior here is the same as for dup
     */
    TRACE (p, "dup2 (%d [%s], %d) = %d\n", fd, flow2str (&p->flows[fd]), 
            new_fd, res);

    if (res < 0)
        return;

    associate_fd (p, new_fd, p->flows[fd].type);
}


void cb_socketpair (proc_t * p, int res, int domain, int type, 
        int proto, int vec[2]) {

    TRACE (p, "socketpair (0x%x, 0x%x, 0x%x, [%d, %d]) = %d\n", 
            domain, type, proto,
            vec[0], vec[1], res);

    if (res < 0)
        return;

    associate_fd (p, vec[0], FD_NET);
    associate_fd (p, vec[1], FD_NET);
}


void cb___read_chk (proc_t * p, ssize_t amnt, int fd, void * buf, size_t bytes, 
        size_t sz) {
    
    TRACE (p, "[%4s] __read_chk (%d, %p, %zu, %zu) = %zd\n", 
            flow2str (&p->flows[fd]), fd, buf, bytes, sz, amnt);

    /*
     * On some systems, this exists as a 'safe' read. It is transparant to
     * the user that this happens and will remain so here. 
     */
    log_call (p, fd, amnt, SC_READ);
}


void cb_sendfile64 (proc_t * p, ssize_t amnt, int skt, int fd, 
        off_t off, size_t sz) {
    /* skt is the *socket*, fd is the file being sent */
    TRACE (p, "[%4s] sendfile64 (%d, %d, %ld, %zu) = %zd\n", 
            flow2str (&p->flows[skt]), skt, fd, off, sz, amnt);

    log_call (p, skt, amnt, SC_SENDFILE64);
}


void cb_sendfile (proc_t * p, ssize_t amnt, int skt, int fd, 
        off_t off, size_t sz) {

    /* skt is the *socket*, fd is the file being sent */
    TRACE (p, "[%4s] sendfile (%d, %d, %ld, %zu) = %zd\n", 
            flow2str (&p->flows[skt]), skt, fd, off, sz, amnt);

    log_call (p, skt, amnt, SC_SENDFILE);
}


void cb_writev (proc_t * p, ssize_t amnt, int fd, 
        const struct iovec * io, int cnt) {

    TRACE (p, "[%4s] writev (%d, %p, %d) = %zd\n", flow2str (&p->flows[fd]),
            fd, io, cnt, amnt);

    log_call (p, fd, amnt, SC_WRITEV);
}

void cb_shutdown (proc_t * p, int res, int fd, int how) {

    TRACE (p, "[%4s] shutdown (%d, %s) = %d\n", flow2str (&p->flows[fd]),
            fd, shutdown2str (how), res);

    if (-1 == res) {
        return;
    }

    release_fd (p, fd);
}

int cb_close (proc_t * p, int res, int fd) {

    TRACE (p, "close (%d) = %d\n", fd, res);

    /*
     * Don't close the fd we are using for a log just yet. 
     * We handle that explicitly on _exit
     */
    if (p->log && fd == fileno (p->log)) {
        return -1;
    }

    /*
     * (3.12.2011) aptitude update will trigger fd < 0
     */
    if (fd < 0 || -1 == res) {
        return res;
    }

    release_fd (p, fd);
    return res;
}


void cb__exit (proc_t * p, int code) {

    TRACE (p, "_exit (%d) = ...\n", code);

    do_cleanup (p);
}

