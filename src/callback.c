/**
 * @file callback.c
 * Callbacks implemented for any intercepted library calls
 */


#include <callback.h>
#include <util.h>

extern int fileno (FILE *);

/**
 * A helpful way to display basic information when dealing with calls like
 * sendto or recvfrom. 
 * @param sa A pointer to a sockaddr structure
 * @return String representation of the family of that structure
 */
static const char * family2str (const struct sockaddr * sa) {
    switch (sa->sa_family) {
        case AF_LOCAL: return "AF_LOCAL"; /* Same as AF_UNIX, AF_FILE */
        case AF_INET: return "AF_INET";
        case AF_INET6: return "AF_INET6";
        case AF_UNSPEC: return "AF_UNSPEC";
        default: return "???";
    }
    return "FAMILY SWITCH FAIL";
}

/**
 * Behavior common to all ingress/egress calls.
 * Log information and update totals
 * @note If amnt is < 0 it is assumed that the call failed and no logging
 * takes place here
 * @note Only network related calls are processed here
 * @param p The process this action is related to 
 * @param fd The file descriptor that received the action
 * @param amnt The result of the call itself
 * @param call The actual call this represents
 */
static void update_and_log (proc_t * p, int fd, ssize_t amnt, call_t call) {

    key_t key = hash_key (p, fd);
    struct timeval tv;


    if (amnt < 0 || p->flows[key].type != FD_NET)
        return;

    /* < SC_WRITE indicates an inbound direction */
    if (call < SC_WRITE) {
        p->flows[key].ingress_count[call] += 1;
        p->flows[key].ingress_bytes[call] += amnt;
        p->flows[key].ingress_total += amnt;
    } else {
        p->flows[key].egress_count[call - SC_WRITE] += 1;
        p->flows[key].egress_bytes[call - SC_WRITE] += amnt;
        p->flows[key].egress_total += amnt;
    }

    gettimeofday (&tv, NULL);

    CALL_LOG (p, CALL_LOG_FMT, 
            call2str (call), fd, p->pid, tv.tv_sec, tv.tv_usec, amnt,
            p->flows[key].ingress_total, p->flows[key].egress_total);
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

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] read (%d, %p, %zu) = %zd\n", flow2str (&p->flows[key]),
            fd, buf, sz, amnt);

    update_and_log (p, fd, amnt, SC_READ);
}


void cb_write (proc_t * p, ssize_t amnt, int fd, const void * buf, size_t sz) {
    
    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] write (%d, %p, %zu) = %zd\n", flow2str (&p->flows[key]),
            fd, buf, sz, amnt);

    update_and_log (p, fd, amnt, SC_WRITE);
}


void cb_recv (proc_t * p, ssize_t amnt, int fd, void * buf, 
        size_t sz, int flags) {

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] recv (%d, %p, %zu, %x) = %zd\n", flow2str (&p->flows[key]),
            fd, buf, sz, flags, amnt);

    update_and_log (p, fd, amnt, SC_RECV);
}


void cb_send (proc_t * p, ssize_t amnt, int fd, const void * buf, 
        size_t sz, int flags) {

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] send (%d, %p, %zu, %x) = %zd\n", flow2str (&p->flows[key]),
            fd, buf, sz, flags, amnt);

    update_and_log (p, fd, amnt, SC_SEND);
}


void cb_sendto (proc_t * p, ssize_t amnt, int fd, const void * buf, size_t sz, 
        int flags, const struct sockaddr * addr, socklen_t len) {

    key_t key = hash_key (p, fd);

    if (addr) {
        TRACE (p, "[%4s] sendto (%d, %p, %zu, %x, [%s, ...], %d) = %zd\n",
            flow2str (&p->flows[key]), fd, buf, sz, flags, 
            family2str (addr), len, amnt);
    } else {
        TRACE (p, "[%4s] sendto (%d, %p, %zu, %x, (nil), %d) = %zd\n",
            flow2str (&p->flows[key]), fd, buf, sz, flags, len, amnt);
    }

    update_and_log (p, fd, amnt, SC_SENDTO);
}


void cb_recvfrom (proc_t * p, ssize_t amnt, int fd, void * buf, size_t sz, 
        int flags, struct sockaddr * addr, socklen_t * len) {

    key_t key = hash_key (p, fd);

    if (addr) {
        TRACE (p, "[%4s] recvfrom (%d, %p, %zu, %x, [%s, ...], %d) = %zd\n", 
            flow2str (&p->flows[key]), fd, buf, sz, flags, 
            family2str (addr), len ? *len : 0, amnt);
    } else {
        TRACE (p, "[%4s] recvfrom (%d, %p, %zu, %x, (nil), %d) = %zd\n", 
            flow2str (&p->flows[key]), fd, buf, sz, flags, 
            len ? *len : 0, amnt);
    }

    update_and_log (p, fd, amnt, SC_RECVFROM);
}


void cb_connect (proc_t * p, int res, int fd,
        const struct sockaddr * addr, socklen_t len) {
    if (addr) {
        TRACE (p, "connect (%d, [%s, ...], %d) = %d\n", 
            fd, family2str (addr), len, res);
    } else {
        TRACE (p, "connect (%d, (nil), %d) = %d\n", fd, len, res);
    }
}


void cb_bind (proc_t * p, int res, int fd,
        const struct sockaddr * addr, socklen_t len) {
    if (addr) {
        TRACE (p, "bind (%d, [%s, ...], %d) = %d\n", 
            fd, family2str (addr), len, res);
    } else {
        TRACE (p, "bind (%d, (nil), %d) = %d\n", fd, len, res);
    }
}


void cb_accept (proc_t * p, int res, int fd,
        struct sockaddr * addr, socklen_t * len) {
    if (addr) {
        TRACE (p, "accept (%d, [%s, ...], %d) = %d\n",
            fd, family2str (addr), len ? *len : 0, res);
    } else {
        TRACE (p, "accept (%d, (nil), %d) = %d\n",
            fd, len ? *len : 0, res);
    }

    if (res < 0)
        return;

    associate_fd (p, res, FD_NET);
}


void cb_socket (proc_t * p, int new_fd, int domain, int type, int proto) {

    TRACE (p, "socket (%x, %x, %x) = %d\n", domain, type, proto, new_fd);

    if (new_fd < 0)
        return;

    associate_fd (p, new_fd, FD_NET);
}


void cb_sendmsg (proc_t * p, ssize_t amnt, int fd, 
        const struct msghdr * msg, int flags) {

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] sendmsg (%d, %p, %x) = %zd\n", flow2str (&p->flows[key]),
            fd, msg, flags, amnt);

    update_and_log (p, fd, amnt, SC_SENDMSG);
}


void cb_recvmsg (proc_t * p, ssize_t amnt, int fd, struct msghdr * msg, 
        int flags) {

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] recvmsg (%d, %p, %x) = %zd\n", flow2str (&p->flows[key]),
            fd, msg, flags, amnt);
    
    update_and_log (p, fd, amnt, SC_RECVMSG);
}


void cb_dup (proc_t * p, int new_fd, int fd) {
   /*
    * On a dup, the method is to copy the association of the original fd
    */

    key_t key = hash_key (p, fd);

    TRACE (p, "dup (%d [%s]) = %d\n", fd, flow2str (&p->flows[key]), new_fd);

    if (new_fd < 0)
        return;

    associate_fd (p, new_fd, p->flows[key].type);
}


void cb_dup2 (proc_t * p, int res, int fd, int new_fd) {
    /*
     * Behavior here is the same as for dup
     */
    key_t key = hash_key (p, fd);

    TRACE (p, "dup2 (%d [%s], %d) = %d\n", fd, flow2str (&p->flows[key]), 
            new_fd, res);

    if (res < 0)
        return;

    associate_fd (p, new_fd, p->flows[key].type);
}


void cb_socketpair (proc_t * p, int res, int domain, int type, 
        int proto, int vec[2]) {

    TRACE (p, "socketpair (%x, %x, %x, [%d, %d]) = %d\n", domain, type, proto,
            vec[0], vec[1], res);

    if (res < 0)
        return;

    associate_fd (p, vec[0], FD_NET);
    associate_fd (p, vec[1], FD_NET);
}


void cb___read_chk (proc_t * p, ssize_t amnt, int fd, void * buf, size_t bytes, 
        size_t sz) {
    
    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] __read_chk (%d, %p, %zu, %zu) = %zd\n", 
            flow2str (&p->flows[key]), fd, buf, bytes, sz, amnt);

    /*
     * On some systems, this exists as a 'safe' read. It is transparant to
     * the user that this happens and will remain so here. 
     */
    update_and_log (p, fd, amnt, SC_READ);
}


void cb_sendfile64 (proc_t * p, ssize_t amnt, int skt, int fd, 
        off_t off, size_t sz) {
    /* skt is the *socket*, fd is the file being sent */
    key_t key = hash_key (p, skt);

    TRACE (p, "[%4s] sendfile64 (%d, %d, %ld, %zu) = %zd\n", 
            flow2str (&p->flows[key]), skt, fd, off, sz, amnt);

    update_and_log (p, skt, amnt, SC_SENDFILE64);
}


void cb_sendfile (proc_t * p, ssize_t amnt, int skt, int fd, 
        off_t off, size_t sz) {

    /* skt is the *socket*, fd is the file being sent */
    key_t key = hash_key (p, skt);

    TRACE (p, "[%4s] sendfile (%d, %d, %ld, %zu) = %zd\n", 
            flow2str (&p->flows[key]), skt, fd, off, sz, amnt);

    update_and_log (p, skt, amnt, SC_SENDFILE);
}


void cb_writev (proc_t * p, ssize_t amnt, int fd, 
        const struct iovec * io, int cnt) {

    key_t key = hash_key (p, fd);

    TRACE (p, "[%4s] writev (%d, %p, %d) = %zd\n", flow2str (&p->flows[key]),
            fd, io, cnt, amnt);

    update_and_log (p, fd, amnt, SC_WRITEV);
}


int cb_close (proc_t * p, int res, int fd) {

    TRACE (p, "close (%d) = %d\n", fd, res);

    /*
     * Don't close the fd we are using for a log just yet. 
     * We handle that explicitly on _exit
     */
    if (p->log && fd == fileno (p->log))
        return -1;

    /*
     * (3.12.2011) aptitude update will trigger this situation
     */
    if (fd < 0)
        return res;

    release_fd (p, fd);
    return res;
}


void cb__exit (proc_t * p, int code) {

    TRACE (p, "_exit (%d) = ...\n", code);

    do_cleanup (p);
}

