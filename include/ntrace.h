/**
 * @file ntrace.h
 * @brief Global definitions and types
 */

#ifndef NTRACE_NTRACE__H__
#define NTRACE_NTRACE__H__

#include <sys/time.h>
#include <sys/types.h>

#define     FLOWS_MAX   255 /**< 255 fd per PID seems reasonable */

/**
 * @enum fd_t
 * All ways that a file descriptor can be represented
 */
typedef enum {
    FD_NET  = 0, FD_PIPE, FD_DISK
} fd_t;

/**
 * @enum syscalls
 * Represents the calls supported by ntrace. These map directly to the 
 * flow_t structure below.
 */
enum {
    /* Inbound data */
    SC_READ = 0, SC_RECV, SC_RECVFROM, SC_RECVMSG,

    /* Outbound data */
    SC_WRITE, SC_SEND, SC_SENDTO, SC_SENDMSG, SC_SENDFILE, 
    SC_SENDFILE64, SC_WRITEV,

    /* loop control and array sizing */
    SC_ENUM_SIZE,
    SC_INGRESS_SIZE = SC_RECVMSG + 1 - SC_READ,
    SC_EGRESS_SIZE = SC_WRITEV + 1 - SC_WRITE,
};

/**
 * @struct flow_t
 * Contains the details of a flow of traffic over a particular file descriptor.
 */
typedef struct {

    int     fd;  /**< file descriptor or socket */
    fd_t    type; /**< data association */
    int     active; /**< has this fd been used yet ? */

    /** Counts of how many times each call was used */
    uint64_t ingress_count[SC_INGRESS_SIZE];

    /** Total bytes read for each supported call */
    uint64_t ingress_bytes[SC_INGRESS_SIZE];

    /** Overall total inbound bytes for this flow */
    uint64_t ingress_total;

    /** Counts of how many times each call was used */
    uint64_t egress_count[SC_EGRESS_SIZE];

    /** Total bytes written for each supported call */
    uint64_t egress_bytes[SC_EGRESS_SIZE];

    /** Overall total outbound bytes for this flow */
    uint64_t egress_total;

    /** Detials regarding when the flow was established and released */
    struct timeval opened, closed;

} flow_t;

/**
 * @struct proc_t
 * Entire set of details necessary to track a process through it's execution
 * and monitir its fd activity.
 */
typedef struct {

    pid_t       pid; /**< pid of the process */
    char        * log; /**< logfile */
    int         initialized; /**< true iff that data here has been set up */
    int         exited; /**< true iff exit has been called */
    flow_t      flows[FLOWS_MAX]; /**< open fds for this pid */

} proc_t;

#endif /*NTRACE_NTRACE__H__*/