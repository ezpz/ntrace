/**
 * @file ntrace.h
 * @brief Global definitions and types
 */

#ifndef NTRACE_NTRACE__H__
#define NTRACE_NTRACE__H__

#include <sys/time.h>
#include <sys/types.h>
#include <inttypes.h> /* PRIu64 */
#include <stdint.h>
#include <stdio.h>

#define CALL_LOG_FMT    "%s,%d,%d,%lu.%06lu,%ld\n"
#define FLOWS_MAX       255 /**< 255 fd per PID seems reasonable */
#define FNAME_SIZE      512 /**< length of file name buffers */
#define MARSHAL_FILE    "/tmp/.%d.state" /**< proc_t marshalled data file */
#define MARSHAL_FMT     "%d %d %s\n" /**< marshalled output fmt */
#define CALL_HEADER     "#call,fd,pid,time,size\n"

#define DEFAULT_NTRACE_LOG_FILE     "ntrace-call.log"
#define DEFAULT_NTRACE_TRACE_FILE   "ntrace.log"


typedef int key_t; /**< type used to index the flows array in a proc_t */

/**
 * @enum fd_t
 * All ways that a file descriptor can be represented
 */
typedef enum {
    FD_NET = 0, FD_PIPE, FD_DISK, FD_ENUM_SIZE
} fd_t;

/**
 * @enum syscalls
 * Represents the calls supported by ntrace. These map directly to the 
 * flow_t structure below.
 */
typedef enum {
    /* Inbound data */
    SC_READ = 0, SC_RECV, SC_RECVFROM, SC_RECVMSG,

    /* Outbound data */
    SC_WRITE, SC_SEND, SC_SENDTO, SC_SENDMSG, SC_SENDFILE, 
    SC_SENDFILE64, SC_WRITEV,

    SC_ENUM_SIZE
} call_t;

/**
 * @struct flow_t
 * Contains the details of a flow of traffic over a particular file descriptor.
 */
typedef struct {

    int     fd;  /**< file descriptor or socket */
    fd_t    type; /**< data association */
    int     active; /**< has this fd been used yet ? */

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
    FILE        * log; /**< logfile */
    FILE        * trace; /**< debugging output */
    int         initialized; /**< true iff that data here has been set up */
    int         exited; /**< true iff exit has been called */
    flow_t      flows[FLOWS_MAX]; /**< open fds for this pid */

} proc_t;

#endif /*NTRACE_NTRACE__H__*/
