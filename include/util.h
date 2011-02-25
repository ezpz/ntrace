/**
 * @file util.h
 * @note Do not define any structures here. Use ntrace.h instead
 */

#ifndef NTRACE_UTIL__H__
#define NTRACE_UTIL__H__

#include <ntrace.h>

/* Process control */
proc_t *    attach_to_process ();


/* initialization and cleanup functions */
void        do_initialize (proc_t *);
void        do_cleanup (proc_t *);


/* General purpose utilities */
key_t       hash_key (pid_t, int);
void        associate_fd (proc_t *, int, fd_t);
void        release_fd (proc_t *, int);
const char *flow2str (flow_t *);

#endif /*NTRACE_UTIL__H__*/
