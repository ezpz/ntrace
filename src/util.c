/**
 * @file util.c
 */

#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <util.h>

/** Represents the current process */
static proc_t * _state = NULL;


/**
 * Glibc provides no wrapper - use syscall direct (see man pages) 
 * @return Non-cached unique pid
 */
pid_t gettid () { return syscall (__NR_gettid); }


/**
 * @brief Marshal the contents of a process to file
 * @param p A handle to the process to save
 */
void save_proc (proc_t * p) {

    FILE * out = NULL;
    int i = 0;
    char name[FNAME_SIZE] = {0};
    snprintf (name, FNAME_SIZE, MARSHAL_FILE, p->pid);
    out = fopen (name, "wb");
    if (! out) 
        return;

    fprintf (out, "%d\n", p->pid);
    for (i = 0; i < FLOWS_MAX; ++i) {
        if (p->flows[i].active) {
            fprintf (out, MARSHAL_FMT, i, p->flows[i].fd, 
                    p->flows[i].ingress_total,
                    p->flows[i].egress_total,
                    flow2str (&p->flows[i]));
        }
    }

    fclose (out);
}


/**
 * @brief Read in marshalled data to a known proc_t structure
 * @param file A file created with save_proc
 * @return The proc_t representing the saved state
 * @note The file should be known to exist *before* this call. No check is 
 * made within this call regarding the validity of the file name
 */
proc_t * load_proc (const char * file) {

    FILE * in = fopen (file, "rb");
    proc_t * p = NULL;
    int i = 0, fd = 0;
    char type[FNAME_SIZE] = {0};
    uint64_t nr = 0, nw = 0;

    if (! in)
        return NULL;

    p = calloc (1, sizeof (proc_t));
    if (! p)
        return NULL;

    fscanf (in, "%d\n", &p->pid);
    while (fscanf (in, MARSHAL_FMT, &i, &fd, &nr, &nw, type) != EOF) {
        p->flows[i].fd = fd;
        p->flows[i].ingress_total = nr;
        p->flows[i].egress_total = nw;
        if (strncmp (type, "NET", FNAME_SIZE) == 0)
            p->flows[i].type = FD_NET;
        else if (strncmp (type, "PIPE", FNAME_SIZE) == 0)
            p->flows[i].type = FD_PIPE;
        else
            p->flows[i].type = FD_DISK;
    }
    fclose (in);
    return p;
}


/**
 * Anything other than SIGINT or a call to _exit calls this function
 */
void exit_fun () {
    TRACE (_state, " [atexit] \n");
    _exit (0);
}


/**
 * Set up to catch SIGINT
 * @param sig THe signal caught
 * @note Signals other than SIGINT are ignored here
 */
void signal_handler (int sig) {
    if (sig != SIGINT)
        return;
    TRACE (_state, " [SIGINT] \n");
    _exit (0);
}


/**
 * Map a SC_* macro to a function call name
 * @param call The macro to map
 * @return The string representation of call
 */
const char * call2str (call_t call) {
    switch (call) {
        case SC_READ: return "read";
        case SC_RECV: return "recv";
        case SC_RECVFROM: return "recvfrom";
        case SC_RECVMSG: return "recvmsg";
        case SC_WRITE: return "write";
        case SC_SEND: return "send";
        case SC_SENDTO: return "sendto";
        case SC_SENDMSG: return "sendmsg";
        case SC_SENDFILE: return "sendfile";
        case SC_SENDFILE64: return "sendfile64";
        case SC_WRITEV: return "writev";
        default: return "???";
    }
    return "CALL SWITCH FAIL";
}


/**
 * Create a human readable form of a fd_t
 * @param flow The type to represent
 * @return Stringified fd_t
 */
const char * type2str (fd_t type) {
    switch (type) {
        case FD_NET: return "NET";
        case FD_PIPE: return "PIPE";
        case FD_DISK: return "DISK";
        default: return "???";
    }
    return "TYPE SWITCH FAIL";
}

/**
 * Create a human readable form of a flow (type of the underlying fd)
 * @param flow The handle to the flow 
 * @return Stringified type information
 */
const char * flow2str (flow_t * flow) {
    return type2str (flow->type);
}


/**
 * Wipe out the details of a flow
 * @param flow The flow to clean
 */
void clear_flow (flow_t * flow) {
    int i = 0;
    for (; i < SC_INGRESS_SIZE; ++i) {
        flow->ingress_count[i] = 0;
        flow->ingress_bytes[i] = 0;
        flow->ingress_total = 0;
    }
    for (i = 0; i < SC_EGRESS_SIZE; ++i) {
        flow->egress_count[i] = 0;
        flow->egress_bytes[i] = 0;
        flow->egress_total = 0;
    }
}

/**
 * Stop monitoring the flow of traffic over this fd.
 * @param p The process the fd is associated with
 * @param fd The file descriptor to release
 */
void release_fd (proc_t * p, int fd) {
    key_t key = hash_key (p, fd);
    flow_t * flow = &(p->flows[key]);

    TRACE (p, " Releasing fd %d\n", fd);
    TRACE (p, "  Type  : %s\n", flow2str (flow));
    TRACE (p, "  Active: %s\n", flow->active ? "yes" : "no");

    gettimeofday (&flow->closed, NULL);

    if (flow->active) {
        double start = (double)flow->opened.tv_sec;
        double end = (double)flow->closed.tv_sec;
        start += (double)flow->opened.tv_usec/1000000.0;
        end += (double)flow->closed.tv_usec/1000000.0;
        TRACE (p, "  Duration: %0.3fs\n", end - start);
        flow->active = 0;
    }

    save_proc (p);
}

/**
 * Tag an fd as a particular type of traffic. If fd is already tagged and
 * active, change the association
 * @param p The process the fd is associated with
 * @param fd The file descriptor to tag
 * @param type The type of traffic this fd is to represent
 */
void associate_fd (proc_t * p, int fd, fd_t type) {

    key_t key = hash_key (p, fd);
    flow_t * flow = &(p->flows[key]);

    /* Alread active and associated; change status and exit */
    if (flow->active) {
        if (flow->type == type) {
            return;
        } else {
            TRACE (p, " fd %d: \n", fd);
            switch (type) {
                case FD_NET:
                    TRACE (p, "%s -> NET\n", flow2str (flow));
                    break;
                case FD_PIPE:
                    TRACE (p, "%s -> PIPE\n", flow2str (flow));
                    break;
                case FD_DISK:
                    TRACE (p, "%s -> DISK\n", flow2str (flow));
                    break;
                default:
                    TRACE (p, " Broken switch (%d)\n", __LINE__);
            }
            flow->type = type;
        }
        save_proc (p);
        return; 
    }

    /* We need to set the flow up for the first time */
    memset (flow, 0, sizeof (flow_t));

    flow->fd = fd;
    flow->active = 1;
    flow->type = type;

    gettimeofday (&flow->opened, NULL);

    TRACE (p, " Created flow: fd => %d, type => %s\n", fd, flow2str (flow));
    save_proc (p);
}


/**
 * Get a key into the flow hash
 * @param p The calling process 
 * @param fd The fd to look up
 * @note When more than FLOWS_MAX flows are allocated this will clobber
 * existing data. 
 */
key_t hash_key (proc_t * p, int fd) {
    (void) p; /* unused */
    return fd % FLOWS_MAX;
}


/**
 * Process management entry point.
 * This function can be entered in one of three states:
 *  1 - The process is not initialized and this is the very first time 
 *      through. 
 *  2 - The current pid does not match the pid stored in the process passed
 *      to this function (fork or clone has recently taken place)
 *  3 - First time through after an exec* call (memory is no longer valid)
 * @param p The state of the current process
 */
void do_initialize (proc_t * p) {

    char *log = NULL, *trace = NULL;
    pid_t ppid = 0, pid = gettid ();
    int first_time = 0, do_reset = 1;


    if (! _state) {

        /*
         * The global state is not valid, chekc if we were just exec'd.
         * State is managed periodically by writing to file so this
         * can be verified by finding a file with our pid or the parent pid.
         */
        int res = 0;
        struct stat stat_buf;
        char fname[FNAME_SIZE] = {0};

        /* check this pid first */
        snprintf (fname, FNAME_SIZE, MARSHAL_FILE, pid);
        res = stat (fname, &stat_buf);

        if (res != 0 && res == ENOENT) {

            /* try the parent */
            snprintf (fname, FNAME_SIZE, MARSHAL_FILE, getppid ());
            res = stat (fname, &stat_buf);

            if (res != 0 && res == ENOENT) {
                /* no apparent saved history, 
                 * first time through ever 
                 *
                 * Fall through
                 */
            } else if (res == 0) {

                /* Use ppid information */
                _state = load_proc (fname);

            }

        } else if (res == 0) {

            /* use state of previous pid */
            _state = load_proc (fname);
        }

        if (! _state) {
            
            /* No previous history found, allocate new memory */
            _state = calloc (1, sizeof (proc_t));
            if (! _state) 
                _exit (42);

            first_time = 1;
            do_reset = 0;
        }

        p = _state;

    }

    if (p->pid == pid && p->initialized)
        return;

    if (p->pid == pid)
        do_reset = 0;

    ppid = p->pid;
    p->pid = pid;
    log = getenv ("NTRACE_LOG_FILE");
    trace = getenv ("NTRACE_TRACE_FILE");

    if (log) {
        p->log = fopen (log, "a");
    } else {
        char logfile[FNAME_SIZE] = {0};
        snprintf (logfile, FNAME_SIZE, "/tmp/call.%d.log", p->pid);
        p->log = fopen (logfile, "w");
    }

    if (trace) {
        p->trace = fopen (trace, "a");
    } else {
        char tracefile[FNAME_SIZE] = {0};
        snprintf (tracefile, FNAME_SIZE, "/tmp/trace.%d.log", p->pid);
        p->trace = fopen (tracefile, "w");
    }

    /*
     * On process creation, std{in,out,err} are assumed to be disk IO.
     * After that, all properties are inherited from the parent
     */
    if (first_time) {
        TRACE (p, " Process created (%p): pid => %d, ppid => %d\n", 
                p, p->pid, ppid);
        associate_fd (p, fileno (stdin), FD_DISK);
        associate_fd (p, fileno (stdout), FD_DISK);
        associate_fd (p, fileno (stderr), FD_DISK);
    }


    /*
     * If this flag is set, a parent's state was used to populate the 
     * current process state. As such, it is necessary to re-hash all 
     * of the flows to their respective positions in the flow storage
     *
     * NOTE: In the case where hash_key (p, fd) returns fd % X, this is
     * entirely a waste of time (current implementation). However, it may
     * be the case that the key becomes a function of the pid and fd in 
     * which case this will be necessary.
     */
    if (do_reset) {
        
        int i = 0;
        flow_t buff[FLOWS_MAX];

        TRACE (p, " Copying details from ppid:%d (getppid:%d)\n", 
                ppid, getppid ());

        for (i = 0; i < FLOWS_MAX; ++i)
            memset (&buff[i], 0, sizeof (flow_t));

        /*
         * While the fds are inherited from the parent, the traffic is *not*
         * Clear all entries before rehashing
         *
         * This implicitly assumes that fds active in the parent are
         * active in the child.
         */
        for (i = 0; i < FLOWS_MAX; ++i) {
            clear_flow (&(p->flows[i]));
            if (p->flows[i].active) {
                key_t key = hash_key (p, p->flows[i].fd);
                TRACE (p, "  rehash %d (%s)\n", 
                        p->flows[i].fd, flow2str (&(p->flows[i])));
                memcpy (&buff[key], &(p->flows[i]), sizeof (flow_t));
            }
        }

        /* copy back only the active flows*/
        for (i = 0; i < FLOWS_MAX; ++i)
            memcpy (&(p->flows[i]), &buff[i], sizeof (flow_t));

    }

    signal (SIGINT, signal_handler);
    atexit (exit_fun);

    p->initialized = 1;

    save_proc (p);
}


/**
 * When a process exits, this is the final call to purge data to file
 * before exiting.
 * @param p The process about to be exited
 * @note This is a potentially long operation but it happens as the process
 * exiting so the impact is minimized to operational context.
 */
void do_cleanup (proc_t * p) {

    fd_t type = FD_NET;

    if (p->exited)
        return;

    p->exited = 1;

    TRACE (p, "(Exiting)\n");

    if (p->trace) {
        fclose (p->trace);
        p->trace = NULL;
    }
    
    if (! p->log)
        return;
    /*
     * Currently, the individual fd activity is elided as it adds a large
     * amount of noise to the summary output. 
     * TODO: enable this behavior with command line option
     */

    CALL_LOG (p, "#---- Summary ----#\n");
    CALL_LOG (p, "# call : count (bytes)\n");
    for (; type < FD_ENUM_SIZE; ++type) {
        int index = 0;
        uint64_t ingress = 0, egress = 0;
        uint64_t in_bytes[SC_INGRESS_SIZE] = {0}; 
        uint64_t in_count[SC_INGRESS_SIZE] = {0};
        uint64_t out_bytes[SC_EGRESS_SIZE] = {0}; 
        uint64_t out_count[SC_EGRESS_SIZE] = {0};
        key_t key = 0;

        /*
         * For now, skip everything not net related.
         * Leave the construct in place in case it becomes
         * necessary to expose this output or the extra details would
         * be useful.
         */
        if (type != FD_NET)
            continue;

        for (; key < FLOWS_MAX; ++key) {
            int i = 0; 
            for (; i < SC_INGRESS_SIZE; ++i) {
                if (p->flows[key].type == type) {
                    in_bytes[i] += p->flows[key].ingress_bytes[i];
                    in_count[i] += p->flows[key].ingress_count[i];
                    ingress += p->flows[key].ingress_bytes[i];
                }
            }
            for (i = 0; i < SC_EGRESS_SIZE; ++i) {
                if (p->flows[key].type == type) {
                    out_bytes[i] += p->flows[key].egress_bytes[i];
                    out_count[i] += p->flows[key].egress_count[i];
                    egress += p->flows[key].egress_bytes[i];
                }
            }
        }
        CALL_LOG (p, "\n");
        CALL_LOG (p, "%s byte totals: (in:%" PRIu64 ", out:%" PRIu64 ")\n", 
                type2str (type), ingress, egress);
        CALL_LOG (p, "       read : %" PRIu64 " (%" PRIu64 ")\n", 
                in_count[SC_READ], in_bytes[SC_READ]);
        CALL_LOG (p, "       recv : %" PRIu64 " (%" PRIu64 ")\n", 
                in_count[SC_RECV], in_bytes[SC_RECV]);
        CALL_LOG (p, "   recvfrom : %" PRIu64 " (%" PRIu64 ")\n", 
                in_count[SC_RECVFROM], in_bytes[SC_RECVFROM]);
        CALL_LOG (p, "    recvmsg : %" PRIu64 " (%" PRIu64 ")\n", 
                in_count[SC_RECVMSG], in_bytes[SC_RECVMSG]);
        /*
         * FIXME: This is horrible. 
         * Clean up the enum abuse so that these will index properly here
         */
        index = SC_WRITE - SC_WRITE;
        CALL_LOG (p, "      write : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_SEND - SC_WRITE;
        CALL_LOG (p, "       send : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_SENDTO - SC_WRITE;
        CALL_LOG (p, "     sendto : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_SENDMSG - SC_WRITE;
        CALL_LOG (p, "    sendmsg : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_SENDFILE - SC_WRITE;
        CALL_LOG (p, "   sendfile : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_SENDFILE64 - SC_WRITE;
        CALL_LOG (p, " sendfile64 : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
        index = SC_WRITEV - SC_WRITE;
        CALL_LOG (p, "     writev : %" PRIu64 " (%" PRIu64 ")\n", 
                out_count[index], out_bytes[index]);
    }

    fclose (p->log);
    p->log = NULL;

    /*
     * FIXME: 
     * Currently, in /tmp there will remain many .PID.state files
     * lying around. This *would* be the place to reclaim them individually
     * except that children rely on parent state at times and removing
     * a state file here would abandon a child.
     * Need a good way to fix this issue (on startup, maybe?)
     */
};
    

/**
 * Return an initialized process state. See do_initialize for details of
 * how this is implemented in certain situations
 */
proc_t * attach_to_process () {
    do_initialize (_state);
    return _state;
}
        

