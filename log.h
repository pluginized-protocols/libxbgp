//
// Created by thomas on 27/01/21.
//

#ifndef UBPF_TOOLS_LOG_H
#define UBPF_TOOLS_LOG_H

#include <stdint.h>
#include <stdio.h>

#define L_DEBUG "\001"            /* Debugging messages */
#define L_TRACE "\002"            /* Protocol tracing */
#define L_INFO "\003"            /* Informational messages */
#define L_REMOTE "\004"            /* Remote protocol errors */
#define L_WARN "\005"            /* Local warnings */
#define L_ERR "\006"            /* Local errors */
#define L_AUTH "\007"            /* Authorization failed etc. */
#define L_FATAL "\010"            /* Fatal errors */
#define L_BUG "\011"            /* BIRD bugs */

// mask bit to be ORed in add_entry_log function
#define MASK_DEBUG (1)
#define MASK_TRACE (1 << 1)
#define MASK_INFO (1 << 2)
#define MASK_REMOTE (1 << 3)
#define MASK_WARN (1 << 4)
#define MASK_ERR (1 << 5)
#define MASK_AUTH (1 << 6)
#define MASK_FATAL (1 << 7)
#define MASK_BUG (1 << 8)
#define MASK_ALL (~0)

#define LOG_BUFFER_SIZE 1024
#define TM_DATETIME_BUFFER_SIZE 32

#define STACK_BUFFER_INIT(buf, size)        \
  do {                        \
    buf.start = alloca(size);            \
    buf.pos = buf.start;            \
    buf.end = buf.start + size;            \
  } while(0)


#define LOG_BUFFER_INIT(buf)            \
  STACK_BUFFER_INIT(buf, LOG_BUFFER_SIZE)


static inline FILE *
rf_open(const char *name, const char *mode) {
    FILE *f = fopen(name, mode);

    if (!f)
        return NULL;

    return f;
}

struct log_config {
    uint mask;               /* Classes to log */
    void *fh;                /* FILE to log to, NULL=syslog */
    FILE *rf;                /* Resource for log file */
    const char *filename;    /* Log filename */
    const char *backup;      /* Secondary filename (for log rotation) */
    off_t pos;               /* Position/size of current log */
    off_t limit;             /* Log size limit */
    int terminal_flag;

    struct log_config *prev, *next;
    int dynamic_alloc;
};

typedef struct buffer {
    char *start;
    char *pos;
    char *end;
} buffer;

/**
 * Used to init the logger. Additionnal file on which log message
 * will be sent and stored
 * @param logs a list of log_config
 * @param file_path file on which the logger will write messages
 * @param mask which
 */
struct log_config *add_log_entry(struct log_config **logs, const char *file_path, int mask);

/**
 * Init the log manager
 * @param dbg 1 if the logger should also output log on stderr. 0 otherwise
 * @param new_syslog_name the name used and prepended on message sent to syslog
 * @param extra_log other file to which logs must be written. By default only
 *                  syslog is enabled. If dbg parameter is set, the logger also
 *                  sends message to stderr
 */
void log_init(int dbg, const char *new_syslog_name, struct log_config *extra_log);

/**
 * Log a message
 * @param msg
 * @param ... format
 */
void msg_log(const char *msg, ...);

/**
 * Close the logger
 */
void logs_close(void);


#endif //UBPF_TOOLS_LOG_H
