/*
 *	BIRD Library -- Logging Functions
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Logging
 *
 * The Logging module offers a simple set of functions for writing
 * messages to system logs and to the debug output. Message classes
 * used by this module are described in |birdlib.h| and also in the
 * user's manual.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <math.h>

#include "log.h"
#include "utlist.h"

static const char *ubpf_tools_name = "ubpf_plugin_manager";

static struct log_config *current_log_list = NULL;
static char *current_syslog_name; /* NULL -> syslog closed */


static inline struct log_config *new_log_config() {
    struct log_config *lc = calloc(1, sizeof(struct log_config));

    if (!lc) return NULL;

    return lc;
}


static inline int get_time(char *buf_time, size_t len) {
    long millisec;
    struct tm *tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    millisec = lrint(tv.tv_usec / 1000.0); // Round to nearest millisec
    if (millisec >= 1000) { // Allow for rounding up to nearest second
        millisec -= 1000;
        tv.tv_sec++;
    }

    tm_info = localtime(&tv.tv_sec);

    strftime(buf_time, len, "%Y-%m-%d %H:%M:%S", tm_info);

    return 0;
}


#include <pthread.h>

static pthread_mutex_t log_mutex;

static inline void log_lock(void) { pthread_mutex_lock(&log_mutex); }

static inline void log_unlock(void) { pthread_mutex_unlock(&log_mutex); }


#include <sys/syslog.h>

static int syslog_priorities[] = {
        LOG_DEBUG,
        LOG_DEBUG,
        LOG_DEBUG,
        LOG_INFO,
        LOG_ERR,
        LOG_WARNING,
        LOG_ERR,
        LOG_ERR,
        LOG_CRIT,
        LOG_CRIT
};

static const char *class_names[] = {
        "???",
        "DBG",
        "TRACE",
        "INFO",
        "RMT",
        "WARN",
        "ERR",
        "AUTH",
        "FATAL",
        "BUG"
};

static inline off_t
log_size(struct log_config *l) {
    struct stat st;
    return (!fstat(fileno(l->rf), &st) && S_ISREG(st.st_mode)) ? st.st_size : 0;
}

static void
log_close(struct log_config *l) {

    if (l->rf) {
        fclose(l->rf);
    }
    l->rf = NULL;
    l->fh = NULL;
}

static int log_open(struct log_config *l) {
    l->rf = rf_open(l->filename, "a");
    if (!l->rf) {
        /* Well, we cannot do much in case of error as log is closed */
        l->mask = 0;
        return -1;
    }

    l->fh = l->rf;
    l->pos = log_size(l);

    return 0;
}

static int
log_rotate(struct log_config *l) {
    log_close(l);

    /* If we cannot rename the logfile, we at least try to delete it
       in order to continue logging and not exceeding logfile size */
    if ((rename(l->filename, l->backup) < 0) &&
        (unlink(l->filename) < 0)) {
        l->mask = 0;
        return -1;
    }

    return log_open(l);
}

/**
 * log_commit - commit a log message
 * @class: message class information (%L_DEBUG to %L_BUG, see |lib/birdlib.h|)
 * @buf: message to write
 *
 * This function writes a message prepared in the log buffer to the
 * log file (as specified in the configuration). The log buffer is
 * reset after that. The log message is a full line, log_commit()
 * terminates it.
 *
 * The message class is an integer, not a first char of a string like
 * in log(), so it should be written like *L_INFO.
 */
static void
log_commit(int class, buffer *buf) {
    struct log_config *l;
    char tbuf[TM_DATETIME_BUFFER_SIZE];

    if (buf->pos == buf->end)
        strcpy(buf->end - 100, " ... <too long>");

    log_lock();
    DL_FOREACH(current_log_list, l) {
        if (!(l->mask & (1 << class)))
            continue;
        if (l->fh) {
            if (l->terminal_flag) {
                fputs("<DGB (plugin_manager)>: ", l->fh);
            } else {
                memset(tbuf, 0, sizeof(tbuf));
                if (get_time(tbuf, TM_DATETIME_BUFFER_SIZE) == -1) {
                    strcpy(tbuf, "<error>");
                }

                if (l->limit) {
                    off_t msg_len = strnlen(tbuf, sizeof(tbuf)) + strnlen(class_names[class], 5) +
                                    (buf->pos - buf->start) + 5;

                    if (l->pos < 0)
                        l->pos = log_size(l);

                    if (l->pos + msg_len > l->limit)
                        if (log_rotate(l) < 0)
                            continue;

                    l->pos += msg_len;
                }

                fprintf(l->fh, "%s <%s> ", tbuf, class_names[class]);
            }
            fputs(buf->start, l->fh);
            fputc('\n', l->fh);
            fflush(l->fh);
        } else {
            syslog(syslog_priorities[class], "%s", buf->start);
        }
    }
    log_unlock();

    buf->pos = buf->start;
}

static int
buffer_vprint(buffer *buf, const char *fmt, va_list args) {
    int i = vsnprintf((char *) buf->pos, buf->end - buf->pos, fmt, args);

    if ((i < 0) && (buf->pos < buf->end))
        *buf->pos = 0;

    buf->pos = (i >= 0) ? (buf->pos + i) : buf->end;
    return i;
}

static void
vlog(int class, const char *msg, va_list args) {
    buffer buf;
    LOG_BUFFER_INIT(buf);
    buffer_vprint(&buf, msg, args);
    log_commit(class, &buf);
}


/**
 * log - log a message
 * @msg: printf-like formatting string with message class information
 * prepended (%L_DEBUG to %L_BUG, see |lib/birdlib.h|)
 *
 * This function formats a message according to the format string @msg
 * and writes it to the corresponding log file (as specified in the
 * configuration). Please note that the message is automatically
 * formatted as a full line, no need to include |\n| inside.
 * It is essentially a sequence of log_reset(), logn() and log_commit().
 */
void
msg_log(const char *msg, ...) {
    int class = 1;
    va_list args;

    va_start(args, msg);
    if (*msg >= 1 && *msg <= 8)
        class = *msg++;
    vlog(class, msg, args);
    va_end(args);
}

static struct log_config *
default_log_list(int stderr_dbg, const char **syslog_name) {
    static struct log_config *log_list = NULL;
    struct log_config *l;

    if (log_list != NULL) {
        /* flush the default log list */
        DL_FOREACH(log_list, l) {
            DL_DELETE(log_list, l); /* lc_syslog and lc_stderr are static vars */
        }
        log_list = NULL;
    }

    *syslog_name = NULL;

    // config syslog
    static struct log_config lc_syslog = {
            .mask = ~0u,
    };
    DL_APPEND(log_list, &lc_syslog);
    *syslog_name = ubpf_tools_name;
    // end config syslog

    // config debug to stderr
    if (stderr_dbg) {
        static struct log_config lc_stderr;
        lc_stderr = (struct log_config) {
                .mask = ~0u,
                .terminal_flag = 1,
                .fh = stderr
        };

        DL_APPEND(log_list, &lc_stderr);
    }
    // end config debug to stderr

    return log_list;
}


struct log_config *add_log_entry(struct log_config **logs, const char *file_path, int mask) {
    struct log_config *n_log;
    n_log = new_log_config();

    if (!n_log) return NULL;

    DL_APPEND(*logs, n_log);

    n_log->mask = mask;
    n_log->filename = file_path;

    return *logs;
}

static inline void append_logs(struct log_config *dest_logs, struct log_config *src_logs) {
    struct log_config *l;
    DL_FOREACH(src_logs, l) {
        DL_APPEND(dest_logs, l);
    }
}


static inline void logs_close_(int close_syslog) {
    struct log_config *l;
    if (current_log_list) {
        DL_FOREACH(current_log_list, l) {
            if (l->rf) {
                log_close(l);
            }
        }
    }

    if (close_syslog) {
        if (current_syslog_name) {
            closelog();
            free(current_syslog_name);
            current_syslog_name = NULL;
        }
    }

}

void logs_close() {
    logs_close_(1);
}

void
log_init(int dbg, const char *new_syslog_name, struct log_config *extra_log) {
    struct log_config *l;
    struct log_config *logs = NULL;

    /* We should not manipulate with log list when other threads may use it */
    log_lock();

    if (!current_log_list || current_log_list == NULL)
        logs = default_log_list(dbg, &new_syslog_name);

    append_logs(logs, extra_log);

    /* Close the logs to avoid pinning them on disk when deleted */
    logs_close_(0);

    /* Reopen the logs, needed for 'configure undo' */
    if (logs) {
        DL_FOREACH(logs, l) {
            if (l->filename && !l->rf) {
                log_open(l);
            }
        }
    }

    current_log_list = logs;

    if (current_syslog_name) {
        if (!strcmp(current_syslog_name, new_syslog_name))
            goto done;
    }

    if (current_syslog_name) {
        closelog();
        free(current_syslog_name);
        current_syslog_name = NULL;
    }

    if (new_syslog_name) {
        current_syslog_name = strdup(new_syslog_name);
        openlog(current_syslog_name, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    }

    done:
    /* Logs exchange done, let the threads log as before */
    log_unlock();
}