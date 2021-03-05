//
// Created by thomas on 18/02/21.
//

#ifndef UBPF_TOOLS_UTILS_TESTS_H
#define UBPF_TOOLS_UTILS_TESTS_H

#define devnull_all_stdstream() \
do {                          \
   std_stream_to_file(STDOUT_FILENO, "/dev/null"); \
   std_stream_to_file(STDERR_FILENO, "/dev/null"); \
   std_stream_to_file(STDIN_FILENO,  "/dev/null"); \
} while(0)


int std_stream_to_file(int std_stream, const char *file);

#endif //UBPF_TOOLS_UTILS_TESTS_H
