//
// Created by thomas on 7/08/20.
//

#include <stdio.h>
#include <string.h>
#include <public.h>

int start_main_program_loop();

int find_idx(int *array, int key, size_t len);

int main(int argc, const char *argv[]) {

    int status;
    char *path_json;
    path_json = "path/plugin1.o";

    status = load_plugin_from_json(path_json, NULL, strlen(path_json));

    if (status == -1) {
        fprintf(stderr, "Failed to inject plugins\n");
        return -1;
    }
    start_main_program_loop();
    return 1;
}

int start_main_program_loop() {
    int key = 17;
    int len = 5;
    int data[5] = {19, 10, 8, 17, 9};
    int res = find_idx(data, key, len);
    printf("%d", res);
    return 0;
}

int find_idx(int *array, int key, size_t len) {
    bpf_args_t args[] = {
            {.arg = array, .len = sizeof(*array) * len, .kind = kind_ptr, .type = 0},
            {.arg = &key, .len = sizeof(key), .kind = kind_primitive, .type = 0},
            {.arg = &len, .len = sizeof(len), .kind = kind_primitive, .type = 0},
    };

    VM_CALL(1, args, 3, {
            int i;
            for (i = 0; i < len; i++){
                if (key == array[i]) RETURN_VM_VAL(i);
            };
            RETURN_VM_VAL(-1);
    })
}