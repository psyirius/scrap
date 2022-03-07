#include <stdio.h>
#include "quickjs/utils/memory.h"

int main(int argc, char *argv[], char *envp[]) {
    uint8_t xyz[9] = {0, 1, 2, 3, 0xa, 4, 5, 6, 7};

    Memory.reverse(xyz, sizeof(xyz));

    printf("%p\n", &xyz);

    return 0;
}
