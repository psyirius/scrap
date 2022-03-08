#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include "quickjs/utils/list.h"

int main(int argc, char *argv[], char *envp[]) {
    ListNode* list = malloc(sizeof(ListNode));

    List.init(list);
    ListNode n1[0x10];

    for (size_t i = 0; i < sizeof(n1); ++i) {
        List.unshift(list, &n1[i]);
        printf("%d\n", i);
    }

    size_t y = List.size(list);
    printf("Size: %d\n", y);

    free(list);

    return 0;
}

