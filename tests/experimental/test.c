#include <stdio.h>
#include <assert.h>

#include "quickjs/utils/list.h"

int main(int argc, char *argv[], char *envp[]) {
    ListNode* list = List.new();
    ListNode* lz;

    for (size_t i = 0; i < 5; ++i) {
        ListNode *n = List.new_node();
        n->data.i8 = (char) (i + 'A');
        List.push(list, lz = n);
        printf("%d\n", i);
    }

    size_t y = List.size(list);
    printf("Size: %d\n", y);

    size_t z = List.indexOf(list, lz);
    printf("Index: %d\n", z);

    List.reverse(list);

    size_t zx = List.indexOf(list, lz);
    printf("Index: %d\n", zx);

    ListNode* zz = List.at(list, z);
    assert(lz != zz);

    List.destroy(list);

    return 0;
}

