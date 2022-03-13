#include <stdio.h>
#include <assert.h>

#include "quickjs/utils/list.h"

int main(int argc, char *argv[], char *envp[]) {
    ListNode *list = List.new();
    ListNode *lz, *ly;

    for (size_t i = 0; i < 5; ++i) {
        ListNode *n = List.new_node();
        n->data.i8 = (char) (i + 'A');
        List.push(list, lz = n);
    }

    size_t y = List.size(list);
    printf("Size: %d\n", y);

    list_for_each(ly, list) {
        printf("%p: %c\n", ly, ly->data.i8);
    }
    printf("\n");

    ListNode* list2 = List.new();

    for (size_t i = 0; i < 5; ++i) {
        ListNode *n = List.new_node();
        n->data.i8 = (char) (i + '0');
        List.push(list, lz = n);
    }

    list_for_each(ly, list2) {
        printf("%p: %c\n", ly, ly->data.i8);
    }
    printf("\n");

    List.splice(list, list2);

    size_t yx = List.size(list);
    printf("Size: %d\n", yx);

    list_for_each(ly, list) {
        printf("%p: %c\n", ly, ly->data.i8);
    }
    printf("\n");

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

