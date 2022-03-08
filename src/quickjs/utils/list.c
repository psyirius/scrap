#include "quickjs/utils/list.h"

#define CT_NAME List
#define CT_TYPE ListNode*
#include "quickjs/macros/ctypi.h"

// Declarations
DECL_METHOD(init, void);
DECL_METHOD(size, size_t);
DECL_METHOD(push, void, ListNode *node);
DECL_METHOD(unshift, void, ListNode *node);
DECL_METHOD(delete, void);
DECL_METHOD(is_empty, bool);

// Implementation
// insert 'elem' between 'prev' and 'next' */
static inline
void list_insert(ListNode *elem, ListNode *prev, ListNode *next) {
    prev->next = elem;
    next->prev = elem;

    elem->prev = prev;
    elem->next = next;
}

IMPL_METHOD(init, void) {
    self->prev = self;
    self->next = self;
}

IMPL_METHOD(size, size_t) {
    size_t len = 0;
    ListNode *elem = self->next;

    while (elem != self) {
        elem = elem->next;
        ++len;
    }

    return len;
}

// add 'node' prev to 'self' (head) (end of list)
IMPL_METHOD(push, void, ListNode* node) {
    list_insert(node, self->prev, self);
}

// add 'node' next to 'self' (head) (begin of list, after head)
IMPL_METHOD(unshift, void, ListNode* node) {
    list_insert(node, self, self->next);
}

IMPL_METHOD(delete, void) {
    ListNode *prev = self->prev;
    ListNode *next = self->next;

    prev->next = next;
    next->prev = prev;

    self->prev = nullptr; /* fail safe */
    self->next = nullptr; /* fail safe */
}

IMPL_METHOD(is_empty, bool) {
    return self->next == self;
}

// Namespace model setup
struct nsList List = {
    REF_METHOD(init),
    REF_METHOD(size),
    REF_METHOD(push),
    REF_METHOD(unshift),
    REF_METHOD(delete),
    REF_METHOD(is_empty),
};

#include "quickjs/macros/ctypi.h"
