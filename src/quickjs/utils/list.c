#include "quickjs/utils/list.h"

#include <stdlib.h>
#include <assert.h>

// Init in-type scope
#define CT_NAME List
#define CT_TYPE ListNode*
#include "quickjs/macros/ctypi.h"

// Declarations
DECL_STATIC_METHOD(new, ListNode*);
DECL_STATIC_METHOD(new_node, ListNode*);
DECL_STATIC_METHOD(ctor, void, ListNode *node);
DECL_METHOD(size, size_t);
DECL_METHOD(indexOf, size_t, ListNode *node);
DECL_METHOD(at, ListNode*, size_t index);
DECL_METHOD(insert_at, bool, ListNode* node, size_t index);
DECL_METHOD(push, void, ListNode *node);
DECL_METHOD(unshift, void, ListNode *node);
DECL_METHOD(splice, bool, ListNode* list);
DECL_STATIC_METHOD(remove, void, ListNode* node);
DECL_STATIC_METHOD(delete, void, ListNode* node);
DECL_METHOD(reverse, void);
DECL_METHOD(is_empty, bool);
DECL_METHOD(clear, size_t);
DECL_METHOD(destroy, void);

// Namespace model setup
ListPrototype List = {
    REF_STATIC_METHOD(new),
    REF_STATIC_METHOD(new_node),
    REF_STATIC_METHOD(ctor),
    REF_METHOD(size),
    REF_METHOD(indexOf),
    REF_METHOD(at),
    REF_METHOD(insert_at),
    REF_METHOD(push),
    REF_METHOD(unshift),
    REF_METHOD(splice),
    REF_STATIC_METHOD(remove),
    REF_STATIC_METHOD(delete),
    REF_METHOD(reverse),
    REF_METHOD(is_empty),
    REF_METHOD(clear),
    REF_METHOD(destroy),
};

// Implementations
static inline
void list_insert_inbetween(ListNode *elem, ListNode *prev, ListNode *next) {
    prev->next = elem;
    next->prev = elem;

    elem->prev = prev;
    elem->next = next;

    assert(prev->head == next->head);

    elem->head = prev->head = next->head;
}

// for list heads allocated on the heap
IMPL_STATIC_METHOD(new, ListNode*) {
    ListNode *self = malloc(sizeof(ListNode));

    REF_STATIC_METHOD(ctor)(self);
    self->on_heap = true;
    self->is_head = true;

    return self;
}

// for list nodes allocated on the heap
IMPL_STATIC_METHOD(new_node, ListNode*) {
    ListNode *self = malloc(sizeof(ListNode));

    REF_STATIC_METHOD(ctor)(self);
    self->on_heap = true;
    self->is_head = false;

    return self;
}

// for list heads allocated on the stack
IMPL_STATIC_METHOD(ctor, void, ListNode *node) {
    node->head = node;

    node->prev = node;
    node->next = node;

    node->is_head = true;

    node->data.ptr = nullptr;
}

// get the size of nodes
IMPL_METHOD(size, size_t) {
    assert(self == self->head);

    size_t len = 0;
    ListNode *elem = self->next;

    while (elem != self) {
        elem = elem->next;
        ++len;
    }

    return len;
}

// get the index of the `node`
IMPL_METHOD(indexOf, size_t, ListNode *node) {
    assert(self == self->head);

    size_t i = 0;
    ListNode *elem = self->next;

    while (elem != self) {
        if (elem == node)
            return i;
        elem = elem->next;
        ++i;
    }

    return -1;
}

// get the node at the `index`
IMPL_METHOD(at, ListNode*, size_t index) {
    assert(self == self->head);

    size_t i = 0;
    ListNode *elem = self->next;

    while (elem != self) {
        if (i == index)
            return elem;
        elem = elem->next;
        ++i;
    }

    return nullptr;
}

// insert `node` at index
IMPL_METHOD(insert_at, bool, ListNode* node, size_t index) {
    assert(self == self->head);

    assert(node->head != self);

    if (node->head == self) {
        return false;
    }

    size_t size = REF_METHOD(size)(self);

    assert(index < size);

    if (index >= size) {
        return false;
    }

    ListNode *ref = REF_METHOD(at)(self, index);
    list_insert_inbetween(node, ref->prev, ref);

    return true;
}

// append `node` at the end of the list
IMPL_METHOD(push, void, ListNode* node) {
    assert(self == self->head);

    list_insert_inbetween(node, self->prev, self);
}

// prepend `node` at the beginning of the list
IMPL_METHOD(unshift, void, ListNode* node) {
    assert(self == self->head);

    list_insert_inbetween(node, self, self->next);
}

// append another list to the end of this list
// warning: list's head will be destroyed
IMPL_METHOD(splice, bool, ListNode* list) {
    assert(self == self->head);

    // check: if self is a self-list head
    if (self != self->head)
        return false;

    // check: if list is a list head
    if (list != list->head)
        return false;

    // check: if self-list is not empty
    if (REF_METHOD(is_empty)(self))
        return false;

    // check: if list is not belongs to self-list
    if (list->head != self->head)
        return false;

    // set self as list-head to all list-nodes
    ListNode* ln;
    list_for_each(ln, list) {
        ln->head = self;
    }

    // extend self-list with list
    ListNode* self_tail = self->prev;
    ListNode* list_start = list->next;
    ListNode* list_tail = list->prev;
    // join list-tail with self-head
    // <----list---->x<self-head><----self---->

    list_tail->next = self;
    self->prev = list_tail;

    // join self-tail with list-start
    // <self-head><----self---->x<----list---->
    self_tail->next = list_start;
    list_start->prev = self_tail;

    REF_STATIC_METHOD(remove)(list);

    return true;
}

IMPL_STATIC_METHOD(remove, void, ListNode *node) {
    ListNode *prev = node->prev;
    ListNode *next = node->next;

    prev->next = next;
    next->prev = prev;

    node->prev = nullptr;
    node->next = nullptr;
    node->head = nullptr;
}

IMPL_STATIC_METHOD(delete, void, ListNode *node) {
    REF_STATIC_METHOD(remove)(node);

    if (node->on_heap) {
        free(node);
    }
}

ListNode* list_swap_links(ListNode *elem, ListNode *prev) {
    ListNode *next = elem->next;
    elem->next = prev;
    return elem->prev = next;
}

IMPL_METHOD(reverse, void) {
    assert(self == self->head);

    DBG_EXPR(size_t size = REF_METHOD(size)(self));

    ListNode *elem = self->next;
    ListNode *next, *prev = elem->prev;

    while (elem != self) {
        next = list_swap_links(elem, prev);

        prev = elem;
        elem = next;
    }

    // swap link the head
    list_swap_links(elem, prev);

    assert(REF_METHOD(size)(self) == size);
}

IMPL_METHOD(is_empty, bool) {
    assert(self == self->head);

    return self->next == self;
}

IMPL_METHOD(clear, size_t) {
    assert(self == self->head);

    size_t len = 0;
    ListNode *elem = self->next;

    while (elem != self) {
        REF_STATIC_METHOD(delete)(elem);
        elem = self->next;
        ++len;
    }

    return len;
}

IMPL_METHOD(destroy, void) {
    assert(self == self->head);

    // Iterate over nodes, remove and free them (if they are heap allocated)
    REF_METHOD(clear)(self);

    assert(REF_METHOD(size)(self) == 0);

    REF_STATIC_METHOD(delete)(self);
}

// De-init in-type scope
#include "quickjs/macros/ctypi.h"
