/*
 * Linux klist like doubly-linked list implementation
 */
#pragma once

#include "quickjs/config.h"

#include "quickjs/macros/struct.h"
#include "quickjs/macros/types.h"
#include "quickjs/macros/function.h"

DEF_UNION(ListData) {
    int8_t  i8;
    uint8_t u8;

    int16_t  i16;
    uint16_t u16;

    int32_t  i32;
    uint32_t u32;

    int64_t  i64;
    uint64_t u64;

    float32_t f32;
    float64_t f64;

    char* str;
    void* ptr;
};

DEF_STRUCT(ListNode) {
    // List props
    ListNode *head;

    ListNode *prev;
    ListNode *next;

    // flags
    bool on_heap;
    bool is_head;

    // data
    ListData data;
};

DEF_FUNC_TYPE(ListComparator, bool, ListNode* prev, ListNode* next);

// Macro definitions
#define list_init(el) { \
    .head=&(el), \
    .prev=&(el), \
    .next=&(el), \
    .on_heap=false, \
    .is_head=true, \
    .data={.ptr=nullptr} \
}

// Iterators
#define list_for_each(elem, head) \
    for ((elem) = (head)->next; (elem) != (head); (elem) = (elem)->next)

#define list_for_each_safe(elem, elt, head) \
    for ((elem) = (head)->next, (elt) = (elem)->next; (elem) != (head); (elem) = (elt), (elt) = (elem)->next)

#define list_for_each_rev(elem, head) \
    for ((elem) = (head)->prev; (elem) != (head); (elem) = (elem)->prev)

#define list_for_each_rev_safe(elem, elt, head) \
    for ((elem) = (head)->prev, (elt) = (elem)->prev; (elem) != (head); (elem) = (elt), (elt) = (elem)->prev)

#define CT_NAME List
#define CT_TYPE ListNode*
#include "quickjs/macros/ctypi.h"

// Namespace model
DEF_STRUCT(ListPrototype) {
    DEF_STATIC_METHOD(new, ListNode*);
    DEF_STATIC_METHOD(new_node, ListNode*);
    DEF_STATIC_METHOD(ctor, void, ListNode *node);
    DEF_METHOD(size, size_t);
    DEF_METHOD(indexOf, size_t, ListNode *node);
    DEF_METHOD(at, ListNode*, size_t index);
    DEF_METHOD(insert_at, bool, ListNode* node, size_t index);
    DEF_METHOD(push, void, ListNode* node);
    DEF_METHOD(unshift, void, ListNode* node);
    DEF_METHOD(splice, bool, ListNode* list);
    DEF_STATIC_METHOD(remove, void, ListNode* node);
    DEF_STATIC_METHOD(delete, void, ListNode* node);
    DEF_METHOD(reverse, void);
    DEF_METHOD(is_empty, bool);
    DEF_METHOD(clear, size_t);
    DEF_METHOD(destroy, void);
};

extern ListPrototype List;

#include "quickjs/macros/ctypi.h"
