/*
 * Linux klist like list implementation
 */
#pragma once

#include "quickjs/macros/struct.h"
#include "quickjs/macros/types.h"

DEF_STRUCT(ListNode) {
    ListNode *prev;
    ListNode *next;
};

// Macro definitions
#define list_init(el) { &(el), &(el) }

/* return the pointer of type 'type *' containing 'el' as field 'member' */
#define list_entry(el, type, member) \
    ((type*)((uint8_t*)(el) - offsetof(type, member)))

// Iterators
#define list_for_each(el, head) \
  for((el) = (head)->next; (el) != (head); (el) = (el)->next)

#define list_for_each_safe(el, el1, head) \
    for((el) = (head)->next, (el1) = (el)->next; (el) != (head); \
        (el) = (el1), (el1) = (el)->next)

#define list_for_each_rev(el, head) \
  for((el) = (head)->prev; (el) != (head); (el) = (el)->prev)

#define list_for_each_rev_safe(el, el1, head) \
    for((el) = (head)->prev, (el1) = (el)->prev; (el) != (head); \
        (el) = (el1), (el1) = (el)->prev)

#define CT_NAME List
#define CT_TYPE ListNode*
#include "quickjs/macros/ctypi.h"

// Namespace model
extern struct nsList {
    DEF_METHOD(init, void);
    DEF_METHOD(size, size_t);
    DEF_METHOD(push, void, ListNode* node);
    DEF_METHOD(unshift, void, ListNode* node);
    DEF_METHOD(delete, void);
    DEF_METHOD(is_empty, bool);
} List;

#include "quickjs/macros/ctypi.h"
