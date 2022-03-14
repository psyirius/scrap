#pragma once

/* return the pointer of type 'type *' containing 'elem' as field 'member' */
#define list_entry(elem, type, member) \
    ((type*)((uint8_t*)(elem) - offsetof(type, member)))
