typedef struct {
    JSObject *obj;
    uint32_t hash_next; /* -1 if no next entry */
} JSObjectListEntry;

/* XXX: reuse it to optimize weak references */
typedef struct {
    JSObjectListEntry *object_tab;
    int object_count;
    int object_size;
    uint32_t *hash_table;
    uint32_t hash_size;
} JSObjectList;

static void js_object_list_init(JSObjectList *s)
{
    memset(s, 0, sizeof(*s));
}

static uint32_t js_object_list_get_hash(JSObject *p, uint32_t hash_size)
{
    return ((uintptr_t)p * 3163) & (hash_size - 1);
}

static int js_object_list_resize_hash(JSContext *ctx, JSObjectList *s,
                                      uint32_t new_hash_size)
{
    JSObjectListEntry *e;
    uint32_t i, h, *new_hash_table;

    new_hash_table = js_malloc(ctx, sizeof(new_hash_table[0]) * new_hash_size);
    if (!new_hash_table)
        return -1;
    js_free(ctx, s->hash_table);
    s->hash_table = new_hash_table;
    s->hash_size = new_hash_size;

    for(i = 0; i < s->hash_size; i++) {
        s->hash_table[i] = -1;
    }
    for(i = 0; i < s->object_count; i++) {
        e = &s->object_tab[i];
        h = js_object_list_get_hash(e->obj, s->hash_size);
        e->hash_next = s->hash_table[h];
        s->hash_table[h] = i;
    }
    return 0;
}

/* the reference count of 'obj' is not modified. Return 0 if OK, -1 if
   memory error */
static int js_object_list_add(JSContext *ctx, JSObjectList *s, JSObject *obj)
{
    JSObjectListEntry *e;
    uint32_t h, new_hash_size;

    if (js_resize_array(ctx, (void *)&s->object_tab,
                        sizeof(s->object_tab[0]),
                        &s->object_size, s->object_count + 1))
        return -1;
    if (unlikely((s->object_count + 1) >= s->hash_size)) {
        new_hash_size = max_uint32(s->hash_size, 4);
        while (new_hash_size <= s->object_count)
            new_hash_size *= 2;
        if (js_object_list_resize_hash(ctx, s, new_hash_size))
            return -1;
    }
    e = &s->object_tab[s->object_count++];
    h = js_object_list_get_hash(obj, s->hash_size);
    e->obj = obj;
    e->hash_next = s->hash_table[h];
    s->hash_table[h] = s->object_count - 1;
    return 0;
}

/* return -1 if not present or the object index */
static int js_object_list_find(JSContext *ctx, JSObjectList *s, JSObject *obj)
{
    JSObjectListEntry *e;
    uint32_t h, p;

    /* must test empty size because there is no hash table */
    if (s->object_count == 0)
        return -1;
    h = js_object_list_get_hash(obj, s->hash_size);
    p = s->hash_table[h];
    while (p != -1) {
        e = &s->object_tab[p];
        if (e->obj == obj)
            return p;
        p = e->hash_next;
    }
    return -1;
}

static void js_object_list_end(JSContext *ctx, JSObjectList *s)
{
    js_free(ctx, s->object_tab);
    js_free(ctx, s->hash_table);
}
