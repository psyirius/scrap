static inline
size_t get_shape_size(size_t hash_size, size_t prop_size) {
    return hash_size * sizeof(uint32_t) + sizeof(JSShape) +
           prop_size * sizeof(JSShapeProperty);
}

static inline
JSShape *get_shape_from_alloc(void *sh_alloc, size_t hash_size) {
    return (JSShape *)(void *)((uint32_t *)sh_alloc + hash_size);
}

static inline
uint32_t *prop_hash_end(JSShape *sh) {
    return (uint32_t *)sh;
}

static inline
void *get_alloc_from_shape(JSShape *sh) {
    return prop_hash_end(sh) - ((intptr_t)sh->prop_hash_mask + 1);
}

static inline
JSShapeProperty *get_shape_prop(JSShape *sh) {
    return sh->prop;
}

static
int init_shape_hash(JSRuntime *rt) {
    rt->shape_hash_bits = 4;   /* 16 shapes */
    rt->shape_hash_size = 1 << rt->shape_hash_bits;
    rt->shape_hash_count = 0;
    rt->shape_hash = js_mallocz_rt(rt, sizeof(rt->shape_hash[0]) *
                                       rt->shape_hash_size);
    if (!rt->shape_hash)
        return -1;
    return 0;
}

/* same magic hash multiplier as the Linux kernel */
static
uint32_t shape_hash(uint32_t h, uint32_t val) {
    return (h + val) * 0x9e370001;
}

/* truncate the shape hash to 'hash_bits' bits */
static
uint32_t get_shape_hash(uint32_t h, int hash_bits) {
    return h >> (32 - hash_bits);
}

static
uint32_t shape_initial_hash(JSObject *proto) {
    uint32_t h;
    h = shape_hash(1, (uintptr_t)proto);
    if (sizeof(proto) > 4)
        h = shape_hash(h, (uint64_t)(uintptr_t)proto >> 32);
    return h;
}

static
int resize_shape_hash(JSRuntime *rt, int new_shape_hash_bits) {
    int new_shape_hash_size, i;
    uint32_t h;
    JSShape **new_shape_hash, *sh, *sh_next;

    new_shape_hash_size = 1 << new_shape_hash_bits;
    new_shape_hash = js_mallocz_rt(rt, sizeof(rt->shape_hash[0]) *
                                       new_shape_hash_size);
    if (!new_shape_hash)
        return -1;
    for(i = 0; i < rt->shape_hash_size; i++) {
        for(sh = rt->shape_hash[i]; sh != NULL; sh = sh_next) {
            sh_next = sh->shape_hash_next;
            h = get_shape_hash(sh->hash, new_shape_hash_bits);
            sh->shape_hash_next = new_shape_hash[h];
            new_shape_hash[h] = sh;
        }
    }
    js_free_rt(rt, rt->shape_hash);
    rt->shape_hash_bits = new_shape_hash_bits;
    rt->shape_hash_size = new_shape_hash_size;
    rt->shape_hash = new_shape_hash;
    return 0;
}

static
void js_shape_hash_link(JSRuntime *rt, JSShape *sh) {
    uint32_t h;
    h = get_shape_hash(sh->hash, rt->shape_hash_bits);
    sh->shape_hash_next = rt->shape_hash[h];
    rt->shape_hash[h] = sh;
    rt->shape_hash_count++;
}

static
void js_shape_hash_unlink(JSRuntime *rt, JSShape *sh) {
    uint32_t h;
    JSShape **psh;

    h = get_shape_hash(sh->hash, rt->shape_hash_bits);
    psh = &rt->shape_hash[h];
    while (*psh != sh)
        psh = &(*psh)->shape_hash_next;
    *psh = sh->shape_hash_next;
    rt->shape_hash_count--;
}

/* create a new empty shape with prototype 'proto' */
static no_inline
        JSShape *js_new_shape2(JSContext *ctx, JSObject *proto, int hash_size, int prop_size) {
JSRuntime *rt = ctx->rt;
void *sh_alloc;
JSShape *sh;

/* resize the shape hash table if necessary */
if (2 * (rt->shape_hash_count + 1) > rt->shape_hash_size) {
resize_shape_hash(rt, rt->shape_hash_bits + 1);
}

sh_alloc = js_malloc(ctx, get_shape_size(hash_size, prop_size));
if (!sh_alloc)
return NULL;
sh = get_shape_from_alloc(sh_alloc, hash_size);
sh->header.ref_count = 1;
add_gc_object(rt, &sh->header, JS_GC_OBJ_TYPE_SHAPE);
if (proto)
JS_DupValue(ctx, JS_MKPTR(JS_TAG_OBJECT, proto));
sh->proto = proto;
memset(prop_hash_end(sh) - hash_size, 0, sizeof(prop_hash_end(sh)[0]) *
hash_size);
sh->prop_hash_mask = hash_size - 1;
sh->prop_size = prop_size;
sh->prop_count = 0;
sh->deleted_prop_count = 0;

/* insert in the hash table */
sh->hash = shape_initial_hash(proto);
sh->is_hashed = TRUE;
sh->has_small_array_index = FALSE;
js_shape_hash_link(ctx->rt, sh);
return sh;
}

static
JSShape* js_new_shape(JSContext *ctx, JSObject *proto) {
    return js_new_shape2(ctx, proto, JS_PROP_INITIAL_HASH_SIZE, JS_PROP_INITIAL_SIZE);
}

/* The shape is cloned. The new shape is not inserted in the shape
   hash table */
static
JSShape* js_clone_shape(JSContext *ctx, JSShape *sh1) {
    JSShape *sh;
    void *sh_alloc, *sh_alloc1;
    size_t size;
    JSShapeProperty *pr;
    uint32_t i, hash_size;

    hash_size = sh1->prop_hash_mask + 1;
    size = get_shape_size(hash_size, sh1->prop_size);
    sh_alloc = js_malloc(ctx, size);
    if (!sh_alloc)
        return NULL;
    sh_alloc1 = get_alloc_from_shape(sh1);
    memcpy(sh_alloc, sh_alloc1, size);
    sh = get_shape_from_alloc(sh_alloc, hash_size);
    sh->header.ref_count = 1;
    add_gc_object(ctx->rt, &sh->header, JS_GC_OBJ_TYPE_SHAPE);
    sh->is_hashed = FALSE;
    if (sh->proto) {
        JS_DupValue(ctx, JS_MKPTR(JS_TAG_OBJECT, sh->proto));
    }
    for(i = 0, pr = get_shape_prop(sh); i < sh->prop_count; i++, pr++) {
        JS_DupAtom(ctx, pr->atom);
    }
    return sh;
}

static
JSShape* js_dup_shape(JSShape *sh) {
    sh->header.ref_count++;
    return sh;
}

static
void js_free_shape0(JSRuntime *rt, JSShape *sh) {
    uint32_t i;
    JSShapeProperty *pr;

    assert(sh->header.ref_count == 0);
    if (sh->is_hashed)
        js_shape_hash_unlink(rt, sh);
    if (sh->proto != NULL) {
        JS_FreeValueRT(rt, JS_MKPTR(JS_TAG_OBJECT, sh->proto));
    }
    pr = get_shape_prop(sh);
    for(i = 0; i < sh->prop_count; i++) {
        JS_FreeAtomRT(rt, pr->atom);
        pr++;
    }
    remove_gc_object(&sh->header);
    js_free_rt(rt, get_alloc_from_shape(sh));
}

static
void js_free_shape(JSRuntime *rt, JSShape *sh) {
    if (unlikely(--sh->header.ref_count <= 0)) {
        js_free_shape0(rt, sh);
    }
}

static
void js_free_shape_null(JSRuntime *rt, JSShape *sh) {
    if (sh)
        js_free_shape(rt, sh);
}
