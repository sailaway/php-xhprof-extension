#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "ext/standard/html.h"
#include "php_tideways_xhprof.h"

extern ZEND_DECLARE_MODULE_GLOBALS(tideways_xhprof);

#include "tracing.h"
#include <stdio.h>

static const char digits[] = "0123456789abcdef";

static void *(*_zend_malloc) (size_t);
static void (*_zend_free) (void *);
static void *(*_zend_realloc) (void *, size_t);

void *tideways_malloc (size_t size);
void tideways_free (void *ptr);
void *tideways_realloc (void *ptr, size_t size);

/**
 * Free any items in the free list.
 */
static zend_always_inline void tracing_free_the_free_list(TSRMLS_D)
{
    xhprof_frame_t *frame = TXRG(frame_free_list);
    xhprof_frame_t *current;

    while (frame) {
        current = frame;
        frame = frame->previous_frame;
        efree(current);
    }
}

void tracing_enter_root_frame(TSRMLS_D)
{
    TXRG(start_time) = time_milliseconds(TXRG(clock_source), TXRG(timebase_factor));
    TXRG(start_timestamp) = current_timestamp();
    TXRG(enabled) = 1;
    TXRG(root) = zend_string_init(TIDEWAYS_XHPROF_ROOT_SYMBOL, sizeof(TIDEWAYS_XHPROF_ROOT_SYMBOL)-1, 0);

    tracing_enter_frame_callgraph(TXRG(root), NULL TSRMLS_CC);
}

void tracing_end(TSRMLS_D)
{
    if (TXRG(enabled) == 1) {
        if (TXRG(root)) {
            zend_string_release(TXRG(root));
        }

        while (TXRG(callgraph_frames)) {
            tracing_exit_frame_callgraph(TSRMLS_C);
        }

        TXRG(enabled) = 0;
        TXRG(callgraph_frames) = NULL;

        if (TXRG(flags) & TIDEWAYS_XHPROF_FLAGS_MEMORY_ALLOC) {
            zend_mm_heap *heap = zend_mm_get_heap();

            if (_zend_malloc || _zend_free || _zend_realloc) {
                zend_mm_set_custom_handlers(heap, _zend_malloc, _zend_free, _zend_realloc);
                _zend_malloc = NULL;
                _zend_free = NULL;
                _zend_realloc = NULL;
            } else {
                // zend_mm_heap is incomplete type, hence one can not access it
                //  the following line is equivalent to heap->use_custom_heap = 0;
                *((int*) heap) = 0;
            }
        }
    }
}

void tracing_callgraph_bucket_free(xhprof_callgraph_bucket *bucket)
{

    if (bucket->child_class) {
        zend_string_release(bucket->child_class);
    }

    if (bucket->child_function) {
        zend_string_release(bucket->child_function);
    }

    efree(bucket);
}

zend_always_inline static zend_ulong hash_data(zend_ulong hash, char *data, size_t size)
{
    size_t i;

    for (i = 0; i < size; ++i) {
        hash = hash * 33 + data[i];
    }

    return hash;
}

zend_always_inline static zend_ulong hash_int(zend_ulong hash, int data)
{
    return hash_data(hash, (char*) &data, sizeof(data));
}

xhprof_callgraph_bucket* find_bucket_in_children(xhprof_callgraph_bucket *parent_bucket,xhprof_frame_t *current_frame){
    if(!parent_bucket || !current_frame){
        return NULL;
    }
    xhprof_callgraph_bucket *bucket = parent_bucket->children;
    while(bucket){
        if(bucket->child_class == current_frame->class_name && zend_string_equals(bucket->child_function, current_frame->function_name)){
            return bucket;
        }
        bucket = bucket->next_sibling;
    }
    return NULL;
}

xhprof_callgraph_bucket* init_find_call_bucket(xhprof_frame_t *current_frame){
    xhprof_frame_t *parent_frame = TXRG(callgraph_frames);
    xhprof_callgraph_bucket *parent_bucket = NULL;
    xhprof_callgraph_bucket *bucket = NULL;
    xhprof_callgraph_bucket *children;

    if(!current_frame){
        return NULL;
    }

    if(parent_frame){
        parent_bucket = parent_frame->call_bucket;
        bucket = find_bucket_in_children(parent_bucket,current_frame);
    }
    if(bucket){
        return bucket;
    }

    bucket = emalloc(sizeof(xhprof_callgraph_bucket));
    bucket->parent = NULL;
    bucket->children = NULL;
    bucket->next_sibling = NULL;
    bucket->parent_recurse_level = 0;

    bucket->child_class = current_frame->class_name ? zend_string_copy(current_frame->class_name) : NULL;
    bucket->child_function = zend_string_copy(current_frame->function_name);
    bucket->count = 0;
    bucket->wall_time = 0;
    bucket->cpu_time = 0;
    bucket->memory = 0;
    bucket->memory_peak = 0;
    bucket->num_alloc = 0;
    bucket->num_free = 0;
    bucket->amount_alloc = 0;
    bucket->child_recurse_level = current_frame->recurse_level;
    bucket->parent = parent_bucket;

    // add child to parent
    if(!parent_bucket){
        return bucket;
    }
    if(parent_bucket->children == NULL){
        parent_bucket->children = bucket;
    } else {
        children = parent_bucket->children;
        while(children->next_sibling){
            children = children->next_sibling;
        }
        children->next_sibling = bucket;
    }
    return bucket;
}

void bucket_tree_to_array(xhprof_callgraph_bucket *bucket,zval *parent_stats,zend_ulong child_index,int as_mu){
    zval stats_zv, *stats = &stats_zv;
    zval children_stats_zv, *children_stats = &children_stats_zv;
    //zval *child_stats;
    zend_ulong cur_child_index = 0;
    xhprof_callgraph_bucket *child_bucket;
    if(!bucket){
        return;
    }

    array_init(stats);
    add_assoc_long(stats, "ct", bucket->count);
    add_assoc_long(stats, "wt", bucket->wall_time);
    if(bucket->child_class){
        add_assoc_string(stats,"cls",ZSTR_VAL(bucket->child_class));
    }
    add_assoc_string(stats,"function",ZSTR_VAL(bucket->child_function));
    if (TXRG(flags) & TIDEWAYS_XHPROF_FLAGS_MEMORY_ALLOC) {
        add_assoc_long(stats, "mem.na", bucket->num_alloc);
        add_assoc_long(stats, "mem.nf", bucket->num_free);
        add_assoc_long(stats, "mem.aa", bucket->amount_alloc);

        if (as_mu) {
            add_assoc_long(stats, "mu", bucket->amount_alloc);
        }
    }

    if (TXRG(flags) & TIDEWAYS_XHPROF_FLAGS_CPU) {
        add_assoc_long(stats, "cpu", bucket->cpu_time);
    }

    if (TXRG(flags) & TIDEWAYS_XHPROF_FLAGS_MEMORY_MU) {
        add_assoc_long(stats, "mu", bucket->memory);
    }

    if (TXRG(flags) & TIDEWAYS_XHPROF_FLAGS_MEMORY_PMU) {
        add_assoc_long(stats, "pmu", bucket->memory_peak);
    }

    child_bucket = bucket->children;
    // append children
    if(!child_bucket){
        add_index_zval(parent_stats, child_index, stats);
        return;
    }
    array_init(children_stats);
    cur_child_index = 0;
    while(child_bucket){
        bucket_tree_to_array(child_bucket,children_stats,cur_child_index,as_mu);
        child_bucket = child_bucket->next_sibling;
        cur_child_index += 1;
    }
    add_assoc_zval(stats, "children", children_stats);
    add_index_zval(parent_stats, child_index, stats);
}

void free_bucket_tree_node(xhprof_callgraph_bucket *bucket){
    xhprof_callgraph_bucket *child;
    if(!bucket){
        return;
    }
    child = bucket->children;
    while(child){
        free_bucket_tree_node(child);
        child = child->next_sibling;
    }
    tracing_callgraph_bucket_free(bucket);
}

void free_bucket_tree(){
    xhprof_callgraph_bucket *bucket = TXRG(callgraph_tree);
    free_bucket_tree_node(bucket);
    TXRG(callgraph_tree) = NULL;
}


void tracing_callgraph_append_to_array(zval *return_value TSRMLS_DC)
{
    int i = 0;

    int as_mu =
        (TXRG(flags) & (TIDEWAYS_XHPROF_FLAGS_MEMORY_ALLOC_AS_MU | TIDEWAYS_XHPROF_FLAGS_MEMORY_MU))
            == TIDEWAYS_XHPROF_FLAGS_MEMORY_ALLOC_AS_MU;

    bucket_tree_to_array(TXRG(callgraph_tree),return_value,0,as_mu);
    free_bucket_tree();
}

void tracing_begin(zend_long flags TSRMLS_DC)
{
    int i;

    TXRG(flags) = flags;
    TXRG(callgraph_frames) = NULL;
    TXRG(callgraph_tree) = NULL;

    for (i = 0; i < TIDEWAYS_XHPROF_CALLGRAPH_COUNTER_SIZE; i++) {
        TXRG(function_hash_counters)[i] = 0;
    }

    if (flags & TIDEWAYS_XHPROF_FLAGS_MEMORY_ALLOC) {
        zend_mm_heap *heap = zend_mm_get_heap();
        zend_mm_get_custom_handlers (heap, &_zend_malloc, &_zend_free, &_zend_realloc);
        zend_mm_set_custom_handlers (heap, &tideways_malloc, &tideways_free, &tideways_realloc);
    }
}

void tracing_request_init(TSRMLS_D)
{
    TXRG(timebase_factor) = get_timebase_factor(TXRG(clock_source));
    TXRG(enabled) = 0;
    TXRG(flags) = 0;
    TXRG(frame_free_list) = NULL;

    TXRG(num_alloc) = 0;
    TXRG(num_free) = 0;
    TXRG(amount_alloc) = 0;
}

void tracing_request_shutdown()
{
    free_bucket_tree();
    tracing_free_the_free_list(TSRMLS_C);
}

void *tideways_malloc (size_t size)
{
    TXRG(num_alloc) += 1;
    TXRG(amount_alloc) += size;

    if (_zend_malloc) {
        return _zend_malloc(size);
    }

    zend_mm_heap *heap = zend_mm_get_heap();
    return zend_mm_alloc(heap, size);
}

void tideways_free (void *ptr)
{
    TXRG(num_free) += 1;

    if (_zend_free) {
        return _zend_free(ptr);
    }

    zend_mm_heap *heap = zend_mm_get_heap();
    return zend_mm_free(heap, ptr);
}

void *tideways_realloc (void *ptr, size_t size)
{
    TXRG(num_alloc) += 1;
    TXRG(num_free) += 1;
    TXRG(amount_alloc) += size;

    if (_zend_realloc) {
        return _zend_realloc(ptr, size);
    }

    zend_mm_heap *heap = zend_mm_get_heap();
    return zend_mm_realloc(heap, ptr, size);
}
