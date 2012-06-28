/*
 * Author: Ian Rose
 * Date Created: Oct 1, 2009
 *
 * Basic memory-allocation tracking implementation.
 */

/* system includes */
#include <errno.h>
#include <stdlib.h>
#include <malloc_np.h>

/* local includes */
#include <click/config.h>
#include <click/glue.hh>
#include <click/hashmap.hh>
#include <click/memtrace.hh>
#include <click/string.hh>

/*
 * NOTE: element-tracking is totally wrong because set_active_element is not
 * called during element transitions.  (query-tracking should be ok though...)
 */

CLICK_DECLS

// un-hook malloc() and friends so that we can call the "real" versions
#undef malloc
#undef calloc
#undef realloc
#undef reallocf
#undef free

// for debugging
#define CHATTER_LARGE_ALLOCS 1

// type definitions
struct MemTracker {
    String name;
    String query;    // for queries, this field is redundant with 'name'
    int32_t usage;   // bytes currently allocated
    int32_t low_limit;
    int32_t high_limit;
};

// static variables

// total memory currently allocated
static int32_t _total_mem = 0;

// total allocated memory not attributed to an element (or query)
static int32_t _total_unattrib = 0;

// memory allocation limit (default: 10 MB and 32 MB)
static int32_t _total_low_limit = 12*1024*1024;
static int32_t _total_high_limit = 32*1024*1024;

// invariant: if _active_element != NULL, then
// _active_element->query == _active_query->name
static MemTracker *_active_element = NULL;
static MemTracker *_active_query = NULL;

static HashMap<String, MemTracker> _element_map;
static HashMap<String, MemTracker> _query_map;

static memtrace_fail_handler _fail_hdlr = NULL;

// methods:

static int
memtrace_check_request(size_t size)
{
    // if active-query is NULL, always fulfill request
    if (_active_query != NULL) {
        int32_t lim;

        if (_total_mem <= _total_low_limit) {
            // if we have not yet reached the low limit of memory allocation,
            // queries are allowed to allocate up to their high-limit
            lim = _active_query->high_limit;
        } else {
            // if we have already allocated more than the low limit of memory,
            // then queries are only allowed to allocate up to their low-limit
            lim = _active_query->low_limit;
        }

        if ((_active_query->usage + (int32_t)size) > lim) {
            if (_fail_hdlr != NULL) {
                _fail_hdlr(_active_query->name, _active_query->usage, size,
                    _total_mem);
            }

            return 0;  // rejected!
        }
    }

    return 1;  // accepted
}

static inline void
memtrace_update(ssize_t size)
{
    _total_mem += size;

    if (_active_element == NULL) {
        _total_unattrib += size;
        return;
    }

    assert(_active_query != NULL);
    assert(_active_element->query == _active_query->name);

    _active_element->usage += size;
    _active_query->usage += size;
}

const String*
memtrace_get_active_element(void)
{
    return _active_element == NULL ? NULL : &_active_element->name;
}

const String*
memtrace_get_active_query(void)
{
    return _active_element == NULL ? NULL : &_active_element->query;
}

int
memtrace_get_element(const String &name, int32_t *usage)
{
    MemTracker *ptr = _element_map.findp(name);
    if (ptr == NULL) {
        errno = EINVAL;
        return -1;
    } else {
        *usage = ptr->usage;
        return 0;
    }
}

int
memtrace_get_query(const String &name, int32_t *usage)
{
    MemTracker *ptr = _query_map.findp(name);
    if (ptr == NULL) {
        errno = EINVAL;
        return -1;
    } else {
        *usage = ptr->usage;
        return 0;
    }
}

int32_t
memtrace_get_total(void)
{
    return _total_mem;
}

int
memtrace_register_element(const String &element)
{
    String query = "";

    int index = element.find_left('/');
    if (index > -1)
        query = element.substring(0, index);

    MemTracker *cur_entry = _element_map.findp(element);
    if (cur_entry != NULL) {
        errno = EALREADY;
        return -1;
    }

    // initialize limits are (essentially) unbounded
    MemTracker mt = MemTracker();
    mt.name = element;
    mt.query = query;
    mt.usage = 0;
    mt.low_limit = 0x7FFFFFFF;
    mt.high_limit = 0x7FFFFFFF;
    _element_map.insert(element, mt);

    // also register the query that this element belongs (if not already done)
    cur_entry = _query_map.findp(query);
    if (cur_entry == NULL) {
        // initialize limits are (essentially) unbounded
        MemTracker mt = MemTracker();
        mt.name = query;
        // ok to leave mt.query blank because its not used
        mt.usage = 0;
        mt.low_limit = 0x7FFFFFFF;
        mt.high_limit = 0x7FFFFFFF;
        _query_map.insert(query, mt);
    }

    return 0;
}

int
memtrace_set_active_element(const String *element)
{
    if (element == NULL) {
        _active_element = NULL;
        return 0;
    }

    MemTracker *ptr = _element_map.findp(*element);
    if (ptr == NULL) {
        _active_element = NULL;
        errno = EINVAL;
        return -1;
    }

    _active_element = ptr;

    ptr = _query_map.findp(_active_element->query);
    // should always be found!
    assert(ptr != NULL);
    _active_query = ptr;
    return 0;
}

void
memtrace_set_fail_handler(memtrace_fail_handler handler)
{
    _fail_hdlr = handler;
}

int
memtrace_set_query_limits(const String &name, int32_t low_limit,
    int32_t high_limit)
{
    MemTracker *ptr = _query_map.findp(name);
    if (ptr == NULL) {
        errno = EINVAL;
        return -1;
    } else {
        ptr->low_limit = low_limit;
        ptr->high_limit = high_limit;
        return 0;
    }
}

void
memtrace_set_total(int32_t usage)
{
    _total_mem = usage;
}

void
memtrace_set_total_limits(int32_t low_limit, int32_t high_limit)
{
    _total_low_limit = low_limit;
    _total_high_limit = high_limit;
}

// implement memhooks_xxx hook functions:

void
memhooks_free(void *ptr)
{
    if (ptr == NULL) return;  // manpage: "If ptr is NULL, no action occurs."
    size_t size = malloc_usable_size(ptr);
    free(ptr);
    memtrace_update(-1*size);
}

void *
memhooks_malloc(size_t size)
{
#ifdef CHATTER_LARGE_ALLOCS
    if (size > (10*1024*1024))
        click_chatter("memtrace: malloc() request for %d bytes", size);
#endif

    if (memtrace_check_request(size) == 0)
        return NULL;  // request rejected

    void* ptr = malloc(size);
    if (ptr == NULL) return NULL;

    size_t real_size = malloc_usable_size(ptr);
    memtrace_update(real_size);
    return ptr;
}

void *
memhooks_calloc(size_t number, size_t size)
{
#ifdef CHATTER_LARGE_ALLOCS
    if (number*size > (10*1024*1024))
        click_chatter("memtrace: calloc() request for %d bytes", number*size);
#endif

    if (memtrace_check_request(size) == 0)
        return NULL;  // request rejected

    void* ptr = calloc(number, size);
    if (ptr == NULL) return NULL;

    size_t real_size = malloc_usable_size(ptr);
    memtrace_update(real_size);

    return ptr;
}

void *
memhooks_realloc(void *ptr, size_t size)
{
#ifdef CHATTER_LARGE_ALLOCS
    if (size > (10*1024*1024))
        click_chatter("memtrace: realloc() request for %d bytes", size);
#endif

    if (memtrace_check_request(size) == 0)
        return NULL;  // request rejected

    size_t prev_size = 0;
    if (ptr != NULL) prev_size = malloc_usable_size(ptr);
    void* newptr = realloc(ptr, size);
    if (newptr == NULL) return NULL;

    size_t new_size = malloc_usable_size(newptr);
    memtrace_update((int32_t)new_size - prev_size);

    return newptr;
}

void *
memhooks_reallocf(void *ptr, size_t size)
{
#ifdef CHATTER_LARGE_ALLOCS
    if (size > (10*1024*1024))
        click_chatter("memtrace: reallocf() request for %d bytes", size);
#endif

    if (memtrace_check_request(size) == 0)
        return NULL;  // request rejected

    size_t prev_size = 0, new_size = 0;
    if (ptr != NULL) prev_size = malloc_usable_size(ptr);
    void* newptr = reallocf(ptr, size);
    if (newptr != NULL) new_size = malloc_usable_size(newptr);

    // note: in reallocf, ptr is *always* freed, regardless of success
    memtrace_update((int32_t)new_size - prev_size);

    return newptr;  // note: could be NULL
}

// re-hook malloc() and friends
#define malloc(size) memhooks_malloc(size)
#define calloc(size) memhooks_calloc(size)
#define realloc(size) memhooks_realloc(size)
#define reallocf(size) memhooks_reallocf(size)
#define free(ptr) memhooks_free(ptr)

CLICK_ENDDECLS
ELEMENT_PROVIDES(memtrace)
