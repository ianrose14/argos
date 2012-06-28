/*
 * Author: Ian Rose
 * Date Created: Jul 14, 2009
 *
 * Additions to utlist.
 */

#ifndef _ARGOS_LIST_H_
#define _ARGOS_LIST_H_


/************/
/*  MACROS  */
/************/

#define LL_FREE_ALL(head,ptr)                    \
    while (head) {                               \
        ptr = head;                              \
        LL_DELETE(head,ptr);                     \
        free(ptr);                               \
    }

#define DL_FREE_ALL(head,ptr)                    \
    while (head) {                               \
        ptr = head;                              \
        DL_DELETE(head,ptr);                     \
        free(ptr);                               \
    }

#define CDL_FREE_ALL(head,ptr)                    \
    while (head) {                                \
        ptr = head;                               \
        CDL_DELETE(head,ptr);                     \
        free(ptr);                                \
    }

#define LL_HEAD(head) (head)

#define DL_HEAD(head) (head)

#define CDL_HEAD(head) (head)

#define LL_INSERT_AFTER(elt,add)                \
    do {                                        \
        if (elt) {                              \
            (add)->next = (elt)->next;          \
            (elt)->next = (add);                \
        } else {                                \
            (elt)=(add);                        \
            (elt)->next = NULL;                 \
        }                                       \
    } while (0)

#define DL_INSERT_AFTER(elt,add)                \
    do {                                        \
        if (elt) {                              \
            (add)->prev = (elt);                \
            (add)->next = (elt)->next;          \
            if ((elt)->prev == (elt))           \
                (elt)->prev = (add);            \
            if ((elt)->next)                    \
                (elt)->next->prev = (add);      \
            (elt)->next = (add);                \
        } else {                                \
            (elt)=(add);                        \
            (elt)->prev = (elt);                \
            (elt)->next = NULL;                 \
        }                                       \
    } while (0)

#define DL_INSERT_BEFORE(head,elt,add)          \
    do {                                        \
        if (elt) {                              \
            (add)->next = (elt);                \
            (add)->prev = (elt)->prev;          \
            if ((elt)->prev->next)              \
                (elt)->prev->next = (add);      \
            (elt)->prev = (add);                \
        } else {                                \
            (elt)=(add);                        \
            (elt)->prev = (elt);                \
            (elt)->next = NULL;                 \
        }                                       \
        if ((head) == (elt))                    \
            (head)=(add);                       \
    } while (0)

#define DL_TAIL(head)  ((head) ? (head->prev) : NULL)


#endif  /* #ifndef _ARGOS_LIST_H_ */
