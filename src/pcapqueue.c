/*
 * Author: Ian Rose
 * Date Created: Feb 27, 2009
 *
 * Layers a Queue-like interface on top of a pcap file.
 */

#include <errno.h>
#include "pcapqueue.h"


/**********************/
/*  EXTERNAL METHODS  */
/**********************/

int
pcapqueue_init(struct pcapqueue *pq, pcap_t *p)
{
    pq->next_hdr = NULL;
    pq->next_pkt = NULL;
    pq->pcap_h = p;
    pq->is_empty = 0;
    return 0;
}

int
pcapqueue_isempty(struct pcapqueue *pq)
{
    if (pq->is_empty)
        return 1;
    if (pcapqueue_peek(pq, NULL, NULL) == -1)
        return -1;
    return pq->is_empty;
}

int
pcapqueue_peek(struct pcapqueue *pq, const struct pcap_pkthdr **h,
    const u_char **sp)
{
    if (pq->is_empty) {
        errno = ENOENT;
        return -1;
    }

    if (pq->next_hdr != NULL) {
        if (h != NULL) *h = pq->next_hdr;
        if (sp != NULL) *sp = pq->next_pkt;
        return 0;
    }

    int rv = pcap_next_ex(pq->pcap_h, &pq->next_hdr, &pq->next_pkt);
    switch (rv) {
    case 1:
        if (h != NULL) *h = pq->next_hdr;
        if (sp != NULL) *sp = pq->next_pkt;
        return 0;
    case 0:  /* live capture timeout */
        errno = ETIMEDOUT;
        return -1;
    case -1:
        errno = EIO;
        return -1;
    case -2:
        pq->is_empty = 1;
        errno = ENOENT;
        return -1;
    default:  /* should never be returned */
        errno = EFAULT;
        return -1;
    }
}

int
pcapqueue_pop(struct pcapqueue *pq, const struct pcap_pkthdr **h,
    const u_char **sp)
{
    if (pcapqueue_peek(pq, h, sp) == -1) {
        errno = EIO;
        return -1;
    }
    pq->next_hdr = NULL;
    return 0;
}
