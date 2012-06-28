/*
 * Author: Ian Rose
 * Date Created: Feb 27, 2009
 *
 * Layers a Queue-like interface on top of a pcap file.
 */

#ifndef _PCAPQUEUE_H_
#define _PCAPQUEUE_H_

#include <pcap.h>       /* for struct pcap_pkthdr */

#ifdef __cplusplus
extern "C" {
#endif 


/************************/
/*  STRUCT DEFINITIONS  */
/************************/

struct pcapqueue {
    struct pcap_pkthdr *next_hdr;
    const u_char *next_pkt;
    pcap_t *pcap_h;
    u_char is_empty;
};

/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int pcapqueue_init(struct pcapqueue *pq, pcap_t *p);

int pcapqueue_isempty(struct pcapqueue *pq);

int pcapqueue_peek(struct pcapqueue *pq, const struct pcap_pkthdr **h,
    const u_char **sp);

int pcapqueue_pop(struct pcapqueue *pq, const struct pcap_pkthdr **h,
    const u_char **sp);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _PCAPQUEUE_H_ */
