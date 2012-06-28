/*
 * Author: Ian Rose
 * Date Created: Jan 22, 2009
 *
 * Network-related utility functions.
 */

#ifndef _ORION_NET_H_
#define _ORION_NET_H_

#include <netinet/in.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

uint8_t orion_net_get_channel(const char * restrict ifname);

int orion_net_lookup_inaddr(const char * restrict hostname, int port,
    int socktype, struct sockaddr_in * restrict sa);

int orion_net_lookup_macaddr(const char * restrict ifname,
    u_char * restrict mac_addr);

int orion_net_set_channel(const char * restrict ifname, uint8_t channel,
    char mode);

int orion_net_sockbind(int sock, const char * restrict hostname, int port);

#ifdef __cplusplus
}
#endif 

#endif  /* #ifndef _ORION_NET_H_ */
