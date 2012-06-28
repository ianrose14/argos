/*
 * Author: Ian Rose
 * Date Created: Jun 2, 2009
 *
 * Definitions common to both the Argos sniffer and server.
 */

#ifndef _ARGOS_COMMON_H_
#define _ARGOS_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

/***************/
/*  CONSTANTS  */
/***************/

/* string sizes */
#define ARGOS_MAX_HOSTNAME_LEN 255
#define ARGOS_MAX_IFNAME_LEN 127
#define ARGOS_MAX_PATH_LEN 511

#define MILLION 1000000

#define MAX_80211G_CHANNEL 11  /* in the U.S., at least */


/************/
/*  MACROS  */
/************/

#define timeval2usec(tv) (tv.tv_sec*(uint64_t)MILLION + tv.tv_usec)


#ifdef __cplusplus
}
#endif

#endif  /* #ifndef _ARGOS_COMMON_H_ */
