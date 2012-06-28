/*
 * Author: Ian Rose
 * Date Created: Jul 7, 2009
 */

#ifndef _ARGOS_SNIFFER_H_
#define _ARGOS_SNIFFER_H_

/* system includes */
#include <pcap/pcap.h>

/* local includes */
#include "argos/common.h"


/***************/
/*  CONSTANTS  */
/***************/

/* defaults for command line arguments / config file settings */
#define ARGOS_DEF_CONFIG            "argos.cfg"
#define ARGOS_DEF_DLTNAME           "IEEE802_11_RADIO"
#define ARGOS_DEF_IFNAME            "ath0"
#define ARGOS_DEF_LOGDIR            "."
#define ARGOS_DEF_LOGNAME           "main.log"
#define ARGOS_DEF_CLICK_PIDFILE     "click.pid"
#define ARGOS_DEF_SNAPLEN           2048       /* 2 KB */
#define ARGOS_DEF_STATS_INTERVAL    10         /* seconds */

/* priority levels to use when registering file descriptors with async */
#define ARGOS_CHILD_READ_ASYNCPRIO   10


#endif  /* #ifndef _ARGOS_SNIFFER_H_ */
