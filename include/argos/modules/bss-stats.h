/*
 * Author: Ian Rose
 * Date Created: Feb 26, 2009
 */

#ifndef _ARGOS_MODULES_BSS_STATS_H_
#define _ARGOS_MODULES_BSS_STATS_H_

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "argos/config.h"


/***************/
/*  CONSTANTS  */
/***************/

#define BSS_STATS_DEF_INTERVAL 60 /* seconds */


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_bssstats_exec_task(const struct timeval *clock);

int argos_bssstats_finalize(void);

void argos_bssstats_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

int argos_bssstats_init(const struct argos_config_file *conf);

#endif  /* #ifndef _ARGOS_MODULES_BSS_STATS_H_ */
