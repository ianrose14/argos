/*
 * Author: Ian Rose
 * Date Created: Mar 31, 2009
 */

#ifndef _ARGOS_MODULES_KEEPALIVE_H_
#define _ARGOS_MODULES_KEEPALIVE_H_

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "argos/config.h"


/***************/
/*  CONSTANTS  */
/***************/

#define KEEPALIVE_DEF_INTERVAL 60 /* seconds */


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_keepalive_exec_task(const struct timeval *clock);

int argos_keepalive_init(const struct argos_config_file *conf);

int argos_keepalive_finalize(void);

void argos_keepalive_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

#endif  /* #ifndef _ARGOS_MODULES_KEEPALIVE_H_ */
