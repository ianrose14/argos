/*
 * Author: Ian Rose
 * Date Created: Feb 26, 2009
 */

#ifndef _ARGOS_MODULES_HELLOWORLD_H_
#define _ARGOS_MODULES_HELLOWORLD_H_

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "argos/config.h"


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_helloworld_init(const struct argos_config_file *conf);

int argos_helloworld_finalize(void);

void argos_helloworld_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

#endif  /* #ifndef _ARGOS_MODULES_HELLOWORLD_H_ */
