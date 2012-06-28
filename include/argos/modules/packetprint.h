/*
 * Author: Ian Rose
 * Date Created: Feb 26, 2009
 */

#ifndef _ARGOS_MODULES_PACKETPRINT_H_
#define _ARGOS_MODULES_PACKETPRINT_H_

/* local includes */
#include <pktparse.h>
#include "argos/server.h"
#include "argos/sniffer.h"  // todo
#include "orion/config.h"


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_packetprint_init(const struct orion_config_file *conf);

int argos_packetprint_finalize(void);

void argos_packetprint_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

#endif  /* #ifndef _ARGOS_MODULES_PACKETPRINT_H_ */
