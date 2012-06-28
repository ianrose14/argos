/*
 * Author: Ian Rose
 * Date Created: May 4, 2009
 */

#ifndef _ARGOS_MODULES_FIDELITY_H_
#define _ARGOS_MODULES_FIDELITY_H_

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "argos/config.h"


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_fidelity_exec_task(const struct timeval *clock);

int argos_fidelity_init(const struct argos_config_file *conf);

int argos_fidelity_finalize(void);

void argos_fidelity_handle_packet(const struct argos_producer *producer,
    const struct packet *pkt, uint8_t channel);

#endif  /* #ifndef _ARGOS_MODULES_FIDELITY_H_ */
