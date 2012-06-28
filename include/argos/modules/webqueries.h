/*
 * Author: Ian Rose
 * Date Created: Feb 26, 2009
 */

#ifndef _ARGOS_MODULES_WEBQUERIES_H_
#define _ARGOS_MODULES_WEBQUERIES_H_

/* local includes */
#include <pktparse.h>
#include "argos.h"
#include "argos/modules/tcpflows.h"


/*************************/
/*  METHOD DECLARATIONS  */
/*************************/

int argos_webqueries_exec_task(const struct timeval *clock);

int argos_webqueries_init(const struct argos_config_file *conf);

int argos_webqueries_finalize(void);

void argos_webqueries_handle_tcpflow(const struct argos_tcp_flow *flow);

#endif  /* #ifndef _ARGOS_MODULES_WEBQUERIES_H_ */
