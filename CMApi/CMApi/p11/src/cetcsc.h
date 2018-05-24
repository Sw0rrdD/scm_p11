/******************************************************************************
 * Copyright (C),  Westone
 *
 * Author:         Dingyong        Version:1.0        Date:2014.11.19
 *
 * Description:    
 *
 * Others:			
 *
 * History:        
******************************************************************************/

#ifndef CETC_H_
#define CETC_H_

#include <stddef.h>
#include "sc_define.h"

/******************************************************************************
** Function: sc_transmit_apdu
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_transmit_apdu(sc_session_t *session, sc_apdu_t *apdu);

#endif /*CETC_H_*/
