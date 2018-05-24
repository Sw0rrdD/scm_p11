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

#ifndef __LIBSCDL_H
#define __LIBSCDL_H

/******************************************************************************
** Function: sc_dlopen
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void *sc_dlopen(const char *filename);

/******************************************************************************
** Function: sc_dlsym
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
void *sc_dlsym(void *handle, const char *symbol);

/******************************************************************************
** Function: sc_dlclose
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
int sc_dlclose(void *handle);

/******************************************************************************
** Function: sc_dlerror
**
** Description
**
** Parameters:
**  none
**
** Returns:
**  none
*******************************************************************************/
const char *sc_dlerror(void);

#endif
