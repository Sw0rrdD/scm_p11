/*
 * main.c
 *
 *  Created on: September 29, 2017
 *      Author: root
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11.h"
#include "init_card.h"
#include "p11_model_test.h"



int main()
{
	CK_RV rv = CKR_OK;
	
	rv = scm_init("12345678", NULL, "0123456789");
	if(rv != 0)
	{
		printf("scm_init failed! ret:%d!\n", (CK_UINT)rv);
		return -1;
	}

	rv = p11_model_test();
	if(rv != 0)
	{
		printf("p11_model_test failed! ret:%d!\n", rv);
		return -1;
	}

	rv = scm_release();
	if(rv != 0)
	{
		printf("scm_release failed! ret:%d!\n", (CK_UINT)rv);
		return -1;
	}
	
	printf("p11_model_test success!\n");

	return 0;
}

