#ifndef _MYDEBUG_H
#define _MYDEBUG_H

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
 
#define DEBUG_FILE_PATH  "/var/log/mydebug.log"

//用法：必须加前三个编译选项，否则会出现??
//gcc -g -rdynamic -no-pie main.c -finstrument-functions -o hello
//./translate.sh hello mydebug.log new.log
 
void  __attribute__((no_instrument_function)) 
debug_log(const char *format,...);


void  __attribute__((no_instrument_function))
__cyg_profile_func_enter(void *this, void *call);
 
void  __attribute__((no_instrument_function))
__cyg_profile_func_exit(void *this, void *call);
#endif
