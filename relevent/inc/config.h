#ifndef __CONFIG_H__
#define __CONFIG_H__
#include <string.h>
#include <stdlib.h>
#include <unistd.h>  
#include <sys/stat.h>
#include <sys/types.h>
#include "writelog.h"

int OpenCfgFile(char *sFileName);
int getItem(char *itemName, char *itemValue);
int closeCfgFile();
char* ltrim(char* lptr);
char* rtrim(char* rptr);
#endif