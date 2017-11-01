#include "config.h"
static char sFullName[128];
static FILE* cfgFp;

/***********************************************************
 * 创建目录
 ***********************************************************/
int makeDir( char *spath)
{
    char confPath[500];
    int llResult, i , j;

    memset(confPath, 0, sizeof(confPath));
    strcpy(confPath, spath);
    j = strlen(confPath);
    for(i=1; i<=j; i++)
    {
        if(confPath[i] == '/' ||
           confPath[i] == '\0')
        {
            confPath[i] = 0;
            if(( llResult = access(confPath, 4)) != 0)
            {
                llResult = mkdir( confPath, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
                if(llResult != 0)
                {
                    return llResult;
                }
            }
            confPath[i] = '/';
        }
    }
    return 0;
}

int OpenCfgFile(char *sFileName)
{
	memset(sFullName, 0x00, sizeof(sFullName));
	
	if(getenv ("config_path")){
		strcpy(sFullName, (char *)getenv("config_path"));
	}
	if(strlen(sFullName) == 0) {
		strcpy(sFullName, (char *)getenv("HOME"));
		strcat(sFullName, "/etc/config.ini");
	}
	if(makeDir(sFullName)){
		WriteLog(LOG_DEBUG, "Call Top_MakeDir[%s] Error", sFullName);
		return (-1);
	}
	strcat(sFullName, "/");
	strcat(sFullName, sFileName);
	
	cfgFp = fopen(sFullName, "r");
	if (cfgFp == NULL ){
		WriteLog(LOG_DEBUG, "Can't open config File[%s]", sFullName);
		return -1;
	}	
	return 0;
}

int getItemBySection(char* sectionName, char *itemName, char *itemValue) {
	char sLine[256];
	char *pTmp = NULL;
	char *pTmpED = NULL;
	int  isFind = 0;
	char *pTempP = NULL;
	char sTempBuf[256];
	
	if(cfgFp == NULL){
		return (-1);	
	}	
	rewind(cfgFp);	
	while(fgets(sLine, sizeof(sLine), cfgFp)){
		if(sLine[0] == '#'){
			continue;	
		}
		/*左侧去除空格*/
		pTmp = ltrim(sLine);
		if(!isFind){
			/*最好不要直接去搜section名称,万一出现那种一个配置段的名字中包含另一个配置段的名字时就会有问题*/
			if(pTmp[0] == '[') {
				pTempP = pTmp+1;
				pTmpED =  strstr(pTempP, "]");
				if(pTmpED == NULL){
					WriteLog(LOG_DEBUG, "Section名配置节有问题, 应该为[section_name]!");
					return -1;
				}
				pTempP = ltrim(pTempP);

				memset(sTempBuf, 0x00, sizeof(sTempBuf));
				memcpy(sTempBuf, pTempP, pTmpED - pTempP);
				rtrim(sTempBuf);
				if(strcmp(sTempBuf, sectionName) == 0) {	
					isFind = 1;
				}
			}
			continue;
		} 
		else {
			/*判断是否到达了下一个Section了*/
			if(pTmp[0] == '[') {
				WriteLog(LOG_DEBUG, "当前Section[%s]所有的配置项已经找完,但没有找到配置项[%s]!", sectionName, itemName);
				return -1;
			}
			
			pTmp = strstr(pTmp, itemName);
			if(pTmp == NULL){
				continue;
			} 
			else {
				/*读取此段中对应item的值*/
				pTmp += (strlen(itemName) + 1);
				pTmpED = strstr(pTmp, "#");
				if(pTmpED != NULL){
					*pTmpED = '\0';
				}
				sprintf(itemValue, "%s", rtrim(pTmp));
				return 0;
			}
		}
	}
	WriteLog(LOG_DEBUG, "Cfg Item Can't be found[%s->%s->%s]", sFullName, sectionName, itemName);
	return -1;
}

int getItem(char *itemName, char *itemValue) {
	return getItemBySection("ENCRYPT", itemName, itemValue);
}

int closeCfgFile() {
	if(cfgFp != NULL)
		return fclose(cfgFp);
	return 0;
}

/*****************************************************************************
        函 数 名: ltrim
        功能描述: 去除左侧空格
        入口参数: lptr
        返 回 值: lptr
*****************************************************************************/
char* ltrim(char* lptr)
{
    char* ptrTmp = lptr;
	while(*ptrTmp++ == ' ') lptr++;	
	return lptr;
}
/*****************************************************************************
        函 数 名: rtrim
        功能描述: 去除右侧空格
        入口参数: ptr
        返 回 值: ptr
*****************************************************************************/
char* rtrim(char* rptr)
{
    char* ptrTmp = rptr + strlen(rptr) - 1;
    while(*ptrTmp == ' ') ptrTmp--;
    *++ptrTmp = '\0';
    return rptr;
}