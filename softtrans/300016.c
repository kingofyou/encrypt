#include "md5encrypt.h"
#include "sha1.h"
#include "softexec.h"

struct REQ300016 {
	char mech[2];
	char abstractLength[4+1];
	char abstract[512];
} req300016;

int unpack300016(char *reqMsg) {
	memset(&req300016, 0, sizeof(req300016));
	cJSON *reqRoot = cJSON_Parse(reqMsg);
	cJSON *tmpJson = cJSON_GetObjectItem(reqRoot,"abstractLength");
	if(tmpJson)
	    memcpy(req300016.abstractLength, tmpJson->valuestring, 4);
	else {
        free(reqRoot);
		return -1;
	}
	tmpJson = cJSON_GetObjectItem(reqRoot,"abstract");
	if(tmpJson)
	    memcpy(req300016.abstract, tmpJson->valuestring, atoi(req300016.abstractLength));
	else {
        free(reqRoot);
		return -1;
	}
	
	tmpJson = cJSON_GetObjectItem(reqRoot,"mech");
	if(tmpJson)
	    memcpy(req300016.mech, tmpJson->valuestring, 1);
	else {
        free(reqRoot);
		return -1;
	}
	
	if(reqRoot) {
	    free(reqRoot);
		reqRoot = NULL;
	}
	return 0;
}

int exec300016s(char *reqMsg, char* rspMsg) {
	WriteLog(LOG_DEBUG, "reqMsg=[%s]", reqMsg);
	if(!strlen(reqMsg)) {
        return errMsgs(rspMsg);
    }
	if(unpack300016(reqMsg)) {
		return errMsgs(rspMsg);
	}
	unsigned char digest[64]={};
	cJSON* rspRoot = cJSON_CreateObject(); 
	if(!memcmp("0", req300016.mech, 1)) {
		unsigned char ensrc[64] = {};
		sha1Encrypt(req300016.abstract, ensrc);
	    int i=0;
		unsigned char tmp[2+1];
	    for(; i<20; i++) {
		    memset(tmp, 0, sizeof(tmp));
		    sprintf(tmp, "%02X", ensrc[i]);
		    strcat(digest, tmp);
	   }
	   cJSON_AddStringToObject(rspRoot, "retCode", "00");  
	}
	else if(!memcmp("1", req300016.mech, 1)) {
	    md5encrypt(req300016.abstract, digest);	    
	    cJSON_AddStringToObject(rspRoot, "retCode", "00");  	    
	}
	
	cJSON_AddStringToObject(rspRoot, "digest", digest);
	strcpy(rspMsg, cJSON_Print(rspRoot));
		
	if(rspRoot) {
	    free(rspRoot);
		rspRoot = NULL;
	}
	WriteLog(LOG_DEBUG, "rspMsg=[%s]", rspMsg);
	
	return 0;
}
	
	
	
	
	
	
	
	
	
	
	
	