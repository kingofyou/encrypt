#include "writelog.h"
/* 初始化日志文件 */
int InitLog( char * psModel)
{
	struct timeval tTp;
	struct tm * ptTm;
	//struct stat64 tStat;
	int nLogSize;
	char sBackupFile[300];
	char sDate[8+1];
	fp = NULL;
	pthread_mutex_init(&logMutex, NULL);

	gettimeofday(&tTp, NULL);
	ptTm = (struct  tm *)localtime( &(tTp.tv_sec) );

	l_nLogLevel = atoi( getenv("LOGLEVEL") );
	if( l_nLogLevel < 0 || l_nLogLevel > 3 )
		l_nLogLevel = 3 ;

	nLogSize = (atoi( getenv("LOGSIZE") )) * 1048576;
	if( nLogSize < 1 )
		nLogSize = 10485760;

	/* 系统日期, 格式：YYYYMMDD */
	memset( sDate, 0x00, sizeof( sDate ) );
	sprintf( sDate,"%04d%02d%02d",
			ptTm->tm_year + 1900, ptTm->tm_mon + 1, ptTm->tm_mday );

	sprintf( l_sLogFile,"%.100s", getenv("LOGDIR") );
	if( strlen(l_sLogFile) < 1 )
		sprintf( l_sLogFile,"%.100s/log",getenv("HOME") );

	//strcat( strcat( l_sLogFile, "/" ), sDate );

	mkdir(l_sLogFile, S_IRWXU);
    
#if 0
	memset( &tStat,0x00,sizeof(tStat) );
	if( stat64 (l_sLogFile, &tStat) )
	{
		printf( "stat64() error: %d, %s\n", errno, strerror(errno) );
    	return -1;
	}

	if( ! (tStat.st_mode & S_IRUSR) )
	{
		printf( "%s read permission denied\n", l_sLogFile );
		return -1;
	}

	if( ! (tStat.st_mode & S_IWUSR) )
	{
		printf( "%s write permission denied\n", l_sLogFile );
		return -1;
	}

	if( ! S_ISDIR(tStat.st_mode) )
	{
		printf( "%s is not a directory\n", l_sLogFile );
		return -1;
	}
#endif
	sprintf( l_sLogFile,"%s/%s.log",l_sLogFile,psModel );
#if 0
	memset( &tStat,0x00,sizeof(tStat) );
	if( stat64 (l_sLogFile, &tStat) == 0 )
	{
		if( tStat.st_size > nLogSize )
		{
			memset( sBackupFile,0x00,sizeof(sBackupFile) );
			sprintf( sBackupFile,"%s.%02d%02d%02d",
					l_sLogFile,
            		ptTm->tm_hour, ptTm->tm_min, ptTm->tm_sec );
			rename (l_sLogFile, sBackupFile);
		}
	}
#endif
	return 0;
}


/* 写交易LOG */
int WriteLog(int iLevel,char * psSrcFile,int nSrcLine,char * pcFmt, ... )
{
	va_list args;
	char * fmt;
	struct timeval tTp;
	struct tm * ptTm;

	if( iLevel > l_nLogLevel )
		return 0;

	gettimeofday(&tTp, NULL);
	ptTm = (struct  tm *)localtime( &(tTp.tv_sec) );

    char logfile[256]={};
	sprintf(logfile,"%s%04d%02d%02d",l_sLogFile,ptTm->tm_year+1900,ptTm->tm_mon+1,ptTm->tm_mday);
	pthread_mutex_lock(&logMutex);
    if(*logfile != (char)0x00) {
		fp = fopen(logfile,"a+");
		if(!fp) fp = stdout;
	}
	else {
		fp = stdout;
	}	

	fprintf( fp, "[%010u][%04d-%02d-%02d %02d:%02d:%02d.%06d %s %d:%s]",
				pthread_self(),ptTm->tm_year+1900,ptTm->tm_mon+1,ptTm->tm_mday,
				ptTm->tm_hour,ptTm->tm_min,ptTm->tm_sec,tTp.tv_usec,
				*(l_sLevel+iLevel),nSrcLine,psSrcFile );

	va_start(args, pcFmt);
	vfprintf(fp,pcFmt,args);
	va_end(args);
	
	fprintf ( fp,"\n" );

	if(fp) {
		fclose(fp);
		fp = NULL;
	}
	pthread_mutex_unlock(&logMutex);

	return 0;
}