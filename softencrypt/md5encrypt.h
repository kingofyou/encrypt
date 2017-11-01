#ifndef __MD5_ENCRYPT__
#define __MD5_ENCRYPT__
#include "softexec.h"
#define F(x,y,z) (((x)&(y))|((~x)&(z)))  
#define G(x,y,z) (((x)&(z))|((y)&(~z)))  
#define H(x,y,z) ((x)^(y)^(z))  
#define I(x,y,z) ((y)^((x)|(~z)))  
//数据移位处理  
#define ROT(x,s) (x=(x<<s)|(x>>(32-s)))  
#define FF(a,b,c,d,j,s,T) {a=a+(F(b,c,d)+M[j]+T);ROT(a,s);a=a+b;}  
#define GG(a,b,c,d,j,s,T) {a=a+(G(b,c,d)+M[j]+T);ROT(a,s);a=a+b;}  
#define HH(a,b,c,d,j,s,T) {a=a+(H(b,c,d)+M[j]+T);ROT(a,s);a=a+b;}  
#define II(a,b,c,d,j,s,T) {a=a+(I(b,c,d)+M[j]+T);ROT(a,s);a=a+b;} 

typedef unsigned int md5_int;
typedef struct MD5_struct  
{  
    md5_int A;  
    md5_int B;  
    md5_int C;  
    md5_int D;  
    md5_int lenbuf;      
    char buffer[128];  
} MD5_struct; 

void initmd5();
void md5_init(MD5_struct* ctx, char * buffer);  
void md5_process(MD5_struct* ctx);  
char * md5_fini(MD5_struct *ctx, char* md5den);  
void md5_buffer_full(MD5_struct * ctx);  
void md5_print(MD5_struct * ctx); 
char* md5encrypt(char* message, char* md5den);

#endif