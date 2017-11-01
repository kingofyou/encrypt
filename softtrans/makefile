incl= -I$(HOME)/relevent/inc 
inclp= -I$(HOME) -I$(HOME)/openssl
incsoft= -I$(HOME)/softencrypt/
softtransobj=300001.o 300002.o 300003.o 300004.o 300008.o\
	300011.o 300012.o 300013.o 300015.o 300016.o \
	300017.o 300023.o 300024.o \
	300027.o \
	300028.o 300029.o 300030.o 300031.o
libsofttrans.a:$(softtransobj)
	ar ruc $(HOME)/lib/libsofttrans.a $^ 
	rm -rf *.o
.c.o:
	gcc -c $< $(incl) $(incsoft) $(inclp) 
clean:
	rm -rf *.o $(HOME)/lib/libsofttrans.a