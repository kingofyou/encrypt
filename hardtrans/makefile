incl= -I$(HOME)/relevent/inc 
hardtransobj=EncryptTrans.o  \
	300001.o 300002.o 300003.o \
	300004.o 300005.o 300006.o \
	300007.o 300008.o 300009.o \
	300010.o 300011.o 300012.o \
	300013.o 300014.o 300015.o \
	300016.o 300017.o 300018.o \
	300019.o 300020.o 300021.o \
	300022.o 300023.o 300024.o \
        300025.o 300026.o 300027.o \
        300028.o 300029.o 300030.o
libhardtrans.a:$(hardtransobj)
	ar ruc $(HOME)/lib/libhardtrans.a $^ 
	rm -rf *.o
.c.o:
	gcc -c $< $(incl) 
clean:
	rm -rf *.o $(HOME)/lib/libhardtrans.a