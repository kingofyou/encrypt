inclp= -I$(HOME) -I$(HOME)/openssl
incl= -I$(HOME)/relevent/inc 
softencryptobj=rsaencrypt.o 3desencrypt.o md5encrypt.o  \
	sm3.o sm4.o aes.o sha1.o
libsoftencrypt.a:$(softencryptobj)
	ar ruc $(HOME)/lib/libsoftencrypt.a $^ 
	rm -rf *.o
.c.o:
	gcc -c $< $(incl) $(inclp)
clean:
	rm -rf *.o $(HOME)/lib/libsoftencrypt.a