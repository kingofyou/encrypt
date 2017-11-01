staticlib=-lrelevent -lpthread -lsoftencrypt -lsofttrans -lhardtrans -ldl -lm -L$(HOME)/lib
openssllib=-lcrypto -lssl -L$(HOME)/openssl/lib
incl = -I$(HOME)/relevent/inc 
inclp = -I$(HOME) -I$(HOME)/openssl
incsoft = -I$(HOME)/softencrypt/
inchard = -I$(HOME)/hardtrans/
frameobj = encrypt_run.o encrypt_server.o pthreadpool.o
encryptServer:$(frameobj)
	gcc -o encryptServer $^ $(staticlib) $(inclp) $(incl) $(incsoft) $(inchard) $(openssllib)
	rm -rf *.o
.c.o: 
	gcc -c $< $(staticlib) $(inclp) $(incl) $(incsoft) $(inchard) $(openssllib)
clean:
	rm -rf *.o $(HOME)/bin/encrypt
