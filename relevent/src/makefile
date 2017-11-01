releventobj=cJSON.o config.o writelog.o
incl=-I../inc
librelevent.a:$(releventobj)
	ar ruc $(HOME)/lib/librelevent.a $^ 
	rm -rf *.o
.c.o:
	gcc -c $< $(incl) 
clean:
	rm -rf *.o $(HOME)/lib/librelevent.a