
thumbulator : thumbulator.c
	gcc -g -o thumbulator -O2 thumbulator.c

clean :
	rm -f thumbulator

install : thumbulator
	install -D thumbulator /usr/local/bin/thumbulator
