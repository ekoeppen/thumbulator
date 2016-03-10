
thumbulator : thumbulator.c
	gcc -g -o thumbulator -O2 thumbulator.c

clean :
	rm -f thumbulator

install : thumbulator
	install -d /usr/local/bin/
	install -m 0755 thumbulator /usr/local/bin/
