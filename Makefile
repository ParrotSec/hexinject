all:
	gcc -std=gnu89 -o hexinject hexinject.c -lpcap
	gcc -std=gnu89 -o prettypacket prettypacket.c
	gcc -std=gnu89 -o hex2raw hex2raw.c

clean:
	rm -f hexinject prettypacket hex2raw *~

