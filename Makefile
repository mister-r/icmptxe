flags=-g3 -Wall -ansi -pedantic -D_GNU_SOURCE

all: icmptx

icmptx: it.o icmptxe.c tun_dev.o
	gcc $(flags) -o icmptxe icmptxe.c it.o tun_dev.o

it.o: it.c tun_dev.h
	gcc $(flags) -c it.c

tun_dev.o: tun_dev.c
	gcc $(flags) -c tun_dev.c

clean:
	rm -f tun_dev.o it.o icmptxe
