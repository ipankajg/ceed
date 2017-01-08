CC=gcc
CFLAGS=-w -std=c99
DEPS = ceed.h ceed.tab.h
OBJ = lex.yy.o ceed.tab.o ceedcmpl.o ceedelf.o ceedpe.o ceedrtl.o

lex.yy.c ceed.tab.c ceed.tab.h: ceed.l ceed.y
	bison -d ceed.y
	flex ceed.l

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

all: ceed

ceed: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

clean:
	rm -f *.o
	rm -f lex.yy.c ceed.tab.c ceed.tab.h
	rm -f ceed ceed.exe

