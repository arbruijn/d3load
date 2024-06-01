CFLAGS += -Wall -g -m32
LDLIBS += -lGL -lSDL2 -lm

d3load: d3load.o winapi.o heap.o sdlkeymap.o lj_gdbjit.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o

winapi.o: winapi.c funs.h defs.h

