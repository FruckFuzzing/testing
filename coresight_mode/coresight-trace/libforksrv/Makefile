.PHONY: all clean

CFLAGS = -fPIC -Wall -Wextra
LDFLAGS = -shared -ldl

all: libforksrv.so

libforksrv.so: libforksrv.c
	-@$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@  

clean:
	rm -f libforksrv.so

