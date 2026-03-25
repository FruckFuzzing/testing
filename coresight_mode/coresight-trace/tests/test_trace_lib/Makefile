CC = gcc
CFLAGS = -Wall -fPIC -g -O0
LDFLAGS = -shared
LIBNAME = libmylib.so 
APP = main


all: $(APP)

$(LIBNAME): mylib.c 
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(APP): main.c $(LIBNAME)
	$(CC) $(CFLAGS) main.c -L. -Wl,-rpath=. -lmylib -o $@

run: $(APP)
	LD_LIBRARY_PATH=. ./$(APP)

clean:
	rm -f $(APP) $(LIBNAME) *.o 

.PHONY: all run clean 