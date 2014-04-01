
CC=gcc
CFLAGS=  -p -g -lnetfilter_queue -lnfnetlink -lpthread -ltinfo
LDFLAGS=
SOURCES=./bfw.c ./utils.c
EXECUTABLE=bfw

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)

