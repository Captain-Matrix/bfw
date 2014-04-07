
CC=gcc
CFLAGS=  -p -g -lnetfilter_queue -lnfnetlink -lpthread -ltinfo
LDFLAGS=
SOURCES=./bfw.c ./utils.c ./server.c  ./processlog.c ./mongoose/mongoose.c 
SOURCES2=./processlog.c ./utils.c
EXECUTABLE=bfw
EXECUTABLE2=processlog

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)
processlog:$(SOURCES)
		 $(CC) $(CFLAGS) -o $(EXECUTABLE2) $(SOURCES2)
