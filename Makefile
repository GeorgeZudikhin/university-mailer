#############################################################################################
# Makefile
#############################################################################################
CC = g++
CFLAGS = -g -Wall -Wextra -O -std=c++17 

rebuild: clean all

all: ./bin/server ./bin/client

clean:
	clear
	rm -f bin/twmailer-client bin/twmailer-server obj/myserver.o obj/myclient.o

./obj/myclient.o: myclient.cpp
	${CC} ${CFLAGS} -o obj/myclient.o myclient.cpp -c

./obj/myserver.o: myserver.cpp
	${CC} ${CFLAGS} -o obj/myserver.o myserver.cpp -c 

./bin/server: ./obj/myserver.o
	${CC} ${CFLAGS} -o bin/twmailer-server obj/myserver.o -lldap -llber

./bin/client: ./obj/myclient.o
	${CC} ${CFLAGS} -o bin/twmailer-client obj/myclient.o -lldap -llber