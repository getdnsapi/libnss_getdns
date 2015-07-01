CC = gcc
CFLAGS = -lm -lgetdns -levent -levent_core -lgetdns_ext_event -Werror
#Dependencies
OBJECTS = $(patsubst %.c,%.o,$(wildcard proc/*.c)) $(patsubst %.c,%.o,$(wildcard schedulers/*.c)) schedulers/sort/sort.o

all : browser_detect options_parse getaddrinfo

test : options_parse_test getaddrinfo_test browsers_test clean
	
browser_detect : browser_detect_test.c ../browsers.c ../browsers.h
	$(CC) -o browser_detect_test browser_detect_test.c ../browsers.c -lm

browsers_test : browser_detect
	./browser_detect_test
	
options_parse : opt_parse_test.c ../opt_parse.c ../opt_parse.h
	$(CC) -o opt_parse_test opt_parse_test.c ../opt_parse.c
	
options_parse_test : options_parse
	./opt_parse_test
	
getaddrinfo : gai_test.c ../*.c
	$(CC) -o gai_test gai_test.c ../*.c $(CFLAGS) 
getaddrinfo_test : getaddrinfo
	./gai_test getdnsapi.net 4
	./gai_test getdnsapi.net 6
	./gai_test getdnsapi.net 7
	./gai_test dnssec-failed.org 4
	./gai_test dnssec-failed.org 6
	./gai_test dnssec-failed.org 7

clean :
	-rm -f gai_test browser_detect_test opt_parse_test *.o *~ *.html.* *.out *.html *.conf *.desktop

