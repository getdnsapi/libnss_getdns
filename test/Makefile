CC = gcc
CTX_PROXY = unix
CTX_PROXY_IMPL = /home/hbucuti/getdns/ipc/context_proxies/unix/*.c
EXTRA_DEPS_INCLUDES = 
EXTRA_LDLIBS = 
CTX_PROXY_IMPL = /home/hbucuti/getdns/ipc/context_proxies/unix/*.c
CFLAGS = $(DEFS) -I/usr/local/include $(EXTRA_DEPS_INCLUDES) -g -Werror 
LDLIBS = -lm -lgetdns -lunbound -lidn -lldns -ldl  -lcrypto -lssl $(EXTRA_LDLIBS)

all : browser_detect options_parse getaddrinfo http_test

test : options_parse_test getaddrinfo_test browsers_test clean
	
browser_detect : browser_detect_test.c ../browsers.c ../opt_parse.c ../browsers.h
	$(CC) -o browser_detect_test browser_detect_test.c ../opt_parse.c ../browsers.c -lm

browsers_test : browser_detect
	./browser_detect_test
	
options_parse : opt_parse_test.c ../opt_parse.c ../opt_parse.h
	$(CC) -o opt_parse_test opt_parse_test.c ../opt_parse.c
	
options_parse_test : options_parse
	./opt_parse_test

http_test: http_test.c ../*.c ../services/*.c $(CTX_PROXY_IMPL)
ifneq ($(CTX_PROXY),)
	$(CC) -o http_test http_test.c ../*.c ../services/*.c $(CTX_PROXY_IMPL) $(CFLAGS) $(LDLIBS) -DHTTP_MAIN
else
	$(CC) -o http_test http_test.c ../*.c ../services/*.c $(CFLAGS) $(LDLIBS) -DHTTP_MAIN
endif

getaddrinfo : gai_test.c ../*.c ../services/*.c $(CTX_PROXY_IMPL)
ifneq ($(CTX_PROXY),)
	$(CC) -o gai_test gai_test.c ../*.c ../services/*.c $(CTX_PROXY_IMPL) $(CFLAGS) $(LDLIBS)
else
	$(CC) -o gai_test gai_test.c ../*.c ../services/*.c $(CFLAGS) $(LDLIBS)
endif
	 
getaddrinfo_test : getaddrinfo
	./gai_test getdns-config.localhost 4 1
	./gai_test getdns-errors.localhost 4 1
	./gai_test getdnsapi.net 4 1
	./gai_test getdnsapi.net 6 1
	./gai_test getdnsapi.net 7 1
	./gai_test dnssec-failed.org 4 1
	time ./gai_test getdnsapi.net 4 10
	time ./gai_test getdnsapi.net 4 100
	time ./gai_test getdnsapi.net 4 1000

	
clean :
	-rm -f gai_test browser_detect_test opt_parse_test *.o *~ *.html.* *.out *.html *.conf *.desktop

