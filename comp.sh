gcc -g -O0 -c nameinfo.c addrinfo.c -lgetdns -fPIC
gcc -shared -o libnss_getdns.so.2 -Wl,-soname,libnss_getdns.so.2 *.o
#cp libnss_getdns.so.2 /opt/lib/libnss_getdns-2.15.so
#ln -sf /opt/lib/libnss_getdns-2.15.so /lib/libnss_getdns.so.2
