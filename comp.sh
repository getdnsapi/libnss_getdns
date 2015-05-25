gcc -g -O0 -c -fPIC -Wall nameinfo.c addrinfo.c common.c -lgetdns
gcc -shared -o libnss_getdns.so.2 -Wl,-soname,libnss_getdns.so.2 *.o -lgetdns -Wl,--no-undefined
cp libnss_getdns.so.2 /opt/lib/libnss_getdns-2.15.so
ldconfig -v -n /opt/lib
ln -sf /opt/lib/libnss_getdns.so.2 /lib/libnss_getdns.so.2
