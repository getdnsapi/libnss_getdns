CC = gcc
MODULE_NAME = libnss_getdns.so.2
INSTALL_PATH = /opt/lib
LIBS_PATH = /lib
LIBNAME = libnss_getdns-2.15.so
LIB_PATH = $(INSTALL_PATH)/$(LIBNAME)
LIB_ALIAS = $(LIBS_PATH)/$(MODULE_NAME)
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))
CFLAGS = -gdwarf-2 -g3 -O0 -c -fPIC -Wall -lgetdns
LDFLAGS = -shared -Wl,-soname,$(MODULE_NAME) -Wl,--no-undefined -lgetdns

obj : $(OBJECTS)
	$(CC) *.c $(CFLAGS)
	$(CC) $(OBJECTS) -o $(MODULE_NAME) $(LDFLAGS)
	
install : $(MODULE_NAME)     
	cp $(MODULE_NAME) $(LIB_PATH)
	ldconfig -v -n $(INSTALL_PATH)
	ln -sf $(LIB_PATH) $(LIB_ALIAS)

clean :
	rm -f *.o *.c~ *.h~ $(MODULE_NAME)

