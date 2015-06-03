CC = cc
MODULE_NAME = nss_getdns.so.1
INSTALL_PATH = /opt/lib
LIBS_PATH = /usr/lib
LIBNAME = getdns-1.15.so
LIB_PATH = $(INSTALL_PATH)/$(LIBNAME)
LIB_ALIAS = $(LIBS_PATH)/$(MODULE_NAME)
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c))
CFLAGS = -I/usr/local/include -gdwarf-2 -O0 -fPIC -Wall
LDFLAGS = -L/usr/local/lib -shared -rdynamic -Wl,-soname,$(MODULE_NAME) -Wl,--no-undefined -lgetdns

obj : 
	$(CC) *.c $(CFLAGS)
	

build : $(OBJECTS)
	$(CC) $(OBJECTS) -o $(MODULE_NAME) $(LDFLAGS)
	
install : build     
	cp $(MODULE_NAME) $(LIB_PATH)
#	ldconfig -v $(INSTALL_PATH)
	ln -sf $(LIB_PATH) $(LIB_ALIAS)

clean :
	rm -f *.o *.c~ *.h~ $(MODULE_NAME)

