MODULE_NAME=libnss_getdns.so.2
DBUS_SERVICE_FILE=net.getdnsapi.StubResolver.service
DBUS_SERVICES_DIR=/usr/share/dbus-1/services
DBUS_INTERFACE_FILE=net.getdnsapi.StubResolver.xml
DBUS_INTERFACES_DIR=/usr/share/dbus-1/interfaces
SERVICE_EXEC_DIR=/usr/local/share/getdns_module
DEFS=-DHAVE_CONFIG_H
CONTEXT_DAEMON_EXEC=getdns_daemon
TEST_DIR=test
PRELOAD_LIB = no
CTX_PROXY = 
CTX_PROXY_IMPL = 
EXTRA_DEPS_INCLUDES = 
EXTRA_LDLIBS = 
CC = gcc
INSTALL_PATH = ${exec_prefix}/lib
LIBS_PATH = ${exec_prefix}/lib
LIBNAME = getdns_shim-1.15.so
LIB_PATH = $(LIBS_PATH)/$(LIBNAME)
LIB_ALIAS = $(LIBS_PATH)/$(MODULE_NAME)
OBJECTS = $(patsubst %.c,%.o,$(wildcard *.c services/*.c))
CFLAGS = $(DEFS) -I/usr/local/include $(EXTRA_DEPS_INCLUDES) -gdwarf-2 -O0 -fPIC -Wall
LDFLAGS = -L/usr/local/lib -shared -rdynamic -Wl,-soname,$(MODULE_NAME) -Wl,--no-undefined 
LDLIBS = -lm -lgetdns -lunbound -lidn -lldns -ldl  -lcrypto -lssl $(EXTRA_LDLIBS)

build : $(OBJECTS)
ifneq ($(CTX_PROXY), )
	$(CC) $(OBJECTS) $(CTX_PROXY_IMPL) -o $(MODULE_NAME) $(CFLAGS) $(LDFLAGS) $(LDLIBS)
	$(CC) -DMAIN $(OBJECTS) $(CTX_PROXY_IMPL) -o $(CONTEXT_DAEMON_EXEC) $(CFLAGS) $(LDLIBS)
else
	$(CC) $(OBJECTS) -o $(MODULE_NAME) $(LDFLAGS) $(LDLIBS)
endif

build_tests :
	$(MAKE) -C $(TEST_DIR)
	
test : build_tests
	$(MAKE) -C $(TEST_DIR) test
	
install : build    
	cp $(MODULE_NAME) $(LIB_PATH)
	ldconfig -v $(INSTALL_PATH)
	ln -sf $(LIB_PATH) $(LIB_ALIAS)
ifeq ($(CTX_PROXY), dbus)
	cp data/$(DBUS_SERVICE_FILE) $(DBUS_SERVICES_DIR)/$(DBUS_SERVICE_FILE)
	cp data/$(DBUS_INTERFACE_FILE) $(DBUS_INTERFACES_DIR)/$(DBUS_INTERFACE_FILE)
	mkdir -p $(SERVICE_EXEC_DIR)
	cp $(CONTEXT_DAEMON_EXEC) $(SERVICE_EXEC_DIR)/$(CONTEXT_DAEMON_EXEC)
endif
	cp data/error.html $(SERVICE_EXEC_DIR)/error.html
	cp data/settings.html $(SERVICE_EXEC_DIR)/settings.html
	cp data/getdns.conf /etc/getdns.conf
	sh ./activate.sh
	
uninstall:
	sh ./activate.sh --reverse
	yes | rm -f $(LIB_ALIAS) $(LIB_PATH) $(DBUS_INTERFACES_DIR)/$(DBUS_INTERFACE_FILE) $(DBUS_SERVICES_DIR)/$(DBUS_SERVICE_FILE) $(CONTEXT_DAEMON_EXEC)
	ldconfig -v $(INSTALL_PATH)

obj : 
	$(CC) *.c $(CFLAGS)
	
clean :
	rm -f *.o *.c~ *.h~ services/*~ services/*.o contexts/*~ contexts/*.o $(MODULE_NAME) $(CONTEXT_DAEMON_EXEC)
	$(MAKE) -C $(TEST_DIR) clean
	
.PHONY: clean test

