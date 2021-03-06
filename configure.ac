#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([getdns_sysmodule], [0.1], [stubresolver@getdnsapi.net])
AC_CONFIG_SRCDIR([hosts.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks getdns library.
AC_CHECK_LIB([getdns], [getdns_context_create],[], AC_MSG_FAILURE([libgetdns is required but not found on the system. Please install it first.], 1))

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS([nss.h nsswitch.h arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([memmove memset strchr strndup strtol])

# Build with dbus-daemon for IPC
EXTRA_DEPS_INCLUDES=""
EXTRA_LDLIBS=""
AC_ARG_WITH([context-proxy], AS_HELP_STRING([--with-context-proxy=relative_path_to_dir],  [Configure with a context proxy implemented in the directory. (default: unix).]))

case "x$with_context_proxy" in
    xno)
    	;;
    x|xyes)
	AC_DEFINE_UNQUOTED([HAVE_CONTEXT_PROXY], [1], [Use a managed getdns context via a context proxy])
	CTX_PROXY="unix"
	CTX_PROXY_IMPL="$(pwd)/context_proxies/$CTX_PROXY/*server.c"
	;;
    *)
	AC_DEFINE_UNQUOTED([HAVE_CONTEXT_PROXY], [1], [Use a managed getdns context via a context proxy])
	CTX_PROXY="$with_context_proxy"
	CTX_PROXY_IMPL="$(pwd)/context_proxies/$with_context_proxy/*server.c"
	;;
esac

if test x_$CTX_PROXY = x_dbus; then
	AC_CHECK_LIB([dbus-1], [dbus_message_set_auto_start], 
 	[EXTRA_DEPS_INCLUDES="$(pkg-config --cflags dbus-glib-1)" EXTRA_LDLIBS="-ldbus-1"], 
 	AC_MSG_FAILURE([dbus not available on this system. Please install dbus before continuing.], 1),
 	[])
elif test x_$CTX_PROXY = x_unix ; then
	AC_DEFINE_UNQUOTED([HAVE_HTTP_SERVICE], [1], [Run http service in the async context proxy])
fi

AC_ARG_ENABLE(daemon-only-mode, AC_HELP_STRING([--disable-daemon-only-mode], [Disable the lookup and https support services through a seperate daemon process only.  Beware!: Disabling will cause calling processes to fork() and run as lookup/http services. (default is enable)]))
case "$enable_daemon_only_mode" in
        no)
                ;;
        yes|*)
                AC_DEFINE_UNQUOTED([DAEMON_ONLY_MODE], [1], [Define this to enable lookup and http services to be run by a separate daemon.])
                ;;
esac

# Specify build information
PRELOAD_OPTION="no"
AC_ARG_ENABLE(api-intercept,
 [ --enable-api-intercept  Configure the library for preloading (to intercept API functions before libc)],
 [ AC_DEFINE([ENABLE_API_INTERCEPT], 1, [Configure the library for LD_PRELOADing (to intercept API functions before libc.)]) 
   PRELOAD_OPTION="yes"])
AC_SUBST(preload_on_install, $PRELOAD_OPTION)

os="$(uname -s)"
case $os in
*BSD*)
	MODULE_NAME=nss_getdns.so.1
	#port-forwarding currently not enabled for *BSD
	port_forward_set=
	port_forward_unset=
	AC_SUBST(init_script_start_cmd, "service getdns-pfw start")
	;;
*Linux*)
	MODULE_NAME=libnss_getdns.so.2
	IPTABLES_NAT_ADD="iptables -t nat -A OUTPUT -p tcp --dst 127.127.127.128,127.127.127.127 --dport 80 -j REDIRECT --to-ports 8080"
	IPTABLES_NAT_DEL="iptables -t nat -D OUTPUT -p tcp --dst 127.127.127.128,127.127.127.127 --dport 80 -j REDIRECT --to-ports 8080"
	AC_SUBST(init_script_start_cmd, "service getdns-pfw start")
	;;
esac

#Create init scripts for port forwarding activation for error pages
AC_CONFIG_FILES([data/getdns-pfw-upstart], [mv data/getdns-pfw-upstart conf/getdns-pfw.conf])
AC_CONFIG_FILES([data/getdns-pfw-sysv], [mv data/getdns-pfw-sysv conf/getdns-pfw])
AC_CONFIG_FILES([data/getdns-pfw.sh], [mv data/getdns-pfw.sh conf/getdns-pfw.sh])
AC_CONFIG_FILES([data/getdns-pfw-systemd], [mv data/getdns-pfw-systemd conf/getdns-pfw.service])
AC_CONFIG_FILES([data/getdns-pfw-bsd], [mv data/getdns-pfw-bsd conf/getdns-pfw-bsd])
#Create default getdns config file
AC_CONFIG_FILES([data/getdns.conf.example], [mv data/getdns.conf.example conf/getdns.conf])
#Makefile substitutions
AC_SUBST(ctx_proxy, $CTX_PROXY)
AC_SUBST(ctx_proxy_impl, $CTX_PROXY_IMPL)
AC_SUBST(extra_ldlibs, $EXTRA_LDLIBS)
AC_SUBST(extra_includes, $EXTRA_DEPS_INCLUDES)
AC_SUBST(module_name, $MODULE_NAME)
AC_SUBST(port_forward_set, $IPTABLES_NAT_ADD)
AC_SUBST(port_forward_unset, $IPTABLES_NAT_DEL)

AC_SUBST(dbus_service_file, net.getdnsapi.StubResolver.service)
AC_SUBST(dbus_interface_file, net.getdnsapi.StubResolver.xml)
AC_SUBST(dbus_services_dir, /usr/share/dbus-1/services)
AC_SUBST(dbus_interfaces_dir, /usr/share/dbus-1/interfaces)
AC_SUBST(dbus_service_exec_dir, /usr/local/share/getdns_module)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_OUTPUT
