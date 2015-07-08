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
USE_CTX_PROXY="no"
EXTRA_DEPS_INCLUDES=""
CTX_PROXY_IMPL=""
AC_ARG_WITH([context-proxy],
  [--with-context-proxy	Configure the module to use a DBUS-facilitated context manager.],
  [AC_CHECK_LIB([dbus-1], [dbus_message_set_auto_start], 
 	[AC_DEFINE([HAVE_CONTEXT_PROXY], 1, [Use a managed getdns context via a context proxy]) USE_CTX_PROXY="yes" 
 	EXTRA_DEPS_INCLUDES="$(pkg-config --cflags dbus-glib-1)" CTX_PROXY_IMPL="$(pwd)/contexts/*.c"], 
 	AC_MSG_FAILURE([dbus not available on this system. Please install dbus before continuing.], 1),
 	[]) 
  ])

AC_SUBST(use_dbus, $USE_CTX_PROXY)
AC_SUBST(ctx_proxy_impl, $CTX_PROXY_IMPL)

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
	;;
*Linux*)
	MODULE_NAME=libnss_getdns.so.2
	;;
esac
AC_SUBST(dbus_includes, $EXTRA_DEPS_INCLUDES)
AC_SUBST(module_name, $MODULE_NAME)
AC_SUBST(dbus_service_file, net.getdnsapi.StubResolver.service)
AC_SUBST(dbus_interface_file, net.getdnsapi.StubResolver.xml)
AC_SUBST(dbus_services_dir, /usr/share/dbus-1/services)
AC_SUBST(dbus_interfaces_dir, /usr/share/dbus-1/interfaces)
AC_SUBST(dbus_service_exec_dir, /usr/local/share/getdns_module)
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([test/Makefile])
AC_OUTPUT
