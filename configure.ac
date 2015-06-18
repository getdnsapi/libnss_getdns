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

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lgetdns':
AC_CHECK_LIB([getdns], [getdns_create_context])

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
AC_SUBST(module_name, $MODULE_NAME)
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
