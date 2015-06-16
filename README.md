Enhanced System Resolver
========================

1. Purpose
__________
  The library provides an alternative for the system's resolver, adding modern DNS capabilities such as security and privacy.

2. Dependencies
_______________
  The library uses the getdns library (libgetdns) to mirror the resolution in getaddrinfo() and getnameinfo() with added DNSSEC support.
libgetdns and its dependencies must be install before building the library.

3. Supported platforms
______________________
  - Ubuntu
  - Centos
  - FreeBSD

4. Installing the library
_________________________
  - Basic installation: the shell commands `./configure; make build; make install' should configure, build and install this library.
  - There is an optional parameter to configure the library for preloading. When preloaded, the library intercepts calls to getaddrinfo() and getnameinfo() to serve them instead of them being handled by libc.
Use the --enable-api-intercept feature for this mode or try the help menu (-h) to the configure script for more details.

5. Configuration
__________________________
  - Enabling the library:
The library can be enabled via nsswitch for platforms that implement the name service switch interface, or by preloading. For the nsswitch option, simply replace the "dns" source for the "hosts" database by "getdns" in /etc/nsswitch.conf.
  - Configurring the library:
A configuration file (/etc/getdns.conf) will contain settings to override the library's default for DNSSEC and privacy.
By default, the library will perform DNSSEC validation and attempt to use TLS for server connections.
    -   A sample of non-default configurations will be given here. 
