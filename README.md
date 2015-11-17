Study code for an enhanced Stub-Resolver with getdns
====================================================

1. Purpose
__________
  This project is the codebase which is part of a study into providing an alternative for the system's resolver, adding modern DNS capabilities such as security and privacy.
  This study has been performed by Theogene H. Bucuti, from the University of North Texas, as a student project at Verisign Labs under the supervision of Gowri Visweswaran and Allison Mankin.
  This code's purpose is to explore the different possibilities to provide system stub alternatives and compare the usability, possibilities and impossibilities of the different options.
  This software is a Proof of Concept and (in its current state) by no means intended to be used in production.
  It is here solely to demonstrate the increased functionality and enriched opportunities that a new modern stub resolver, like getdns, can offer applications, even without applications being aware.

2. Dependencies
_______________
  The library uses the getdns library (libgetdns) to mirror the resolution in getaddrinfo() and getnameinfo() with added DNSSEC support.
libgetdns and its dependencies must be installed before building the library.

3. Supported platforms
______________________
  - Ubuntu
  - CentOS
  - Debian
  - FreeBSD

4. Installing the library
_________________________
  - Basic installation: the shell commands `./configure [--with-context-proxy=[unix|dbus|...]]; make; make install' should configure, build and install this library. Currently gmake must be used instead of make on FreeBSD.
  - The ``--with-context-proxy`` feature configures the library to use a managed context shared between processes.  There are two available options for IPC context management: UNIX sockets (--with-context-proxy=unix), and DBUS (--with-context-proxy=dbus). It is easy to plug in any other by implementing it following the context interface (see examples in contexts/unix and contexts/dbus, and context_interface.h.  By default, the UNIX sockets based context proxy is used.   It is also possible to compile --without-context-proxy.  Then contexts are created and destroyed per query, which is too inefficient. 
  - There is another optional parameter to configure the library for preloading. When preloaded, the library intercepts calls to getaddrinfo() and getnameinfo() to serve them instead of them being handled by libc.
Use the --enable-api-intercept feature for this mode or try the help menu (-h) to the configure script for more details.
  - Note well: by OS policy, the library preloading and dbus service autoloading do normally NOT work with setuid programs.

5. Configuration
__________________________
  - Enabling the library:
The library can be enabled via nsswitch for platforms that implement the name service switch interface, or by preloading. For the nsswitch option, simply replace the "dns" source for the "hosts" database by "getdns" in /etc/nsswitch.conf.
  - Configurring the library:
A configuration file (/etc/getdns.conf) will contain settings to override the library's default for DNSSEC and privacy.
User preferences are located in a .getdns directory under $HOME. This file can be edited through a web form in browsers on localhost (getdns-config.localhost:8080) or manually.
By default, the library will perform DNSSEC validation and attempt to use TLS for server connections.
  -   The following example configures the library to validate DNSSEC statuses on answers, and uses TLS when possible:
```
  dnssec: validate
  tls: prefer_tls
  logging: critical
  #Comments start with a #-sign
  #A specification such as (dnssec: secure_only validate) is redundant 
  #because only one of the options ("secure_only" in this case) will take effect.
```
  
  -   Other available options:
    
    | Option | Attributes | Default | Always Implied |
    | -------- | ------------ | -------- | ----------|
    | dnssec | validate, secure_only, roadblock_avoidance | validate | validate |
    | tls   | disable_tls , prefer_tls,  require_tls | prefer_tls | N/A |
    | logging | debug, info, warning, critical | warning | critical |

Based on the meaning of the above attributes, only one attribute per option will take effect, with the least secure attribute being overriden whenever a combination of them is encountered. Thus specifying more than one attribute per option should be considered redundant rather than incorrect.

