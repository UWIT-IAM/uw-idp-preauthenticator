bin_PROGRAMS=idp

idp_SOURCES=preauth.c cfg.c gws.c ads.c proxd.c
idp_LDADD=-lpthread 
idp_LDFLAGS=

EXTRA_DIST= README preauth.h etc/preauth.conf.tmpl

AM_CFLAGS=-g -DHAVE_CONFIG_H -DLDAP_DEPRECATED 
