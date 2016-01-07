AC_INIT
AM_INIT_AUTOMAKE(preauth, 1.0)
AC_PROG_CC

# look for document root
PREAUTH_ROOT=
AC_ARG_WITH(document-root,
    AC_HELP_STRING([--with-document-root=PATH], [web document root]),
[ case "$withval" in
   no)
     AC_MSG_ERROR(document root must be specified!)
     ;;
   *)
     PREAUTH_ROOT=$withval
     ;;
  esac ])


# look for app name
PREAUTH_NAME=idp-preauth
AC_ARG_WITH(app-name,
    AC_HELP_STRING([--with-app-name=PATH], [preauth application name]),
[ case "$withval" in
   no)
     AC_MSG_ERROR(app name must be specified!)
     ;;
   *)
     PREAUTH_NAME=$withval
     ;;
  esac ])



# look for ssl 
LIBS="$LIBS -lssl -lcrypto"
AC_ARG_WITH(ssl,
    AC_HELP_STRING([--with-ssl=PATH], [openssl install path]),
[ case "$withval" in
   no)
     AC_MSG_ERROR(openssl library is required!)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval/lib"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     ;;
  esac ])

# look for curl install
AC_ARG_WITH(curl,
    AC_HELP_STRING([--with-curl=PATH], [Curl install path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval/lib"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     ;;
  esac ])
# look for curl lib
AC_ARG_WITH(curl-lib,
    AC_HELP_STRING([--with-curl-lib=PATH], [Curl lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

# look for curl includes
AC_ARG_WITH(curl-include,
    AC_HELP_STRING([--with-curl-include=PATH], [Curl include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_CHECK_LIB(curl,curl_easy_init,,
      AC_MSG_ERROR(Cannot find the curl library),
      [-lssl -lcrypto -lz])
AC_CHECK_HEADER([curl/curl.h])

# look for sasl
LIBS="$LIBS -lsasl2"
AC_ARG_WITH(sasl2,
    AC_HELP_STRING([--with-sasl2=PATH], [sasl2 install path]),
[ case "$withval" in
   no)
     AC_MSG_ERROR(sasl2 library is required!)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval/lib"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     ;;
  esac ])

AC_CHECK_HEADER([sasl/sasl.h])

# look for ldap
LIBS="$LIBS -lldap_r -llber"
AC_ARG_WITH(ldap,
    AC_HELP_STRING([--with-ldap=PATH], [openldap install path]),
[ case "$withval" in
   no)
     AC_MSG_ERROR(openldap library is required!)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval/lib"
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     ;;
  esac ])

AC_CHECK_LIB(ldap_r,ldap_get_values,,
      AC_MSG_ERROR(Cannot find the openldap library),
      [-lsasl2 -lpthread])
AC_CHECK_HEADER([ldap.h])



# fcgi support
AC_ARG_WITH(fcgi,
    AC_HELP_STRING([--with-fcgi=PATH],[include fastcgi support]),
[ case "${withval}" in
   no) AC_SUBST(EXEC_EXT, "cgi")
    ;;
   *)
    CPPFLAGS="$CPPFLAGS -I$withval/include -DWITH_FCGI"
    LIBS="$LIBS -lfcgi"
    LDFLAGS="$LDFLAGS -L$withval/lib"
    AC_SUBST(EXEC_EXT, "fcgi")
    ;;
  esac ])


if test "${PREAUTH_ROOT}" == ""; then
   AC_MSG_ERROR(document root must be specified!)
fi
bindir=${PREAUTH_ROOT}/${PREAUTH_NAME}

AC_SUBST(PREAUTH_ROOT)
AC_SUBST(PREAUTH_NAME)


AC_OUTPUT(Makefile)

