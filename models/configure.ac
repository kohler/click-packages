dnl -*- mode: shell-script -*-
dnl 'configure.ac' file for the Click models package
dnl Process this file with autoconf to produce a configure script.
dnl
dnl Permission is hereby granted, free of charge, to any person obtaining a
dnl copy of this software and associated documentation files (the "Software"),
dnl to deal in the Software without restriction, subject to the conditions
dnl listed in the Click LICENSE file. These conditions include: you must
dnl preserve this copyright notice, and you cannot mention the copyright
dnl holders in advertising related to the Software without their permission.
dnl The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
dnl notice is a summary of the Click LICENSE file; the license in that file is
dnl legally binding.

AC_INIT(click-models, 1.5.0)
AC_CONFIG_HEADER(config.h)
AC_SUBST(ac_configure_args)

CLICKPACKAGENAME=models
AC_SUBST(CLICKPACKAGENAME)

AH_TOP([#ifndef CLICK_PKG_MODELS_CONFIG_H
#define CLICK_PKG_MODELS_CONFIG_H 1])
AH_BOTTOM([#endif /* CLICK_PKG_MODELS_CONFIG_H */])


dnl
dnl locate Click install directory
dnl

AC_ARG_WITH(click, [  --with-click[[=DIR]]      Click install path is DIR [[PREFIX]]],
    [clickprefix=$withval; if test -z "$withval" -o "$withval" = yes; then clickprefix=$prefix; fi],
    clickprefix=NONE)

dnl Preset $prefix and $exec_prefix.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
test "x$clickprefix" != xNONE -a "x$prefix" = xNONE && prefix="$clickprefix"
test "x$clickprefix" = xNONE && clickprefix="$prefix"

clickdatadir="${clickprefix}/share/click"

if test ! -r $clickdatadir/config.mk; then
    AC_MSG_ERROR([
==============================================

'$clickdatadir/config.mk' not found.
Are you sure '$clickprefix' is a Click install directory?

==============================================])
fi

clickbuild_prefix="$clickprefix"
. $clickdatadir/config.mk

AC_SUBST(clickbuild_prefix)
AC_SUBST(clickbuild_datadir)


dnl
dnl build userlevel? Linux module? FreeBSD module?
dnl

onezero () {
    { [[ "$1" = yes ]] && echo 1; } || echo 0
}

AC_ARG_ENABLE(userlevel, [  --enable-userlevel      enable user-level driver],
    [BUILD_USERLEVEL=`onezero $enableval`],
    [BUILD_USERLEVEL=$CLICK_HAVE_USERLEVEL_DRIVER])
AC_ARG_ENABLE(linuxmodule, [  --enable-linuxmodule    enable Linux kernel driver],
    [BUILD_LINUXMODULE=`onezero $enableval`],
    [BUILD_LINUXMODULE=0])
AC_ARG_ENABLE(bsdmodule, [  --enable-bsdmodule      enable FreeBSD kernel driver
                          [[Default driver is userlevel only.]]],
    [BUILD_BSDMODULE=`onezero $enableval`],
    [BUILD_BSDMODULE=0])

AC_SUBST(BUILD_USERLEVEL)
AC_SUBST(BUILD_LINUXMODULE)
AC_SUBST(BUILD_BSDMODULE)


dnl
dnl Output
dnl

AC_OUTPUT(Makefile package/Makefile)
