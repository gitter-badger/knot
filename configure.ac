#                                               -*- Autoconf -*-

AC_PREREQ([2.60])
AC_INIT([knot], [2.1.0-dev], [knot-dns@labs.nic.cz])
AM_INIT_AUTOMAKE([gnits subdir-objects no-dist-gzip dist-xz -Wall -Werror])
AM_SILENT_RULES([yes])
AC_CONFIG_SRCDIR([src/knot/main.c])
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS([_GNU_SOURCE])
AC_CANONICAL_HOST

# Here are a set of rules to help you update your library version
# information:
#
# 1. Start with version information of ‘0:0:0’ for each libtool library.
#
# 2. Update the version information only immediately before a public
#    release of your software. More frequent updates are unnecessary,
#    and only guarantee that the current interface number gets larger
#    faster.
#
# 3. If the library source code has changed at all since the last
#    update, then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
#
# 4. If any interfaces have been added, removed, or changed since the
#    last update, increment current, and set revision to 0.
#
# 5. If any interfaces have been added since the last public release,
#    then increment age.
#
# 6. If any interfaces have been removed or changed since the last
#    public release, then set age to 0.

AC_SUBST([libknot_VERSION_INFO],["-version-info 1:0:0"])
AC_SUBST([libdnssec_VERSION_INFO],["-version-info 0:0:0"])
AC_SUBST([libzscanner_VERSION_INFO],["-version-info 0:1:0"])

# Automatically update release date based on configure.ac date
AC_PROG_SED
release_date=$($SED -n 's/^Knot DNS .* (\(.*\))/\1/p;q;' ${srcdir}/NEWS)
AC_SUBST([RELEASE_DATE], $release_date)

# Set compiler compatibility flags
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CPP_WERROR

# Default compiler flags
CFLAGS="$CFLAGS -Wall -Werror=format-security -Werror=implicit"

# Checks for programs.
m4_ifdef([AM_PROG_AR], [AM_PROG_AR]) # call AM_PROG_AR only if available

# Initialize libtool
AC_PROG_LIBTOOL
LT_INIT

# Use pkg-config
PKG_PROG_PKG_CONFIG
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR], [AC_SUBST([pkgconfigdir], ['${libdir}/pkgconfig'])])
AC_CONFIG_FILES([src/libknot.pc
		 src/dnssec/libdnssec.pc
		 src/zscanner/libzscanner.pc
		 ])

# Build Knot DNS daemon
AC_ARG_ENABLE([daemon],
    AS_HELP_STRING([--disable-daemon], [Don't build Knot DNS main daemon]), [], [enable_daemon=yes])
AM_CONDITIONAL([HAVE_DAEMON], [test "$enable_daemon" = "yes"])

# Build Knot DNS utilities
AC_ARG_ENABLE([utilities],
    AS_HELP_STRING([--disable-utilities], [Don't build Knot DNS utilities]), [], [enable_utilities=yes])
AM_CONDITIONAL([HAVE_UTILS], [test "$enable_utilities" = "yes"])

# Build Knot DNS documentation
AC_ARG_ENABLE([documentation],
    AS_HELP_STRING([--disable-documentation], [Don't build Knot DNS documentation]), [], [enable_documentation=yes])
AM_CONDITIONAL([HAVE_DOCS], [test "$enable_documentation" = "yes"])

######################
# Generic dependencies
######################

AC_PROG_INSTALL

AX_CC_LLVM

AC_ARG_ENABLE([fastparser],
    AS_HELP_STRING([--disable-fastparser], [Disable use of fastest zone parser]),[],[
    # Set zone parser type - fastest on release build, slowest on dev build
    AS_IF([test -d ".git" -o "$PATCH_VERSION" = "dev"],[
        enable_fastparser=no
    	],[
    	enable_fastparser=yes
    	])
    ])

AS_IF([test "$enable_fastparser" = "yes"],[
    AS_IF([test "${CC_LLVM}" = "yes"],[
        AC_MSG_WARN([LLVM based compiler detected; disabling fastest zone parser, see https://gitlab.labs.nic.cz/labs/knot/issues/351])
        enable_fastparser=no
        ])
    ])

AM_CONDITIONAL([FAST_PARSER], [test "$enable_fastparser" = "yes"])

# GnuTLS crypto backend
PKG_CHECK_MODULES([gnutls], [gnutls >= 3.0 nettle])

# JSON for DNSSEC status storage
PKG_CHECK_MODULES([jansson], [jansson >= 2.3])

# Debug modules
AC_ARG_ENABLE([debug],
    AS_HELP_STRING([--enable-debug=server,zones,ns,loader,dnssec],
    [compile selected debug modules [default=none]]),
    [
    echo ${enableval}|tr "," "\n"|while read val; do
        case "${val}" in
            server) AC_DEFINE([KNOTD_SERVER_DEBUG], [1], [Server debug.]) ;;
            zones) AC_DEFINE([KNOT_ZONES_DEBUG], [1], [Zones debug.]) ;;
            ns) AC_DEFINE([KNOT_NS_DEBUG], [1], [Nameserver debug.]) ;;
            loader) AC_DEFINE([KNOT_LOADER_DEBUG], [1], [Zone loading debug.]) ;;
            dnssec) AC_DEFINE([KNOT_DNSSEC_DEBUG], [1], [DNSSEC debug.]) ;;
        esac
    done
    ], [])

# Debug level
AC_ARG_ENABLE([debuglevel],
    AS_HELP_STRING([--enable-debuglevel=brief|verbose|details], [enable given debug level [default=disabled]]),
    # Not all shells support fall-through with ;& so I have to duplicate
    [case "x${enableval}" in
      xdetails)
        AC_DEFINE([DEBUG_ENABLE_DETAILS], [1], [Enable details debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_VERBOSE], [1], [Enable verbose debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
      xverbose)
        AC_DEFINE([DEBUG_ENABLE_VERBOSE], [1], [Enable verbose debugging messages.])
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
      xbrief)
        AC_DEFINE([DEBUG_ENABLE_BRIEF], [1], [Enable brief debugging messages.])
        ;;
    esac], [])

# recvmmsg() (valgrind doesn't support it, so disable for debugging)
# The check for struct mmsghdr is required when libc doesn't have an API but the function links
AC_ARG_ENABLE([recvmmsg],
    AS_HELP_STRING([--enable-recvmmsg=yes|no], [enable recvmmsg() network API under Linux (kernel support required) (set to 'no' if you have trouble running server under valgrind) [default=yes]]),
    [case "${enableval}" in
      yes)
	  AC_CHECK_FUNCS([sendmmsg])
          AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>]], [[struct mmsghdr v; recvmmsg(0,0,0,0,0);]])],
          [AC_DEFINE(HAVE_RECVMMSG, 1, [Define if struct mmsghdr and recvmmsg() exists.])])
          ;;
      no)
          ;;
      *)
          AC_MSG_ERROR([bad value ${enableval} for --enable-recvmmsg])
          ;;
    esac],
    [
      AC_CHECK_FUNCS([sendmmsg])
      AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sys/socket.h>]], [[struct mmsghdr v; recvmmsg(0,0,0,0,0);]])],
      [AC_DEFINE(HAVE_RECVMMSG, 1, [Define if struct mmsghdr and recvmmsg() exists.])])
    ])

# Check for link time optimizations support and predictive commoning
AC_ARG_ENABLE([lto],
    AS_HELP_STRING([--enable-lto=yes|no], [enable link-time optimizations, enable if not broken for some extra speed [default=no]]),
    [case "${enableval}" in
      yes) AX_CHECK_COMPILE_FLAG("-flto", [CFLAGS="$CFLAGS -flto"], []) ;;
      no) ;;
      *)  AC_MSG_ERROR([bad value ${enableval} for --enable-lto]) ;;
    esac])

AX_CHECK_COMPILE_FLAG("-fpredictive-commoning", [CFLAGS="$CFLAGS -fpredictive-commoning"], [], "-Werror")

# Default directories
run_dir="${localstatedir}/run/knot"
AC_ARG_WITH([rundir],
        AC_HELP_STRING([--with-rundir=path], [Path to run-time variable data (pid, sockets...). [default=LOCALSTATEDIR/run/knot]]),
        [run_dir=$withval])
AC_SUBST(run_dir)

storage_dir="${localstatedir}/lib/knot"
AC_ARG_WITH([storage],
        AC_HELP_STRING([--with-storage=path], [Default storage directory (slave zones, persistent data). [default=LOCALSTATEDIR/lib/knot]]),
        [storage_dir=$withval])
AC_SUBST(storage_dir)

config_dir="${sysconfdir}/knot"
AC_ARG_WITH([configdir],
        AC_HELP_STRING([--with-configdir=path], [Default directory for configuration. [default=SYSCONFDIR/knot]]),
        [config_dir=$withval])
AC_SUBST(config_dir)

#########################################
# Dependencies needed for Knot DNS daemon
#########################################

# Systemd integration
AC_ARG_ENABLE([systemd],
    AS_HELP_STRING([--enable-systemd=auto|yes|no], [enable systemd integration [default=auto]]),
    [enable_systemd="$enableval"], [enable_systemd=auto])

AS_IF([test "$enable_daemon" = "yes"],[

AS_IF([test "$enable_systemd" != "no"],[
  AS_CASE([$enable_systemd],
    [auto],[PKG_CHECK_MODULES([systemd], [libsystemd], [enable_systemd=yes], [
            PKG_CHECK_MODULES([systemd], [libsystemd-daemon libsystemd-journal], [enable_systemd=yes], [enable_systemd=no])])],
    [yes],[PKG_CHECK_MODULES([systemd], [libsystemd], [], [
    	    PKG_CHECK_MODULES([systemd], [libsystemd-daemon libsystemd-journal])])],
    [*],[AC_MSG_ERROR([Invalid value of --enable-systemd.])])
    ])

AS_IF([test "$enable_systemd" = "yes"],[
  AC_DEFINE([ENABLE_SYSTEMD], [1], [Use systemd integration.])])
])

dnl Check for userspace-rcu library
AC_ARG_WITH(urcu,
[  --with-urcu=DIR        where to find userspace-rcu library])

AS_IF([test "$enable_daemon" = "yes"],[

AS_IF([test "$with_urcu" != "no"], [
  PKG_CHECK_MODULES([liburcu], liburcu, [
    liburcu_PKGCONFIG="liburcu >= 0.4.0"
    AC_SUBST([liburcu_PKGCONFIG])
    with_urcu=yes
  ],[
    for try_urcu in "$with_urcu" "" "/usr/local"; do
      save_LIBS="$LIBS"
      save_CPPFLAGS="$CPPFLAGS"

      AS_IF([test -d "$try_urcu"], [
        liburcu_CFLAGS="-I$try_urcu/include"
        liburcu_LIBS="-L$try_urcu/lib"
      ],[
        liburcu_CFLAGS=""
        liburcu_LIBS=""
      ])

      CPPFLAGS="$CPPFLAGS $liburcu_CFLAGS"
      LIBS="$LIBS $liburcu_LIBS"

      AC_SEARCH_LIBS([rcu_set_pointer_sym], [urcu], [
        with_urcu=yes
	liburcu_LIBS="$liburcu_LIBS -lurcu"
	AC_SUBST([liburcu_CFLAGS])
	AC_SUBST([liburcu_LIBS])
	break
      ],[
        CPPFLAGS="$save_CPPFLAGS"
        LIBS="$save_LIBS"
        with_urcu=no
	# do not cache result of AC_SEARCH_LIBS test
	unset ac_cv_search_rcu_set_pointer_sym
      ])
    done
    CPPFLAGS="$save_CPPFLAGS"
    LIBS="$save_LIBS"

    AS_IF([test "$with_urcu" = "no"],[
      AC_MSG_ERROR([liburcu is required])
      ])
  ])
])

AC_SEARCH_LIBS([urcu_init], [urcu], [AC_MSG_ERROR([liburcu is too old (< 0.4.0), urcu_init symbol found])])
])

opt_dnstap=no
AS_IF([test "$enable_daemon" = "yes"],[
dnl Check for dnstap.
dt_DNSTAP([
    AC_DEFINE([USE_DNSTAP], [1], [Define to 1 to enable dnstap support])
    AC_SUBST(DNSTAP_CFLAGS)
    AC_SUBST(DNSTAP_LIBS)
    ])
])

AM_CONDITIONAL([HAVE_DNSTAP], test "$opt_dnstap" != "no")

dnl Check for LMDB
AC_ARG_WITH([lmdb],
    AC_HELP_STRING([--with-lmdb=[DIR]], [Link with external LMDB]),[
    with_lmdb=$withval
    ],[
    with_lmdb=yes
    ])

have_lmdb=no

AS_IF([test "$with_lmdb" != "no"],[
    save_CPPFLAGS=$CPPFLAGS
    save_LIBS=$LIBS
    for try_lmdb in "$with_lmdb" "" "/usr/local"; do

      AS_IF([test -d "$try_lmdb"], [
        lmdb_CFLAGS="-I$try_lmdb/include"
        lmdb_LIBS="-L$try_lmdb/lib"
        ],[
        lmdb_CFLAGS=""
        lmdb_LIBS=""
	])

      CPPFLAGS="$CPPFLAGS $lmdb_CFLAGS"
      LIBS="$LIBS $lmdb_LIBS"

      AC_SEARCH_LIBS([mdb_env_open], [lmdb], [
          AC_CHECK_HEADERS([lmdb.h], [], [
              AC_ERROR([lmdb headers not found in `$try_lmdb', is your installation complete?])])
	  lmdb_LIBS="$lmdb_LIBS -llmdb"
          have_lmdb=yes
          break
          ],[
	  have_lmdb=no
	  # do not cache result of AC_SEARCH_LIBS test
	  unset ac_cv_search_mdb_env_open
	  ])

      CPPFLAGS="$save_CPPFLAGS"
      LIBS="$save_LIBS"
    done
    CPPFLAGS="$save_CPPFLAGS"
    LIBS="$save_LIBS"
    ])

AS_IF([test "$have_lmdb" != "no"],[
    AC_SUBST([lmdb_CFLAGS])
    AC_SUBST([lmdb_LIBS])
    enable_lmdb=shared
    ],[enable_lmdb=embedded])
AM_CONDITIONAL([HAVE_LMDB], test "$have_lmdb" != "no")

AS_IF([test "$enable_daemon" = "yes"],[

dnl Check for rosedb module
AC_ARG_ENABLE([rosedb],
    AS_HELP_STRING([--enable-rosedb], [Enable static RR query module.]),
    [], [enable_rosedb=no])
]) # Knot DNS daemon dependencies

AS_IF([test "$enable_rosedb" = yes], [AC_DEFINE([HAVE_ROSEDB], [1], [Define to 1 to enable static RR query module.])])
AM_CONDITIONAL([HAVE_ROSEDB], [test "$enable_rosedb" = yes])

############################################
# Dependencies needed for Knot DNS utilities
############################################

dnl Check for libidn.
AC_ARG_WITH(libidn,
    AC_HELP_STRING([--with-libidn=[DIR]], [Support IDN (needs GNU Libidn)]),
    with_libidn=$withval,
    with_libidn=yes
    )

AS_IF([test "$enable_utilities" = "yes"],[
AS_IF([test "$with_libidn" != "no"],[
    PKG_CHECK_MODULES([libidn], [libidn >= 0.0.0], [
        with_libidn=yes
        AC_DEFINE([LIBIDN], [1], [Define to 1 to enable IDN support])
        ],[
        with_libidn=no
        AC_MSG_WARN([libidn not found])
	])])

]) # Knot DNS utilities dependencies

# Bash completions
AC_ARG_WITH([bash-completions],
  AC_HELP_STRING([--with-bash-completions=[DIR]], [Bash completions directory [default=auto]]),
  [with_bash_completions="$withval"],
  [with_bash_completions=auto]
)
AS_CASE([$with_bash_completions],
  [auto], [PKG_CHECK_VAR([bash_completions_dir], [bash-completion], [completionsdir])],
  [yes], [PKG_CHECK_VAR([bash_completions_dir], [bash-completion], [completionsdir], [], [AC_MSG_ERROR([bash completions not found])])],
  [no], [bash_completions_dir=],
  [bash_completions_dir="$with_bash_completions"]
)
AM_CONDITIONAL([HAVE_BASH_COMPLETIONS], [test -n "$bash_completions_dir"])
AS_IF([test -n "$bash_completions_dir"],
  [bash_completions_output="${bash_completions_dir}"],
  [bash_completions_output=no]
)

AC_SEARCH_LIBS([pow], [m])
AC_SEARCH_LIBS([pthread_create], [pthread], [], [AC_MSG_ERROR([pthreads not found])])
AC_SEARCH_LIBS([dlopen], [dl])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_SEARCH_LIBS([capng_apply], [cap-ng])

# Checks for header files.
AC_HEADER_RESOLV
AC_CHECK_HEADERS_ONCE([cap-ng.h netinet/in_systm.h pthread_np.h signal.h sys/select.h sys/time.h sys/wait.h sys/uio.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([clock_gettime gettimeofday fgetln getline madvise malloc_trim poll posix_memalign pthread_setaffinity_np regcomp select setgroups strlcat strlcpy initgroups])

# Check for be64toh function
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <endian.h>]], [[return be64toh(0);]])],
[AC_DEFINE(HAVE_BE64TOH, 1, [Define to 1 if you have the 'be64toh' function.])])

# Check for cpu_set_t/cpuset_t compatibility
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread.h>]], [[cpu_set_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_LINUX, 1, [Define if Linux-like cpu_set_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <pthread_np.h>]], [[cpuset_t set; CPU_ZERO(&set);]])],
[AC_DEFINE(HAVE_CPUSET_BSD, 1, [Define if FreeBSD-like cpuset_t exists.])])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <sched.h>]], [[cpuset_t* set = cpuset_create(); cpuset_destroy(set);]])],
[AC_DEFINE(HAVE_CPUSET_NETBSD, 1, [Define if cpuset_t and cpuset(3) exists.])])

# Prepare CFLAG_VISIBILITY to be used where needed
gl_VISIBILITY()

# Add code coverage macro
AX_CODE_COVERAGE

AS_IF([test "$enable_documentation" = "yes"],[

AC_PATH_PROGS([SPHINXBUILD], [sphinx-build sphinx-build-3], [false])
AS_IF([test "$SPHINXBUILD" = "false"],
  [AC_MSG_WARN([Could not find the 'sphinx-build' executable, you will be unable to regenerate documentation.])],
  [AC_PATH_PROG([PDFLATEX], [pdflatex], [false])
   AS_IF([test "$PDFLATEX" = ""],
     [AC_MSG_WARN([Could not find the 'pdflatex' executable, you will be unable to generate PDF documentation.])])
   AC_PATH_PROG([MAKEINFO], [makeinfo], [false])
   AS_IF([test "$MAKEINFO" = "false"],
     [AC_MSG_WARN([Could not find the 'makeinfo' executable, you will be unable to generate info documentation.])])
  ])

])

AM_CONDITIONAL([HAVE_SPHINXBUILD], test "$SPHINXBUILD" != "false")
AM_CONDITIONAL([HAVE_PDFLATEX], test "$PDFLATEX" != "false")
AM_CONDITIONAL([HAVE_MAKEINFO], test "$MAKEINFO" != "false")

AC_CONFIG_FILES([Makefile
		 doc/Makefile
		 samples/Makefile
		 libtap/Makefile
		 src/Makefile
		 tests/Makefile
		 tests-fuzz/Makefile
		 src/dnstap/Makefile
		 src/zscanner/Makefile
		 src/dnssec/Makefile
		 src/dnssec/tests/Makefile
		 src/dnssec/utils/Makefile
		 ])

AC_OUTPUT

AC_MSG_RESULT([
  $PACKAGE $VERSION

    Target:   $host_os $host_cpu
    Compiler: ${CC}
    CFLAGS:   ${CFLAGS} ${CPPFLAGS}
    LIBS:     ${LIBS} ${LDFLAGS}
    LibURCU:  ${liburcu_LIBS} ${liburcu_CFLAGS}
    GnuTLS:   ${gnutls_LIBS} ${gnutls_CFLAGS}
    Jansson:  ${jansson_LIBS} ${jansson_CFLAGS}
    LMDB:     ${enable_lmdb} ${lmdb_LIBS} ${lmdb_CFLAGS}

    Prefix:		${prefix}
    Run dir:		${run_dir}
    Storage dir:	${storage_dir}
    Config dir: 	${config_dir}

    Knot DNS libraries:     yes
    Knot DNS daemon:        ${enable_daemon}
    Knot DNS utils:         ${enable_utilities}
    Knot DNS documentation: ${enable_documentation}

    Fast zone parser:    ${enable_fastparser}
    Utilities with IDN:  ${with_libidn}
    Systemd integration: ${enable_systemd}
    Dnstap support:      ${opt_dnstap}
    Code coverage:       ${enable_code_coverage}
    Bash completions:    ${bash_completions_output}

  Continue with 'make' command
])
