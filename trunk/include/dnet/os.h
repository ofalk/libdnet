/*
 * os.h
 *
 * Sleazy OS-specific defines.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id$
 */

#ifndef DNET_OS_H
#define DNET_OS_H

/* XXX - require POSIX */
#include <sys/param.h>

/* XXX - Linux <feature.h>, IRIX <sys/endian.h>, etc. */
#include <netinet/in.h>
#include <arpa/inet.h>

#define DNET_LIL_ENDIAN		1234
#define DNET_BIG_ENDIAN		4321

/* BSD and IRIX */
#ifdef BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif BYTE_ORDER == BIG_ENDIAN
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif
#endif

/* Linux */
#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __LITTLE_ENDIAN
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif
#endif

/* Solaris */
#if defined(_BIT_FIELDS_LTOH)
# define DNET_BYTESEX		DNET_LIL_ENDIAN
#elif defined (_BIT_FIELDS_HTOL)
# define DNET_BYTESEX		DNET_BIG_ENDIAN
#endif
#if defined(_SYS_INT_TYPES_H) || defined(__INTTYPES_INCLUDED)
# define u_int64_t		uint64_t
# define u_int32_t		uint32_t
# define u_int16_t		uint16_t
# define u_int8_t		uint8_t
#endif

#ifndef DNET_BYTESEX
# include "bytesex unknown"	/* XXX - HP-UX cpp lacks 'error' directive */
#endif

#endif /* DNET_OS_H */
