@BOTTOM@

#include <sys/types.h>

#ifdef __svr4__
#define BSD_COMP	1
#endif

#ifndef HAVE_INET_PTON
int	inet_pton(int, const char *, void *);
#endif

#ifndef HAVE_STRLCAT
size_t	strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t	strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRSEP
char	*strsep(char **, const char *);
#endif
