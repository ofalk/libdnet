@BOTTOM@
#include <sys/types.h>

#ifndef HAVE_INET_PTON
int	inet_pton(int, const char *, void *);
#endif

#ifndef HAVE_STRLCAT
size_t	strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t	strlcpy(char *, const char *, size_t);
#endif
