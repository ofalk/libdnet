@BOTTOM@
#ifndef HAVE_ERR
void	err(int, const char *, ...);
void	warn(const char *, ...);
void	errx(int, const char *, ...);
void	warnx(const char *, ...);
#endif

#ifndef HAVE_INET_PTON
int	inet_pton(int, const char *, void *);
#endif

#ifndef HAVE_STRLCAT
size_t	strlcat(char *, const char *, size_t);
#endif

#ifndef HAVE_STRLCPY
size_t	strlcat(char *, const char *, size_t);
#endif
