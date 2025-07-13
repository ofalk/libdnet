cdef extern from "string.h":
    size_t     strlcpy(char *dst, char *src, size_t size)
