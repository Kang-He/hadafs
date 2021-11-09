#include <sys/types.h>

extern int
booster_stat (const char *path, void *buf);
extern int
booster_stat64 (const char *path, void *buf);

extern int
booster_xstat (int ver, const char *path, void *buf);
extern int
booster_xstat64 (int ver, const char *path, void *buf);

extern int
booster_fxstat (int ver, int fd, void *buf);
extern int
booster_fxstat64 (int ver, int fd, void *buf);

extern int
booster_fstat (int fd, void *buf);
extern int
booster_fstat64 (int fd, void *buf);

extern int
booster_lstat (const char *path, void *buf);
extern int
booster_lstat64 (const char *path, void *buf);

extern int
booster_lxstat (int ver, const char *path, void *buf);
extern int
booster_lxstat64 (int ver, const char *path, void *buf);



int
stat (const char *path, void *buf)
{
        return booster_stat (path, buf);
}

int
stat64 (const char *path, void *buf)
{
        return booster_stat64 (path, buf);
}

int
__xstat (int ver, const char *path, void *buf)
{
        return booster_xstat (ver, path, buf);
}

int
__xstat64 (int ver, const char *path, void *buf)
{
        return booster_xstat64 (ver, path, buf);
}

int
__fxstat (int ver, int fd, void *buf)
{
        return booster_fxstat (ver, fd, buf);
}

int
__fxstat64 (int ver, int fd, void *buf)
{
        return booster_fxstat64 (ver, fd, buf);
}

int
fstat (int fd, void *buf)
{
        return booster_fstat (fd, buf);
}

int
fstat64 (int fd, void *buf)
{
        return booster_fstat64 (fd, buf);
}



