/* log functions */

#ifndef LOG_H
#define LOG_H

struct gocrypt_logstack {
  char *message;
  struct gocrypt_logstack *prev;
};

void gocrypt_log(int, const char *, void *);
void gocrypt_log_default(int, const char *, void *);

#endif /* LOG_H */
