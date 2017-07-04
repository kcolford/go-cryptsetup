/* log functions */

#include "log.h"
#include <string.h>
#include <stdlib.h>

void gocrypt_log(int level, const char *msg, void *usrptr) {
  extern void golang_gocrypt_log(char *, struct gocrypt_logstack **);
  golang_gocrypt_log((char *) msg, usrptr);
}

void gocrypt_log_default(int level, const char *msg, void *usrptr) {
  extern void golang_gocrypt_log_default(char *);
  golang_gocrypt_log_default((char *) msg);
}
