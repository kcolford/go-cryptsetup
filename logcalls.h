/* manage logging in libcryptsetup */

#ifndef LOGCALLS_H
#define LOGCALLS_H

#include <libcryptsetup.h>

struct gocrypt_logstack {
  char *message;
  struct gocrypt_logstack *prev;
};

void gocrypt_logstack_free(struct gocrypt_logstack *);


int gocrypt_crypt_format(struct gocrypt_logstack **, struct crypt_device *, const char *, const char *, const char *, const char *, void *, size_t, void *);

int gocrypt_crypt_set_data_device(struct gocrypt_logstack **, struct crypt_device *, const char *);

int gocrypt_crypt_get_rng_type(struct gocrypt_logstack **, struct crypt_device *);

int gocrypt_crypt_set_uuid(struct gocrypt_logstack **, struct crypt_device *, const char *);

int gocrypt_crypt_keyslot_add_by_passphrase(struct gocrypt_logstack **, struct crypt_device *, int, void *, size_t, void *, size_t);

int gocrypt_crypt_keyslot_change_by_passphrase(struct gocrypt_logstack **, struct crypt_device *, int, int, void *, size_t, void *, size_t);

int gocrypt_crypt_keyslot_add_by_keyfile_offset(struct gocrypt_logstack **, struct crypt_device *, int, const char *, size_t, size_t, const char *, size_t, size_t);

int gocrypt_crypt_keyslot_add_by_volume_key(struct gocrypt_logstack **, struct crypt_device *, int, void *, size_t, void *, size_t);

int gocrypt_crypt_keyslot_destroy(struct gocrypt_logstack **, struct crypt_device *, int);

int gocrypt_crypt_activate_by_passphrase(struct gocrypt_logstack **, struct crypt_device *, const char *, int, void *, size_t, uint32_t);

int gocrypt_crypt_activate_by_keyfile_offset(struct gocrypt_logstack **, struct crypt_device *, const char *, int, const char *, size_t, size_t, uint32_t);

int gocrypt_crypt_deactivate(struct gocrypt_logstack **, struct crypt_device *, const char *);

int gocrypt_crypt_benchmark(struct gocrypt_logstack **, struct crypt_device *, const char *, const char *, size_t, size_t, size_t, double *, double *);

int gocrypt_crypt_benchmark_kdf(struct gocrypt_logstack **, struct crypt_device *, const char *, const char *, void *, size_t, void *, size_t, uint64_t *);


#endif /* LOGCALLS_H */
