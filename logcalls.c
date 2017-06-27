/* manage logging in libcryptsetup */

#include "logcalls.h"
#include <libcryptsetup.h>
#include <string.h>
#include <stdlib.h>
#include "gocryptsetup.h"

void gocrypt_logstack_free(struct gocrypt_logstack *ls) {
  while (ls != NULL) {
    if (ls->message != NULL)
      free(ls->message);
    struct gocrypt_logstack *t = ls;
    ls = ls->prev;
    free(t);
  }
}

static void gocrypt_log(int level, const char *msg, void *usrptr) {
  struct gocrypt_logstack **ls = usrptr;
  struct gocrypt_logstack *out = malloc(sizeof *out);
  out->message = memcpy(calloc(strlen(msg)+1, sizeof *out->message), msg, strlen(msg));
  out->prev = *ls;
  *ls = out;
}


int gocrypt_gocrypt_format_luks(struct gocrypt_logstack **ls, struct crypt_device *cd) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = gocrypt_format_luks(cd);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_set_data_device(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * device) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_set_data_device(cd, device);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_get_rng_type(struct gocrypt_logstack **ls, struct crypt_device *cd) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_get_rng_type(cd);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_set_uuid(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * uuid) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_set_uuid(cd, uuid);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_keyslot_add_by_passphrase(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot, void * passphrase, size_t passphrase_size, void * new_passphrase, size_t new_passphrase_size) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_keyslot_add_by_passphrase(cd, keyslot, passphrase, passphrase_size, new_passphrase, new_passphrase_size);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_keyslot_change_by_passphrase(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot_old, int keyslot_new, void * passphrase, size_t passphrase_size, void * new_passphrase, size_t new_passphrase_size) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_keyslot_change_by_passphrase(cd, keyslot_old, keyslot_new, passphrase, passphrase_size, new_passphrase, new_passphrase_size);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_keyslot_add_by_keyfile_offset(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot, const char * keyfile, size_t keyfile_size, size_t keyfile_offset, const char * new_keyfile, size_t new_keyfile_size, size_t new_keyfile_offset) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_keyslot_add_by_keyfile_offset(cd, keyslot, keyfile, keyfile_size, keyfile_offset, new_keyfile, new_keyfile_size, new_keyfile_offset);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_keyslot_add_by_volume_key(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot, void * volume_key, size_t volume_key_size, void * passphrase, size_t passphrase_size) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_keyslot_add_by_volume_key(cd, keyslot, volume_key, volume_key_size, passphrase, passphrase_size);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_keyslot_destroy(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_keyslot_destroy(cd, keyslot);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

int gocrypt_crypt_activate_by_passphrase(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * name, int keyslot, void * passphrase, size_t passphrase_size, uint32_t flags) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = crypt_activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}

