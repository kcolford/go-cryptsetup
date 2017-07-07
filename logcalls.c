/* manage logging in libcryptsetup */

#include "logcalls.h"
#include "log.h"
#include <libcryptsetup.h>


int gocrypt_crypt_init(struct gocrypt_logstack **ls, struct crypt_device **cd, const char * name) {
  int out;
  if (*cd)
    crypt_set_log_callback(*cd, gocrypt_log, ls);
  out = crypt_init(cd, name);
  if (*cd)
    crypt_set_log_callback(*cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_format(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * format, const char * cipher, const char * cipher_mode, const char * uuid, void * volume_key, size_t volume_key_size, void * params) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_format(cd, format, cipher, cipher_mode, uuid, volume_key, volume_key_size, params);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_load(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * requested_type, void * params) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_load(cd, requested_type, params);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_get_rng_type(struct gocrypt_logstack **ls, struct crypt_device *cd) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_get_rng_type(cd);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_set_uuid(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * uuid) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_set_uuid(cd, uuid);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_set_data_device(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * name) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_set_data_device(cd, name);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_keyslot_add_by_passphrase(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot, void * passphrase, size_t passphrase_size, void * new_passphrase, size_t new_passphrase_size) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_keyslot_add_by_passphrase(cd, keyslot, passphrase, passphrase_size, new_passphrase, new_passphrase_size);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_keyslot_destroy(struct gocrypt_logstack **ls, struct crypt_device *cd, int keyslot) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_keyslot_destroy(cd, keyslot);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_activate_by_passphrase(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * name, int keyslot, void * passphrase, size_t passphrase_size, uint32_t flags) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_activate_by_passphrase(cd, name, keyslot, passphrase, passphrase_size, flags);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_get_active_device(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * name, struct crypt_active_device * cad) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_get_active_device(cd, name, cad);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_deactivate(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * name) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_deactivate(cd, name);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_benchmark(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * cipher, const char * cipher_mode, size_t volume_key_size, size_t iv_size, size_t buffer_size, double * encryption_mbs, double * decryption_mbs) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_benchmark(cd, cipher, cipher_mode, volume_key_size, iv_size, buffer_size, encryption_mbs, decryption_mbs);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

int gocrypt_crypt_benchmark_kdf(struct gocrypt_logstack **ls, struct crypt_device *cd, const char * kdf, const char * hash, void * password, size_t password_size, void * salt, size_t salt_size, uint64_t * iterations_sec) {
  int out;
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log, ls);
  out = crypt_benchmark_kdf(cd, kdf, hash, password, password_size, salt, salt_size, iterations_sec);
  if (cd)
    crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}

