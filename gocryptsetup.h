#ifndef GOCRYPTSETUP_H
#define GOCRYPTSETUP_H

struct crypt_device;

int gocrypt_format_luks(struct crypt_device *);

#endif /* GOCRYPTSETUP_H */
