/* simplified invocation of crypt_format */

#include "gocryptsetup.h"
#include <libcryptsetup.h>
#include <stdlib.h>

int gocrypt_format_luks(struct crypt_device *cd) {
  struct crypt_params_luks1 params;
  params.hash = "sha256";
  params.data_alignment = 0;
  params.data_device = NULL;
  return crypt_format(cd,
		      CRYPT_LUKS1,
		      "aes",
		      "xts-plain64",
		      NULL,
		      NULL,
		      256 / 8,
		      &params);
}

  
    
