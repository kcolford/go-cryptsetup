/* manage logging in libcryptsetup */

#include "logcalls.h"
#include "log.h"
#include <libcryptsetup.h>
#include <string.h>
#include <stdlib.h>

{{range .Methods}}
int {{$.Ns}}_{{.Name}}(struct gocrypt_logstack **ls, struct crypt_device *cd{{range .Params}}, {{.Type}} {{.Name}}{{end}}) {
  crypt_set_log_callback(cd, gocrypt_log, ls);
  int out = {{.Name}}(cd{{range .Params}}, {{.Name}}{{end}});
  crypt_set_log_callback(cd, gocrypt_log_default, NULL);
  return out;
}
{{end}}
