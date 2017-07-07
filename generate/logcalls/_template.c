/* manage logging in libcryptsetup */

#include "logcalls.h"
#include "log.h"
#include <libcryptsetup.h>

{{range .Methods}}
int {{$.Ns}}_{{.Name}}(struct gocrypt_logstack **ls, struct crypt_device *{{if .SetContext}}*{{end}}cd{{range .Params}}, {{.Type}} {{.Name}}{{end}}) {
  int out;
  if ({{if .SetContext}}*{{end}}cd)
    crypt_set_log_callback({{if .SetContext}}*{{end}}cd, gocrypt_log, ls);
  out = {{.Name}}(cd{{range .Params}}, {{.Name}}{{end}});
  if ({{if .SetContext}}*{{end}}cd)
    crypt_set_log_callback({{if .SetContext}}*{{end}}cd, gocrypt_log_default, NULL);
  return out;
}
{{end}}
