/* manage logging in libcryptsetup */

#ifndef {{$.HeaderGuard}}
#define {{$.HeaderGuard}}

#include "log.h"
#include <libcryptsetup.h>

{{range .Methods}}
int {{$.Ns}}_{{.Name}}(struct gocrypt_logstack **, struct crypt_device *{{range .Params}}, {{.Type}}{{end}});
{{end}}

#endif /* {{$.HeaderGuard}} */
