/* manage logging in libcryptsetup */

#ifndef {{$.HeaderGuard}}
#define {{$.HeaderGuard}}

#include <libcryptsetup.h>

struct {{$.Ns}}_logstack {
  char *message;
  struct {{$.Ns}}_logstack *prev;
};

void {{$.Ns}}_logstack_free(struct {{$.Ns}}_logstack *);

{{range .Methods}}
int {{$.Ns}}_{{.Name}}(struct {{$.Ns}}_logstack **, struct crypt_device *{{range .Params}}, {{.Type}}{{end}});
{{end}}

#endif /* {{$.HeaderGuard}} */
