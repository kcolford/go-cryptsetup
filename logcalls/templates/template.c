/* manage logging in libcryptsetup */

#include "logcalls.h"
#include <libcryptsetup.h>
#include <string.h>
#include <stdlib.h>
#include "gocryptsetup.h"

void {{$.Ns}}_logstack_free(struct {{$.Ns}}_logstack *ls) {
  while (ls != NULL) {
    if (ls->message != NULL)
      free(ls->message);
    struct {{$.Ns}}_logstack *t = ls;
    ls = ls->prev;
    free(t);
  }
}

static void {{$.Ns}}_log(int level, const char *msg, void *usrptr) {
  struct {{$.Ns}}_logstack **ls = usrptr;
  struct {{$.Ns}}_logstack *out = malloc(sizeof *out);
  out->message = memcpy(calloc(strlen(msg)+1, sizeof *out->message), msg, strlen(msg));
  out->prev = *ls;
  *ls = out;
}

{{range .Methods}}
int {{$.Ns}}_{{.Name}}(struct {{$.Ns}}_logstack **ls, struct crypt_device *cd{{range .Params}}, {{.Type}} {{.Name}}{{end}}) {
  crypt_set_log_callback(cd, {{$.Ns}}_log, ls);
  int out = {{.Name}}(cd{{range .Params}}, {{.Name}}{{end}});
  crypt_set_log_callback(cd, NULL, NULL);
  return out;
}
{{end}}
