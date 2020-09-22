#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "rabe.h"

int main () {
  struct KpAbeContext *ctx;
  char *attributes ="C,B";
  char *ct_buf;
  int32_t ct_len;
  int32_t pt_len;
  char *pt = "grias earna =)";
  char *buf;
  pt_len = strlen (pt) + 1;

  /* Setup */
  ctx = kpabe_create ();

  /* Encrypt */
  assert (0 == kpabe_encrypt (ctx, attributes, pt, pt_len, &ct_buf, &ct_len));

  /* Destroy Context */
  kpabe_destroy(ctx);

  return 0;
}
