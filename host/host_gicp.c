#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <tee_client_api.h>
#include <ta_shared_gicp.h>


int arguments(char** out_b, int in_n, char** in_b) {
  int len = strlen(in_b[0]) + 1;
  *out_b = (char *) malloc(len);
  strcat(*out_b, in_b[0]);
  for (int i = 1; i < in_n; i++) { // skip "./prog"
    if (i == 1) // workaround for .ke --arguments
      len += 3 + strlen(in_b[i]); // separator + "--" + argument
    else
      len += 1 + strlen(in_b[i]); // separator + argument
    *out_b = (char *) realloc(*out_b, len);
    strcat(*out_b, "|");
    if (i == 1)  {
      strcat(*out_b, "--");
      strcat(*out_b, in_b[i]);
    } else
      strcat(*out_b, in_b[i]);
  }
  return len;
}

static void toolbox(int argc, char** argv) {
  TEEC_Result res;
  uint32_t eo;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  const TEEC_UUID uuid = TA_UUID;

  res = TEEC_InitializeContext("default", &ctx);
  if (res != TEEC_SUCCESS) {
    errorf("FAILED: TEEC_InitializeContext: %d, %x\n", eo, res);
    exit(-1);
  }

  res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &eo);
  if (res != TEEC_SUCCESS) {
    errorf("FAILED: TEEC_OpenSession: %d, %x\n", eo, res);
    exit(-1);
  }

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
                                   TEEC_NONE,TEEC_NONE,TEEC_NONE);

  char* buffer = NULL;
  int len = arguments(&buffer, argc, argv);
  op.params[0].tmpref.buffer = buffer;
  op.params[0].tmpref.size = len;

  res = TEEC_InvokeCommand(&sess, TA_TOOLBOX, &op, &eo);
  if (res != TEEC_SUCCESS) {
    errorf("TEEC_InvokeCommand(TA_TOOLBOX): %d, %x\n", eo, res);
    exit(-1);
  }

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
  free(buffer);
}

int host_usage(char** argv) {
  fprintf(stderr,
         "Usage: %s (test|benchmark|groupsig|mondrian|help) [OPTS]\n", argv[0]);
  return 1;
}

int main(int argc, char** argv) {
  setvbuf(stdout, 0, _IONBF, 0);

  if (argc > 1)
    toolbox(argc, argv);
  else
    return host_usage(argv);
  return 0;
}
