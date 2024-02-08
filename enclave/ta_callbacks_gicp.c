#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <openssl/rand.h>

#include "groupsig.h"
#include "kty04.h"
#include "ps16.h"
#include "gl19.h"
#include "common.h"
#include "mondrian.h"
#include "gicp/base64.h"

// Only required header for using SPIRS GlobalPlatform TEE Internal API
#include <tee_ta_api_gicp.h>

#include "../../debug/debug.h"


TEE_Result TA_CreateEntryPoint(void)
{
    debug("%s\n", __FUNCTION__);
    // Executed once the TA is created, like a TA's main() function
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    debug("%s\n", __FUNCTION__);
    // Executed after the session is closed and TA is going to be destroyed
    // Last function executed by the TA
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                    TEE_Param  params[4],
                                    void **session)
{
    debug("%s: %d\n", __FUNCTION__, param_types);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session)
{
    debug("%s\n", __FUNCTION__);

    if (session)
        free(session);
}

TEE_Result test_mondrian(uint32_t param_types,
                         TEE_Param params[TEE_NUM_PARAMS])
{
  mondrian_test(); // defined in tests/mondrian.c
  return TEE_SUCCESS;
}

TEE_Result test_pairings(uint32_t param_types,
                        TEE_Param params[TEE_NUM_PARAMS])
{
  pairings_test("123", "456"); // defined in tests/pairing.cpp
  return TEE_SUCCESS;
}

// below tests are defined in libgroupsig/src/test/basic
TEE_Result test_kty04(uint32_t param_types,
                            TEE_Param params[TEE_NUM_PARAMS])
{
  kty04_test();
  return TEE_SUCCESS;
}

TEE_Result test_ps16(uint32_t param_types,
                     TEE_Param params[TEE_NUM_PARAMS])
{
  ps16_test();
  return TEE_SUCCESS;
}

TEE_Result benchmark_kty04(uint32_t param_types,
                     TEE_Param params[TEE_NUM_PARAMS])
{
  kty04_benchmark();
  return TEE_SUCCESS;
}

TEE_Result benchmark_ps16(uint32_t param_types,
                     TEE_Param params[TEE_NUM_PARAMS])
{
  ps16_benchmark();
  return TEE_SUCCESS;
}

TEE_Result toolbox(uint32_t param_types,
                   TEE_Param params[TEE_NUM_PARAMS])
{
  char* buffer = (char*) params[0].memref.buffer;
  char** argv = NULL;
  int argc = 0;

  // Tokenize buffer using '|' as separator
  char* token = strtok(buffer, "|");
  while (token != NULL) {
    char* arg = (char*) malloc(strlen(token) + 1); // extra space for \0
    strcpy(arg, token);
    argc++;
    argv = (char**)realloc(argv, sizeof(char*) * argc);
    argv[argc - 1] = arg;
    token = strtok(NULL, "|");
  }
  toolbox_main(argc, argv); // defined in tests/toolbox.c
  // Free each string in the argv array
  for (int i = 0; i < argc; i++) {
    free(argv[i]);
  }
  // Free the argv array itself
  free(argv);
  return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
                                      uint32_t param_types,
                                      TEE_Param params[TEE_NUM_PARAMS])
{
    debug("%s\n", __FUNCTION__);

    switch (cmd) {
    case TA_DEMO_MONDRIAN:
      return test_mondrian(param_types, params);
    case TA_DEMO_PAIRINGS:
      return test_pairings(param_types, params);
    case TA_DEMO_KTY04:
      return test_kty04(param_types, params);
    case TA_DEMO_PS16:
      return test_ps16(param_types, params);
    case TA_BENCHMARK_KTY04:
      return benchmark_kty04(param_types, params);
    case TA_BENCHMARK_PS16:
      return benchmark_ps16(param_types, params);
    case TA_TOOLBOX:
      return toolbox(param_types, params);
    default:
        errorf("Command ID %d is not supported\n", cmd);
        return TEE_ERROR_NOT_SUPPORTED;
    }
    return TEE_SUCCESS;
}
