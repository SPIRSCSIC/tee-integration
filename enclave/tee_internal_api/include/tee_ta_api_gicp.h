#ifndef TEE_TA_API_H
#define TEE_TA_API_H

#include "tee_core_api.h"
#include <ta_shared_gicp.h>

#include "eapp_utils.h"
#include "malloc.h"
#include "string.h"
#include "edge_call.h"
#include "h2ecall.h"

void TEE_GenerateRandom(void* randomBuffer, size_t randomBufferLen);

#endif
