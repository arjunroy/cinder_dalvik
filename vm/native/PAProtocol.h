#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__

#include <stdint.h>

// Request Types
#define PA_STAT_RESERVE 1
#define PA_GET_TAP_PARAMS 2
#define PA_SET_TAP_PARAMS 3
#define PA_ADD_UID_PARAMS 4
#define PA_REMOVE_UID_PARAMS 5
#define PA_GOODBYE 6

// Error codes in response
#define PA_NO_ERROR 0
#define PA_BAD_PERMISSIONS 1
#define PA_UID_NOT_FOUND 2
#define PA_INVALID_INPUT 3
#define PA_FAILURE 4
#define PA_UID_EXISTS 5

// Flags for PAStatReserveResponse
#define PA_RESERVE_GRANTED 0x1
#define PA_USE_ROOT_RESERVE 0x2

typedef struct __pa_request {
	uint32_t request_type;
} PARequest;

/* Get Reserve ID and access to UID specific reserve  */

typedef struct __pa_stat_reserve_query {
	uint64_t uid;
} PAStatReserveQuery;

typedef struct __pa_stat_reserve_response {
	int32_t rid;
	uint32_t flags;
	uint32_t error;
} PAStatReserveResponse;

/* Get and Set Tap Parameters for UID Reserve */

typedef struct __pa_get_tap_params_query {
	uint64_t uid;
} PAGetTapParamsQuery;

typedef struct __pa_get_tap_params_response {
	uint64_t tap_type;
	int64_t tap_value;
	uint32_t error;
} PAGetTapParamsResponse;

typedef struct __pa_set_tap_params_query {
	uint64_t uid;
	uint64_t tap_type;
	int64_t tap_value;
} PASetTapParamsQuery;

typedef struct __pa_set_tap_params_response {
	uint32_t error;
} PASetTapParamsResponse;

typedef struct __pa_add_uid_params_query {
	uint64_t uid;
	int64_t tap_value;
	uint64_t tap_type;
} PAAddUIDParamsQuery;

typedef struct __pa_add_uid_params_response {
	uint32_t error;
} PAAddUIDParamsResponse;

typedef struct __pa_remove_uid_params_query {
	uint64_t uid;
} PARemoveUIDParamsQuery;

typedef struct __pa_remove_uid_params_response {
	uint32_t error;
} PARemoveUIDParamsResponse;

#endif /* ifndef __PROTOCOL_H__ */

