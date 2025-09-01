/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

typedef struct Manager Manager;

/* From ModemManager-enums.h */
typedef enum {
        MM_BEARER_IP_FAMILY_NONE   = 0,
        MM_BEARER_IP_FAMILY_IPV4   = 1 << 0,
        MM_BEARER_IP_FAMILY_IPV6   = 1 << 1,
        MM_BEARER_IP_FAMILY_IPV4V6 = 1 << 2,
        MM_BEARER_IP_FAMILY_ANY    = 0xFFFFFFFF
} MMBearerIpFamily;

typedef enum {
        MM_BEARER_TYPE_UNKNOWN        = 0,
        MM_BEARER_TYPE_DEFAULT        = 1,
        MM_BEARER_TYPE_DEFAULT_ATTACH = 2,
        MM_BEARER_TYPE_DEDICATED      = 3
} MMBearerType;

typedef enum {
        MM_MODEM_STATE_FAILED        = -1,
        MM_MODEM_STATE_UNKNOWN       = 0,
        MM_MODEM_STATE_INITIALIZING  = 1,
        MM_MODEM_STATE_LOCKED        = 2,
        MM_MODEM_STATE_DISABLED      = 3,
        MM_MODEM_STATE_DISABLING     = 4,
        MM_MODEM_STATE_ENABLING      = 5,
        MM_MODEM_STATE_ENABLED       = 6,
        MM_MODEM_STATE_SEARCHING     = 7,
        MM_MODEM_STATE_REGISTERED    = 8,
        MM_MODEM_STATE_DISCONNECTING = 9,
        MM_MODEM_STATE_CONNECTING    = 10,
        MM_MODEM_STATE_CONNECTED     = 11
} MMModemState;

typedef enum { /*< underscore_name=mm_modem_state_failed_reason >*/
        MM_MODEM_STATE_FAILED_REASON_NONE                  = 0,
        MM_MODEM_STATE_FAILED_REASON_UNKNOWN               = 1,
        MM_MODEM_STATE_FAILED_REASON_SIM_MISSING           = 2,
        MM_MODEM_STATE_FAILED_REASON_SIM_ERROR             = 3,
        MM_MODEM_STATE_FAILED_REASON_UNKNOWN_CAPABILITIES  = 4,
        MM_MODEM_STATE_FAILED_REASON_ESIM_WITHOUT_PROFILES = 5,
        __MM_MODEM_STATE_FAILED_REASON_MAX                 = 6,
} MMModemStateFailedReason;

typedef enum {
        MM_BEARER_IP_METHOD_UNKNOWN = 0,
        MM_BEARER_IP_METHOD_PPP     = 1,
        MM_BEARER_IP_METHOD_STATIC  = 2,
        MM_BEARER_IP_METHOD_DHCP    = 3,
} MMBearerIpMethod;

typedef enum { /*< underscore_name=mm_core_error >*/
        MM_CORE_ERROR_FAILED          = 0,  /*< nick=Failed        >*/
        MM_CORE_ERROR_CANCELLED       = 1,  /*< nick=Cancelled     >*/
        MM_CORE_ERROR_ABORTED         = 2,  /*< nick=Aborted       >*/
        MM_CORE_ERROR_UNSUPPORTED     = 3,  /*< nick=Unsupported   >*/
        MM_CORE_ERROR_NO_PLUGINS      = 4,  /*< nick=NoPlugins     >*/
        MM_CORE_ERROR_UNAUTHORIZED    = 5,  /*< nick=Unauthorized  >*/
        MM_CORE_ERROR_INVALID_ARGS    = 6,  /*< nick=InvalidArgs   >*/
        MM_CORE_ERROR_IN_PROGRESS     = 7,  /*< nick=InProgress    >*/
        MM_CORE_ERROR_WRONG_STATE     = 8,  /*< nick=WrongState    >*/
        MM_CORE_ERROR_CONNECTED       = 9,  /*< nick=Connected     >*/
        MM_CORE_ERROR_TOO_MANY        = 10, /*< nick=TooMany       >*/
        MM_CORE_ERROR_NOT_FOUND       = 11, /*< nick=NotFound      >*/
        MM_CORE_ERROR_RETRY           = 12, /*< nick=Retry         >*/
        MM_CORE_ERROR_EXISTS          = 13, /*< nick=Exists        >*/
        MM_CORE_ERROR_WRONG_SIM_STATE = 14, /*< nick=WrongSimState >*/
        MM_CORE_ERROR_RESET_AND_RETRY = 15, /*< nick=ResetRetry    >*/
        MM_CORE_ERROR_TIMEOUT         = 16, /*< nick=Timeout       >*/
        MM_CORE_ERROR_PROTOCOL        = 17, /*< nick=Protocol      >*/
        MM_CORE_ERROR_THROTTLED       = 18, /*< nick=Throttled     >*/
} MMCoreError;

typedef enum { /*< underscore_name=mm_modem_port_type >*/
        MM_MODEM_PORT_TYPE_UNKNOWN = 1,
        MM_MODEM_PORT_TYPE_NET     = 2,
        MM_MODEM_PORT_TYPE_AT      = 3,
        MM_MODEM_PORT_TYPE_QCDM    = 4,
        MM_MODEM_PORT_TYPE_GPS     = 5,
        MM_MODEM_PORT_TYPE_QMI     = 6,
        MM_MODEM_PORT_TYPE_MBIM    = 7,
        MM_MODEM_PORT_TYPE_AUDIO   = 8,
        MM_MODEM_PORT_TYPE_IGNORED = 9,
        MM_MODEM_PORT_TYPE_XMMRPC  = 10,
} MMModemPortType;

typedef enum {
        MODEM_RECONNECT_DONE,           /* No reconnect is required, e.g. connected. */
        MODEM_RECONNECT_SCHEDULED,      /* Reconnect is in progress. */
        MODEM_RECONNECT_WAITING,        /* Waiting for modem to recover. */
} ModemReconnectState;

int manager_notify_mm_bus_connected(Manager *manager);
int manager_match_modemmanager_signals(Manager *manager);
