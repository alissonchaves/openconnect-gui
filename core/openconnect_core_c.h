#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct openconnect_core_session openconnect_core_session;

typedef enum openconnect_core_state {
    OPENCONNECT_CORE_DISCONNECTING = 0,
    OPENCONNECT_CORE_DISCONNECTED = 1,
    OPENCONNECT_CORE_CONNECTING = 2,
    OPENCONNECT_CORE_CONNECTED = 3
} openconnect_core_state;

typedef struct openconnect_core_profile {
    const char* gateway;
    const char* protocol;
    const char* username;
    const char* password;
    const char* group;
    const char* token;
    const char* vpnc_script;
    int disable_udp;
    int dtls_reconnect_timeout;
    int reconnect_timeout;
    int log_level;
    int route_mode;
    const char* custom_routes;
} openconnect_core_profile;

typedef struct openconnect_core_status {
    openconnect_core_state state;
    const char* ipv4;
    const char* ipv6;
    const char* dns;
    const char* dns_search;
    const char* cstp_cipher;
    const char* dtls_cipher;
    uint64_t uploaded_bytes;
    uint64_t downloaded_bytes;
} openconnect_core_status;

typedef int (*openconnect_core_auth_callback)(void* context,
    const char* prompt,
    int secret,
    char* value,
    uint32_t value_size);
typedef void (*openconnect_core_status_callback)(void* context,
    const openconnect_core_status* status);
typedef void (*openconnect_core_log_callback)(void* context, const char* message);

typedef struct openconnect_core_callbacks {
    void* context;
    openconnect_core_auth_callback auth;
    openconnect_core_status_callback status;
    openconnect_core_log_callback log;
} openconnect_core_callbacks;

// Writes one supported OpenConnect protocol per line as: name<TAB>display name.
// Returns the number of bytes required, excluding the terminating NUL.
uint32_t openconnect_core_supported_protocols(char* output, uint32_t output_size);

openconnect_core_session* openconnect_core_session_create(void);
void openconnect_core_session_destroy(openconnect_core_session* session);

int openconnect_core_session_connect(openconnect_core_session* session,
    const openconnect_core_profile* profile,
    const openconnect_core_callbacks* callbacks,
    char* error,
    uint32_t error_size);
void openconnect_core_session_run(openconnect_core_session* session);
void openconnect_core_session_disconnect(openconnect_core_session* session);
void openconnect_core_session_status(const openconnect_core_session* session,
    openconnect_core_status* status);

#ifdef __cplusplus
}
#endif
