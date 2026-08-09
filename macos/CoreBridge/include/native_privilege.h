#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Launches the native helper after requesting administrator authorization.
// The returned descriptor is a bidirectional pipe connected to the helper's
// stdin/stdout. Returns 0 on success and an OSStatus otherwise.
int native_privilege_launch(const char* tool,
    const char* gateway,
    const char* protocol,
    const char* script,
    int* communication_fd);

int native_privilege_launch_openvpn(const char* tool,
    const char* config,
    int* communication_fd);

// Native macOS interface counters, shared by all VPN protocols.
int native_find_interface_for_ipv4(const char* ipv4, char* interface_name, unsigned int interface_name_size);
int native_interface_counters(const char* interface_name, unsigned long long* received, unsigned long long* sent);

#ifdef __cplusplus
}
#endif
