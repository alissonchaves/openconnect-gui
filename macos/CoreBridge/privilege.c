#include "native_privilege.h"

#include <Security/Authorization.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

// Keep the authorization reference alive for the lifetime of the UI process.
// A separate reference per VPN caused macOS to display an administrator
// password prompt for every helper launch, even when connecting several VPNs
// in a row.
static pthread_mutex_t authorization_mutex = PTHREAD_MUTEX_INITIALIZER;
static AuthorizationRef cached_authorization = NULL;

static int launch_authorized_tool(const char* tool, char** arguments, int* communication_fd)
{
    if (tool == NULL || arguments == NULL || communication_fd == NULL) {
        return errAuthorizationInvalidRef;
    }

    pthread_mutex_lock(&authorization_mutex);
    OSStatus status = errAuthorizationSuccess;
    if (cached_authorization == NULL) {
        status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &cached_authorization);
    }

    if (status == errAuthorizationSuccess) {
        AuthorizationItem right = { "system.privilege.admin", 0, NULL, 0 };
        AuthorizationRights rights = { 1, &right };
        status = AuthorizationCopyRights(cached_authorization, &rights, kAuthorizationEmptyEnvironment,
            kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    }

    if (status == errAuthorizationSuccess) {
        FILE* pipe = NULL;
        status = AuthorizationExecuteWithPrivileges(cached_authorization, tool, 0, arguments, &pipe);
        if (status == errAuthorizationSuccess && pipe != NULL) {
            *communication_fd = dup(fileno(pipe));
            if (*communication_fd < 0) status = errAuthorizationToolExecuteFailure;
            fclose(pipe);
        }
    }

    pthread_mutex_unlock(&authorization_mutex);
    return status;
}

int native_privilege_launch(const char* tool,
    const char* gateway,
    const char* protocol,
    const char* script,
    int* communication_fd)
{
    if (tool == NULL || gateway == NULL || protocol == NULL || communication_fd == NULL) {
        return errAuthorizationInvalidRef;
    }

    char* arguments[] = {
        (char*)"--gateway", (char*)gateway,
        (char*)"--protocol", (char*)protocol,
        (char*)"--script", (char*)(script != NULL ? script : ""),
        NULL
    };
    return launch_authorized_tool(tool, arguments, communication_fd);
}

int native_privilege_launch_openvpn(const char* tool,
    const char* config,
    int* communication_fd)
{
    if (tool == NULL || config == NULL || communication_fd == NULL) {
        return errAuthorizationInvalidRef;
    }

    char* arguments[] = { (char*)"--config", (char*)config, NULL };
    return launch_authorized_tool(tool, arguments, communication_fd);
}
