#include "native_privilege.h"

#include <Security/Authorization.h>
#include <stdio.h>
#include <unistd.h>

int native_privilege_launch(const char* tool,
    const char* gateway,
    const char* protocol,
    const char* script,
    int* communication_fd)
{
    if (tool == NULL || gateway == NULL || protocol == NULL || communication_fd == NULL) {
        return errAuthorizationInvalidRef;
    }

    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess) return status;

    AuthorizationItem right = {
        "system.privilege.admin",
        0,
        NULL,
        0
    };
    AuthorizationRights rights = { 1, &right };
    status = AuthorizationCopyRights(authorization, &rights, kAuthorizationEmptyEnvironment,
        kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    if (status != errAuthorizationSuccess) {
        AuthorizationFree(authorization, kAuthorizationFlagDefaults);
        return status;
    }

    char* arguments[] = {
        (char*)"--gateway", (char*)gateway,
        (char*)"--protocol", (char*)protocol,
        (char*)"--script", (char*)(script != NULL ? script : ""),
        NULL
    };
    FILE* pipe = NULL;
    status = AuthorizationExecuteWithPrivileges(authorization, tool, 0, arguments, &pipe);
    if (status == errAuthorizationSuccess && pipe != NULL) {
        *communication_fd = dup(fileno(pipe));
        if (*communication_fd < 0) status = errAuthorizationToolExecuteFailure;
        fclose(pipe);
    }
    AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    return status;
}

int native_privilege_launch_openvpn(const char* tool,
    const char* config,
    int* communication_fd)
{
    if (tool == NULL || config == NULL || communication_fd == NULL) {
        return errAuthorizationInvalidRef;
    }

    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, NULL, kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess) return status;

    AuthorizationItem right = { "system.privilege.admin", 0, NULL, 0 };
    AuthorizationRights rights = { 1, &right };
    status = AuthorizationCopyRights(authorization, &rights, kAuthorizationEmptyEnvironment,
        kAuthorizationFlagInteractionAllowed | kAuthorizationFlagExtendRights, NULL);
    if (status != errAuthorizationSuccess) {
        AuthorizationFree(authorization, kAuthorizationFlagDefaults);
        return status;
    }

    char* arguments[] = { (char*)"--config", (char*)config, NULL };
    FILE* pipe = NULL;
    status = AuthorizationExecuteWithPrivileges(authorization, tool, 0, arguments, &pipe);
    if (status == errAuthorizationSuccess && pipe != NULL) {
        *communication_fd = dup(fileno(pipe));
        if (*communication_fd < 0) status = errAuthorizationToolExecuteFailure;
        fclose(pipe);
    }
    AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    return status;
}
