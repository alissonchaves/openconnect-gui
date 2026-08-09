#include "openconnect_core_c.h"

#include "openconnect_session.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>

using openconnect::core::ConnectionState;
using openconnect::core::EventSink;
using openconnect::core::OpenConnectSession;
using openconnect::core::Profile;
using openconnect::core::Status;

namespace {

const char* string_or_empty(const char* value)
{
    return value != nullptr ? value : "";
}

void copy_error(char* destination, uint32_t size, const std::string& error)
{
    if (destination == nullptr || size == 0) return;
    const size_t count = std::min<size_t>(size - 1, error.size());
    std::memcpy(destination, error.data(), count);
    destination[count] = '\0';
}

openconnect_core_state to_c_state(ConnectionState state)
{
    switch (state) {
    case ConnectionState::disconnecting: return OPENCONNECT_CORE_DISCONNECTING;
    case ConnectionState::connecting: return OPENCONNECT_CORE_CONNECTING;
    case ConnectionState::connected: return OPENCONNECT_CORE_CONNECTED;
    case ConnectionState::disconnected: return OPENCONNECT_CORE_DISCONNECTED;
    }
    return OPENCONNECT_CORE_DISCONNECTED;
}

class CallbackSink final : public EventSink {
public:
    explicit CallbackSink(const openconnect_core_callbacks* callbacks)
        : callbacks_(callbacks != nullptr ? *callbacks : openconnect_core_callbacks{})
    {
    }

    void on_status(const Status& status) override
    {
        if (callbacks_.status == nullptr) return;
        openconnect_core_status value{};
        value.state = to_c_state(status.state);
        value.ipv4 = status.ipv4.c_str();
        value.ipv6 = status.ipv6.c_str();
        value.dns = status.dns.c_str();
        value.dns_search = status.dns_search.c_str();
        value.cstp_cipher = status.cstp_cipher.c_str();
        value.dtls_cipher = status.dtls_cipher.c_str();
        value.uploaded_bytes = status.uploaded_bytes;
        value.downloaded_bytes = status.downloaded_bytes;
        callbacks_.status(callbacks_.context, &value);
    }

    void on_log(const std::string& message) override
    {
        if (callbacks_.log != nullptr) callbacks_.log(callbacks_.context, message.c_str());
    }

    bool on_authentication_required(const std::string& prompt,
        bool secret,
        std::string& value) override
    {
        if (callbacks_.auth == nullptr) return false;
        char buffer[4096] = {};
        if (!callbacks_.auth(callbacks_.context, prompt.c_str(), secret ? 1 : 0,
                buffer, sizeof(buffer))) {
            return false;
        }
        value = buffer;
        return true;
    }

private:
    openconnect_core_callbacks callbacks_{};
};

} // namespace

extern "C" uint32_t openconnect_core_supported_protocols(char* output, uint32_t output_size)
{
    struct oc_vpn_proto* protocols = nullptr;
    std::string value;
    if (openconnect_get_supported_protocols(&protocols) >= 0 && protocols != nullptr) {
        for (const oc_vpn_proto* protocol = protocols; protocol->name != nullptr; ++protocol) {
            value += protocol->name;
            value += '\t';
            value += (protocol->pretty_name != nullptr ? protocol->pretty_name : protocol->name);
            value += '\n';
        }
        openconnect_free_supported_protocols(protocols);
    }

    if (output != nullptr && output_size > 0) {
        const size_t count = std::min<size_t>(value.size(), output_size - 1);
        std::memcpy(output, value.data(), count);
        output[count] = '\0';
    }
    return static_cast<uint32_t>(value.size());
}

struct openconnect_core_session {
    OpenConnectSession session;
    std::unique_ptr<EventSink> events;
};

extern "C" openconnect_core_session* openconnect_core_session_create(void)
{
    return new openconnect_core_session();
}

extern "C" void openconnect_core_session_destroy(openconnect_core_session* session)
{
    delete session;
}

extern "C" int openconnect_core_session_connect(openconnect_core_session* session,
    const openconnect_core_profile* profile,
    const openconnect_core_callbacks* callbacks,
    char* error,
    uint32_t error_size)
{
    if (session == nullptr || profile == nullptr) {
        copy_error(error, error_size, "Invalid session or profile");
        return 0;
    }

    Profile value;
    value.gateway = string_or_empty(profile->gateway);
    value.protocol = string_or_empty(profile->protocol);
    value.username = string_or_empty(profile->username);
    value.password = string_or_empty(profile->password);
    value.group = string_or_empty(profile->group);
    value.token = string_or_empty(profile->token);
    value.vpnc_script = string_or_empty(profile->vpnc_script);
    value.disable_udp = profile->disable_udp != 0;
    value.dtls_reconnect_timeout = profile->dtls_reconnect_timeout;
    value.reconnect_timeout = profile->reconnect_timeout;
    value.log_level = profile->log_level;

    session->events = std::make_unique<CallbackSink>(callbacks);
    std::string message;
    if (!session->session.connect(value, *session->events, message)) {
        copy_error(error, error_size, message);
        session->events.reset();
        return 0;
    }
    copy_error(error, error_size, "");
    return 1;
}

extern "C" void openconnect_core_session_run(openconnect_core_session* session)
{
    if (session != nullptr) session->session.run();
}

extern "C" void openconnect_core_session_disconnect(openconnect_core_session* session)
{
    if (session != nullptr) session->session.disconnect();
}

extern "C" void openconnect_core_session_status(const openconnect_core_session* session,
    openconnect_core_status* status)
{
    if (session == nullptr || status == nullptr) return;
    const Status value = session->session.status();
    status->state = to_c_state(value.state);
    status->ipv4 = value.ipv4.c_str();
    status->ipv6 = value.ipv6.c_str();
    status->dns = value.dns.c_str();
    status->dns_search = value.dns_search.c_str();
    status->cstp_cipher = value.cstp_cipher.c_str();
    status->dtls_cipher = value.dtls_cipher.c_str();
    status->uploaded_bytes = value.uploaded_bytes;
    status->downloaded_bytes = value.downloaded_bytes;
}
