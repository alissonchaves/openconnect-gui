#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace openconnect::core {

enum class ConnectionState {
    disconnecting,
    disconnected,
    connecting,
    connected
};

struct Route {
    std::string destination;
    std::string netmask;
    std::string gateway;
};

struct Profile {
    std::string name;
    std::string gateway;
    std::string protocol;
    std::string username;
    std::string password;
    std::string group;
    std::string token;
    std::string vpnc_script;
    std::string interface_name;
    std::string dns_search_domains;
    std::string openvpn_config;
    std::vector<Route> routes;
    bool batch_mode = false;
    bool disable_udp = false;
    bool minimize_on_connect = false;
    int reconnect_timeout = 300;
    int dtls_reconnect_timeout = 25;
    int route_policy = 0;
    int token_type = 0;
    int log_level = -1;
};

struct Status {
    ConnectionState state = ConnectionState::disconnected;
    std::string ipv4;
    std::string ipv6;
    std::string dns;
    std::string dns_search;
    std::string cstp_cipher;
    std::string dtls_cipher;
    std::uint64_t uploaded_bytes = 0;
    std::uint64_t downloaded_bytes = 0;
};

class EventSink {
public:
    virtual ~EventSink() = default;
    virtual void on_status(const Status& status) = 0;
    virtual void on_log(const std::string& message) = 0;
    virtual bool on_authentication_required(const std::string& prompt,
        bool secret,
        std::string& value) = 0;
};

class ProfileStore {
public:
    virtual ~ProfileStore() = default;
    virtual std::vector<Profile> list() const = 0;
    virtual bool save(const Profile& profile, const std::string& original_name, std::string& error) = 0;
    virtual bool remove(const std::string& name, std::string& error) = 0;
};

class VpnSession {
public:
    virtual ~VpnSession() = default;
    virtual bool connect(const Profile& profile, EventSink& events, std::string& error) = 0;
    virtual void run() = 0;
    virtual void disconnect() = 0;
    virtual Status status() const = 0;
};

} // namespace openconnect::core
