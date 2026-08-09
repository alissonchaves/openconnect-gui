#pragma once

#include "vpn_types.h"

#include <atomic>
#include <memory>
#include <map>
#include <string>
#include <vector>

extern "C" {
#include <openconnect.h>
}

namespace openconnect::core {

class OpenConnectSession final : public VpnSession {
public:
    OpenConnectSession();
    ~OpenConnectSession() override;

    bool connect(const Profile& profile, EventSink& events, std::string& error) override;
    void run() override;
    void disconnect() override;
    Status status() const override;

private:
    static int auth_form(void* userdata, struct oc_auth_form* form);
    static int validate_peer_cert(void* userdata, const char* reason);
    static void progress(void* userdata, int level, const char* format, ...);
    static void stats(void* userdata, const struct oc_stats* stats);
    static void setup_tun(void* userdata);

    bool configure(const Profile& profile, std::string& error);
    void notify_status(ConnectionState state);
    void update_network_status();
    void handle_progress_message(const std::string& message);
    void apply_split_dns();
    void clear_split_dns();
    void clear_vpn_dns_from_network_services();
    void capture_network_dns_state();
    std::string find_tunnel_interface() const;

    struct openconnect_info* vpninfo_ = nullptr;
    EventSink* events_ = nullptr;
    Profile profile_;
    Status status_;
    std::atomic_bool disconnect_requested_{false};
    std::atomic_bool setup_failed_{false};
    int command_fd_ = -1;
    std::vector<std::string> split_dns_domains_;
    std::vector<std::string> split_dns_servers_;
    std::vector<std::string> vpn_dns_servers_;
    std::vector<std::string> vpn_dns_domains_;
    std::map<std::string, std::vector<std::string>> baseline_dns_domains_;
    std::map<std::string, std::vector<std::string>> baseline_dns_servers_;
    std::string split_dns_interface_;
};

} // namespace openconnect::core
