#include "openconnect_session.h"

#include <cstdarg>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <strings.h>
#include <array>
#include <algorithm>
#include <fstream>
#include <map>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

namespace openconnect::core {

static std::string run_command(const std::string& command);

OpenConnectSession::OpenConnectSession()
{
    vpninfo_ = openconnect_vpninfo_new(
        "OpenConnect native core",
        validate_peer_cert,
        nullptr,
        auth_form,
        progress,
        this);
    if (vpninfo_ != nullptr) {
        openconnect_set_stats_handler(vpninfo_, stats);
        openconnect_set_setup_tun_handler(vpninfo_, setup_tun);
        command_fd_ = openconnect_setup_cmd_pipe(vpninfo_);
    }
}

OpenConnectSession::~OpenConnectSession()
{
    clear_split_dns();
    if (vpninfo_ != nullptr) {
        openconnect_vpninfo_free(vpninfo_);
    }
}

int OpenConnectSession::validate_peer_cert(void* userdata, const char* reason)
{
    auto* session = static_cast<OpenConnectSession*>(userdata);
    if (session != nullptr && session->events_ != nullptr) {
        std::string message = "VPN server certificate rejected";
        if (reason != nullptr && reason[0] != '\0') {
            message += ": ";
            message += reason;
        }
        session->events_->on_log(message);
    }
    // OpenConnect calls this only after its normal certificate validation
    // failed. Reject by default; accepting an exception will require an
    // explicit certificate-pinning flow in the native Keychain integration.
    return 1;
}

bool OpenConnectSession::connect(const Profile& profile, EventSink& events, std::string& error)
{
    if (vpninfo_ == nullptr) {
        error = "Unable to initialize OpenConnect";
        return false;
    }

    profile_ = profile;
    events_ = &events;
    disconnect_requested_.store(false);
    setup_failed_.store(false);
    status_ = {};
    split_dns_domains_.clear();
    split_dns_servers_.clear();
    vpn_dns_servers_.clear();
    vpn_dns_domains_.clear();
    split_dns_interface_.clear();
    capture_network_dns_state();
    notify_status(ConnectionState::connecting);

    if (!configure(profile, error)) {
        notify_status(ConnectionState::disconnected);
        return false;
    }

    int ret = openconnect_obtain_cookie(vpninfo_);
    if (ret != 0) {
        error = "Authentication error; cannot obtain cookie";
        notify_status(ConnectionState::disconnected);
        return false;
    }

    ret = openconnect_make_cstp_connection(vpninfo_);
    if (ret != 0) {
        error = "Error establishing the CSTP channel";
        notify_status(ConnectionState::disconnected);
        return false;
    }

    if (!profile.disable_udp) {
        ret = openconnect_setup_dtls(vpninfo_, profile.dtls_reconnect_timeout);
        if (ret != 0) {
            openconnect_disable_dtls(vpninfo_);
        }
    }

    update_network_status();
    return true;
}

void OpenConnectSession::run()
{
    if (vpninfo_ == nullptr || events_ == nullptr) {
        return;
    }

    while (!disconnect_requested_.load()) {
        if (openconnect_mainloop(vpninfo_, profile_.reconnect_timeout, 10) != 0) {
            break;
        }
    }
    // The OpenConnect teardown invokes vpnc-script after mainloop returns.
    // Cleaning DNS before that point allows the script to add the VPN
    // resolver back to the physical interface.  Remove it only after the
    // tunnel and its script have finished shutting down.
    clear_split_dns();
    notify_status(ConnectionState::disconnected);
}

void OpenConnectSession::disconnect()
{
    if (status_.state != ConnectionState::disconnected) {
        notify_status(ConnectionState::disconnecting);
    }
    disconnect_requested_.store(true);
    if (command_fd_ >= 0) {
        const char cancel = OC_CMD_CANCEL;
        write(command_fd_, &cancel, 1);
    }
}

Status OpenConnectSession::status() const
{
    return status_;
}

bool OpenConnectSession::configure(const Profile& profile, std::string& error)
{
    const std::string url = profile.gateway.find("://") == std::string::npos
        ? "https://" + profile.gateway
        : profile.gateway;
    if (openconnect_parse_url(vpninfo_, url.c_str()) != 0) {
        error = "Invalid VPN gateway";
        return false;
    }

    if (openconnect_set_protocol(vpninfo_, profile.protocol.c_str()) != 0) {
        error = "Unsupported VPN protocol";
        return false;
    }

    openconnect_set_reported_os(vpninfo_, "mac-intel");
    openconnect_set_loglevel(vpninfo_, profile.log_level < 0 ? PRG_INFO : profile.log_level);

    if (profile.disable_udp) {
        openconnect_disable_dtls(vpninfo_);
    }

    if (!profile.token.empty()) {
        openconnect_set_token_mode(vpninfo_, static_cast<oc_token_mode_t>(profile.token_type), profile.token.c_str());
    }

    return true;
}

void OpenConnectSession::notify_status(ConnectionState state)
{
    status_.state = state;
    if (events_ != nullptr) {
        events_->on_status(status_);
    }
}

void OpenConnectSession::update_network_status()
{
    const struct oc_ip_info* info = nullptr;
    if (openconnect_get_ip_info(vpninfo_, &info, nullptr, nullptr) == 0 && info != nullptr) {
        if (info->addr != nullptr) status_.ipv4 = info->addr;
        if (info->addr6 != nullptr) status_.ipv6 = info->addr6;
        status_.dns.clear();
        for (const char* server : info->dns) {
            if (server == nullptr) break;
            if (!status_.dns.empty()) status_.dns += ", ";
            status_.dns += server;
        }
        if (status_.dns_search.empty()) {
            status_.dns_search = info->domain != nullptr ? info->domain : "";
        }
    }
    const char* cstp = openconnect_get_cstp_cipher(vpninfo_);
    const char* dtls = openconnect_get_dtls_cipher(vpninfo_);
    status_.cstp_cipher = cstp != nullptr ? cstp : "";
    status_.dtls_cipher = dtls != nullptr ? dtls : "";
}

int OpenConnectSession::auth_form(void* userdata, struct oc_auth_form* form)
{
    auto* session = static_cast<OpenConnectSession*>(userdata);
    if (session->events_ == nullptr) return OC_FORM_RESULT_CANCELLED;

    bool username_used = false;
    bool password_used = false;

    if (form->authgroup_opt != nullptr) {
        auto* option = reinterpret_cast<oc_form_opt_select*>(form->authgroup_opt);
        if (option->nr_choices == 0) return OC_FORM_RESULT_CANCELLED;
        std::string value = session->profile_.group;
        if (value.empty() && !session->events_->on_authentication_required(
                "Authentication group", false, value)) {
            value = option->choices[0]->name;
        }
        openconnect_set_option_value(&option->form, value.c_str());
    }

    for (struct oc_form_opt* option = form->opts; option != nullptr; option = option->next) {
        if ((option->flags & OC_FORM_OPT_IGNORE) != 0) continue;
        std::string value;
        const bool secret = option->type == OC_FORM_OPT_PASSWORD;
        const char* name = option->name != nullptr ? option->name : "";
        if (strcasecmp(name, "username") == 0 || strcasecmp(name, "user") == 0) {
            value = session->profile_.username;
            username_used = true;
        } else if (strcasecmp(name, "password") == 0 || strcasecmp(name, "pass") == 0) {
            value = session->profile_.password;
            password_used = true;
        } else if (strcasecmp(name, "token") == 0) {
            value = session->profile_.token;
        }

        // Fortinet and some SSO gateways use provider-specific option names.
        // Use the first ordinary text/password field as the saved credential,
        // while leaving subsequent fields (OTP, security code, etc.) interactive.
        if (value.empty() && !secret && !username_used && !session->profile_.username.empty()) {
            value = session->profile_.username;
            username_used = true;
        } else if (value.empty() && secret && !password_used && !session->profile_.password.empty()) {
            value = session->profile_.password;
            password_used = true;
        }
        if (value.empty() && !session->events_->on_authentication_required(
                option->label ? option->label : option->name, secret, value)) {
            return OC_FORM_RESULT_CANCELLED;
        }
        openconnect_set_option_value(option, value.c_str());
    }
    return OC_FORM_RESULT_OK;
}

void OpenConnectSession::progress(void* userdata, int level, const char* format, ...)
{
    auto* session = static_cast<OpenConnectSession*>(userdata);
    if (session->events_ == nullptr || level == PRG_TRACE) return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    std::vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    session->handle_progress_message(buffer);
    if (std::strstr(buffer, "Got split-DNS") != nullptr &&
        std::strstr(buffer, "not yet implemented") != nullptr) {
        return;
    }
    session->events_->on_log(buffer);
}

void OpenConnectSession::handle_progress_message(const std::string& message)
{
    const std::string domains_marker = "Got split-DNS domains ";
    if (const auto start = message.find(domains_marker); start != std::string::npos) {
        std::string domains = message.substr(start + domains_marker.size());
        if (const auto note = domains.find(" ("); note != std::string::npos) domains.resize(note);
        std::istringstream values(domains);
        std::string value;
        while (std::getline(values, value, ',')) {
            while (!value.empty() && value.front() == ' ') value.erase(value.begin());
            while (!value.empty() && value.back() == ' ') value.pop_back();
            if (!value.empty()) split_dns_domains_.push_back(value);
            if (!value.empty()) vpn_dns_domains_.push_back(value);
        }
        status_.dns_search.clear();
        for (const auto& domain : split_dns_domains_) {
            if (!status_.dns_search.empty()) status_.dns_search += ", ";
            status_.dns_search += domain;
        }
    }

    const std::string server_marker = "Got split-DNS server ";
    if (const auto start = message.find(server_marker); start != std::string::npos) {
        std::string server = message.substr(start + server_marker.size());
        if (const auto note = server.find(" ("); note != std::string::npos) server.resize(note);
        while (!server.empty() && server.back() == ' ') server.pop_back();
        if (!server.empty()) split_dns_servers_.push_back(server);
    }

    const std::string dns_marker = "Got IPv4 DNS server ";
    if (const auto start = message.find(dns_marker); start != std::string::npos) {
        std::string server = message.substr(start + dns_marker.size());
        while (!server.empty() && (server.back() == '\r' || server.back() == '\n' || server.back() == ' ')) server.pop_back();
        if (!server.empty()) vpn_dns_servers_.push_back(server);
    }
}

static std::string run_command(const std::string& command)
{
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) return {};
    std::string result;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) result += buffer.data();
    pclose(pipe);
    return result;
}

void OpenConnectSession::capture_network_dns_state()
{
    baseline_dns_domains_.clear();
    baseline_dns_servers_.clear();
    const std::string output = run_command("/usr/sbin/scutil --dns");
    std::istringstream lines(output);
    std::string line;
    std::string interface_name;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
    auto flush = [&] {
        if (!interface_name.empty()) {
            baseline_dns_servers_[interface_name] = servers;
            baseline_dns_domains_[interface_name] = domains;
        }
        interface_name.clear();
        servers.clear();
        domains.clear();
    };
    while (std::getline(lines, line)) {
        if (line.rfind("resolver #", 0) == 0) flush();
        const auto nameserver = line.find("nameserver[");
        if (nameserver != std::string::npos) {
            const auto colon = line.find(':', nameserver);
            if (colon != std::string::npos) {
                const std::string value = line.substr(colon + 1);
                const auto first = value.find_first_not_of(' ');
                if (first != std::string::npos) servers.push_back(value.substr(first));
            }
        }
        const auto search = line.find("search domain[");
        if (search != std::string::npos) {
            const auto colon = line.find(':', search);
            if (colon != std::string::npos) {
                const std::string value = line.substr(colon + 1);
                const auto first = value.find_first_not_of(' ');
                if (first != std::string::npos) domains.push_back(value.substr(first));
            }
        }
        const auto index = line.find("if_index");
        if (index != std::string::npos) {
            const auto open = line.find('(', index);
            const auto close = line.find(')', open);
            if (open != std::string::npos && close != std::string::npos) interface_name = line.substr(open + 1, close - open - 1);
        }
    }
    flush();
}

static std::string shell_quote(const std::string& value)
{
    std::string quoted = "'";
    for (const char character : value) {
        if (character == '\'') quoted += "'\\''";
        else quoted += character;
    }
    quoted += "'";
    return quoted;
}

void OpenConnectSession::clear_vpn_dns_from_network_services()
{
    std::vector<std::string> vpn_servers = vpn_dns_servers_;
    vpn_servers.insert(vpn_servers.end(), split_dns_servers_.begin(), split_dns_servers_.end());
    std::istringstream dns_values(status_.dns);
    std::string dns_value;
    while (std::getline(dns_values, dns_value, ',')) {
        while (!dns_value.empty() && dns_value.front() == ' ') dns_value.erase(dns_value.begin());
        while (!dns_value.empty() && dns_value.back() == ' ') dns_value.pop_back();
        if (!dns_value.empty()) vpn_servers.push_back(dns_value);
    }
    if (vpn_servers.empty()) return;

    const std::string output = run_command("/usr/sbin/networksetup -listallnetworkservices");
    std::istringstream network_services(output);
    std::string service;
    while (std::getline(network_services, service)) {
        if (service.empty() || service.find("An asterisk") != std::string::npos || service.front() == '*') continue;
        while (!service.empty() && (service.back() == '\r' || service.back() == '\n')) service.pop_back();
        const std::string current = run_command("/usr/sbin/networksetup -getdnsservers " + shell_quote(service));
        std::istringstream current_values(current);
        std::vector<std::string> kept;
        std::string address;
        while (current_values >> address) {
            bool is_vpn_server = false;
            for (const auto& server : vpn_servers) {
                if (address == server) {
                    is_vpn_server = true;
                    break;
                }
            }
            if (!is_vpn_server && address.find('.') != std::string::npos) kept.push_back(address);
        }
        if (kept.size() == 0 && current.find("There aren't any DNS") == std::string::npos) {
            std::system(("/usr/sbin/networksetup -setdnsservers " + shell_quote(service) + " Empty").c_str());
        } else if (!kept.empty()) {
            std::string command = "/usr/sbin/networksetup -setdnsservers " + shell_quote(service);
            for (const auto& address : kept) command += " " + shell_quote(address);
            std::system(command.c_str());
        }

        const std::string current_domains = run_command("/usr/sbin/networksetup -getsearchdomains " + shell_quote(service));
        std::istringstream domain_values(current_domains);
        std::vector<std::string> kept_domains;
        std::string domain;
        while (domain_values >> domain) {
            bool is_vpn_domain = false;
            for (const auto& vpn_domain : vpn_dns_domains_) {
                if (domain == vpn_domain) {
                    is_vpn_domain = true;
                    break;
                }
            }
            if (!is_vpn_domain && domain.find('.') != std::string::npos) kept_domains.push_back(domain);
        }
        if (kept_domains.empty() && current_domains.find("There aren't any Search Domains") == std::string::npos) {
            std::system(("/usr/sbin/networksetup -setsearchdomains " + shell_quote(service) + " Empty").c_str());
        } else if (!kept_domains.empty()) {
            std::string command = "/usr/sbin/networksetup -setsearchdomains " + shell_quote(service);
            for (const auto& value : kept_domains) command += " " + shell_quote(value);
            std::system(command.c_str());
        }
    }

    // networksetup may report no manually configured DNS while scutil still
    // contains VPN DNS inherited through DHCP/service state. Restore the
    // affected physical services from scutil, keeping only non-VPN values.
    struct ResolverState {
        std::vector<std::string> servers;
        std::vector<std::string> domains;
    };
    std::map<std::string, ResolverState> affected;
    const std::string scutil_dns = run_command("/usr/sbin/scutil --dns");
    std::istringstream dns_lines(scutil_dns);
    std::string line;
    ResolverState resolver;
    std::string interface_name;
    auto flush_resolver = [&] {
        if (interface_name.empty()) return;
        bool has_vpn_server = false;
        for (const auto& server : resolver.servers) {
            for (const auto& vpn_server : vpn_servers) {
                if (server == vpn_server) has_vpn_server = true;
            }
        }
        if (has_vpn_server) affected[interface_name] = resolver;
        resolver = {};
        interface_name.clear();
    };
    while (std::getline(dns_lines, line)) {
        if (line.rfind("resolver #", 0) == 0) flush_resolver();
        const auto nameserver = line.find("nameserver[");
        if (nameserver != std::string::npos) {
            const auto colon = line.find(':', nameserver);
            if (colon != std::string::npos) resolver.servers.push_back(line.substr(colon + 1).substr(line.substr(colon + 1).find_first_not_of(' ')));
        }
        const auto search = line.find("search domain[");
        if (search != std::string::npos) {
            const auto colon = line.find(':', search);
            if (colon != std::string::npos) resolver.domains.push_back(line.substr(colon + 1).substr(line.substr(colon + 1).find_first_not_of(' ')));
        }
        const auto index = line.find("if_index");
        if (index != std::string::npos) {
            const auto open = line.find('(', index);
            const auto close = line.find(')', open);
            if (open != std::string::npos && close != std::string::npos) interface_name = line.substr(open + 1, close - open - 1);
        }
    }
    flush_resolver();

    std::map<std::string, std::string> services;
    const std::string service_order = run_command("/usr/sbin/networksetup -listnetworkserviceorder");
    std::istringstream service_lines(service_order);
    std::string pending_service;
    while (std::getline(service_lines, line)) {
        if (line.size() > 3 && line[0] == '(') {
            const auto close = line.find(") ");
            if (close != std::string::npos) {
                pending_service = line.substr(close + 2);
                const auto hardware = pending_service.find(" (Hardware Port:");
                if (hardware != std::string::npos) pending_service.resize(hardware);
            }
        }
        const auto device = line.find("Device: ");
        if (device != std::string::npos) {
            const auto start = device + 8;
            const auto end = line.find(')', start);
            const std::string device_name = line.substr(start, end == std::string::npos ? std::string::npos : end - start);
            if (affected.find(device_name) != affected.end()) services[device_name] = pending_service;
        }
    }

    for (const auto& [device, state] : affected) {
        const auto service = services.find(device);
        if (service == services.end() || service->second.empty()) continue;
        std::vector<std::string> kept_servers;
        for (const auto& server : state.servers) {
            if (std::find(vpn_servers.begin(), vpn_servers.end(), server) == vpn_servers.end()) kept_servers.push_back(server);
        }
        std::string dns_command = "/usr/sbin/networksetup -setdnsservers " + shell_quote(service->second);
        if (kept_servers.empty()) dns_command += " Empty";
        else for (const auto& server : kept_servers) dns_command += " " + shell_quote(server);
        std::system(dns_command.c_str());

        std::vector<std::string> kept_domains;
        const auto baseline_domains = baseline_dns_domains_.find(device);
        const auto& source_domains = baseline_domains != baseline_dns_domains_.end()
            ? baseline_domains->second
            : state.domains;
        for (const auto& domain : source_domains) {
            if (std::find(vpn_dns_domains_.begin(), vpn_dns_domains_.end(), domain) == vpn_dns_domains_.end()) kept_domains.push_back(domain);
        }
        std::string domain_command = "/usr/sbin/networksetup -setsearchdomains " + shell_quote(service->second);
        if (kept_domains.empty()) domain_command += " Empty";
        else for (const auto& domain : kept_domains) domain_command += " " + shell_quote(domain);
        std::system(domain_command.c_str());
    }
}

std::string OpenConnectSession::find_tunnel_interface() const
{
    const std::string interfaces = run_command("/sbin/ifconfig -l");
    std::istringstream values(interfaces);
    std::string interface_name;
    while (values >> interface_name) {
        if (interface_name.rfind("utun", 0) != 0) continue;
        const std::string details = run_command("/sbin/ifconfig " + interface_name);
        if (details.find(status_.ipv4) != std::string::npos) return interface_name;
    }
    return {};
}

static void run_scutil(const std::string& script)
{
    int input[2];
    if (pipe(input) != 0) return;
    const pid_t child = fork();
    if (child == 0) {
        dup2(input[0], STDIN_FILENO);
        close(input[0]);
        close(input[1]);
        execl("/usr/sbin/scutil", "scutil", nullptr);
        _exit(127);
    }
    close(input[0]);
    write(input[1], script.data(), script.size());
    close(input[1]);
    waitpid(child, nullptr, 0);
}

void OpenConnectSession::apply_split_dns()
{
    if (split_dns_domains_.empty() || split_dns_servers_.empty()) return;
    split_dns_interface_ = find_tunnel_interface();
    if (split_dns_interface_.empty()) return;

    const std::string service = "openconnect-gui-" + split_dns_interface_;
    std::string script = "d.init\n";
    script += "d.add ServerAddresses * " + [&] {
        std::string value;
        for (const auto& server : split_dns_servers_) {
            if (!value.empty()) value += " ";
            value += server;
        }
        return value;
    }() + "\n";
    script += "d.add SearchDomains *";
    for (const auto& domain : split_dns_domains_) script += " " + domain;
    script += "\nd.add SupplementalMatchDomains *";
    for (const auto& domain : split_dns_domains_) script += " " + domain;
    script += "\nd.add InterfaceName " + split_dns_interface_ + "\n";
    script += "set State:/Network/Service/" + service + "/DNS\nquit\n";
    run_scutil(script);
    // vpnc-script may have prepended the VPN DNS to the physical service.
    // Keep DNS scoped to the utun resolver instead.
    clear_vpn_dns_from_network_services();
}

void OpenConnectSession::clear_split_dns()
{
    if (!split_dns_interface_.empty()) {
        run_scutil("remove State:/Network/Service/openconnect-gui-" + split_dns_interface_ + "/DNS\nquit\n");
        split_dns_interface_.clear();
    }
    clear_vpn_dns_from_network_services();
}

void OpenConnectSession::stats(void* userdata, const struct oc_stats* stats)
{
    auto* session = static_cast<OpenConnectSession*>(userdata);
    if (stats == nullptr) return;
    session->status_.uploaded_bytes = stats->tx_bytes;
    session->status_.downloaded_bytes = stats->rx_bytes;
    if (session->events_ != nullptr) session->events_->on_status(session->status_);
}

void OpenConnectSession::setup_tun(void* userdata)
{
    auto* session = static_cast<OpenConnectSession*>(userdata);
    if (session->vpninfo_ == nullptr) return;

    // The packaged app will provide its own script path in the profile. This
    // conventional Homebrew path keeps local development usable meanwhile.
    const char* script = session->profile_.vpnc_script.empty()
        ? "/opt/homebrew/etc/vpnc/vpnc-script"
        : session->profile_.vpnc_script.c_str();
    if (openconnect_setup_tun_device(session->vpninfo_, script, nullptr) != 0) {
        session->setup_failed_.store(true);
        session->disconnect_requested_.store(true);
        if (session->events_ != nullptr) {
            session->events_->on_log("Unable to configure the VPN network interface");
        }
    } else {
        session->apply_split_dns();
        session->notify_status(ConnectionState::connected);
    }
}

} // namespace openconnect::core
