#include <cerrno>
#include <cstdint>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <array>
#include <algorithm>
#include <utility>
#include <vector>
#include <mutex>
#include <atomic>
#include <chrono>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

namespace {
volatile sig_atomic_t child_pid = -1;
std::mutex output_stream_mutex;

void forward_signal(int signal)
{
    if (child_pid > 0) kill(child_pid, signal);
}

const char* option(int argc, char** argv, const char* name)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return nullptr;
}

const char* find_openvpn()
{
#if defined(__APPLE__)
    static char executable_path[PATH_MAX] = {};
    uint32_t executable_size = sizeof(executable_path);
    if (_NSGetExecutablePath(executable_path, &executable_size) == 0) {
        std::string path(executable_path);
        const auto separator = path.find_last_of('/');
        if (separator != std::string::npos) {
            const std::string directory = path.substr(0, separator);
            static std::string bundled_paths[2];
            bundled_paths[0] = directory + "/openvpn";
            bundled_paths[1] = directory + "/../Resources/openvpn";
            for (const auto& bundled : bundled_paths) {
                if (access(bundled.c_str(), X_OK) == 0) return bundled.c_str();
            }
        }
    }
#endif
    const char* candidates[] = {
        "/opt/homebrew/sbin/openvpn",
        "/opt/homebrew/bin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
        "/usr/sbin/openvpn",
        nullptr
    };
    for (const char** candidate = candidates; *candidate != nullptr; ++candidate) {
        if (access(*candidate, X_OK) == 0) return *candidate;
    }
    return nullptr;
}

void configured_drop_identity(const char* config, uid_t& uid, gid_t& gid, bool& found)
{
    FILE* file = std::fopen(config, "r");
    if (file == nullptr) return;
    char line[1024];
    std::string user;
    std::string group;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::string value(line);
        const std::string::size_type comment = value.find_first_of("#;");
        if (comment != std::string::npos) value.resize(comment);
        const std::string::size_type split = value.find_first_of(" \t");
        if (split == std::string::npos) continue;
        const std::string key = value.substr(0, split);
        const std::string::size_type argument_start = value.find_first_not_of(" \t", split);
        if (argument_start == std::string::npos) continue;
        std::string argument = value.substr(argument_start);
        while (!argument.empty() && (argument.back() == '\r' || argument.back() == '\n'
                || argument.back() == ' ' || argument.back() == '\t')) {
            argument.pop_back();
        }
        if (key == "user") user = argument;
        if (key == "group") group = argument;
    }
    std::fclose(file);
    if (user.empty()) return;

    const struct passwd* password_entry = getpwnam(user.c_str());
    if (password_entry == nullptr) return;
    uid = password_entry->pw_uid;
    gid = password_entry->pw_gid;
    if (!group.empty()) {
        const struct group* group_entry = getgrnam(group.c_str());
        if (group_entry != nullptr) gid = group_entry->gr_gid;
    }
    found = true;
}

bool configured_openvpn_device(const char* config)
{
    FILE* file = std::fopen(config, "r");
    if (file == nullptr) return false;
    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::string value(line);
        const std::string::size_type comment = value.find_first_of("#;");
        if (comment != std::string::npos) value.resize(comment);
        const std::string::size_type split = value.find_first_of(" \t\r\n");
        const std::string key = value.substr(0, split);
        if (key == "dev") {
            found = true;
            break;
        }
    }
    std::fclose(file);
    return found;
}

bool openvpn_auth_user_pass_from_stdin(const char* config)
{
    FILE* file = std::fopen(config, "r");
    if (file == nullptr) return false;
    char line[1024];
    bool found = false;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::string value(line);
        const std::string::size_type comment = value.find_first_of("#;");
        if (comment != std::string::npos) value.resize(comment);
        const std::string::size_type split = value.find_first_of(" \t\r\n");
        const std::string key = value.substr(0, split);
        if (key != "auth-user-pass") continue;
        const std::string::size_type argument_start = value.find_first_not_of(" \t\r\n", split);
        found = argument_start == std::string::npos;
        break;
    }
    std::fclose(file);
    return found;
}

std::vector<std::string> configured_openvpn_remotes(const char* config)
{
    FILE* file = std::fopen(config, "r");
    if (file == nullptr) return {};
    char line[1024];
    std::vector<std::string> remotes;
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::string value(line);
        const std::string::size_type comment = value.find_first_of("#;");
        if (comment != std::string::npos) value.resize(comment);
        std::istringstream stream(value);
        std::string key;
        std::string remote;
        stream >> key >> remote;
        if (key == "remote" && !remote.empty()) remotes.push_back(remote);
    }
    std::fclose(file);
    return remotes;
}

std::string shell_output(const std::string& command)
{
    FILE* pipe = popen(command.c_str(), "r");
    if (pipe == nullptr) return {};
    std::string output;
    std::array<char, 256> buffer{};
    while (std::fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output.append(buffer.data());
    }
    pclose(pipe);
    return output;
}

std::string shell_quote(const std::string& value)
{
    std::string quoted = "'";
    for (const char character : value) {
        if (character == '\'') quoted += "'\\''";
        else quoted += character;
    }
    quoted += "'";
    return quoted;
}

struct NetworkDNSState {
    std::string service;
    std::vector<std::string> servers;
    std::vector<std::string> domains;
};

std::vector<std::string> networksetup_values(const std::string& command)
{
    std::vector<std::string> values;
    const std::string output = shell_output(command);
    if (output.find("There aren't any") != std::string::npos) return values;
    std::istringstream lines(output);
    std::string value;
    while (std::getline(lines, value)) {
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) value.pop_back();
        if (!value.empty()) values.push_back(value);
    }
    return values;
}

std::vector<NetworkDNSState> capture_network_dns_state()
{
    std::vector<NetworkDNSState> state;
    std::istringstream services(shell_output("/usr/sbin/networksetup -listallnetworkservices"));
    std::string service;
    while (std::getline(services, service)) {
        while (!service.empty() && (service.back() == '\r' || service.back() == '\n')) service.pop_back();
        if (service.empty() || service.find("An asterisk") != std::string::npos || service.front() == '*') continue;
        NetworkDNSState entry;
        entry.service = service;
        entry.servers = networksetup_values("/usr/sbin/networksetup -getdnsservers " + shell_quote(service));
        entry.domains = networksetup_values("/usr/sbin/networksetup -getsearchdomains " + shell_quote(service));
        state.push_back(std::move(entry));
    }
    return state;
}

void restore_network_dns_state(const std::vector<NetworkDNSState>& state)
{
    for (const auto& entry : state) {
        std::string dns = "/usr/sbin/networksetup -setdnsservers " + shell_quote(entry.service);
        if (entry.servers.empty()) dns += " Empty";
        else for (const auto& server : entry.servers) dns += " " + shell_quote(server);
        std::system(dns.c_str());

        std::string domains = "/usr/sbin/networksetup -setsearchdomains " + shell_quote(entry.service);
        if (entry.domains.empty()) domains += " Empty";
        else for (const auto& domain : entry.domains) domains += " " + shell_quote(domain);
        std::system(domains.c_str());
    }
}

std::pair<std::string, std::string> interface_addresses(const std::string& interface_name)
{
    if (interface_name.empty()) return {};
    const std::string output = shell_output("/sbin/ifconfig " + interface_name + " 2>/dev/null");
    auto address = [&output](const std::string& marker) {
        const auto start = output.find(marker);
        if (start == std::string::npos) return std::string();
        const auto value_start = start + marker.size();
        const auto value_end = output.find_first_of(" \t\n", value_start);
        return output.substr(value_start, value_end == std::string::npos ? std::string::npos : value_end - value_start);
    };
    return { address("inet "), address("inet6 ") };
}

std::pair<std::string, std::string> find_tunnel_addresses(const std::string& preferred_interface)
{
    if (!preferred_interface.empty()) {
        const auto addresses = interface_addresses(preferred_interface);
        if (!addresses.first.empty() || !addresses.second.empty()) return addresses;
    }
    const auto interfaces = shell_output("/sbin/ifconfig -l");
    std::string names;
    for (std::size_t start = 0; start < interfaces.size();) {
        const auto end = interfaces.find_first_of(" \t\n", start);
        const std::string name = interfaces.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (name.rfind("utun", 0) == 0 || name.rfind("tun", 0) == 0 || name.rfind("tap", 0) == 0) {
            const auto addresses = interface_addresses(name);
            if (!addresses.first.empty() && addresses.first != "127.0.0.1") return addresses;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

std::pair<std::uint64_t, std::uint64_t> interface_counters(const std::string& interface_name)
{
    if (interface_name.empty()) return {};
    const std::string output = shell_output("/usr/sbin/netstat -ib -I " + interface_name + " 2>/dev/null");
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        std::istringstream fields(line);
        std::string name;
        fields >> name;
        if (name != interface_name) continue;
        std::vector<std::string> columns;
        std::string value;
        while (fields >> value) columns.push_back(value);
        // The first macOS row is the link-layer row and has one fewer
        // address column. Use the IPv4/network row (11 columns after name),
        // where Ibytes and Obytes are columns 6 and 9 (including the name).
        if (columns.size() < 10) continue;
        const auto ibytes = std::strtoull(columns[5].c_str(), nullptr, 10);
        const auto obytes = std::strtoull(columns[8].c_str(), nullptr, 10);
        return { obytes, ibytes };
    }
    return {};
}

std::pair<std::uint64_t, std::uint64_t> status_file_counters(const std::string& path)
{
    if (path.empty()) return {};
    FILE* file = std::fopen(path.c_str(), "r");
    if (file == nullptr) return {};
    std::uint64_t uploaded = 0;
    std::uint64_t downloaded = 0;
    char line[512];
    while (std::fgets(line, sizeof(line), file) != nullptr) {
        std::string value(line);
        const auto comma = value.find(',');
        if (comma == std::string::npos) continue;
        const auto number = std::strtoull(value.c_str() + comma + 1, nullptr, 10);
        if (value.rfind("TUN_BYTES_SENT,", 0) == 0 || value.rfind("TUN_BYTES_OUT,", 0) == 0) uploaded = number;
        if (value.rfind("TUN_BYTES_RECEIVED,", 0) == 0 || value.rfind("TUN_BYTES_IN,", 0) == 0) downloaded = number;
    }
    std::fclose(file);
    return { uploaded, downloaded };
}

void emit_status(int state, const std::string& ipv4, const std::string& ipv6,
    const std::string& dns, const std::string& dns_search, const std::string& cipher,
    std::uint64_t uploaded, std::uint64_t downloaded)
{
    std::lock_guard<std::mutex> stream_lock(output_stream_mutex);
    std::cout << "STATUS\t" << state
              << "\t" << ipv4
              << "\t" << ipv6
              << "\t" << dns
              << "\t" << dns_search
              << "\t" << cipher
              << "\t\t" << uploaded << "\t" << downloaded << std::endl;
}

void run_scutil(const std::string& script)
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

void apply_tunnel_dns(const std::string& interface_name, const std::string& dns,
    const std::string& dns_search)
{
    if (interface_name.empty() || dns.empty()) return;
    const std::string service = "openconnect-gui-" + interface_name;
    std::string script = "d.init\n";
    script += "d.add ServerAddresses *";
    std::istringstream servers(dns);
    std::string server;
    while (std::getline(servers, server, ',')) script += " " + server;
    script += "\n";
    if (!dns_search.empty()) {
        script += "d.add SearchDomains *";
        std::istringstream domains(dns_search);
        std::string domain;
        while (std::getline(domains, domain, ',')) script += " " + domain;
        script += "\n";
        script += "d.add SupplementalMatchDomains *";
        std::istringstream matches(dns_search);
        while (std::getline(matches, domain, ',')) script += " " + domain;
        script += "\n";
    }
    script += "d.add InterfaceName " + interface_name + "\n";
    script += "set State:/Network/Service/" + service + "/DNS\nquit\n";
    run_scutil(script);
}

std::string find_tunnel_interface_for_ip(const std::string& ip)
{
    if (ip.empty()) return {};
    const std::string interfaces = shell_output("/sbin/ifconfig -l");
    std::istringstream values(interfaces);
    std::string interface_name;
    while (values >> interface_name) {
        if (interface_name.rfind("utun", 0) != 0 &&
            interface_name.rfind("tun", 0) != 0 &&
            interface_name.rfind("tap", 0) != 0) continue;
        if (shell_output("/sbin/ifconfig " + interface_name).find(ip) != std::string::npos) {
            return interface_name;
        }
    }
    return {};
}

void clear_tunnel_dns(const std::string& interface_name)
{
    if (!interface_name.empty()) {
        run_scutil("remove State:/Network/Service/openconnect-gui-" + interface_name + "/DNS\nquit\n");
    }
}

void clear_all_tunnel_dns()
{
    // The interface may already have been destroyed when cleanup runs. In
    // that case scanning ifconfig cannot find it, so enumerate the dynamic
    // store keys themselves and remove every key owned by this helper.
    const std::string keys = shell_output("printf 'list\\nquit\\n' | /usr/sbin/scutil");
    std::istringstream values(keys);
    std::string line;
    const std::string prefix = "State:/Network/Service/openconnect-gui-";
    const std::string suffix = "/DNS";
    while (std::getline(values, line)) {
        const auto start = line.find(prefix);
        if (start == std::string::npos) continue;
        const auto end = line.find(suffix, start);
        if (end == std::string::npos) continue;
        run_scutil("remove " + line.substr(start, end + suffix.size()) + "\nquit\n");
    }
}

bool parse_openvpn_dns_options(const std::string& message, std::string& dns,
    std::string& dns_search)
{
    bool changed = false;
    auto append = [](std::string& target, const std::string& value) {
        if (value.empty() || target.find(value) != std::string::npos) return false;
        if (!target.empty()) target += ", ";
        target += value;
        return true;
    };
    std::size_t cursor = 0;
    while ((cursor = message.find("dhcp-option DNS ", cursor)) != std::string::npos) {
        cursor += 16;
        const auto end = message.find_first_of(" ,\t\r\n", cursor);
        changed |= append(dns, message.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor));
    }
    cursor = 0;
    while ((cursor = message.find("dhcp-option DOMAIN", cursor)) != std::string::npos) {
        cursor += 19;
        if (message.compare(cursor, 7, "-SEARCH") == 0) cursor += 7;
        cursor = message.find_first_not_of(" \t", cursor);
        if (cursor == std::string::npos) break;
        const auto end = message.find_first_of(" ,\t\r\n", cursor);
        changed |= append(dns_search, message.substr(cursor, end == std::string::npos ? std::string::npos : end - cursor));
    }
    return changed;
}

unsigned short reserve_management_port()
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return 0;
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        close(fd);
        return 0;
    }
    const unsigned short port = ntohs(address.sin_port);
    close(fd);
    return port;
}

void management_loop(unsigned short port, std::atomic<bool>& stopping, std::mutex& output_mutex,
    std::string& tunnel_ip, std::string& cipher, std::string& dns, std::string& dns_search,
    std::uint64_t& uploaded, std::uint64_t& downloaded,
    const std::string& password, const std::string& status_file)
{
    int connection = -1;
    while (!stopping && connection < 0) {
        connection = socket(AF_INET, SOCK_STREAM, 0);
        if (connection < 0) break;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(port);
        if (connect(connection, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            close(connection);
            connection = -1;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    bool management_authenticated = password.empty();
    if (connection >= 0) {
        const std::string commands = "log on all\nstate on\nbytecount 1\n";
        // Match the original client: send the credential and monitoring
        // commands in the same initial management write.
        const std::string initial = password.empty() ? commands : password + "\n" + commands;
        send(connection, initial.data(), initial.size(), 0);
    }

    std::string buffer;
    std::array<char, 4096> chunk{};
    auto last_interface_update = std::chrono::steady_clock::now();
    bool interface_baseline_set = false;
    std::uint64_t baseline_uploaded = 0;
    std::uint64_t baseline_downloaded = 0;
    std::pair<std::uint64_t, std::uint64_t> baseline_interface{};
    while (!stopping && connection >= 0) {
        pollfd descriptor{ connection, POLLIN, 0 };
        if (poll(&descriptor, 1, 500) <= 0) {
            if (!tunnel_ip.empty() &&
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - last_interface_update).count() >= 1) {
                const auto interface_name = find_tunnel_interface_for_ip(tunnel_ip);
                const auto interface_values = interface_counters(interface_name);
                const auto status_values = status_file_counters(status_file);
                if (interface_name.empty()) continue;
                std::lock_guard<std::mutex> lock(output_mutex);
                if (!interface_baseline_set) {
                    baseline_interface = interface_values;
                    baseline_uploaded = uploaded;
                    baseline_downloaded = downloaded;
                    interface_baseline_set = true;
                }
                const auto previous_uploaded = uploaded;
                const auto previous_downloaded = downloaded;
                const auto interface_uploaded = interface_values.first >= baseline_interface.first
                    ? baseline_uploaded + interface_values.first - baseline_interface.first : baseline_uploaded;
                const auto interface_downloaded = interface_values.second >= baseline_interface.second
                    ? baseline_downloaded + interface_values.second - baseline_interface.second : baseline_downloaded;
                uploaded = std::max(uploaded, std::max(interface_uploaded, status_values.first));
                downloaded = std::max(downloaded, std::max(interface_downloaded, status_values.second));
                if (uploaded != previous_uploaded || downloaded != previous_downloaded) {
                    emit_status(3, tunnel_ip, "", dns, dns_search,
                        cipher.empty() ? "OpenVPN" : cipher, uploaded, downloaded);
                }
                last_interface_update = std::chrono::steady_clock::now();
            }
            continue;
        }
        if (!(descriptor.revents & POLLIN)) break;
        const ssize_t count = recv(connection, chunk.data(), chunk.size(), 0);
        if (count <= 0) break;
        buffer.append(chunk.data(), static_cast<std::size_t>(count));
        std::size_t newline = 0;
        while ((newline = buffer.find('\n')) != std::string::npos) {
            std::string line = buffer.substr(0, newline);
            buffer.erase(0, newline + 1);
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
            if (!management_authenticated &&
                (line.find("SUCCESS: password is correct") != std::string::npos ||
                 line.rfind(">INFO:", 0) == 0)) {
                const std::string commands = "log on all\nstate on\nbytecount 1\n";
                send(connection, commands.data(), commands.size(), 0);
                management_authenticated = true;
                continue;
            }
            if (!management_authenticated && line.rfind(">PASSWORD:", 0) == 0) {
                const std::string value = password + "\n";
                send(connection, value.data(), value.size(), 0);
                continue;
            }
            if (line.rfind(">STATE:", 0) == 0) {
                std::vector<std::string> fields;
                std::size_t start = 7;
                while (start <= line.size()) {
                    const std::size_t end = line.find(',', start);
                    fields.push_back(line.substr(start, end == std::string::npos ? std::string::npos : end - start));
                    if (end == std::string::npos) break;
                    start = end + 1;
                }
                if (fields.size() >= 4 && fields[1] == "CONNECTED") {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    tunnel_ip = fields[3];
                    const auto interface_name = find_tunnel_interface_for_ip(tunnel_ip);
                    const auto interface_values = interface_counters(interface_name);
                    if (!interface_name.empty()) {
                        baseline_interface = interface_values;
                        baseline_uploaded = uploaded;
                        baseline_downloaded = downloaded;
                        interface_baseline_set = true;
                    }
                    apply_tunnel_dns(find_tunnel_interface_for_ip(tunnel_ip), dns, dns_search);
                    emit_status(3, tunnel_ip, "", dns, dns_search,
                        cipher.empty() ? "OpenVPN" : cipher, uploaded, downloaded);
                }
            } else if (line.rfind(">BYTECOUNT:", 0) == 0) {
                const std::size_t comma = line.find(',', 11);
                if (comma != std::string::npos) {
                    const auto input = std::strtoull(line.substr(11, comma - 11).c_str(), nullptr, 10);
                    const auto output = std::strtoull(line.substr(comma + 1).c_str(), nullptr, 10);
                    {
                        std::lock_guard<std::mutex> stream_lock(output_stream_mutex);
                        std::cout << "LOG\tOpenVPN BYTECOUNT in=" << input
                                  << " out=" << output << std::endl;
                    }
                    std::lock_guard<std::mutex> lock(output_mutex);
                    downloaded = input;
                    uploaded = output;
                    if (!tunnel_ip.empty()) {
                        const auto interface_name = find_tunnel_interface_for_ip(tunnel_ip);
                        const auto interface_values = interface_counters(interface_name);
                        if (!interface_name.empty()) {
                            if (!interface_baseline_set) {
                                baseline_interface = interface_values;
                                baseline_uploaded = uploaded;
                                baseline_downloaded = downloaded;
                                interface_baseline_set = true;
                            }
                            if (interface_values.first >= baseline_interface.first) {
                                uploaded = std::max(uploaded, baseline_uploaded + interface_values.first - baseline_interface.first);
                            }
                            if (interface_values.second >= baseline_interface.second) {
                                downloaded = std::max(downloaded, baseline_downloaded + interface_values.second - baseline_interface.second);
                            }
                        }
                    }
                    if (!tunnel_ip.empty()) emit_status(3, tunnel_ip, "", dns, dns_search,
                        cipher.empty() ? "OpenVPN" : cipher, uploaded, downloaded);
                }
            } else if (line.rfind(">LOG:", 0) == 0) {
                const auto first = line.find(',', 5);
                const auto second = first == std::string::npos ? std::string::npos : line.find(',', first + 1);
                const std::string message = second == std::string::npos ? line : line.substr(second + 1);
                std::lock_guard<std::mutex> lock(output_mutex);
                if (parse_openvpn_dns_options(message, dns, dns_search) && !tunnel_ip.empty()) {
                    apply_tunnel_dns(find_tunnel_interface_for_ip(tunnel_ip), dns, dns_search);
                    emit_status(3, tunnel_ip, "", dns, dns_search,
                        cipher.empty() ? "OpenVPN" : cipher, uploaded, downloaded);
                }
            }
        }
    }
    if (connection >= 0) close(connection);
}

} // namespace

int main(int argc, char** argv)
{
    const char* config = option(argc, argv, "--config");
    std::cout << "PID\t" << getpid() << std::endl;
    if (config == nullptr || access(config, R_OK) != 0) {
        std::cout << "ERROR\tOpenVPN configuration file cannot be read" << std::endl;
        return 2;
    }

    // Recover from a previous helper/app crash before creating a new
    // resolver. Only the app-owned service namespace is touched.
    clear_all_tunnel_dns();
    const auto baseline_network_dns = capture_network_dns_state();

    std::string username;
    std::string password;
    std::getline(std::cin, username);
    std::getline(std::cin, password);

    if (openvpn_auth_user_pass_from_stdin(config) &&
        (username.empty() || password.empty())) {
        std::cout << "ERROR\tThis OpenVPN profile requires a username and password" << std::endl;
        return 1;
    }

    char status_template[] = "/tmp/openconnect-openvpn-status-XXXXXX";
    const int status_fd = mkstemp(status_template);
    if (status_fd < 0) {
        std::cout << "ERROR\tUnable to create OpenVPN status file" << std::endl;
        return 1;
    }
    close(status_fd);
    const std::string status_file = status_template;
    // Reserve a unique path, then let OpenVPN create the file itself. This
    // avoids permission/ownership checks when the daemon drops privileges.
    unlink(status_file.c_str());

    char auth_template[] = "/tmp/openconnect-openvpn-auth-XXXXXX";
    // A certificate-only profile must not receive an auth-user-pass file.
    // Passing a file with an empty first line makes OpenVPN abort before the
    // TLS handshake, even when the .ovpn bundle already contains cert/key.
    const bool have_credentials = !username.empty();
    if (have_credentials) {
        const int auth_fd = mkstemp(auth_template);
        if (auth_fd < 0) {
            std::cout << "ERROR\tUnable to create temporary OpenVPN credentials file" << std::endl;
            return 1;
        }
        // OpenVPN may validate/read auth-user-pass before or after applying
        // the user/group from the configuration. Use a transient readable
        // file for compatibility with both behaviours; it is random, removed
        // when the process exits, and never passed on the command line.
        uid_t drop_uid = 0;
        gid_t drop_gid = 0;
        bool has_drop_identity = false;
        configured_drop_identity(config, drop_uid, drop_gid, has_drop_identity);
        bool readable_by_openvpn = false;
        if (has_drop_identity) {
            readable_by_openvpn = fchown(auth_fd, drop_uid, drop_gid) == 0;
        }
        fchmod(auth_fd, readable_by_openvpn ? 0600 : 0644);
        const std::string credentials = username + "\n" + password + "\n";
        if (write(auth_fd, credentials.data(), credentials.size()) != static_cast<ssize_t>(credentials.size())) {
            close(auth_fd);
            unlink(auth_template);
            std::cout << "ERROR\tUnable to write OpenVPN credentials" << std::endl;
            return 1;
        }
        close(auth_fd);
    } else {
        auth_template[0] = '\0';
    }

    const char* openvpn = find_openvpn();
    if (openvpn == nullptr) {
        if (have_credentials) unlink(auth_template);
        std::cout << "ERROR\tOpenVPN executable was not found" << std::endl;
        return 1;
    }

    unsigned short management_port = reserve_management_port();
    std::string management_password_file;
    std::string management_password;
    if (management_port != 0) {
        char password_template[] = "/tmp/openconnect-openvpn-mgmt-XXXXXX";
        const int password_fd = mkstemp(password_template);
        if (password_fd >= 0) {
            management_password = "openconnect-" + std::to_string(getpid());
            uid_t drop_uid = 0;
            gid_t drop_gid = 0;
            bool has_drop_identity = false;
            configured_drop_identity(config, drop_uid, drop_gid, has_drop_identity);
            bool readable_by_openvpn = false;
            if (has_drop_identity) {
                readable_by_openvpn = fchown(password_fd, drop_uid, drop_gid) == 0;
            }
            fchmod(password_fd, readable_by_openvpn ? 0600 : 0644);
            write(password_fd, management_password.data(), management_password.size());
            close(password_fd);
            management_password_file = password_template;
        }
    }

    int output_pipe[2];
    if (pipe(output_pipe) != 0) {
        if (have_credentials) unlink(auth_template);
        if (!management_password_file.empty()) unlink(management_password_file.c_str());
        std::cout << "ERROR\tUnable to create OpenVPN output pipe" << std::endl;
        return 1;
    }

    child_pid = fork();
    if (child_pid == 0) {
        // OpenVPN configurations commonly reference certificates and keys by
        // relative path. Resolve them relative to the .ovpn file, not the
        // arbitrary working directory inherited by the privileged helper.
        const std::string config_path(config);
        const std::string::size_type separator = config_path.find_last_of('/');
        const std::string config_directory = separator == std::string::npos
            ? "."
            : config_path.substr(0, separator);
        chdir(config_directory.c_str());
        dup2(output_pipe[1], STDOUT_FILENO);
        dup2(output_pipe[1], STDERR_FILENO);
        close(output_pipe[0]);
        close(output_pipe[1]);
        std::vector<std::string> arguments = { openvpn, "--config", config };
        // Some exported .ovpn bundles omit the device because the original
        // client supplied it implicitly. Preserve an explicit device and
        // provide the normal tunnel device only when it is absent.
        if (!configured_openvpn_device(config)) {
            arguments.push_back("--dev");
            arguments.push_back("tun");
        }
        // A pushed route can contain the VPN endpoint itself. Keep every
        // configured endpoint reachable through the physical gateway so the
        // control connection is not accidentally routed into its own tunnel.
        for (const auto& remote : configured_openvpn_remotes(config)) {
            arguments.push_back("--route");
            arguments.push_back(remote);
            arguments.push_back("255.255.255.255");
            arguments.push_back("net_gateway");
        }
        if (have_credentials) {
            arguments.push_back("--auth-user-pass");
            arguments.push_back(auth_template);
            arguments.push_back("--auth-nocache");
        }
        if (management_port != 0) {
            arguments.push_back("--management");
            arguments.push_back("127.0.0.1");
            arguments.push_back(std::to_string(management_port));
        if (!management_password_file.empty()) arguments.push_back(management_password_file);
            arguments.push_back("--management-log-cache");
            arguments.push_back("100");
            arguments.push_back("--verb");
            arguments.push_back("4");
        }
        arguments.push_back("--status");
        arguments.push_back(status_file);
        arguments.push_back("1");
        arguments.push_back("--status-version");
        arguments.push_back("1");
        std::vector<char*> raw_arguments;
        for (auto& argument : arguments) raw_arguments.push_back(argument.data());
        raw_arguments.push_back(nullptr);
        execv(openvpn, raw_arguments.data());
        _exit(127);
    }
    close(output_pipe[1]);
    if (child_pid < 0) {
        close(output_pipe[0]);
        if (have_credentials) unlink(auth_template);
        if (!management_password_file.empty()) unlink(management_password_file.c_str());
        std::cout << "ERROR\tUnable to start OpenVPN" << std::endl;
        return 1;
    }

    std::signal(SIGTERM, forward_signal);
    std::signal(SIGINT, forward_signal);
    std::thread control([] {
        std::string command;
        bool requested = false;
        while (std::getline(std::cin, command)) {
            if (command == "DISCONNECT") {
                forward_signal(SIGTERM);
                requested = true;
                break;
            }
        }
        if (!requested) forward_signal(SIGTERM);
    });
    control.detach();
    std::atomic<bool> management_stopping{false};
    std::mutex output_mutex;
    std::string management_ip;
    std::string dns;
    std::string dns_search;
    std::string cipher;
    std::uint64_t management_uploaded = 0;
    std::uint64_t management_downloaded = 0;
    std::thread management;
    if (management_port != 0) {
        management = std::thread(management_loop, management_port,
            std::ref(management_stopping), std::ref(output_mutex),
            std::ref(management_ip), std::ref(cipher), std::ref(dns),
            std::ref(dns_search),
            std::ref(management_uploaded), std::ref(management_downloaded),
            std::cref(management_password), std::cref(status_file));
        management.detach();
    }
    FILE* output = fdopen(output_pipe[0], "r");
    char line[2048];
    bool connected = false;
    std::string tunnel_interface;
    std::pair<std::uint64_t, std::uint64_t> counters;
    while (output != nullptr && std::fgets(line, sizeof(line), output) != nullptr) {
        std::string message(line);
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) message.pop_back();
        const std::string device_marker = "TUN/TAP device ";
        if (const auto start = message.find(device_marker); start != std::string::npos) {
            const auto value_start = start + device_marker.size();
            const auto value_end = message.find_first_of(" \t", value_start);
            tunnel_interface = message.substr(value_start,
                value_end == std::string::npos ? std::string::npos : value_end - value_start);
        }
        const std::string opened_marker = "Opened utun device ";
        if (const auto start = message.find(opened_marker); start != std::string::npos) {
            const auto value_start = start + opened_marker.size();
            const auto value_end = message.find_first_of(" \t", value_start);
            tunnel_interface = message.substr(value_start,
                value_end == std::string::npos ? std::string::npos : value_end - value_start);
        }
        const std::string bracketed_marker = "utun device [";
        if (const auto start = message.find(bracketed_marker); start != std::string::npos) {
            const auto value_start = start + bracketed_marker.size();
            const auto value_end = message.find(']', value_start);
            if (value_end != std::string::npos) tunnel_interface = message.substr(value_start, value_end - value_start);
        }
        {
            std::lock_guard<std::mutex> lock(output_mutex);
            parse_openvpn_dns_options(message, dns, dns_search);
        }
        const std::string dns_marker = "dhcp-option DNS ";
        if (const auto start = message.find(dns_marker); start != std::string::npos) {
            const auto value_start = start + dns_marker.size();
            const auto value_end = message.find_first_of(" ,\t", value_start);
            std::lock_guard<std::mutex> lock(output_mutex);
            const std::string value = message.substr(value_start,
                value_end == std::string::npos ? std::string::npos : value_end - value_start);
            if (dns.find(value) == std::string::npos) {
                if (!dns.empty()) dns += ", ";
                dns += value;
            }
        }
        const std::string domain_marker = "dhcp-option DOMAIN";
        if (const auto start = message.find(domain_marker); start != std::string::npos) {
            std::string remainder = message.substr(start + domain_marker.size());
            if (remainder.rfind("-SEARCH", 0) == 0) remainder.erase(0, 7);
            const auto value_start = remainder.find_first_not_of(" \t");
            if (value_start != std::string::npos) {
                const auto value_end = remainder.find_first_of(" ,\t", value_start);
                const std::string value = remainder.substr(value_start,
                    value_end == std::string::npos ? std::string::npos : value_end - value_start);
                std::lock_guard<std::mutex> lock(output_mutex);
                if (!value.empty() && dns_search.find(value) == std::string::npos) {
                    if (!dns_search.empty()) dns_search += ", ";
                    dns_search += value;
                }
            }
        }
        const auto lower_cipher = message.find("cipher '");
        const auto upper_cipher = message.find("Cipher '");
        const auto cipher_start = lower_cipher != std::string::npos ? lower_cipher : upper_cipher;
        if (cipher_start != std::string::npos) {
            const auto value_start = cipher_start + 8;
            const auto value_end = message.find('\'', value_start);
            std::lock_guard<std::mutex> lock(output_mutex);
            cipher = message.substr(value_start,
                value_end == std::string::npos ? std::string::npos : value_end - value_start);
        }
        if (message.find("Initialization Sequence Completed") != std::string::npos) {
            connected = true;
            const auto addresses = find_tunnel_addresses(tunnel_interface);
            counters = interface_counters(tunnel_interface);
            std::lock_guard<std::mutex> lock(output_mutex);
            apply_tunnel_dns(tunnel_interface, dns, dns_search);
            emit_status(3, addresses.first, addresses.second, dns, dns_search,
                cipher.empty() ? "OpenVPN" : cipher,
                counters.first, counters.second);
        }
        {
            std::lock_guard<std::mutex> stream_lock(output_stream_mutex);
            std::cout << "LOG\t" << message << std::endl;
        }
    }
    if (output != nullptr) fclose(output);

    int child_status = 0;
    waitpid(child_pid, &child_status, 0);
    child_pid = -1;
    management_stopping.store(true);
    if (have_credentials) unlink(auth_template);
    if (!management_password_file.empty()) unlink(management_password_file.c_str());
    unlink(status_file.c_str());
    clear_tunnel_dns(tunnel_interface);
    clear_all_tunnel_dns();
    restore_network_dns_state(baseline_network_dns);
    emit_status(1, "", "", "", "", "", 0, 0);
    return connected && WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 ? 0 : 1;
}
