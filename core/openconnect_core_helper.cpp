#include "openconnect_session.h"

#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>
#include <unistd.h>
#include <string>

namespace {

struct StdioEvents final : openconnect::core::EventSink {
    void on_status(const openconnect::core::Status& status) override
    {
        std::cout << "STATUS\t" << static_cast<int>(status.state)
                  << "\t" << status.ipv4
                  << "\t" << status.ipv6
                  << "\t" << status.dns
                  << "\t" << status.dns_search
                  << "\t" << status.cstp_cipher
                  << "\t" << status.dtls_cipher
                  << "\t" << status.uploaded_bytes
                  << "\t" << status.downloaded_bytes << std::endl;
    }

    void on_log(const std::string& message) override
    {
        std::cout << "LOG\t" << message << std::endl;
    }

    bool on_authentication_required(const std::string& prompt,
        bool secret,
        std::string& value) override
    {
        std::cout << "AUTH\t" << (secret ? 1 : 0) << "\t" << prompt << std::endl;
        return static_cast<bool>(std::getline(std::cin, value));
    }
};

const char* option(int argc, char** argv, const char* name)
{
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], name) == 0) return argv[i + 1];
    }
    return nullptr;
}

} // namespace

int main(int argc, char** argv)
{
    std::cout << "PID\t" << getpid() << std::endl;
    const char* gateway = option(argc, argv, "--gateway");
    const char* protocol = option(argc, argv, "--protocol");
    if (gateway == nullptr || protocol == nullptr) {
        std::cout << "ERROR\tinvalid helper arguments" << std::endl;
        return 2;
    }

    openconnect::core::Profile profile;
    profile.gateway = gateway;
    profile.protocol = protocol;
    if (const char* value = option(argc, argv, "--script")) profile.vpnc_script = value;

    // Credentials arrive through stdin after the privileged pipe is created;
    // they never appear in the helper's argument list or process table.
    std::getline(std::cin, profile.username);
    std::getline(std::cin, profile.password);

    StdioEvents events;
    openconnect::core::OpenConnectSession session;
    std::string error;
    if (!session.connect(profile, events, error)) {
        std::cout << "ERROR\t" << error << std::endl;
        return 1;
    }

    std::thread control([&session] {
        std::string command;
        bool requested = false;
        while (std::getline(std::cin, command)) {
            if (command == "DISCONNECT") {
                session.disconnect();
                requested = true;
                break;
            }
        }
        // The UI pipe closes when the app exits. Treat that exactly like
        // an explicit disconnect so routes, DNS and the tunnel are cleaned.
        if (!requested) session.disconnect();
    });
    control.detach();
    session.run();
    return 0;
}
