// Header-only C target used to expose the core ABI to Swift's Clang importer.
#include "openconnect_core_c.h"
#include "native_privilege.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int native_find_interface_for_ipv4(const char* ipv4, char* interface_name, unsigned int interface_name_size)
{
    if (ipv4 == NULL || interface_name == NULL || interface_name_size == 0) return 0;
    struct in_addr wanted;
    if (inet_aton(ipv4, &wanted) == 0) return 0;

    struct ifaddrs* addresses = NULL;
    if (getifaddrs(&addresses) != 0) return 0;
    int found = 0;
    for (struct ifaddrs* item = addresses; item != NULL; item = item->ifa_next) {
        if (item->ifa_name == NULL || item->ifa_addr == NULL ||
            item->ifa_addr->sa_family != AF_INET ||
            strncmp(item->ifa_name, "utun", 4) != 0) continue;
        const struct sockaddr_in* address = (const struct sockaddr_in*)item->ifa_addr;
        if (address->sin_addr.s_addr != wanted.s_addr) continue;
        snprintf(interface_name, interface_name_size, "%s", item->ifa_name);
        found = 1;
        break;
    }
    freeifaddrs(addresses);
    return found;
}

int native_interface_counters(const char* interface_name, unsigned long long* received, unsigned long long* sent)
{
    if (interface_name == NULL || received == NULL || sent == NULL) return 0;
    struct ifaddrs* addresses = NULL;
    if (getifaddrs(&addresses) != 0) return 0;
    int found = 0;
    for (struct ifaddrs* item = addresses; item != NULL; item = item->ifa_next) {
        if (item->ifa_name == NULL || item->ifa_data == NULL ||
            strcmp(item->ifa_name, interface_name) != 0 ||
            item->ifa_addr == NULL) continue;
        struct if_data* data = (struct if_data*)item->ifa_data;
        *received = data->ifi_ibytes;
        *sent = data->ifi_obytes;
        found = 1;
        break;
    }
    freeifaddrs(addresses);
    return found;
}
