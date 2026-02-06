/*
 * Minimal OpenVPN config parser/builder for profile UI.
 */

#pragma once

#include <QString>
#include <QStringList>

struct OpenVpnConfig {
    QString dev;
    bool persist_tun{ false };
    bool persist_key{ false };
    QString cipher;
    QString data_ciphers;
    QString data_ciphers_fallback;
    bool ncp_disable{ false };
    QString auth;
    bool tls_client{ false };
    bool client{ false };
    QString resolv_retry;
    QString remote_host;
    QString remote_port;
    QString remote_proto;
    bool auth_user_pass{ false };
    QString remote_cert_tls;
    bool nobind{ false };
    QString compress;
    QString ca;
    QString cert;
    QString key;
    QString tls_auth;
    QString tls_crypt;
    QString key_direction;
    QString setenv_client_cert;
    QStringList dns_search_domains;
};

bool parse_openvpn_config_file(const QString& path, OpenVpnConfig& out, QString* error);
bool parse_openvpn_config_text(const QString& text, OpenVpnConfig& out, QString* error);
QString build_openvpn_config_text(const OpenVpnConfig& cfg);
QString update_openvpn_config_text(const QString& base, const OpenVpnConfig& cfg);
QString apply_openvpn_route_policy(const QString& base, int policy, const QStringList& routes);
