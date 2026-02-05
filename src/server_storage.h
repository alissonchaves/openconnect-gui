/*
 * Copyright (C) 2014 Red Hat
 *
 * This file is part of openconnect-gui.
 *
 * openconnect-gui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "keypair.h"
#include <QVector>

class StoredServer {
public:
    StoredServer();
    ~StoredServer();

    int load(QString& name);
    int save();

    const QString& get_username() const;
    void set_username(const QString& username);

    const QString& get_password() const;
    void set_password(const QString& password);

    const QString& get_groupname() const;
    void set_groupname(const QString& groupname);

    const QString& get_server_gateway() const;
    void set_server_gateway(const QString& server_gateway);

    const QString& get_label() const;
    void set_label(const QString& label);

    bool get_disable_udp() const;
    void set_disable_udp(bool v);

    QString get_cert_file();
    QString get_key_file();
    QString get_key_url() const;
    QString get_ca_cert_file();

    void clear_cert();
    void clear_key();
    void clear_ca();
    void clear_password();
    void clear_groupname();
    void clear_server_pin();

    QString get_client_cert_pin();
    int set_client_cert(const QString& filename);

    QString get_ca_cert_pin();
    int set_ca_cert(const QString& filename);

    bool get_batch_mode() const;
    void set_batch_mode(const bool mode);

    bool get_minimize() const;
    void set_minimize(const bool t);

    bool get_proxy() const;
    void set_proxy(const bool t);

    int get_reconnect_timeout() const;
    void set_reconnect_timeout(const int timeout);

    int get_dtls_reconnect_timeout() const;
    void set_dtls_reconnect_timeout(const int timeout);

    QString get_token_str();
    void set_token_str(const QString& str);

    int get_token_type();
    void set_token_type(const int type);

    const QString&  get_protocol_name() const;
    void set_protocol_name(const QString name);

    bool server_pin_algo_is_legacy(void);
    unsigned get_server_pin(QByteArray& hash) const;
    void get_server_pin(QString& hash) const;
    void set_server_pin(const unsigned algo, const QByteArray& hash);

    bool client_is_complete() const;

    void set_window(QWidget* w);

    int set_client_key(const QString& filename);

    QString m_last_err;

    const QString& get_interface_name() const;
    void set_interface_name(const QString& interface_name);
    const QString& get_dns_search_domains() const;
    void set_dns_search_domains(const QString& dns_search_domains);

    const QString& get_vpnc_script_filename() const;
    void set_vpnc_script_filename(const QString& vpnc_script_filename);

    enum RoutePolicy {
        RoutePolicyServer = 0,
        RoutePolicyVpnDefault = 1,
        RoutePolicyManual = 2
    };

    struct RouteEntry {
        QString destination;
        QString netmask;
        QString gateway;
    };

    int get_route_policy() const;
    void set_route_policy(int policy);
    const QVector<RouteEntry>& get_route_entries() const;
    void set_route_entries(const QVector<RouteEntry>& entries);

    const QString& get_openvpn_config() const;
    void set_openvpn_config(const QString& openvpn_config);
    const QString& get_openvpn_config_text() const;
    void set_openvpn_config_text(const QString& text);
    const QString& get_openvpn_remote_host() const;
    void set_openvpn_remote_host(const QString& host);
    const QString& get_openvpn_remote_port() const;
    void set_openvpn_remote_port(const QString& port);
    const QString& get_openvpn_remote_proto() const;
    void set_openvpn_remote_proto(const QString& proto);
    const QString& get_openvpn_dev() const;
    void set_openvpn_dev(const QString& dev);
    const QString& get_openvpn_cipher() const;
    void set_openvpn_cipher(const QString& cipher);
    const QString& get_openvpn_data_ciphers() const;
    void set_openvpn_data_ciphers(const QString& value);
    const QString& get_openvpn_data_ciphers_fallback() const;
    void set_openvpn_data_ciphers_fallback(const QString& value);
    const QString& get_openvpn_auth() const;
    void set_openvpn_auth(const QString& auth);
    const QString& get_openvpn_resolv_retry() const;
    void set_openvpn_resolv_retry(const QString& value);
    const QString& get_openvpn_remote_cert_tls() const;
    void set_openvpn_remote_cert_tls(const QString& value);
    bool get_openvpn_nobind() const;
    void set_openvpn_nobind(bool value);
    const QString& get_openvpn_compress() const;
    void set_openvpn_compress(const QString& value);
    const QString& get_openvpn_ca() const;
    void set_openvpn_ca(const QString& value);
    const QString& get_openvpn_cert() const;
    void set_openvpn_cert(const QString& value);
    const QString& get_openvpn_key() const;
    void set_openvpn_key(const QString& value);
    const QString& get_openvpn_tls_auth() const;
    void set_openvpn_tls_auth(const QString& value);
    const QString& get_openvpn_tls_crypt() const;
    void set_openvpn_tls_crypt(const QString& value);
    const QString& get_openvpn_key_direction() const;
    void set_openvpn_key_direction(const QString& value);
    const QString& get_openvpn_setenv_client_cert() const;
    void set_openvpn_setenv_client_cert(const QString& value);
    bool get_openvpn_auth_user_pass() const;
    void set_openvpn_auth_user_pass(bool value);
    bool get_openvpn_persist_tun() const;
    void set_openvpn_persist_tun(bool value);
    bool get_openvpn_persist_key() const;
    void set_openvpn_persist_key(bool value);
    bool get_openvpn_ncp_disable() const;
    void set_openvpn_ncp_disable(bool value);
    bool get_openvpn_tls_client() const;
    void set_openvpn_tls_client(bool value);
    bool get_openvpn_client() const;
    void set_openvpn_client(bool value);

    int get_log_level();
    void set_log_level(const int log_level);

private:
    bool m_batch_mode;
    bool m_minimize_on_connect;
    bool m_proxy;
    bool m_disable_udp;
    int m_reconnect_timeout;
    int m_dtls_attempt_period;
    QString m_username;
    QString m_password;
    QString m_groupname;
    QString m_server_gateway;
    QString m_token_string;
    QString m_label;
    int m_token_type;
    QString m_protocol_name;
    QByteArray m_server_pin;
    unsigned m_server_pin_algo;
    Cert m_ca_cert;
    KeyPair m_client;
    QString m_interface_name;
    QString m_dns_search_domains;
    QString m_vpnc_script_filename;
    QString m_openvpn_config;
    QString m_openvpn_config_text;
    QString m_openvpn_remote_host;
    QString m_openvpn_remote_port;
    QString m_openvpn_remote_proto;
    QString m_openvpn_dev;
    QString m_openvpn_cipher;
    QString m_openvpn_data_ciphers;
    QString m_openvpn_data_ciphers_fallback;
    QString m_openvpn_auth;
    QString m_openvpn_resolv_retry;
    QString m_openvpn_remote_cert_tls;
    bool m_openvpn_nobind;
    QString m_openvpn_compress;
    QString m_openvpn_ca;
    QString m_openvpn_cert;
    QString m_openvpn_key;
    QString m_openvpn_tls_auth;
    QString m_openvpn_tls_crypt;
    QString m_openvpn_key_direction;
    QString m_openvpn_setenv_client_cert;
    bool m_openvpn_auth_user_pass;
    bool m_openvpn_persist_tun;
    bool m_openvpn_persist_key;
    bool m_openvpn_ncp_disable;
    bool m_openvpn_tls_client;
    bool m_openvpn_client;
    int m_route_policy;
    QVector<RouteEntry> m_route_entries;
    int m_log_level;
};
