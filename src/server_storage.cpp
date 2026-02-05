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

#include "server_storage.h"
#include "cryptdata.h"
#include "common.h"
#include "openvpn_config.h"
#include <OcSettings.h>
#include <cstdio>

StoredServer::~StoredServer(void)
{
}

StoredServer::StoredServer()
    : m_batch_mode{ false }
    , m_minimize_on_connect{ false }
    , m_proxy{ false }
    , m_disable_udp{ false }
    , m_reconnect_timeout{ 300 }
    , m_dtls_attempt_period{ 25 }
    , m_server_pin_algo(0)
    , m_openvpn_nobind(false)
    , m_openvpn_auth_user_pass(false)
    , m_openvpn_persist_tun(false)
    , m_openvpn_persist_key(false)
    , m_openvpn_ncp_disable(false)
    , m_openvpn_tls_client(false)
    , m_openvpn_client(false)
    , m_route_policy(RoutePolicyServer)
    , m_log_level (-1)
{
    set_window(nullptr);
}

// LCA: drop this define from whole project...
#define PREFIX "server:"

void StoredServer::clear_password()
{
    this->m_password.clear();
}

void StoredServer::clear_groupname()
{
    this->m_groupname.clear();
}

void StoredServer::clear_cert()
{
    this->m_client.cert.clear();
}

void StoredServer::clear_key()
{
    this->m_client.key.clear();
}

void StoredServer::clear_ca()
{
    this->m_ca_cert.clear();
}

void StoredServer::clear_server_pin()
{
    this->m_server_pin.clear();
    this->m_server_pin_algo = 0;
}

QString StoredServer::get_cert_file()
{
    QString File;
    if (this->m_client.cert.is_ok()) {
        this->m_client.cert.tmpfile_export(File);
    }
    return File;
}

QString StoredServer::get_key_file()
{
    QString File;
    if (this->m_client.key.is_ok()) {
        this->m_client.key.tmpfile_export(File);
    }
    return File;
}

QString StoredServer::get_key_url() const
{
    QString File;
    if (this->m_client.key.is_ok()) {
        this->m_client.key.get_url(File);
    }
    return File;
}

QString StoredServer::get_ca_cert_file()
{
    QString File;
    if (this->m_ca_cert.is_ok()) {
        this->m_ca_cert.tmpfile_export(File);
    }
    return File;
}

int StoredServer::set_ca_cert(const QString& filename)
{
    int ret = this->m_ca_cert.import_file(filename);
    this->m_last_err = this->m_ca_cert.last_err;
    return ret;
}

int StoredServer::set_client_cert(const QString& filename)
{
    int ret = this->m_client.import_cert(filename);
    this->m_last_err = this->m_client.last_err;

    if (ret != 0) {
        ret = this->m_client.import_pfx(filename);
        this->m_last_err = this->m_client.last_err;
    }
    return ret;
}

int StoredServer::set_client_key(const QString& filename)
{
    int ret = this->m_client.import_key(filename);
    this->m_last_err = this->m_client.last_err;
    return ret;
}

bool StoredServer::server_pin_algo_is_legacy(void)
{
    if (this->m_server_pin_algo != GNUTLS_DIG_SHA256)
        return true;
    else
        return false;
}

void StoredServer::get_server_pin(QString& hash) const
{
    if (this->m_server_pin_algo == 0) {
        hash = "";
    } else {
        if (this->m_server_pin_algo == GNUTLS_DIG_SHA256) {
            hash = "pin-sha256:";
            hash += this->m_server_pin.toBase64();
        } else {
            hash = gnutls_mac_get_name((gnutls_mac_algorithm_t)this->m_server_pin_algo);
            hash += ":";
            hash += this->m_server_pin.toHex();
        }
    }
}

// Returns: < 0 on error to load
//          0 if no entry existed
//          1 if an entry existed
int StoredServer::load(QString& name)
{
    this->m_label = name;
    OcSettings settings;
    int rval = 1;

    settings.beginGroup(PREFIX + name);

    m_protocol_name = settings.value("protocol-name").toString();
    m_openvpn_config = settings.value("openvpn-config").toString();
    m_openvpn_config_text = settings.value("openvpn-config-text").toString();
    m_openvpn_remote_host = settings.value("openvpn-remote-host").toString();
    m_openvpn_remote_port = settings.value("openvpn-remote-port").toString();
    m_openvpn_remote_proto = settings.value("openvpn-remote-proto").toString();
    m_openvpn_dev = settings.value("openvpn-dev").toString();
    m_openvpn_cipher = settings.value("openvpn-cipher").toString();
    m_openvpn_data_ciphers = settings.value("openvpn-data-ciphers").toString();
    m_openvpn_data_ciphers_fallback = settings.value("openvpn-data-ciphers-fallback").toString();
    m_openvpn_auth = settings.value("openvpn-auth").toString();
    m_openvpn_resolv_retry = settings.value("openvpn-resolv-retry").toString();
    m_openvpn_remote_cert_tls = settings.value("openvpn-remote-cert-tls").toString();
    m_openvpn_nobind = settings.value("openvpn-nobind", false).toBool();
    m_openvpn_compress = settings.value("openvpn-compress").toString();
    m_openvpn_ca = settings.value("openvpn-ca").toString();
    m_openvpn_cert = settings.value("openvpn-cert").toString();
    m_openvpn_key = settings.value("openvpn-key").toString();
    m_openvpn_tls_auth = settings.value("openvpn-tls-auth").toString();
    m_openvpn_tls_crypt = settings.value("openvpn-tls-crypt").toString();
    m_openvpn_key_direction = settings.value("openvpn-key-direction").toString();
    m_openvpn_setenv_client_cert = settings.value("openvpn-setenv-client-cert").toString();
    m_openvpn_auth_user_pass = settings.value("openvpn-auth-user-pass", false).toBool();
    m_openvpn_persist_tun = settings.value("openvpn-persist-tun", false).toBool();
    m_openvpn_persist_key = settings.value("openvpn-persist-key", false).toBool();
    m_openvpn_ncp_disable = settings.value("openvpn-ncp-disable", false).toBool();
    m_openvpn_tls_client = settings.value("openvpn-tls-client", false).toBool();
    m_openvpn_client = settings.value("openvpn-client", false).toBool();
    m_route_policy = settings.value("route-policy", RoutePolicyServer).toInt();
    m_route_entries.clear();
    const QStringList route_list = settings.value("route-entries").toStringList();
    for (const QString& entry : route_list) {
        const QStringList parts = entry.split(QLatin1Char('|'));
        RouteEntry route;
        if (parts.size() > 0) route.destination = parts.at(0);
        if (parts.size() > 1) route.netmask = parts.at(1);
        if (parts.size() > 2) route.gateway = parts.at(2);
        if (!route.destination.isEmpty() || !route.netmask.isEmpty() || !route.gateway.isEmpty()) {
            m_route_entries.push_back(route);
        }
    }

    if (m_protocol_name == QLatin1String(OCG_PROTO_OPENVPN)
        && m_openvpn_config_text.isEmpty() == false
        && m_openvpn_remote_host.isEmpty()) {
        OpenVpnConfig cfg;
        if (parse_openvpn_config_text(m_openvpn_config_text, cfg, nullptr)) {
            if (m_openvpn_remote_host.isEmpty()) m_openvpn_remote_host = cfg.remote_host;
            if (m_openvpn_remote_port.isEmpty()) m_openvpn_remote_port = cfg.remote_port;
            if (m_openvpn_remote_proto.isEmpty()) m_openvpn_remote_proto = cfg.remote_proto;
            if (m_openvpn_dev.isEmpty()) m_openvpn_dev = cfg.dev;
            if (m_openvpn_cipher.isEmpty()) m_openvpn_cipher = cfg.cipher;
            if (m_openvpn_data_ciphers.isEmpty()) m_openvpn_data_ciphers = cfg.data_ciphers;
            if (m_openvpn_data_ciphers_fallback.isEmpty()) m_openvpn_data_ciphers_fallback = cfg.data_ciphers_fallback;
            if (m_openvpn_auth.isEmpty()) m_openvpn_auth = cfg.auth;
            if (m_openvpn_resolv_retry.isEmpty()) m_openvpn_resolv_retry = cfg.resolv_retry;
            if (m_openvpn_remote_cert_tls.isEmpty()) m_openvpn_remote_cert_tls = cfg.remote_cert_tls;
            if (m_openvpn_compress.isEmpty()) m_openvpn_compress = cfg.compress;
            if (m_openvpn_ca.isEmpty()) m_openvpn_ca = cfg.ca;
            if (m_openvpn_cert.isEmpty()) m_openvpn_cert = cfg.cert;
            if (m_openvpn_key.isEmpty()) m_openvpn_key = cfg.key;
            if (m_openvpn_tls_auth.isEmpty()) m_openvpn_tls_auth = cfg.tls_auth;
            if (m_openvpn_tls_crypt.isEmpty()) m_openvpn_tls_crypt = cfg.tls_crypt;
            if (m_openvpn_key_direction.isEmpty()) m_openvpn_key_direction = cfg.key_direction;
            if (m_openvpn_setenv_client_cert.isEmpty()) m_openvpn_setenv_client_cert = cfg.setenv_client_cert;
            if (!m_openvpn_auth_user_pass) m_openvpn_auth_user_pass = cfg.auth_user_pass;
            if (!m_openvpn_persist_tun) m_openvpn_persist_tun = cfg.persist_tun;
            if (!m_openvpn_persist_key) m_openvpn_persist_key = cfg.persist_key;
            if (!m_openvpn_ncp_disable) m_openvpn_ncp_disable = cfg.ncp_disable;
            if (!m_openvpn_tls_client) m_openvpn_tls_client = cfg.tls_client;
            if (!m_openvpn_client) m_openvpn_client = cfg.client;
        }
    }

    this->m_server_gateway = settings.value("server").toString();
    if (this->m_server_gateway.isEmpty() == true) {
        this->m_server_gateway = name;
        if (m_protocol_name == QLatin1String(OCG_PROTO_OPENVPN) && m_openvpn_config_text.isEmpty() == false) {
            rval = 1;
        } else {
            rval = 0;
        }
    }

    this->m_username = settings.value("username").toString();
    this->m_batch_mode = settings.value("batch", false).toBool();
    this->m_proxy = settings.value("proxy", false).toBool();
    this->m_disable_udp = settings.value("disable-udp", false).toBool();
    this->m_minimize_on_connect = settings.value("minimize-on-connect", false).toBool();
    this->m_reconnect_timeout = settings.value("reconnect-timeout", 300).toInt();
    this->m_dtls_attempt_period = settings.value("dtls_attempt_period", 25).toInt();

    bool ret = false;

    if (this->m_batch_mode == true) {
        this->m_groupname = settings.value("groupname").toString();
        ret = CryptData::decode(this->m_server_gateway,
            settings.value("password").toByteArray(),
            this->m_password);
        if (ret == false) {
            m_last_err = "decoding of password failed";
            rval = -1;
        }
    }

    QByteArray data;
    data = settings.value("ca-cert").toByteArray();
    if (data.isEmpty() == false && this->m_ca_cert.import_pem(data) < 0) {
        this->m_last_err = this->m_ca_cert.last_err;
        rval = -1;
    }

    data = settings.value("client-cert").toByteArray();
    if (data.isEmpty() == false && this->m_client.cert.import_pem(data) < 0) {
        this->m_last_err = this->m_client.cert.last_err;
        rval = -1;
    }

    QString str;
    ret = CryptData::decode(this->m_server_gateway,
        settings.value("client-key").toByteArray(), str);
    if (ret == false) {
        m_last_err = "decoding of client keyfailed";
        rval = -1;
    }

    if (is_url(str) == true) {
        this->m_client.key.import_file(str);
    } else {
        data = str.toLatin1();
        this->m_client.key.import_pem(data);
    }

    this->m_server_pin = settings.value("server-hash").toByteArray();
    this->m_server_pin_algo = settings.value("server-hash-algo").toInt();

    ret = CryptData::decode(this->m_server_gateway,
        settings.value("token-str").toByteArray(),
        this->m_token_string);
    if (ret == false) {
        m_last_err = "decoding of OTP token failed";
        rval = -1;
    }

    this->m_token_type = settings.value("token-type").toInt();

    m_interface_name = settings.value("interface-name").toString();
#ifdef _WIN32
    /* truncate interface name to OC_IFNAME_MAX_LENGTH in case it was saved by a previous version
     * that did not impose the length constraint in the text edit
     */
    m_interface_name.truncate(OC_IFNAME_MAX_LENGTH);
#endif
    m_vpnc_script_filename = settings.value("vpnc-script").toString();

    m_log_level = settings.value("log-level", -1).toInt();

    settings.endGroup();
    return rval;
}

int StoredServer::save()
{
    OcSettings settings;
    settings.beginGroup(PREFIX + this->m_label);
    settings.setValue("server", this->m_server_gateway);
    settings.setValue("batch", this->m_batch_mode);
    settings.setValue("proxy", this->m_proxy);
    settings.setValue("disable-udp", this->m_disable_udp);
    settings.setValue("minimize-on-connect", this->m_minimize_on_connect);
    settings.setValue("reconnect-timeout", this->m_reconnect_timeout);
    settings.setValue("dtls_attempt_period", this->m_dtls_attempt_period);
    settings.setValue("username", this->m_username);

    if (this->m_batch_mode == true) {
        settings.setValue("password",
            CryptData::encode(this->m_server_gateway, this->m_password));
        settings.setValue("groupname", this->m_groupname);
    }

    QByteArray data;
    this->m_ca_cert.data_export(data);
    settings.setValue("ca-cert", data);

    this->m_client.cert_export(data);
    settings.setValue("client-cert", data);

    this->m_client.key_export(data);
    QString str = QString::fromLatin1(data);
    settings.setValue("client-key", CryptData::encode(this->m_server_gateway, str));

    settings.setValue("server-hash", this->m_server_pin);
    settings.setValue("server-hash-algo", this->m_server_pin_algo);

    settings.setValue("token-str",
        CryptData::encode(this->m_server_gateway, this->m_token_string));
    settings.setValue("token-type", this->m_token_type);

    settings.setValue("protocol-name", m_protocol_name);

    settings.setValue("interface-name", m_interface_name);
    settings.setValue("vpnc-script", m_vpnc_script_filename);
    if (m_log_level == -1)
        settings.remove("log-level");
    else
        settings.setValue("log-level", m_log_level);
    if (m_openvpn_config.isEmpty()) {
        settings.remove("openvpn-config");
    } else {
        settings.setValue("openvpn-config", m_openvpn_config);
    }
    if (m_openvpn_config_text.isEmpty()) {
        settings.remove("openvpn-config-text");
    } else {
        settings.setValue("openvpn-config-text", m_openvpn_config_text);
    }
    settings.setValue("openvpn-remote-host", m_openvpn_remote_host);
    settings.setValue("openvpn-remote-port", m_openvpn_remote_port);
    settings.setValue("openvpn-remote-proto", m_openvpn_remote_proto);
    settings.setValue("openvpn-dev", m_openvpn_dev);
    settings.setValue("openvpn-cipher", m_openvpn_cipher);
    settings.setValue("openvpn-data-ciphers", m_openvpn_data_ciphers);
    settings.setValue("openvpn-data-ciphers-fallback", m_openvpn_data_ciphers_fallback);
    settings.setValue("openvpn-auth", m_openvpn_auth);
    settings.setValue("openvpn-resolv-retry", m_openvpn_resolv_retry);
    settings.setValue("openvpn-remote-cert-tls", m_openvpn_remote_cert_tls);
    settings.setValue("openvpn-nobind", m_openvpn_nobind);
    settings.setValue("openvpn-compress", m_openvpn_compress);
    settings.setValue("openvpn-ca", m_openvpn_ca);
    settings.setValue("openvpn-cert", m_openvpn_cert);
    settings.setValue("openvpn-key", m_openvpn_key);
    settings.setValue("openvpn-tls-auth", m_openvpn_tls_auth);
    settings.setValue("openvpn-tls-crypt", m_openvpn_tls_crypt);
    settings.setValue("openvpn-key-direction", m_openvpn_key_direction);
    settings.setValue("openvpn-setenv-client-cert", m_openvpn_setenv_client_cert);
    settings.setValue("openvpn-auth-user-pass", m_openvpn_auth_user_pass);
    settings.setValue("openvpn-persist-tun", m_openvpn_persist_tun);
    settings.setValue("openvpn-persist-key", m_openvpn_persist_key);
    settings.setValue("openvpn-ncp-disable", m_openvpn_ncp_disable);
    settings.setValue("openvpn-tls-client", m_openvpn_tls_client);
    settings.setValue("openvpn-client", m_openvpn_client);
    settings.setValue("route-policy", m_route_policy);
    QStringList route_list;
    route_list.reserve(m_route_entries.size());
    for (const RouteEntry& route : m_route_entries) {
        route_list << (route.destination + QLatin1Char('|') + route.netmask + QLatin1Char('|') + route.gateway);
    }
    settings.setValue("route-entries", route_list);

    settings.endGroup();
    return 0;
}

const QString& StoredServer::get_username() const
{
    return this->m_username;
}

const QString& StoredServer::get_password() const
{
    return this->m_password;
}

const QString& StoredServer::get_groupname() const
{
    return this->m_groupname;
}

const QString& StoredServer::get_server_gateway() const
{
    return this->m_server_gateway;
}

const QString& StoredServer::get_label() const
{
    return this->m_label;
}

void StoredServer::set_username(const QString& username)
{
    this->m_username = username;
}

void StoredServer::set_password(const QString& password)
{
    this->m_password = password;
}

void StoredServer::set_groupname(const QString& groupname)
{
    this->m_groupname = groupname;
}

void StoredServer::set_server_gateway(const QString& server_gateway)
{
    this->m_server_gateway = server_gateway;
}

void StoredServer::set_label(const QString& label)
{
    this->m_label = label;
}

void StoredServer::set_disable_udp(bool v)
{
    this->m_disable_udp = v;
}

bool StoredServer::get_disable_udp() const
{
    return this->m_disable_udp;
}

QString StoredServer::get_client_cert_pin()
{
    return m_client.cert.cert_pin();
}

QString StoredServer::get_ca_cert_pin()
{
    return m_ca_cert.cert_pin();
}

void StoredServer::set_window(QWidget* w)
{
    m_client.set_window(w);
}

void StoredServer::set_batch_mode(const bool mode)
{
    this->m_batch_mode = mode;
}

bool StoredServer::get_batch_mode() const
{
    return this->m_batch_mode;
}

bool StoredServer::get_minimize() const
{
    return this->m_minimize_on_connect;
}

bool StoredServer::get_proxy() const
{
    return this->m_proxy;
}

bool StoredServer::client_is_complete() const
{
    return m_client.is_complete();
}

void StoredServer::set_minimize(const bool t)
{
    this->m_minimize_on_connect = t;
}

void StoredServer::set_proxy(const bool t)
{
    this->m_proxy = t;
}

int StoredServer::get_reconnect_timeout() const
{
    return m_reconnect_timeout;
}

void StoredServer::set_reconnect_timeout(const int timeout)
{
    m_reconnect_timeout = timeout;
}

int StoredServer::get_dtls_reconnect_timeout() const
{
    return m_dtls_attempt_period;
}

void StoredServer::set_dtls_reconnect_timeout(const int timeout)
{
    m_dtls_attempt_period = timeout;
}

QString StoredServer::get_token_str()
{
    return this->m_token_string;
}

void StoredServer::set_token_str(const QString& str)
{
    this->m_token_string = str;
}

int StoredServer::get_token_type()
{
    return this->m_token_type;
}

void StoredServer::set_token_type(const int type)
{
    this->m_token_type = type;
}

const QString& StoredServer::get_protocol_name() const
{
    return m_protocol_name;
}

void StoredServer::set_protocol_name(const QString name)
{
    m_protocol_name = name;
}

const QString& StoredServer::get_openvpn_config() const
{
    return this->m_openvpn_config;
}

void StoredServer::set_openvpn_config(const QString& openvpn_config)
{
    this->m_openvpn_config = openvpn_config;
}

const QString& StoredServer::get_openvpn_config_text() const
{
    return this->m_openvpn_config_text;
}

void StoredServer::set_openvpn_config_text(const QString& text)
{
    this->m_openvpn_config_text = text;
}

const QString& StoredServer::get_openvpn_remote_host() const { return this->m_openvpn_remote_host; }
void StoredServer::set_openvpn_remote_host(const QString& host) { this->m_openvpn_remote_host = host; }
const QString& StoredServer::get_openvpn_remote_port() const { return this->m_openvpn_remote_port; }
void StoredServer::set_openvpn_remote_port(const QString& port) { this->m_openvpn_remote_port = port; }
const QString& StoredServer::get_openvpn_remote_proto() const { return this->m_openvpn_remote_proto; }
void StoredServer::set_openvpn_remote_proto(const QString& proto) { this->m_openvpn_remote_proto = proto; }
const QString& StoredServer::get_openvpn_dev() const { return this->m_openvpn_dev; }
void StoredServer::set_openvpn_dev(const QString& dev) { this->m_openvpn_dev = dev; }
const QString& StoredServer::get_openvpn_cipher() const { return this->m_openvpn_cipher; }
void StoredServer::set_openvpn_cipher(const QString& cipher) { this->m_openvpn_cipher = cipher; }
const QString& StoredServer::get_openvpn_data_ciphers() const { return this->m_openvpn_data_ciphers; }
void StoredServer::set_openvpn_data_ciphers(const QString& value) { this->m_openvpn_data_ciphers = value; }
const QString& StoredServer::get_openvpn_data_ciphers_fallback() const { return this->m_openvpn_data_ciphers_fallback; }
void StoredServer::set_openvpn_data_ciphers_fallback(const QString& value) { this->m_openvpn_data_ciphers_fallback = value; }
const QString& StoredServer::get_openvpn_auth() const { return this->m_openvpn_auth; }
void StoredServer::set_openvpn_auth(const QString& auth) { this->m_openvpn_auth = auth; }
const QString& StoredServer::get_openvpn_resolv_retry() const { return this->m_openvpn_resolv_retry; }
void StoredServer::set_openvpn_resolv_retry(const QString& value) { this->m_openvpn_resolv_retry = value; }
const QString& StoredServer::get_openvpn_remote_cert_tls() const { return this->m_openvpn_remote_cert_tls; }
void StoredServer::set_openvpn_remote_cert_tls(const QString& value) { this->m_openvpn_remote_cert_tls = value; }
bool StoredServer::get_openvpn_nobind() const { return this->m_openvpn_nobind; }
void StoredServer::set_openvpn_nobind(bool value) { this->m_openvpn_nobind = value; }
const QString& StoredServer::get_openvpn_compress() const { return this->m_openvpn_compress; }
void StoredServer::set_openvpn_compress(const QString& value) { this->m_openvpn_compress = value; }
const QString& StoredServer::get_openvpn_ca() const { return this->m_openvpn_ca; }
void StoredServer::set_openvpn_ca(const QString& value) { this->m_openvpn_ca = value; }
const QString& StoredServer::get_openvpn_cert() const { return this->m_openvpn_cert; }
void StoredServer::set_openvpn_cert(const QString& value) { this->m_openvpn_cert = value; }
const QString& StoredServer::get_openvpn_key() const { return this->m_openvpn_key; }
void StoredServer::set_openvpn_key(const QString& value) { this->m_openvpn_key = value; }
const QString& StoredServer::get_openvpn_tls_auth() const { return this->m_openvpn_tls_auth; }
void StoredServer::set_openvpn_tls_auth(const QString& value) { this->m_openvpn_tls_auth = value; }
const QString& StoredServer::get_openvpn_tls_crypt() const { return this->m_openvpn_tls_crypt; }
void StoredServer::set_openvpn_tls_crypt(const QString& value) { this->m_openvpn_tls_crypt = value; }
const QString& StoredServer::get_openvpn_key_direction() const { return this->m_openvpn_key_direction; }
void StoredServer::set_openvpn_key_direction(const QString& value) { this->m_openvpn_key_direction = value; }
const QString& StoredServer::get_openvpn_setenv_client_cert() const { return this->m_openvpn_setenv_client_cert; }
void StoredServer::set_openvpn_setenv_client_cert(const QString& value) { this->m_openvpn_setenv_client_cert = value; }
bool StoredServer::get_openvpn_auth_user_pass() const { return this->m_openvpn_auth_user_pass; }
void StoredServer::set_openvpn_auth_user_pass(bool value) { this->m_openvpn_auth_user_pass = value; }
bool StoredServer::get_openvpn_persist_tun() const { return this->m_openvpn_persist_tun; }
void StoredServer::set_openvpn_persist_tun(bool value) { this->m_openvpn_persist_tun = value; }
bool StoredServer::get_openvpn_persist_key() const { return this->m_openvpn_persist_key; }
void StoredServer::set_openvpn_persist_key(bool value) { this->m_openvpn_persist_key = value; }
bool StoredServer::get_openvpn_ncp_disable() const { return this->m_openvpn_ncp_disable; }
void StoredServer::set_openvpn_ncp_disable(bool value) { this->m_openvpn_ncp_disable = value; }
bool StoredServer::get_openvpn_tls_client() const { return this->m_openvpn_tls_client; }
void StoredServer::set_openvpn_tls_client(bool value) { this->m_openvpn_tls_client = value; }
bool StoredServer::get_openvpn_client() const { return this->m_openvpn_client; }
void StoredServer::set_openvpn_client(bool value) { this->m_openvpn_client = value; }

void StoredServer::set_server_pin(const unsigned algo, const QByteArray& hash)
{
    this->m_server_pin_algo = algo;
    if (algo != GNUTLS_DIG_SHA256) {
        throw std::runtime_error("sha256 is the expected certificate algorithm pin");
    }
    this->m_server_pin = hash;
}

unsigned StoredServer::get_server_pin(QByteArray& hash) const
{
    hash = this->m_server_pin;
    return this->m_server_pin_algo;
}

const QString& StoredServer::get_interface_name() const
{
    return this->m_interface_name;
}

void StoredServer::set_interface_name(const QString& interface_name)
{
    this->m_interface_name = interface_name;
}

const QString& StoredServer::get_vpnc_script_filename() const
{
    return this->m_vpnc_script_filename;
}

void StoredServer::set_vpnc_script_filename(const QString& vpnc_script_filename)
{
    this->m_vpnc_script_filename = vpnc_script_filename;
}

int StoredServer::get_route_policy() const
{
    return m_route_policy;
}

void StoredServer::set_route_policy(int policy)
{
    m_route_policy = policy;
}

const QVector<StoredServer::RouteEntry>& StoredServer::get_route_entries() const
{
    return m_route_entries;
}

void StoredServer::set_route_entries(const QVector<RouteEntry>& entries)
{
    m_route_entries = entries;
}

int StoredServer::get_log_level()
{
    return this->m_log_level;
}

void StoredServer::set_log_level(const int log_level)
{
    this->m_log_level = log_level;
}
