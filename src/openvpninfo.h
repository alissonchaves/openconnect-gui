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

#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QStringList>
#include <QTcpSocket>
#include <QElapsedTimer>

#include <atomic>
#include <memory>

class MainWindow;
class StoredServer;

class OpenVpnInfo {
public:
    OpenVpnInfo(StoredServer* ss, MainWindow* m);
    ~OpenVpnInfo();

    int connect();
    void mainloop();
    void requestStop();
    bool stopRequested() const;
    void saveProfile();

    QString last_err;

private:
    bool prepareAuthFile(QString& err);
    bool prepareConfigFile(QString& err);
    QString findOpenVpnBinary(QString& err) const;
    void logOutputLines(const QString& chunk);
    void handleOpenVpnLine(const QString& line);
    void updateOpenVpnDnsFromSystem();
    void connectOpenVpnManagement();
    void handleOpenVpnManagementData();
    void pollOpenVpnManagement();
    void handleOpenVpnManagementLine(const QString& line);
    static QString normalizeByteSize(uint64_t bytes);
    void ensureOpenVpnManagement();

    StoredServer* ss;
    MainWindow* m;
    std::unique_ptr<QProcess> proc;
    std::unique_ptr<QTemporaryFile> auth_file;
    std::unique_ptr<QTemporaryFile> config_file;
    std::atomic_bool stop_requested;
    QString output_buffer;
    bool connected;
    QString openvpn_ip;
    QString openvpn_dns;
    QString openvpn_iface;
    QString openvpn_cipher;
    QStringList openvpn_mgmt_dns;
    std::unique_ptr<QTcpSocket> openvpn_mgmt_socket;
    QByteArray openvpn_mgmt_buffer;
    quint16 openvpn_mgmt_port = 0;
    QString openvpn_mgmt_password;
    QString openvpn_mgmt_pass_file;
    int openvpn_mgmt_retries = 0;
    bool openvpn_mgmt_authed = false;
    QElapsedTimer openvpn_mgmt_timer;
};
