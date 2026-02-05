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

#include "openvpninfo.h"
#include "openvpn_config.h"

#include "common.h"
#include "logger.h"
#include "dialog/MyInputDialog.h"
#include "server_storage.h"
#include "dialog/mainwindow.h"

#include <QFileDevice>
#include <QStandardPaths>
#include <QTextStream>
#include <QRegularExpression>
#include <QProcess>
#include <QFile>
#include <QTcpServer>
#include <QTimer>
#include <QUuid>
#include <QMetaObject>

OpenVpnInfo::OpenVpnInfo(StoredServer* ss, MainWindow* m)
    : ss(ss)
    , m(m)
    , proc(std::make_unique<QProcess>())
    , auth_file(nullptr)
    , config_file(nullptr)
    , stop_requested(false)
    , connected(false)
    , openvpn_ip()
    , openvpn_dns()
    , openvpn_iface()
    , openvpn_cipher()
    , openvpn_mgmt_dns()
    , openvpn_mgmt_socket(nullptr)
    , openvpn_mgmt_buffer()
    , openvpn_mgmt_port(0)
    , openvpn_mgmt_password()
    , openvpn_mgmt_pass_file()
    , openvpn_mgmt_retries(0)
    , openvpn_mgmt_authed(false)
    , openvpn_mgmt_timer()
{
    proc->setProcessChannelMode(QProcess::MergedChannels);
}

OpenVpnInfo::~OpenVpnInfo()
{
    if (proc && proc->state() != QProcess::NotRunning) {
        proc->terminate();
        proc->waitForFinished(2000);
        if (proc->state() != QProcess::NotRunning) {
            proc->kill();
            proc->waitForFinished(2000);
        }
    }
    if (openvpn_mgmt_socket) {
        openvpn_mgmt_socket->disconnectFromHost();
        openvpn_mgmt_socket.reset();
    }
    if (!openvpn_mgmt_pass_file.isEmpty()) {
        QFile::remove(openvpn_mgmt_pass_file);
        openvpn_mgmt_pass_file.clear();
    }

    delete ss;
}

bool OpenVpnInfo::stopRequested() const
{
    return stop_requested.load();
}

void OpenVpnInfo::requestStop()
{
    stop_requested.store(true);
}

void OpenVpnInfo::saveProfile()
{
    ss->save();
}

QString OpenVpnInfo::findOpenVpnBinary(QString& err) const
{
    QString path = QStandardPaths::findExecutable(QStringLiteral("openvpn"));
    if (path.isEmpty()) {
        err = QObject::tr("OpenVPN binary not found in PATH");
    }
    return path;
}

bool OpenVpnInfo::prepareAuthFile(QString& err)
{
    const QString username = ss->get_username();
    const QString password = ss->get_password();
    if (username.isEmpty() && password.isEmpty()) {
        return true;
    }

    auth_file = std::make_unique<QTemporaryFile>(QStringLiteral("/tmp/openconnect-gui-auth-XXXXXX"));
    auth_file->setAutoRemove(true);
    if (auth_file->open() == false) {
        err = QObject::tr("Failed to create OpenVPN auth file");
        return false;
    }

    auth_file->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    QTextStream out(auth_file.get());
    out << username << "\n" << password << "\n";
    out.flush();
    auth_file->flush();
    Logger::instance().addMessage(QObject::tr("OpenVPN auth file: %1").arg(auth_file->fileName()));

    return true;
}

bool OpenVpnInfo::prepareConfigFile(QString& err)
{
    if (ss->get_openvpn_config_text().isEmpty()) {
        return true;
    }

    QStringList route_entries;
    for (const StoredServer::RouteEntry& route : ss->get_route_entries()) {
        route_entries << (route.destination + QLatin1Char('|') + route.netmask + QLatin1Char('|') + route.gateway);
    }
    const QString config_text = apply_openvpn_route_policy(ss->get_openvpn_config_text(),
        ss->get_route_policy(),
        route_entries);

    config_file = std::make_unique<QTemporaryFile>(QStringLiteral("/tmp/openconnect-gui-ovpn-XXXXXX"));
    config_file->setAutoRemove(true);
    if (config_file->open() == false) {
        err = QObject::tr("Failed to create OpenVPN config file");
        return false;
    }

    config_file->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    QTextStream out(config_file.get());
    out << config_text;
    out.flush();
    config_file->flush();
    Logger::instance().addMessage(QObject::tr("OpenVPN config temp file: %1").arg(config_file->fileName()));
    return true;
}

static bool config_requires_auth(const QString& cfg)
{
    const QRegularExpression auth_re(
        QStringLiteral(R"(^\s*auth-user-pass(\s+.*)?$)"),
        QRegularExpression::CaseInsensitiveOption | QRegularExpression::MultilineOption);
    return auth_re.match(cfg).hasMatch();
}

int OpenVpnInfo::connect()
{
    QString err;
    if (ss->get_openvpn_config_text().isEmpty()) {
        last_err = QObject::tr("OpenVPN config is missing from the profile");
        return -1;
    }

    QString username = ss->get_username();
    QString password = ss->get_password();
    const bool has_auth_directive = config_requires_auth(ss->get_openvpn_config_text());
    if (has_auth_directive) {
        bool ok = true;
        if (username.isEmpty()) {
            QString input;
            MyInputDialog dialog(m, QLatin1String("Username input"),
                QLatin1String("Enter OpenVPN username"), QLineEdit::Normal);
            dialog.show();
            ok = dialog.result(input);
            if (ok && input.isEmpty() == false) {
                username = input;
                ss->set_username(username);
            }
        }
        if (ok && password.isEmpty()) {
            QString input;
            MyInputDialog dialog(m, QLatin1String("Password input"),
                QLatin1String("Enter OpenVPN password"), QLineEdit::Password);
            dialog.show();
            ok = dialog.result(input);
            if (ok && input.isEmpty() == false) {
                password = input;
                ss->set_password(password);
            }
        }
        if (!ok || username.isEmpty() || password.isEmpty()) {
            last_err = QObject::tr("OpenVPN authentication cancelled or incomplete");
            return -1;
        }
    }

    QString openvpn_path = findOpenVpnBinary(err);
    if (openvpn_path.isEmpty()) {
        last_err = err;
        return -1;
    }

    if (prepareAuthFile(err) == false) {
        last_err = err;
        return -1;
    }
    if (prepareConfigFile(err) == false) {
        last_err = err;
        return -1;
    }

    QStringList args;
    if (config_file != nullptr) {
        args << "--config" << config_file->fileName();
    }
    if (auth_file != nullptr) {
        args << "--auth-user-pass" << auth_file->fileName();
        args << "--auth-nocache";
    }
    // Ensure PUSH_REPLY and management logs for DNS/byte counts.
    args << "--verb" << "4";
    {
        QTcpServer mgmtPortProbe;
        if (mgmtPortProbe.listen(QHostAddress::LocalHost, 0)) {
            openvpn_mgmt_port = mgmtPortProbe.serverPort();
            mgmtPortProbe.close();
            openvpn_mgmt_password = QUuid::createUuid().toString(QUuid::WithoutBraces);
            QTemporaryFile mgmtPassFile(QStringLiteral("/tmp/openconnect-gui-openvpn-mgmt-XXXXXX"));
            mgmtPassFile.setAutoRemove(false);
            if (mgmtPassFile.open()) {
                mgmtPassFile.write(openvpn_mgmt_password.toUtf8());
                mgmtPassFile.flush();
                openvpn_mgmt_pass_file = mgmtPassFile.fileName();
                QFile::setPermissions(openvpn_mgmt_pass_file,
                    QFileDevice::ReadOwner | QFileDevice::WriteOwner
                        | QFileDevice::ReadGroup | QFileDevice::ReadOther);
                mgmtPassFile.close();
                args << "--management" << "127.0.0.1"
                     << QString::number(openvpn_mgmt_port) << openvpn_mgmt_pass_file;
                args << "--management-log-cache" << "100";
            } else {
                openvpn_mgmt_password.clear();
                openvpn_mgmt_port = 0;
            }
        }
    }

    proc->start(openvpn_path, args);
    if (proc->waitForStarted(10000) == false) {
        last_err = QObject::tr("Failed to start OpenVPN process: %1").arg(proc->errorString());
        return -1;
    }

    if (openvpn_mgmt_port != 0) {
        connectOpenVpnManagement();
    }

    return 0;
}

void OpenVpnInfo::logOutputLines(const QString& chunk)
{
    output_buffer += chunk;

    int eol = output_buffer.indexOf('\n');
    while (eol >= 0) {
        QString line = output_buffer.left(eol);
        output_buffer.remove(0, eol + 1);
        line = line.trimmed();
        if (!line.isEmpty()) {
            Logger::instance().addMessage(line);
            handleOpenVpnLine(line);
        }
        eol = output_buffer.indexOf('\n');
    }
}

void OpenVpnInfo::handleOpenVpnLine(const QString& line)
{
    if (line.contains(QLatin1String("/sbin/ifconfig utun")) || line.contains(QLatin1String("ifconfig utun"))) {
        const QRegularExpression re(QStringLiteral(R"(ifconfig\s+(utun\d+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+))"));
        const QRegularExpressionMatch match = re.match(line);
        if (match.hasMatch()) {
            openvpn_iface = match.captured(1);
            openvpn_ip = match.captured(2);
        }
    } else if (line.contains(QLatin1String("Data Channel: cipher"), Qt::CaseInsensitive)) {
        const QRegularExpression re(QStringLiteral(R"(Data Channel:\s+cipher\s+'([^']+)')"), QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch match = re.match(line);
        if (match.hasMatch()) {
            openvpn_cipher = match.captured(1).trimmed();
        }
    } else if (line.contains(QLatin1String("PUSH_REPLY"))) {
        QString msg = line;
        msg.replace(QLatin1Char(','), QLatin1Char(' '));
        if (openvpn_cipher.isEmpty()) {
            QRegularExpression cipherRe(QStringLiteral(R"(cipher\s+([^\s]+))"), QRegularExpression::CaseInsensitiveOption);
            const QRegularExpressionMatch cipherMatch = cipherRe.match(msg);
            if (cipherMatch.hasMatch()) {
                openvpn_cipher = cipherMatch.captured(1).trimmed();
            }
        }
        QRegularExpression re(QStringLiteral(R"(dhcp-option\s+DNS\s+([^\s,]+))"));
        QRegularExpressionMatchIterator it = re.globalMatch(msg);
        bool dnsUpdated = false;
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            QString dns = m.captured(1).trimmed();
            dns.remove(QLatin1Char('\''));
            if (!dns.isEmpty() && !openvpn_mgmt_dns.contains(dns)) {
                openvpn_mgmt_dns << dns;
                dnsUpdated = true;
            }
        }
        if (dnsUpdated) {
            openvpn_dns = openvpn_mgmt_dns.join(QLatin1String(", "));
            if (connected) {
                QString ip6;
                QString cstp = QStringLiteral("OpenVPN");
                QString dtls;
                m->vpn_status_changed(STATUS_CONNECTED, openvpn_dns, openvpn_ip, ip6, cstp, dtls);
            }
        }
    } else if (line.contains(QLatin1String("dhcp-option DNS"))) {
        QString normalized = line;
        normalized.replace(QLatin1Char(','), QLatin1Char(' '));
        QRegularExpression re(QStringLiteral(R"(dhcp-option\s+DNS\s+([^\s,]+))"));
        QRegularExpressionMatchIterator it = re.globalMatch(normalized);
        QStringList dnsList;
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            QString dns = m.captured(1).trimmed();
            dns.remove(QLatin1Char('\''));
            if (!dns.isEmpty() && !dnsList.contains(dns)) {
                dnsList << dns;
            }
        }
        if (!dnsList.isEmpty()) {
            openvpn_dns = dnsList.join(QLatin1String(", "));
        }
    }

    if (!connected && line.contains(QStringLiteral("Initialization Sequence Completed"), Qt::CaseInsensitive)) {
        connected = true;
        QString dns = openvpn_dns;
        QString ip = openvpn_ip;
        QString ip6;
        QString cstp = openvpn_cipher.isEmpty() ? QStringLiteral("OpenVPN") : openvpn_cipher;
        QString dtls;
        m->vpn_status_changed(STATUS_CONNECTED, dns, ip, ip6, cstp, dtls);
        if (openvpn_dns.isEmpty()) {
            updateOpenVpnDnsFromSystem();
        }
    }
}

QString OpenVpnInfo::normalizeByteSize(uint64_t bytes)
{
    const double step = 1024.0;
    if (bytes < step) {
        return QString::number(bytes) + " B";
    }
    double value = static_cast<double>(bytes);
    QString suffix = " KB";
    value /= step;
    if (value >= step) {
        value /= step;
        suffix = " MB";
    }
    if (value >= step) {
        value /= step;
        suffix = " GB";
    }
    return QString::number(value, 'f', value >= 10.0 ? 1 : 2) + suffix;
}

void OpenVpnInfo::connectOpenVpnManagement()
{
    if (openvpn_mgmt_port == 0 || !proc || proc->state() == QProcess::NotRunning) {
        return;
    }
    if (openvpn_mgmt_socket) {
        openvpn_mgmt_socket->disconnectFromHost();
        openvpn_mgmt_socket.reset();
    }

    openvpn_mgmt_socket = std::make_unique<QTcpSocket>();
    openvpn_mgmt_authed = false;
    openvpn_mgmt_socket->connectToHost(QHostAddress::LocalHost, openvpn_mgmt_port);
    if (!openvpn_mgmt_socket->waitForConnected(1000)) {
        openvpn_mgmt_socket.reset();
        return;
    }
    openvpn_mgmt_retries = 0;
    if (openvpn_mgmt_password.isEmpty()) {
        openvpn_mgmt_authed = true;
        const QByteArray cmds = QByteArrayLiteral("log on all\nstate on\nbytecount 1\n");
        openvpn_mgmt_socket->write(cmds);
        openvpn_mgmt_socket->flush();
    } else {
        openvpn_mgmt_socket->write(openvpn_mgmt_password.toUtf8() + QByteArrayLiteral("\n"));
        openvpn_mgmt_socket->flush();
        const QByteArray cmds = QByteArrayLiteral("log on all\nstate on\nbytecount 1\n");
        openvpn_mgmt_socket->write(cmds);
        openvpn_mgmt_socket->flush();
    }
    handleOpenVpnManagementData();
}

void OpenVpnInfo::handleOpenVpnManagementData()
{
    if (!openvpn_mgmt_socket) {
        return;
    }
    openvpn_mgmt_buffer.append(openvpn_mgmt_socket->readAll());
    int newlineIndex = -1;
    while ((newlineIndex = openvpn_mgmt_buffer.indexOf('\n')) != -1) {
        const QByteArray lineBytes = openvpn_mgmt_buffer.left(newlineIndex);
        openvpn_mgmt_buffer.remove(0, newlineIndex + 1);
        const QString line = QString::fromLocal8Bit(lineBytes).trimmed();
        if (!line.isEmpty()) {
            handleOpenVpnManagementLine(line);
        }
    }
}

void OpenVpnInfo::pollOpenVpnManagement()
{
    if (openvpn_mgmt_socket && openvpn_mgmt_socket->waitForReadyRead(10)) {
        handleOpenVpnManagementData();
    }
}

void OpenVpnInfo::ensureOpenVpnManagement()
{
    if (openvpn_mgmt_port == 0 || openvpn_mgmt_socket || openvpn_mgmt_retries >= 5) {
        return;
    }
    if (!openvpn_mgmt_timer.isValid() || openvpn_mgmt_timer.elapsed() > 1000) {
        openvpn_mgmt_timer.restart();
        openvpn_mgmt_retries++;
        connectOpenVpnManagement();
    }
}

void OpenVpnInfo::handleOpenVpnManagementLine(const QString& line)
{
    if (line.startsWith(QLatin1String(">STATE:"))) {
        const QString payload = line.mid(7);
        const QStringList parts = payload.split(QLatin1Char(','));
        if (parts.size() >= 3) {
            const QString state = parts.at(1);
            if (parts.size() >= 4) {
                openvpn_ip = parts.at(3);
            }
            if (state == QLatin1String("CONNECTED")) {
                connected = true;
                QString dns = openvpn_dns;
                if (!openvpn_mgmt_dns.isEmpty()) {
                    openvpn_dns = openvpn_mgmt_dns.join(QLatin1String(", "));
                    dns = openvpn_dns;
                }
                QString ip = openvpn_ip;
                QString ip6;
                QString cstp = openvpn_cipher.isEmpty() ? QStringLiteral("OpenVPN") : openvpn_cipher;
                QString dtls;
                m->vpn_status_changed(STATUS_CONNECTED, dns, ip, ip6, cstp, dtls);
                if (openvpn_dns.isEmpty()) {
                    updateOpenVpnDnsFromSystem();
                }
            }
        }
        return;
    }

    if (line.startsWith(QLatin1String(">BYTECOUNT:"))) {
        const QString payload = line.mid(11);
        const QStringList parts = payload.split(QLatin1Char(','));
        if (parts.size() >= 2) {
            bool okIn = false;
            bool okOut = false;
            const uint64_t bytesIn = parts.at(0).toULongLong(&okIn);
            const uint64_t bytesOut = parts.at(1).toULongLong(&okOut);
            if (okIn && okOut) {
                const QString down = normalizeByteSize(bytesOut);
                const QString up = normalizeByteSize(bytesIn);
                QMetaObject::invokeMethod(m, "stats_changed_sig", Qt::QueuedConnection,
                    Q_ARG(QString, down),
                    Q_ARG(QString, up),
                    Q_ARG(QString, QString()));
            }
        }
        return;
    }

    if (line.startsWith(QLatin1String(">PASSWORD:")) || line.contains(QLatin1String("ENTER PASSWORD"), Qt::CaseInsensitive)) {
        if (!openvpn_mgmt_password.isEmpty() && openvpn_mgmt_socket) {
            openvpn_mgmt_socket->write(openvpn_mgmt_password.toUtf8() + QByteArrayLiteral("\n"));
            openvpn_mgmt_socket->flush();
        }
        return;
    }

    if (line.contains(QLatin1String("password is correct"), Qt::CaseInsensitive)) {
        if (!openvpn_mgmt_authed && openvpn_mgmt_socket) {
            openvpn_mgmt_authed = true;
            const QByteArray cmds = QByteArrayLiteral("log on all\nstate on\nbytecount 1\n");
            openvpn_mgmt_socket->write(cmds);
            openvpn_mgmt_socket->flush();
        }
        return;
    }

    if (line.startsWith(QLatin1String(">INFO:")) && openvpn_mgmt_password.isEmpty()) {
        if (!openvpn_mgmt_authed && openvpn_mgmt_socket) {
            openvpn_mgmt_authed = true;
            const QByteArray cmds = QByteArrayLiteral("log on all\nstate on\nbytecount 1\n");
            openvpn_mgmt_socket->write(cmds);
            openvpn_mgmt_socket->flush();
        }
    }

    if (line.startsWith(QLatin1String(">LOG:"))) {
        QString msg = line.mid(5);
        int firstComma = msg.indexOf(QLatin1Char(','));
        if (firstComma != -1) {
            msg = msg.mid(firstComma + 1);
            int secondComma = msg.indexOf(QLatin1Char(','));
            if (secondComma != -1) {
                msg = msg.mid(secondComma + 1);
            }
        }
        msg = msg.trimmed();
        if (!msg.isEmpty()) {
            Logger::instance().addMessage(msg);
        }

        QString msgNormalized = msg;
        msgNormalized.replace(QLatin1Char(','), QLatin1Char(' '));
        QRegularExpression re(QStringLiteral(R"(dhcp-option\s+DNS\s+([^\s,]+))"));
        QRegularExpressionMatchIterator it = re.globalMatch(msgNormalized);
        bool dnsUpdated = false;
        while (it.hasNext()) {
            const QRegularExpressionMatch m = it.next();
            const QString dns = m.captured(1);
            if (!dns.isEmpty() && !openvpn_mgmt_dns.contains(dns)) {
                openvpn_mgmt_dns << dns;
                dnsUpdated = true;
            }
        }
        if (dnsUpdated) {
            openvpn_dns = openvpn_mgmt_dns.join(QLatin1String(", "));
            if (connected) {
                QString ip6;
                QString cstp = openvpn_cipher.isEmpty() ? QStringLiteral("OpenVPN") : openvpn_cipher;
                QString dtls;
                m->vpn_status_changed(STATUS_CONNECTED, openvpn_dns, openvpn_ip, ip6, cstp, dtls);
            }
        }
    }
}

void OpenVpnInfo::updateOpenVpnDnsFromSystem()
{
#ifdef Q_OS_MAC
    if (openvpn_iface.isEmpty()) {
        return;
    }
    QProcess proc;
    proc.start(QStringLiteral("/usr/sbin/scutil"), QStringList() << QStringLiteral("--dns"));
    if (!proc.waitForFinished(2000)) {
        return;
    }
    const QString output = QString::fromLocal8Bit(proc.readAllStandardOutput());
    const QStringList lines = output.split('\n');
    QString currentIface;
    QStringList currentDns;
    auto flush = [&]() -> bool {
        if (currentIface == openvpn_iface && !currentDns.isEmpty()) {
            openvpn_dns = currentDns.join(QLatin1String(", "));
            if (connected) {
                QString ip6;
                QString cstp = QStringLiteral("OpenVPN");
                QString dtls;
                m->vpn_status_changed(STATUS_CONNECTED, openvpn_dns, openvpn_ip, ip6, cstp, dtls);
            }
            return true;
        }
        return false;
    };

    for (const QString& rawLine : lines) {
        const QString line = rawLine.trimmed();
        if (line.startsWith(QLatin1String("resolver #"))) {
            if (flush()) {
                return;
            }
            currentIface.clear();
            currentDns.clear();
            continue;
        }
        if (line.startsWith(QLatin1String("nameserver["))) {
            const int colon = line.indexOf(QLatin1Char(':'));
            if (colon != -1) {
                const QString dns = line.mid(colon + 1).trimmed();
                if (!dns.isEmpty() && !currentDns.contains(dns)) {
                    currentDns << dns;
                }
            }
            continue;
        }
        if (line.startsWith(QLatin1String("interface"))) {
            const int colon = line.indexOf(QLatin1Char(':'));
            if (colon != -1) {
                currentIface = line.mid(colon + 1).trimmed();
            }
            continue;
        }
        if (line.contains(QLatin1String("if_index"))) {
            const QRegularExpression re(QStringLiteral(R"(\(([^)]+)\))"));
            const QRegularExpressionMatch match = re.match(line);
            if (match.hasMatch()) {
                currentIface = match.captured(1);
            }
        }
    }
    flush();
#endif
}

void OpenVpnInfo::mainloop()
{
    while (true) {
        if (stopRequested()) {
            if (proc->state() != QProcess::NotRunning) {
                proc->terminate();
                proc->waitForFinished(5000);
                if (proc->state() != QProcess::NotRunning) {
                    proc->kill();
                    proc->waitForFinished(5000);
                }
            }
            break;
        }

        if (proc->waitForReadyRead(200)) {
            const QByteArray data = proc->readAll();
            if (data.isEmpty() == false) {
                logOutputLines(QString::fromUtf8(data));
            }
        }
        ensureOpenVpnManagement();
        pollOpenVpnManagement();

        if (proc->state() == QProcess::NotRunning) {
            const QByteArray data = proc->readAll();
            if (data.isEmpty() == false) {
                logOutputLines(QString::fromUtf8(data));
            }
            break;
        }
    }

    if (openvpn_mgmt_socket) {
        openvpn_mgmt_socket->disconnectFromHost();
        openvpn_mgmt_socket.reset();
    }
    if (!openvpn_mgmt_pass_file.isEmpty()) {
        QFile::remove(openvpn_mgmt_pass_file);
        openvpn_mgmt_pass_file.clear();
    }

    if (output_buffer.trimmed().isEmpty() == false) {
        Logger::instance().addMessage(output_buffer.trimmed());
        output_buffer.clear();
    }
}
