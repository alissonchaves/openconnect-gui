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

#include "common.h"
#include "logger.h"
#include "dialog/MyInputDialog.h"
#include "server_storage.h"
#include "dialog/mainwindow.h"

#include <QFileDevice>
#include <QStandardPaths>
#include <QTextStream>
#include <QRegularExpression>

OpenVpnInfo::OpenVpnInfo(StoredServer* ss, MainWindow* m)
    : ss(ss)
    , m(m)
    , proc(std::make_unique<QProcess>())
    , auth_file(nullptr)
    , config_file(nullptr)
    , stop_requested(false)
    , connected(false)
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

    config_file = std::make_unique<QTemporaryFile>(QStringLiteral("/tmp/openconnect-gui-ovpn-XXXXXX"));
    config_file->setAutoRemove(true);
    if (config_file->open() == false) {
        err = QObject::tr("Failed to create OpenVPN config file");
        return false;
    }

    config_file->setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ReadGroup | QFileDevice::ReadOther);
    QTextStream out(config_file.get());
    out << ss->get_openvpn_config_text();
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

    proc->start(openvpn_path, args);
    if (proc->waitForStarted(10000) == false) {
        last_err = QObject::tr("Failed to start OpenVPN process: %1").arg(proc->errorString());
        return -1;
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
            if (connected == false && line.contains(QStringLiteral("Initialization Sequence Completed"), Qt::CaseInsensitive)) {
                connected = true;
                QString empty;
                m->vpn_status_changed(STATUS_CONNECTED, empty, empty, empty, empty, empty);
            }
        }
        eol = output_buffer.indexOf('\n');
    }
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

        if (proc->state() == QProcess::NotRunning) {
            const QByteArray data = proc->readAll();
            if (data.isEmpty() == false) {
                logOutputLines(QString::fromUtf8(data));
            }
            break;
        }
    }

    if (output_buffer.trimmed().isEmpty() == false) {
        Logger::instance().addMessage(output_buffer.trimmed());
        output_buffer.clear();
    }
}
