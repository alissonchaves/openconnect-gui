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

#include "openvpn_import.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QObject>
#include <QRegularExpression>

static QString read_file_text(const QString& path, QString& err)
{
    QFile f(path);
    if (f.open(QIODevice::ReadOnly | QIODevice::Text) == false) {
        err = QObject::tr("Failed to read file: %1").arg(path);
        return {};
    }
    QByteArray data = f.readAll();
    return QString::fromUtf8(data);
}

bool import_openvpn_config(const QString& file_path, OpenVpnConfig& out_cfg, QString& out_text, QString& err)
{
    QFileInfo fi(file_path);
    if (fi.exists() == false || fi.isFile() == false) {
        err = QObject::tr("OpenVPN config not found: %1").arg(file_path);
        return false;
    }

    QString content = read_file_text(file_path, err);
    if (content.isEmpty() && err.isEmpty() == false) {
        return false;
    }

    const QDir base_dir = fi.dir();
    const QRegularExpression directive_re(
        QStringLiteral(R"(^\s*(ca|cert|key|pkcs12|tls-auth|tls-crypt)\s+(.+?)\s*$)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression auth_re(
        QStringLiteral(R"(^\s*auth-user-pass\s+.+$)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpression drop_user_group_re(
        QStringLiteral(R"(^\s*(user|group)\s+.+$)"),
        QRegularExpression::CaseInsensitiveOption);

    QStringList lines = content.split('\n');
    QStringList out_lines;

    for (int i = 0; i < lines.size(); ++i) {
        QString line = lines.at(i);
        QString trimmed = line.trimmed();

        if (trimmed.startsWith("<ca>", Qt::CaseInsensitive)
            || trimmed.startsWith("<cert>", Qt::CaseInsensitive)
            || trimmed.startsWith("<key>", Qt::CaseInsensitive)
            || trimmed.startsWith("<pkcs12>", Qt::CaseInsensitive)
            || trimmed.startsWith("<tls-auth>", Qt::CaseInsensitive)
            || trimmed.startsWith("<tls-crypt>", Qt::CaseInsensitive)) {
            out_lines << line;
            const QString end_tag = "</" + trimmed.mid(1, trimmed.indexOf('>') - 1) + ">";
            while (i + 1 < lines.size()) {
                ++i;
                out_lines << lines.at(i);
                if (lines.at(i).trimmed().compare(end_tag, Qt::CaseInsensitive) == 0) {
                    break;
                }
            }
            continue;
        }

        if (drop_user_group_re.match(trimmed).hasMatch()) {
            continue;
        }

        if (auth_re.match(trimmed).hasMatch()) {
            out_lines << QStringLiteral("auth-user-pass");
            continue;
        }

        const QRegularExpressionMatch m = directive_re.match(trimmed);
        if (m.hasMatch()) {
            const QString directive = m.captured(1).toLower();
            QString rest = m.captured(2).trimmed();
            QStringList tokens = rest.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
            if (tokens.isEmpty()) {
                out_lines << line;
                continue;
            }
            QString file_token = tokens.takeFirst();
            if ((file_token.startsWith('"') && file_token.endsWith('"'))
                || (file_token.startsWith('\'') && file_token.endsWith('\''))) {
                file_token = file_token.mid(1, file_token.size() - 2);
            }
            const QString file_path_resolved = QDir::isAbsolutePath(file_token)
                ? file_token
                : base_dir.absoluteFilePath(file_token);
            QString file_err;
            const QString file_content = read_file_text(file_path_resolved, file_err);
            if (file_content.isEmpty() && file_err.isEmpty() == false) {
                err = file_err;
                return false;
            }

            out_lines << QStringLiteral("<%1>").arg(directive);
            out_lines << file_content.trimmed();
            out_lines << QStringLiteral("</%1>").arg(directive);

            if (directive == QLatin1String("tls-auth") && tokens.isEmpty() == false) {
                const QString dir_token = tokens.takeFirst();
                if (dir_token == QLatin1String("0") || dir_token == QLatin1String("1")) {
                    out_lines << QStringLiteral("key-direction %1").arg(dir_token);
                }
            }
            continue;
        }

        out_lines << line;
    }

    out_text = out_lines.join('\n');
    return parse_openvpn_config_text(out_text, out_cfg, &err);
}
