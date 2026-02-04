/*
 * Minimal OpenVPN config parser/builder for profile UI.
 */

#include "openvpn_config.h"

#include <QFile>
#include <QRegularExpression>
#include <QStringList>
#include <QTextStream>

static QString normalize_proto(QString value)
{
    value = value.trimmed();
    if (value.endsWith(QLatin1Char('4')) || value.endsWith(QLatin1Char('6'))) {
        value.chop(1);
    }
    return value;
}

static bool is_comment_or_empty(const QString& line)
{
    const QString trimmed = line.trimmed();
    return trimmed.isEmpty() || trimmed.startsWith(QLatin1Char('#')) || trimmed.startsWith(QLatin1Char(';'));
}

static QString read_block(QTextStream& in, const QString& end_tag)
{
    QStringList lines;
    while (!in.atEnd()) {
        const QString line = in.readLine();
        if (line.trimmed() == end_tag) {
            break;
        }
        lines << line;
    }
    return lines.join(QLatin1String("\n"));
}

bool parse_openvpn_config_text(const QString& text, OpenVpnConfig& out, QString* error)
{
    const QStringList lines = text.split('\n');
    int i = 0;
    while (i < lines.size()) {
        const QString raw = lines.at(i++);
        if (is_comment_or_empty(raw)) {
            continue;
        }
        const QString line = raw.trimmed();

        if (line == QLatin1String("<ca>")) {
            QStringList block;
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</ca>")) {
                    break;
                }
                block << blk;
            }
            out.ca = block.join(QLatin1String("\n"));
            continue;
        }
        if (line == QLatin1String("<cert>")) {
            QStringList block;
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</cert>")) {
                    break;
                }
                block << blk;
            }
            out.cert = block.join(QLatin1String("\n"));
            continue;
        }
        if (line == QLatin1String("<key>")) {
            QStringList block;
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</key>")) {
                    break;
                }
                block << blk;
            }
            out.key = block.join(QLatin1String("\n"));
            continue;
        }
        if (line == QLatin1String("<tls-auth>")) {
            QStringList block;
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</tls-auth>")) {
                    break;
                }
                block << blk;
            }
            out.tls_auth = block.join(QLatin1String("\n"));
            continue;
        }
        if (line == QLatin1String("<tls-crypt>")) {
            QStringList block;
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</tls-crypt>")) {
                    break;
                }
                block << blk;
            }
            out.tls_crypt = block.join(QLatin1String("\n"));
            continue;
        }

        const QStringList parts = line.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        if (parts.isEmpty()) {
            continue;
        }
        const QString key = parts.at(0);

        if (key == QLatin1String("dev") && parts.size() > 1) {
            out.dev = parts.at(1);
        } else if (key == QLatin1String("persist-tun")) {
            out.persist_tun = true;
        } else if (key == QLatin1String("persist-key")) {
            out.persist_key = true;
        } else if (key == QLatin1String("cipher") && parts.size() > 1) {
            out.cipher = parts.at(1);
        } else if (key == QLatin1String("data-ciphers") && parts.size() > 1) {
            out.data_ciphers = parts.mid(1).join(QLatin1String(" "));
        } else if (key == QLatin1String("data-ciphers-fallback") && parts.size() > 1) {
            out.data_ciphers_fallback = parts.mid(1).join(QLatin1String(" "));
        } else if (key == QLatin1String("ncp-disable")) {
            out.ncp_disable = true;
        } else if (key == QLatin1String("auth") && parts.size() > 1) {
            out.auth = parts.at(1);
        } else if (key == QLatin1String("tls-client")) {
            out.tls_client = true;
        } else if (key == QLatin1String("client")) {
            out.client = true;
        } else if (key == QLatin1String("resolv-retry") && parts.size() > 1) {
            out.resolv_retry = parts.mid(1).join(QLatin1String(" "));
        } else if (key == QLatin1String("proto") && parts.size() > 1) {
            out.remote_proto = normalize_proto(parts.at(1));
        } else if (key == QLatin1String("remote") && parts.size() > 1) {
            out.remote_host = parts.at(1);
            if (parts.size() > 2) {
                out.remote_port = parts.at(2);
            }
            if (parts.size() > 3) {
                out.remote_proto = normalize_proto(parts.at(3));
            }
        } else if (key == QLatin1String("auth-user-pass")) {
            out.auth_user_pass = true;
        } else if (key == QLatin1String("remote-cert-tls") && parts.size() > 1) {
            out.remote_cert_tls = parts.at(1);
        } else if (key == QLatin1String("nobind")) {
            out.nobind = true;
        } else if (key == QLatin1String("compress")) {
            out.compress = parts.size() > 1 ? parts.at(1) : QStringLiteral("yes");
        } else if (key == QLatin1String("key-direction") && parts.size() > 1) {
            out.key_direction = parts.at(1);
        } else if (key == QLatin1String("setenv") && parts.size() > 2 && parts.at(1) == QLatin1String("CLIENT_CERT")) {
            out.setenv_client_cert = parts.at(2);
        }
    }
    Q_UNUSED(error);
    return true;
}

bool parse_openvpn_config_file(const QString& path, OpenVpnConfig& out, QString* error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (error) {
            *error = QStringLiteral("Failed to open OpenVPN config.");
        }
        return false;
    }

    const QString text = QString::fromUtf8(file.readAll());
    return parse_openvpn_config_text(text, out, error);
}

QString build_openvpn_config_text(const OpenVpnConfig& cfg)
{
    QStringList lines;

    lines << QLatin1String("client");
    if (!cfg.dev.isEmpty()) {
        lines << (QLatin1String("dev ") + cfg.dev);
    }
    if (cfg.persist_tun) {
        lines << QLatin1String("persist-tun");
    }
    if (cfg.persist_key) {
        lines << QLatin1String("persist-key");
    }
    if (!cfg.cipher.isEmpty()) {
        lines << (QLatin1String("cipher ") + cfg.cipher);
    }
    if (!cfg.data_ciphers.isEmpty()) {
        lines << (QLatin1String("data-ciphers ") + cfg.data_ciphers);
    }
    if (!cfg.data_ciphers_fallback.isEmpty()) {
        lines << (QLatin1String("data-ciphers-fallback ") + cfg.data_ciphers_fallback);
    }
    if (cfg.ncp_disable) {
        lines << QLatin1String("ncp-disable");
    }
    if (!cfg.auth.isEmpty()) {
        lines << (QLatin1String("auth ") + cfg.auth);
    }
    if (cfg.tls_client) {
        lines << QLatin1String("tls-client");
    }
    if (!cfg.resolv_retry.isEmpty()) {
        lines << (QLatin1String("resolv-retry ") + cfg.resolv_retry);
    }
    if (!cfg.remote_host.isEmpty()) {
        QString remote = QLatin1String("remote ") + cfg.remote_host;
        if (!cfg.remote_port.isEmpty()) {
            remote += QLatin1Char(' ') + cfg.remote_port;
        }
        if (!cfg.remote_proto.isEmpty()) {
            remote += QLatin1Char(' ') + cfg.remote_proto;
        }
        lines << remote;
    }
    if (cfg.auth_user_pass) {
        lines << QLatin1String("auth-user-pass");
    }
    if (!cfg.remote_cert_tls.isEmpty()) {
        lines << (QLatin1String("remote-cert-tls ") + cfg.remote_cert_tls);
    }
    if (cfg.nobind) {
        lines << QLatin1String("nobind");
    }
    if (!cfg.compress.isEmpty()) {
        if (cfg.compress == QLatin1String("yes")) {
            lines << QLatin1String("compress");
        } else {
            lines << (QLatin1String("compress ") + cfg.compress);
        }
    }
    if (!cfg.setenv_client_cert.isEmpty()) {
        lines << (QLatin1String("setenv CLIENT_CERT ") + cfg.setenv_client_cert);
    }
    if (!cfg.key_direction.isEmpty()) {
        lines << (QLatin1String("key-direction ") + cfg.key_direction);
    }
    if (!cfg.ca.isEmpty()) {
        lines << QLatin1String("<ca>");
        lines << cfg.ca;
        lines << QLatin1String("</ca>");
    }
    if (!cfg.cert.isEmpty()) {
        lines << QLatin1String("<cert>");
        lines << cfg.cert;
        lines << QLatin1String("</cert>");
    }
    if (!cfg.key.isEmpty()) {
        lines << QLatin1String("<key>");
        lines << cfg.key;
        lines << QLatin1String("</key>");
    }
    if (!cfg.tls_auth.isEmpty()) {
        lines << QLatin1String("<tls-auth>");
        lines << cfg.tls_auth;
        lines << QLatin1String("</tls-auth>");
    }
    if (!cfg.tls_crypt.isEmpty()) {
        lines << QLatin1String("<tls-crypt>");
        lines << cfg.tls_crypt;
        lines << QLatin1String("</tls-crypt>");
    }

    return lines.join(QLatin1String("\n")) + QLatin1String("\n");
}

QString update_openvpn_config_text(const QString& base, const OpenVpnConfig& cfg)
{
    if (base.trimmed().isEmpty()) {
        return build_openvpn_config_text(cfg);
    }

    QStringList kept;
    const QStringList lines = base.split('\n');
    int i = 0;
    while (i < lines.size()) {
        const QString raw = lines.at(i++);
        const QString line = raw.trimmed();
        if (line.isEmpty()) {
            kept << raw;
            continue;
        }

        const QString lower = line.toLower();
        if (lower == QLatin1String("<ca>")) {
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</ca>")) {
                    break;
                }
            }
            continue;
        }
        if (lower == QLatin1String("<cert>")) {
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</cert>")) {
                    break;
                }
            }
            continue;
        }
        if (lower == QLatin1String("<key>")) {
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</key>")) {
                    break;
                }
            }
            continue;
        }
        if (lower == QLatin1String("<tls-auth>")) {
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</tls-auth>")) {
                    break;
                }
            }
            continue;
        }
        if (lower == QLatin1String("<tls-crypt>")) {
            while (i < lines.size()) {
                const QString blk = lines.at(i++);
                if (blk.trimmed() == QLatin1String("</tls-crypt>")) {
                    break;
                }
            }
            continue;
        }

        if (lower.startsWith(QLatin1String("dev "))
            || lower == QLatin1String("persist-tun")
            || lower == QLatin1String("persist-key")
            || lower.startsWith(QLatin1String("cipher "))
            || lower.startsWith(QLatin1String("data-ciphers "))
            || lower.startsWith(QLatin1String("data-ciphers-fallback "))
            || lower == QLatin1String("ncp-disable")
            || lower.startsWith(QLatin1String("auth "))
            || lower == QLatin1String("tls-client")
            || lower == QLatin1String("client")
            || lower.startsWith(QLatin1String("resolv-retry "))
            || lower.startsWith(QLatin1String("proto "))
            || lower.startsWith(QLatin1String("remote "))
            || lower.startsWith(QLatin1String("auth-user-pass"))
            || lower.startsWith(QLatin1String("remote-cert-tls "))
            || lower == QLatin1String("nobind")
            || lower.startsWith(QLatin1String("compress"))
            || lower.startsWith(QLatin1String("key-direction "))
            || lower.startsWith(QLatin1String("setenv client_cert "))) {
            continue;
        }

        kept << raw;
    }

    QString updated = build_openvpn_config_text(cfg);
    if (!kept.isEmpty()) {
        updated += kept.join(QLatin1String("\n"));
        if (!updated.endsWith(QLatin1Char('\n'))) {
            updated += QLatin1Char('\n');
        }
    }
    return updated;
}
