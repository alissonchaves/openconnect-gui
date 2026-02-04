#include "NewProfileDialog.h"
#include "ui_NewProfileDialog.h"

#include "common.h"
#include "VpnProtocolModel.h"
#include "openvpn_import.h"

#include "server_storage.h"

#include <QFileInfo>
#include <QFileDialog>
#include <QMessageBox>
#include <QPushButton>
#include <OcSettings.h>
#include <QUrl>

#include <memory>

NewProfileDialog::NewProfileDialog(QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::NewProfileDialog)
    , openvpn_config_imported()
    , openvpn_import_path()
    , openvpn_config_parsed()
{
    ui->setupUi(this);
    VpnProtocolModel* model = new VpnProtocolModel(this);
    ui->protocolComboBox->setModel(model);

    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setText(tr("Save && Connect"));
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setDefault(true);

    ui->buttonBox->button(QDialogButtonBox::Save)->setEnabled(false);
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(false);

    updateGatewayUiForProtocol(ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString());

    quick_connect = false;
}

NewProfileDialog::~NewProfileDialog()
{
    delete ui;
}

void NewProfileDialog::setQuickConnect()
{
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(true);
    ui->buttonBox->button(QDialogButtonBox::Save)->setVisible(false);
    ui->checkBoxCustomize->setVisible(false);
    ui->protocolComboBox->setFocus();
    this->quick_connect = true;
}

QString NewProfileDialog::urlToName(QUrl & url)
{
    if (url.port(443) == 443)
        return url.host();
    else
        return (url.host() + tr(":%1").arg(url.port(443)));
}

void NewProfileDialog::updateName(QUrl & url)
{
    ui->lineEditName->setText(urlToName(url));
}

void NewProfileDialog::setUrl(QUrl & url)
{
    if (url.isLocalFile()) {
        ui->lineEditGateway->setText(url.toLocalFile());
        updateNameFromGateway();
    } else {
        updateName(url);
        ui->lineEditGateway->setText(url.toString());
    }
}

QString NewProfileDialog::getNewProfileName() const
{
    return ui->lineEditName->text();
}

void NewProfileDialog::changeEvent(QEvent* e)
{
    QDialog::changeEvent(e);
    switch (e->type()) {
    case QEvent::LanguageChange:
        ui->retranslateUi(this);
        break;
    default:
        break;
    }
}

void NewProfileDialog::on_checkBoxCustomize_toggled(bool checked)
{
    if (checked == false) {
        updateNameFromGateway();

        ui->lineEditGateway->setFocus();
    } else {
        ui->lineEditName->setFocus();
    }
}

void NewProfileDialog::on_lineEditName_textChanged(const QString&)
{
    if (quick_connect == false)
        updateButtons();
}

void NewProfileDialog::on_lineEditGateway_textChanged(const QString& text)
{
    if (ui->checkBoxCustomize->isChecked() == false) {
        updateNameFromGateway();
    }

    if (ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString() == QLatin1String(OCG_PROTO_OPENVPN)) {
        if (openvpn_import_path.isEmpty() == false && text != openvpn_import_path) {
            openvpn_config_imported.clear();
            openvpn_import_path.clear();
            openvpn_config_parsed = OpenVpnConfig{};
        }
    }

    updateButtons();
}

#define PREFIX "server:"
void NewProfileDialog::updateButtons()
{
    bool enableButtons{ false };
    if (ui->lineEditName->text().isEmpty() == false && ui->lineEditGateway->text().isEmpty() == false) {

        enableButtons = true;

        // TODO: refactor this too :/
        OcSettings settings;
        for (const auto& key : settings.allKeys()) {
            if (key.startsWith(PREFIX) && key.endsWith("/server")) {
                QString str{ key };
                str.remove(0, sizeof(PREFIX) - 1); /* remove prefix */
                str.remove(str.size() - 7, 7); /* remove /server suffix */
                if (str == ui->lineEditName->text()) {
                    enableButtons = false;
                    break;
                }
            }
        }
    }

    ui->buttonBox->button(QDialogButtonBox::Save)->setEnabled(enableButtons);
    ui->buttonBox->button(QDialogButtonBox::SaveAll)->setEnabled(enableButtons);
}

void NewProfileDialog::updateGatewayUiForProtocol(const QString& protocol_name)
{
    ui->openvpnImportButton->setVisible(protocol_name == QLatin1String(OCG_PROTO_OPENVPN));
    if (protocol_name == QLatin1String(OCG_PROTO_OPENVPN)) {
        ui->labelGateway->setText(tr("OpenVPN Config"));
        ui->lineEditGateway->setPlaceholderText(tr("/path/to/config.ovpn"));
        ui->lineEditGateway->setToolTip(tr("Path to the OpenVPN configuration file (will be imported into the profile)"));
    } else {
        ui->labelGateway->setText(tr("Gateway"));
        ui->lineEditGateway->setPlaceholderText(tr("https://my_server[:443]/[usergroup]"));
        ui->lineEditGateway->setToolTip(tr("Specify the hostname to connect to; a port may be specified after the host separated with a colon ':'"));
    }
}

void NewProfileDialog::updateNameFromGateway()
{
    if (ui->checkBoxCustomize->isChecked()) {
        return;
    }

    const QString protocol_name = ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString();
    const QString gateway_text = ui->lineEditGateway->text().trimmed();

    if (protocol_name == QLatin1String(OCG_PROTO_OPENVPN)) {
        QFileInfo fi(gateway_text);
        if (fi.exists() && fi.isFile()) {
            ui->lineEditName->setText(fi.completeBaseName());
        } else if (!gateway_text.isEmpty()) {
            ui->lineEditName->setText(fi.fileName().isEmpty() ? gateway_text : fi.fileName());
        }
        return;
    }

    QUrl url = QUrl::fromUserInput(gateway_text);
    if (url.isValid()) {
        updateName(url);
    }
}

void NewProfileDialog::on_protocolComboBox_currentIndexChanged(int)
{
    const QString protocol_name = ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString();
    updateGatewayUiForProtocol(protocol_name);
    updateNameFromGateway();
    updateButtons();

    if (protocol_name != QLatin1String(OCG_PROTO_OPENVPN)) {
        openvpn_config_imported.clear();
        openvpn_import_path.clear();
        openvpn_config_parsed = OpenVpnConfig{};
    }
}

void NewProfileDialog::on_openvpnImportButton_clicked()
{
    const QString file_path = QFileDialog::getOpenFileName(
        this,
        tr("Import OpenVPN config"),
        ui->lineEditGateway->text(),
        tr("OpenVPN Config (*.ovpn *.conf);;All Files (*.*)"));
    if (file_path.isEmpty()) {
        return;
    }

    QString config;
    QString err;
    OpenVpnConfig cfg;
    if (import_openvpn_config(file_path, cfg, config, err) == false) {
        QMessageBox::information(this, qApp->applicationName(), err);
        return;
    }

    ui->lineEditGateway->setText(file_path);
    updateNameFromGateway();
    updateButtons();

    openvpn_config_imported = config;
    openvpn_import_path = file_path;
    openvpn_config_parsed = cfg;
}

void NewProfileDialog::on_buttonBox_clicked(QAbstractButton* button)
{
    if (quick_connect == false && ui->buttonBox->standardButton(button) == QDialogButtonBox::SaveAll) {
        emit connect();
    }
}

void NewProfileDialog::on_buttonBox_accepted()
{
    auto ss{ std::make_unique<StoredServer>() };
    ss->set_label(ui->lineEditName->text());
    ss->set_server_gateway(ui->lineEditGateway->text());
    ss->set_protocol_name(ui->protocolComboBox->currentData(ROLE_PROTOCOL_NAME).toString());
    if (ss->get_protocol_name() == QLatin1String(OCG_PROTO_OPENVPN)) {
        if (openvpn_config_imported.isEmpty()) {
            QMessageBox::information(this, qApp->applicationName(),
                tr("Please import the OpenVPN config using the Import button."));
            return;
        }
        ss->set_openvpn_config_text(openvpn_config_imported);
        ss->set_openvpn_config(QString());
        ss->set_openvpn_remote_host(openvpn_config_parsed.remote_host);
        ss->set_openvpn_remote_port(openvpn_config_parsed.remote_port);
        ss->set_openvpn_remote_proto(openvpn_config_parsed.remote_proto);
        ss->set_openvpn_dev(openvpn_config_parsed.dev);
        ss->set_openvpn_cipher(openvpn_config_parsed.cipher);
        ss->set_openvpn_data_ciphers(openvpn_config_parsed.data_ciphers);
        ss->set_openvpn_data_ciphers_fallback(openvpn_config_parsed.data_ciphers_fallback);
        ss->set_openvpn_auth(openvpn_config_parsed.auth);
        ss->set_openvpn_auth_user_pass(openvpn_config_parsed.auth_user_pass);
        ss->set_openvpn_remote_cert_tls(openvpn_config_parsed.remote_cert_tls);
        ss->set_openvpn_compress(openvpn_config_parsed.compress);
        ss->set_openvpn_resolv_retry(openvpn_config_parsed.resolv_retry);
        ss->set_openvpn_nobind(openvpn_config_parsed.nobind);
        ss->set_openvpn_persist_tun(openvpn_config_parsed.persist_tun);
        ss->set_openvpn_persist_key(openvpn_config_parsed.persist_key);
        ss->set_openvpn_ncp_disable(openvpn_config_parsed.ncp_disable);
        ss->set_openvpn_tls_client(openvpn_config_parsed.tls_client);
        ss->set_openvpn_client(openvpn_config_parsed.client);
        ss->set_openvpn_setenv_client_cert(openvpn_config_parsed.setenv_client_cert);
        ss->set_openvpn_key_direction(openvpn_config_parsed.key_direction);
        ss->set_openvpn_ca(openvpn_config_parsed.ca);
        ss->set_openvpn_cert(openvpn_config_parsed.cert);
        ss->set_openvpn_key(openvpn_config_parsed.key);
        ss->set_openvpn_tls_auth(openvpn_config_parsed.tls_auth);
        ss->set_openvpn_tls_crypt(openvpn_config_parsed.tls_crypt);
        ss->set_server_gateway(QString());
    }
    ss->save();

    accept();
}
