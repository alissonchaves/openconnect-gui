#pragma once

#include <QDialog>
#include <QUrl>

#include "openvpn_config.h"

class QAbstractButton;
namespace Ui {
class NewProfileDialog;
}

class NewProfileDialog : public QDialog {
    Q_OBJECT

public:
    explicit NewProfileDialog(QWidget* parent = 0);
    ~NewProfileDialog();
    void setUrl(QUrl &);
    static QString urlToName(QUrl & url);
    void setQuickConnect();

    QString getNewProfileName() const;

signals:
    void connect();

protected:
    void changeEvent(QEvent* e);

private slots:
    void on_checkBoxCustomize_toggled(bool checked);
    void on_lineEditName_textChanged(const QString&);
    void on_lineEditGateway_textChanged(const QString& text);
    void on_protocolComboBox_currentIndexChanged(int index);
    void on_openvpnImportButton_clicked();

    void on_buttonBox_clicked(QAbstractButton* button);
    void on_buttonBox_accepted();

private:
    void updateName(QUrl &);
    void updateNameFromGateway();
    void updateButtons();
    void updateGatewayUiForProtocol(const QString& protocol_name);

    Ui::NewProfileDialog* ui;
    bool quick_connect;
    QString openvpn_config_imported;
    QString openvpn_import_path;
    OpenVpnConfig openvpn_config_parsed;
};
