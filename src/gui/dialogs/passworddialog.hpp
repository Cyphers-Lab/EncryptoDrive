#pragma once

#include <QDialog>
#include <QDialogButtonBox>
#include <memory>

namespace Ui {
class PasswordDialog;
}

namespace encrypto::gui {

class PasswordDialog : public QDialog {
    Q_OBJECT

public:
    explicit PasswordDialog(QWidget* parent = nullptr);
    ~PasswordDialog();

    QString password() const;
    bool useRecoveryKey() const;
    QString recoveryKey() const;

private slots:
    void onRecoveryToggled(bool checked);
    void onTextChanged();

private:
    void updateUi();
    void setupConnections();

private:
    std::unique_ptr<Ui::PasswordDialog> ui_;
};

} // namespace encrypto::gui
