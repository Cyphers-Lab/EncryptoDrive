#include "passworddialog.hpp"
#include "ui_passworddialog.h"
#include <QPushButton>

namespace encrypto::gui {

PasswordDialog::PasswordDialog(QWidget* parent)
    : QDialog(parent)
    , ui_(std::make_unique<Ui::PasswordDialog>()) {
    ui_->setupUi(this);
    setupConnections();
    updateUi();
}

PasswordDialog::~PasswordDialog() = default;

void PasswordDialog::setupConnections() {
    connect(ui_->useRecoveryCheckBox, &QCheckBox::toggled,
            this, &PasswordDialog::onRecoveryToggled);
            
    connect(ui_->passwordEdit, &QLineEdit::textChanged,
            this, &PasswordDialog::onTextChanged);
    connect(ui_->recoveryKeyEdit, &QLineEdit::textChanged,
            this, &PasswordDialog::onTextChanged);
    
    connect(ui_->buttonBox, &QDialogButtonBox::accepted,
            this, &PasswordDialog::accept);
    connect(ui_->buttonBox, &QDialogButtonBox::rejected,
            this, &PasswordDialog::reject);
}

QString PasswordDialog::password() const {
    return ui_->passwordEdit->text();
}

bool PasswordDialog::useRecoveryKey() const {
    return ui_->useRecoveryCheckBox->isChecked();
}

QString PasswordDialog::recoveryKey() const {
    return ui_->recoveryKeyEdit->text();
}

void PasswordDialog::onRecoveryToggled(bool checked) {
    ui_->recoveryKeyLabel->setEnabled(checked);
    ui_->recoveryKeyEdit->setEnabled(checked);
    
    if (checked) {
        ui_->recoveryKeyEdit->setFocus();
    } else {
        ui_->passwordEdit->setFocus();
    }
    
    updateUi();
}

void PasswordDialog::onTextChanged() {
    updateUi();
}

void PasswordDialog::updateUi() {
    bool hasPassword = !ui_->passwordEdit->text().isEmpty();
    bool hasRecoveryKey = !ui_->recoveryKeyEdit->text().isEmpty();
    bool useRecovery = ui_->useRecoveryCheckBox->isChecked();
    
    QPushButton* okButton = ui_->buttonBox->button(QDialogButtonBox::Ok);
    if (okButton) {
        okButton->setEnabled(hasPassword || (useRecovery && hasRecoveryKey));
    }
}

} // namespace encrypto::gui
