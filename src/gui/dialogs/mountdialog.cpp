#include "mountdialog.hpp"
#include "ui_mountdialog.h"

#include <QFileDialog>
#include <QShowEvent>
#include <QCloseEvent>
#include <QMessageBox>
#include <QDir>
#include <QCompleter>
#include <QFileSystemModel>

namespace encrypto::gui {

MountDialog::MountDialog(QWidget* parent)
    : QDialog(parent)
    , ui_(std::make_unique<Ui::MountDialog>())
    , password_saved_(false)
    , advanced_visible_(false) {
    setupUi();
    setupConnections();
    setupValidators();
    setupCompleter();
    applyDefaults();
    loadSettings();
    updateButtons();
}

MountDialog::MountDialog(const fs::MountOptions& options, QWidget* parent)
    : MountDialog(parent) {
    Options opts;
    opts.read_only = options.read_only;
    opts.allow_other = options.allow_other;
    opts.mount_point = QString::fromStdString(options.mount_point.string());
    setOptions(opts);
}

MountDialog::~MountDialog() = default;

void MountDialog::setupUi() {
    ui_->setupUi(this);
    ui_->advancedGroupBox->setVisible(false);
}

void MountDialog::setupConnections() {
    connect(ui_->passwordEdit, &QLineEdit::textChanged,
            this, &MountDialog::onPasswordChanged);
    connect(ui_->mountPointEdit, &QLineEdit::textChanged,
            this, &MountDialog::onMountPointChanged);
    connect(ui_->keyFileCheckBox, &QCheckBox::toggled,
            this, &MountDialog::onKeyFileToggled);
    connect(ui_->advancedCheckBox, &QCheckBox::toggled,
            this, &MountDialog::onAdvancedToggled);
    connect(ui_->buttonBox, &QDialogButtonBox::clicked,
            this, &MountDialog::onButtonClicked);

    // Advanced options connections
    connect(ui_->cacheCheckBox, &QCheckBox::toggled,
            this, &MountDialog::onOptionsChanged);
}

void MountDialog::setupValidators() {
    // Add any input validators here
}

void MountDialog::setupCompleter() {
    auto* model = new QFileSystemModel(this);
    model->setRootPath(QDir::rootPath());
    model->setFilter(QDir::Dirs | QDir::NoDotAndDotDot);
    
    auto* completer = new QCompleter(model, this);
    completer->setCompletionMode(QCompleter::PopupCompletion);
    ui_->mountPointEdit->setCompleter(completer);
}

void MountDialog::setTitle(const QString& title) {
    setWindowTitle(title);
}

void MountDialog::setPrompt(const QString& prompt) {
    ui_->promptLabel->setText(prompt);
}

void MountDialog::setHelpText(const QString& text) {
    ui_->helpLabel->setText(text);
    ui_->helpLabel->setVisible(!text.isEmpty());
}

void MountDialog::setOptions(const Options& options) {
    options_ = options;
    
    ui_->readOnlyCheckBox->setChecked(options.read_only);
    ui_->mountPointEdit->setText(options.mount_point);
    ui_->cacheCheckBox->setChecked(options.enable_cache);
    ui_->cacheSizeSpinBox->setValue(options.cache_size);
    
    updateAdvancedState();
    updateButtons();
}

MountDialog::Options MountDialog::getOptions() const {
    Options opts = options_;
    opts.read_only = ui_->readOnlyCheckBox->isChecked();
    opts.mount_point = ui_->mountPointEdit->text();
    opts.enable_cache = ui_->cacheCheckBox->isChecked();
    opts.cache_size = ui_->cacheSizeSpinBox->value();
    return opts;
}

void MountDialog::setPassword(const QString& password) {
    ui_->passwordEdit->setText(password);
}

QString MountDialog::getPassword() const {
    return ui_->passwordEdit->text();
}

bool MountDialog::isPasswordSaved() const {
    return ui_->savePasswordCheckBox->isChecked();
}

void MountDialog::setKeyFile(const QString& path) {
    options_.key_file = path;
    updateButtons();
}

QString MountDialog::getKeyFile() const {
    return options_.key_file;
}

bool MountDialog::isKeyFileEnabled() const {
    return ui_->keyFileCheckBox->isChecked();
}

void MountDialog::setMountPoint(const QString& path) {
    ui_->mountPointEdit->setText(path);
}

QString MountDialog::getMountPoint() const {
    return ui_->mountPointEdit->text();
}

bool MountDialog::isMountPointValid() const {
    return validateMountPoint();
}

void MountDialog::browseKeyFile() {
    QString path = QFileDialog::getOpenFileName(this,
        tr("Select Key File"),
        options_.key_file,
        tr("All Files (*.*)"));
        
    if (!path.isEmpty()) {
        setKeyFile(path);
    }
}

void MountDialog::browseMountPoint() {
    QString path = QFileDialog::getExistingDirectory(this,
        tr("Select Mount Point"),
        options_.mount_point,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
        
    if (!path.isEmpty()) {
        setMountPoint(path);
    }
}

void MountDialog::validateInput() {
    updateButtons();
}

void MountDialog::showAdvancedOptions(bool show) {
    ui_->advancedCheckBox->setChecked(show);
}

void MountDialog::updatePasswordStrength(const QString& password) {
    Q_UNUSED(password);
    // TODO: Implement password strength meter
}

void MountDialog::showEvent(QShowEvent* event) {
    QDialog::showEvent(event);
    ui_->passwordEdit->setFocus();
}

void MountDialog::closeEvent(QCloseEvent* event) {
    saveSettings();
    QDialog::closeEvent(event);
}

bool MountDialog::eventFilter(QObject* obj, QEvent* event) {
    return QDialog::eventFilter(obj, event);
}

void MountDialog::onPasswordChanged() {
    updateButtons();
    emit passwordEntered(ui_->passwordEdit->text());
}

void MountDialog::onKeyFileToggled(bool enabled) {
    Q_UNUSED(enabled);
    updateButtons();
}

void MountDialog::onAdvancedToggled(bool enabled) {
    ui_->advancedGroupBox->setVisible(enabled);
    advanced_visible_ = enabled;
    if (!enabled) {
        adjustSize();
    }
}

void MountDialog::onButtonClicked(QAbstractButton* button) {
    if (ui_->buttonBox->standardButton(button) == QDialogButtonBox::Ok) {
        if (validateOptions()) {
            accept();
        }
    }
}

void MountDialog::onMountPointChanged() {
    updateButtons();
    emit mountPointSelected(ui_->mountPointEdit->text());
}

void MountDialog::onOptionsChanged() {
    updateButtons();
    emit optionsChanged();
}

void MountDialog::updateButtons() {
    bool hasPassword = !ui_->passwordEdit->text().isEmpty();
    bool valid = hasPassword && validateMountPoint() && validateOptions();
    ui_->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(valid);
}

void MountDialog::updateTooltips() {
    if (const QString error = getValidationError(); !error.isEmpty()) {
        ui_->buttonBox->button(QDialogButtonBox::Ok)->setToolTip(error);
    } else {
        ui_->buttonBox->button(QDialogButtonBox::Ok)->setToolTip(QString());
    }
}

void MountDialog::loadSettings() {
    // TODO: Load settings from QSettings
}

void MountDialog::saveSettings() {
    // TODO: Save settings to QSettings
}

bool MountDialog::validateKeyFile() const {
    if (!isKeyFileEnabled()) return true;
    return !options_.key_file.isEmpty() && QFile::exists(options_.key_file);
}

bool MountDialog::validateMountPoint() const {
    const QString path = ui_->mountPointEdit->text();
    if (path.isEmpty()) return false;
    
    QDir dir(path);
    return dir.exists() && dir.isEmpty();
}

bool MountDialog::validateOptions() const {
    return validateMountPoint() && validateKeyFile();
}

QString MountDialog::getValidationError() const {
    if (!validateMountPoint()) {
        return tr("Invalid mount point: Directory must exist and be empty");
    }
    if (!validateKeyFile()) {
        return tr("Invalid key file: File does not exist");
    }
    return QString();
}

QString MountDialog::suggestMountPoint() const {
    return QString();
}

void MountDialog::applyDefaults() {
    options_ = Options();
    updateAdvancedState();
}

void MountDialog::updateAdvancedState() {
    ui_->advancedGroupBox->setVisible(advanced_visible_);
    ui_->cacheCheckBox->setChecked(options_.enable_cache);
    ui_->cacheSizeSpinBox->setValue(options_.cache_size);
    ui_->cacheSizeSpinBox->setEnabled(options_.enable_cache);
}

} // namespace encrypto::gui
