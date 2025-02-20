#pragma once

#include <QDialog>
#include <QDialogButtonBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QSpinBox>
#include <QAbstractButton>
#include <memory>
#include <string>
#include "../../fs/fusefs.hpp"

namespace Ui {
class MountDialog;
}

namespace encrypto::gui {

class MountDialog : public QDialog {
    Q_OBJECT

public:
    // Mount options
    struct Options {
        bool read_only = false;
        bool allow_other = false;
        bool enable_cache = true;
        bool verify_reads = true;
        bool verify_writes = true;
        bool use_direct_io = false;
        int cache_size = 64;      // MB
        int timeout = 30;         // minutes
        QString mount_point;
        QString volume_name;
        QString key_file;
    };

    // Constructor and destructor
    explicit MountDialog(QWidget* parent = nullptr);
    explicit MountDialog(const fs::MountOptions& options, QWidget* parent = nullptr);
    ~MountDialog();

    // Dialog settings
    void setTitle(const QString& title);
    void setPrompt(const QString& prompt);
    void setHelpText(const QString& text);
    void setOptions(const Options& options);
    Options getOptions() const;

    // Password handling
    void setPassword(const QString& password);
    QString getPassword() const;
    bool isPasswordSaved() const;

    // Key file handling
    void setKeyFile(const QString& path);
    QString getKeyFile() const;
    bool isKeyFileEnabled() const;

    // Mount point handling
    void setMountPoint(const QString& path);
    QString getMountPoint() const;
    bool isMountPointValid() const;

public Q_SLOTS:
    // UI actions
    void browseKeyFile();
    void browseMountPoint();
    void validateInput();
    void showAdvancedOptions(bool show);
    void updatePasswordStrength(const QString& password);

Q_SIGNALS:
    // User interactions 
    void optionsChanged();
    void passwordEntered(const QString& password);
    void keyFileSelected(const QString& path);
    void mountPointSelected(const QString& path);

protected:
    // Qt overrides
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    bool eventFilter(QObject* obj, QEvent* event) override;

private Q_SLOTS:
    // Internal slots
    void onPasswordChanged();
    void onKeyFileToggled(bool enabled);
    void onAdvancedToggled(bool enabled);
    void onButtonClicked(QAbstractButton* button);
    void onMountPointChanged();
    void onOptionsChanged();

private:
    // UI setup
    void setupUi();
    void setupConnections();
    void setupValidators();
    void setupCompleter();

    // State management  
    void updateButtons();
    void updateTooltips();
    void loadSettings();
    void saveSettings();

    // Validation
    bool validateKeyFile() const;
    bool validateMountPoint() const;
    bool validateOptions() const;
    QString getValidationError() const;

    // Helper functions
    QString suggestMountPoint() const;
    void applyDefaults();
    void updateAdvancedState();

private:
    std::unique_ptr<Ui::MountDialog> ui_;
    Options options_;
    bool password_saved_;
    bool advanced_visible_;
};

} // namespace encrypto::gui
