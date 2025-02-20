#pragma once

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QMessageBox>
#include <QTimer>
#include <QString>
#include <QCloseEvent>
#include <memory>
#include <vector>
#include <string>
#include "../widgets/drivelist.hpp"
#include "../../fs/fusefs.hpp"

namespace Ui {
class MainWindow;
}

namespace encrypto::gui {

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    // Constructor and destructor
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

    // Window state
    void saveState();
    void restoreState();

protected:
    // Qt event handlers
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;

Q_SIGNALS:
    void driveStatusChanged(const QString& path, bool mounted);

private Q_SLOTS:
    // Menu actions
    void onNewDrive();
    void onOpenDrive();
    void onCloseDrive();
    void onEjectDrive();
    void onDriveSettings();
    void onImportDrive();
    void onExportDrive();
    void onQuit();

    // Drive operations
    void onDriveStatusChanged(const QString& path, bool mounted);
    void onDriveError(const QString& path, const QString& error);
    void onDriveProgress(const QString& path, int progress);

    // View actions
    void onRefreshDrives();
    void onToggleToolbar(bool show);
    void onToggleStatusBar(bool show);
    void onViewMode(int mode);

    // Settings
    void onPreferences();
    void onChangePassword();
    void onManageKeys();

    // Help actions
    void onAbout();
    void onHelp();
    void onCheckUpdates();

    // Tray icon
    void onTrayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void onShowHideWindow();

    // Drive list
    void onDriveSelected(const QString& path);
    void onDriveDoubleClicked(const QString& path);
    void onDriveContextMenu(const QPoint& pos);

private:
    // UI setup
    void setupUi();
    void setupMenusAndActions();
    void setupTrayIcon();
    void setupDriveList();

    // State management
    void updateWindowTitle();
    void updateActions();
    void updateStatusBar();
    void updateTrayIcon();

    // Drive management
    void mountDrive(const QString& path, bool prompt = true);
    void unmountDrive(const QString& path, bool force = false);
    void refreshDriveList();
    QString getSelectedDrive() const;

    // Settings
    void loadSettings();
    void saveSettings();

    // Error handling
    void handleError(const QString& message, bool showDialog = true);
    void logMessage(const QString& message);

    // Window management
    void minimizeToTray();
    void restoreFromTray();
    bool confirmClose();

protected:
    QString formatSize(qint64 size) const;

private:
    std::unique_ptr<Ui::MainWindow> ui_;  // Qt UI class
    std::unique_ptr<QSystemTrayIcon> tray_icon_;
    std::unique_ptr<QMenu> tray_menu_;
    QToolBar* toolbar_{nullptr};

    // Menu items and actions
    struct {
        QAction* new_drive{nullptr};
        QAction* open_drive{nullptr};
        QAction* close_drive{nullptr};
        QAction* eject_drive{nullptr};
        QAction* settings{nullptr};
        QAction* import{nullptr};
        QAction* export_{nullptr};
        QAction* quit{nullptr};
        QAction* mount{nullptr};
        QAction* unmount{nullptr};
        QAction* change_password{nullptr};
        QAction* manage_keys{nullptr};
        QAction* refresh{nullptr};
        QAction* show_toolbar{nullptr};
        QAction* show_statusbar{nullptr};
        QAction* help{nullptr};
        QAction* check_updates{nullptr};
        QAction* about{nullptr};
    } actions_;

    DriveList* drive_list_{nullptr};
    std::vector<std::shared_ptr<fs::FuseFilesystem>> mounted_drives_;

    // Settings
    bool minimize_to_tray_{false};
    bool confirm_unmount_{true};
    bool auto_mount_{false};
    bool show_notifications_{true};
    QString last_directory_;

    // State flags
    bool shutting_down_{false};
    bool has_pending_operations_{false};
};

} // namespace encrypto::gui
