#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "gui/dialogs/mountdialog.hpp"
#include "gui/dialogs/passworddialog.hpp"
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QMessageBox>
#include <QSettings>
#include <QFileDialog>
#include <QStandardPaths>
#include <QTimer>

namespace encrypto::gui {

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
    , ui_(std::make_unique<Ui::MainWindow>()) {
    ui_->setupUi(this);
    setupUi();
    setupMenusAndActions();
    setupTrayIcon();
    setupDriveList();
    
    loadSettings();
    updateActions();
}

MainWindow::~MainWindow() = default;

void MainWindow::saveState() {
    saveSettings();
}

void MainWindow::restoreState() {
    loadSettings();
}

void MainWindow::setupUi() {
    drive_list_ = qobject_cast<DriveList*>(ui_->driveListWidget);
    
    connect(drive_list_, &DriveList::driveSelected,
            this, &MainWindow::onDriveSelected);
    connect(drive_list_, &DriveList::driveDoubleClicked,
            this, &MainWindow::onDriveDoubleClicked);
    connect(drive_list_, &DriveList::driveContextMenu,
            this, &MainWindow::onDriveContextMenu);
            
    connect(ui_->createDriveButton, &QPushButton::clicked,
            this, &MainWindow::onNewDrive);
    connect(ui_->mountDriveButton, &QPushButton::clicked,
            this, &MainWindow::onOpenDrive);
    connect(ui_->unmountDriveButton, &QPushButton::clicked,
            this, &MainWindow::onCloseDrive);
}

void MainWindow::setupMenusAndActions() {
    // Create all actions
    actions_.new_drive = new QAction(QIcon(":/resources/icons/new.png"), tr("&New Drive..."), this);
    actions_.open_drive = new QAction(QIcon(":/resources/icons/open.png"), tr("&Open..."), this);
    actions_.close_drive = new QAction(QIcon(":/resources/icons/close.png"), tr("&Close"), this);
    actions_.eject_drive = new QAction(QIcon(":/resources/icons/eject.png"), tr("&Eject"), this);
    actions_.settings = new QAction(QIcon(":/resources/icons/settings.png"), tr("&Settings..."), this);
    actions_.import = new QAction(QIcon(":/resources/icons/import.png"), tr("&Import..."), this);
    actions_.export_ = new QAction(QIcon(":/resources/icons/export.png"), tr("&Export..."), this);
    actions_.quit = new QAction(QIcon(":/resources/icons/quit.png"), tr("&Quit"), this);
    actions_.mount = new QAction(QIcon(":/resources/icons/mount.png"), tr("&Mount"), this);
    actions_.unmount = new QAction(QIcon(":/resources/icons/unmount.png"), tr("&Unmount"), this);
    actions_.change_password = new QAction(QIcon(":/resources/icons/password.png"), tr("Change &Password..."), this);
    actions_.manage_keys = new QAction(QIcon(":/resources/icons/keys.png"), tr("Manage &Keys..."), this);
    actions_.refresh = new QAction(QIcon(":/resources/icons/refresh.png"), tr("&Refresh"), this);
    actions_.show_toolbar = new QAction(tr("Show &Toolbar"), this);
    actions_.show_statusbar = new QAction(tr("Show &Status Bar"), this);
    actions_.help = new QAction(QIcon(":/resources/icons/help.png"), tr("&Help"), this);
    actions_.check_updates = new QAction(QIcon(":/resources/icons/update.png"), tr("Check for &Updates..."), this);
    actions_.about = new QAction(QIcon(":/resources/icons/about.png"), tr("&About"), this);

    // Set shortcuts
    actions_.new_drive->setShortcut(QKeySequence::New);
    actions_.open_drive->setShortcut(QKeySequence::Open);
    actions_.close_drive->setShortcut(QKeySequence::Close);
    actions_.quit->setShortcut(QKeySequence::Quit);
    actions_.refresh->setShortcut(QKeySequence::Refresh);
    actions_.help->setShortcut(QKeySequence::HelpContents);
    actions_.mount->setShortcut(tr("Ctrl+M"));
    actions_.unmount->setShortcut(tr("Ctrl+U"));
    actions_.eject_drive->setShortcut(tr("Ctrl+E"));

    // Set checkable actions
    actions_.show_toolbar->setCheckable(true);
    actions_.show_toolbar->setChecked(true);
    actions_.show_statusbar->setCheckable(true);
    actions_.show_statusbar->setChecked(true);

    // Create menus
    QMenu* fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(actions_.new_drive);
    fileMenu->addAction(actions_.open_drive);
    fileMenu->addAction(actions_.close_drive);
    fileMenu->addAction(actions_.eject_drive);
    fileMenu->addSeparator();
    fileMenu->addAction(actions_.settings);
    fileMenu->addAction(actions_.import);
    fileMenu->addAction(actions_.export_);
    fileMenu->addSeparator();
    fileMenu->addAction(actions_.quit);

    QMenu* driveMenu = menuBar()->addMenu(tr("&Drive"));
    driveMenu->addAction(actions_.mount);
    driveMenu->addAction(actions_.unmount);
    driveMenu->addSeparator();
    driveMenu->addAction(actions_.change_password);
    driveMenu->addAction(actions_.manage_keys);

    QMenu* viewMenu = menuBar()->addMenu(tr("&View"));
    viewMenu->addAction(actions_.refresh);
    viewMenu->addSeparator();
    viewMenu->addAction(actions_.show_toolbar);
    viewMenu->addAction(actions_.show_statusbar);

    QMenu* helpMenu = menuBar()->addMenu(tr("&Help"));
    helpMenu->addAction(actions_.help);
    helpMenu->addAction(actions_.check_updates);
    helpMenu->addSeparator();
    helpMenu->addAction(actions_.about);

    // Connect signals
    connect(actions_.new_drive, &QAction::triggered, this, &MainWindow::onNewDrive);
    connect(actions_.open_drive, &QAction::triggered, this, &MainWindow::onOpenDrive);
    connect(actions_.close_drive, &QAction::triggered, this, &MainWindow::onCloseDrive);
    connect(actions_.eject_drive, &QAction::triggered, this, &MainWindow::onEjectDrive);
    connect(actions_.settings, &QAction::triggered, this, &MainWindow::onDriveSettings);
    connect(actions_.import, &QAction::triggered, this, &MainWindow::onImportDrive);
    connect(actions_.export_, &QAction::triggered, this, &MainWindow::onExportDrive);
    connect(actions_.quit, &QAction::triggered, this, &MainWindow::onQuit);

    connect(actions_.mount, &QAction::triggered, this, &MainWindow::onOpenDrive);
    connect(actions_.unmount, &QAction::triggered, this, &MainWindow::onCloseDrive);
    connect(actions_.change_password, &QAction::triggered, this, &MainWindow::onChangePassword);
    connect(actions_.manage_keys, &QAction::triggered, this, &MainWindow::onManageKeys);

    connect(actions_.refresh, &QAction::triggered, this, &MainWindow::onRefreshDrives);
    connect(actions_.show_toolbar, &QAction::triggered, this, &MainWindow::onToggleToolbar);
    connect(actions_.show_statusbar, &QAction::triggered, this, &MainWindow::onToggleStatusBar);

    connect(actions_.help, &QAction::triggered, this, &MainWindow::onHelp);
    connect(actions_.check_updates, &QAction::triggered, this, &MainWindow::onCheckUpdates);
    connect(actions_.about, &QAction::triggered, this, &MainWindow::onAbout);

    // Create and set up toolbar
    toolbar_ = new QToolBar(tr("Main Toolbar"), this);
    toolbar_->setMovable(false);
    toolbar_->setIconSize(QSize(24, 24));
    toolbar_->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    
    toolbar_->addAction(actions_.new_drive);
    toolbar_->addAction(actions_.open_drive);
    toolbar_->addAction(actions_.close_drive);
    toolbar_->addSeparator();
    toolbar_->addAction(actions_.refresh);
    
    addToolBar(toolbar_);
}

void MainWindow::setupTrayIcon() {
    tray_icon_ = std::make_unique<QSystemTrayIcon>(QIcon(":/resources/icons/drive.png"), this);
    tray_menu_ = std::make_unique<QMenu>(this);
    
    auto showHideAction = tray_menu_->addAction(tr("Show/Hide"));
    tray_menu_->addSeparator();
    tray_menu_->addAction(actions_.quit);
    
    connect(showHideAction, &QAction::triggered, this, &MainWindow::onShowHideWindow);
    
    tray_icon_->setContextMenu(tray_menu_.get());
    tray_icon_->setToolTip(tr("EncryptoDrive"));
    
    connect(tray_icon_.get(), &QSystemTrayIcon::activated,
            this, &MainWindow::onTrayIconActivated);
            
    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        tray_icon_->show();
    }
}

void MainWindow::setupDriveList() {
    drive_list_->setViewMode(0); // List view mode
    drive_list_->setShowMountedOnly(false);
    drive_list_->setShowEncryptedOnly(true);
    drive_list_->refresh();
}

void MainWindow::updateActions() {
    QString selected = getSelectedDrive();
    bool hasDrive = !selected.isEmpty();
    bool isMounted = hasDrive && drive_list_->getDriveInfo(selected).mounted;
    
    actions_.close_drive->setEnabled(hasDrive);
    actions_.eject_drive->setEnabled(hasDrive);
    actions_.settings->setEnabled(hasDrive);
    actions_.export_->setEnabled(hasDrive);
    actions_.change_password->setEnabled(hasDrive);
    actions_.manage_keys->setEnabled(hasDrive);
    
    actions_.mount->setEnabled(hasDrive && !isMounted);
    actions_.unmount->setEnabled(isMounted);
    ui_->unmountDriveButton->setEnabled(isMounted);
}

QString MainWindow::getSelectedDrive() const {
    return drive_list_->selectedDrive();
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (minimize_to_tray_ && !shutting_down_) {
        event->ignore();
        minimizeToTray();
    } else if (confirmClose()) {
        saveSettings();
        event->accept();
    } else {
        event->ignore();
    }
}

void MainWindow::changeEvent(QEvent* event) {
    if (event->type() == QEvent::WindowStateChange) {
        if (isMinimized() && minimize_to_tray_) {
            QTimer::singleShot(0, this, &MainWindow::hide);
        }
    }
    QMainWindow::changeEvent(event);
}

void MainWindow::onNewDrive() {
    QString path = QFileDialog::getSaveFileName(this,
        tr("Create New Drive"),
        QDir::homePath(),
        tr("Encrypted Drives (*.edrv);;All Files (*.*)"));
    
    if (path.isEmpty()) return;
    
    // TODO: Implement drive creation
}

void MainWindow::onOpenDrive() {
    QString path = QFileDialog::getOpenFileName(this,
        tr("Open Drive"),
        QDir::homePath(),
        tr("Encrypted Drives (*.edrv);;All Files (*.*)"));
    
    if (path.isEmpty()) return;
    mountDrive(path);
}

void MainWindow::onCloseDrive() {
    QString path = getSelectedDrive();
    if (path.isEmpty()) return;
    unmountDrive(path);
}

void MainWindow::onEjectDrive() {
    QString path = getSelectedDrive();
    if (path.isEmpty()) return;
    unmountDrive(path, true);
}

void MainWindow::onDriveSettings() {
    // TODO: Implement drive settings dialog
}

void MainWindow::onImportDrive() {
    // TODO: Implement drive import
}

void MainWindow::onExportDrive() {
    // TODO: Implement drive export
}

void MainWindow::onQuit() {
    shutting_down_ = true;
    close();
}

void MainWindow::onDriveStatusChanged(const QString& path, bool mounted) {
    refreshDriveList();
    updateActions();
    updateStatusBar();
    updateTrayIcon();
    
    if (show_notifications_) {
        QString status = mounted ? tr("mounted") : tr("unmounted");
        tray_icon_->showMessage(tr("Drive Status"),
            tr("Drive %1 was %2").arg(path).arg(status),
            QSystemTrayIcon::Information,
            3000);
    }
}

void MainWindow::onDriveError(const QString& path, const QString& error) {
    handleError(tr("Drive error on %1: %2").arg(path).arg(error));
}

void MainWindow::onDriveProgress(const QString& path, int progress) {
    Q_UNUSED(path);
    ui_->progressBar->setValue(progress);
    ui_->progressBar->setVisible(progress > 0 && progress < 100);
}

void MainWindow::onRefreshDrives() {
    refreshDriveList();
}

void MainWindow::onToggleToolbar(bool show) {
    if (toolbar_) {
        toolbar_->setVisible(show);
    }
}

void MainWindow::onToggleStatusBar(bool show) {
    statusBar()->setVisible(show);
}

void MainWindow::onViewMode(int mode) {
    drive_list_->setViewMode(mode);
}

void MainWindow::onPreferences() {
    // TODO: Implement preferences dialog
}

void MainWindow::onChangePassword() {
    // TODO: Implement change password dialog
}

void MainWindow::onManageKeys() {
    // TODO: Implement key management dialog
}

void MainWindow::onAbout() {
    QMessageBox::about(this, tr("About EncryptoDrive"),
        tr("EncryptoDrive - Secure encrypted drive manager\n\n"
           "Version: %1\n"
           "Build: %2\n\n"
           "Copyright © 2025").arg("0.1.0").arg("Debug"));
}

void MainWindow::onHelp() {
    // TODO: Open online help
}

void MainWindow::onCheckUpdates() {
    // TODO: Implement update checker
}

void MainWindow::onTrayIconActivated(QSystemTrayIcon::ActivationReason reason) {
    if (reason == QSystemTrayIcon::Trigger || 
        reason == QSystemTrayIcon::DoubleClick) {
        onShowHideWindow();
    }
}

void MainWindow::onShowHideWindow() {
    if (isVisible()) {
        hide();
    } else {
        show();
        raise();
        activateWindow();
    }
}

void MainWindow::minimizeToTray() {
    hide();
    if (show_notifications_) {
        tray_icon_->showMessage(tr("EncryptoDrive"),
            tr("Application minimized to tray"),
            QSystemTrayIcon::Information,
            3000);
    }
}

void MainWindow::restoreFromTray() {
    show();
    raise();
    activateWindow();
}

bool MainWindow::confirmClose() {
    if (!confirm_unmount_ || mounted_drives_.empty()) return true;
    
    return QMessageBox::question(this,
        tr("Confirm Close"),
        tr("There are mounted drives. Do you want to unmount them and quit?"),
        QMessageBox::Yes | QMessageBox::No) == QMessageBox::Yes;
}

void MainWindow::onDriveSelected(const QString& path) {
    updateActions();
    statusBar()->showMessage(path.isEmpty() ? tr("Ready") : path);
}

void MainWindow::onDriveDoubleClicked(const QString& path) {
    mountDrive(path);
}

void MainWindow::onDriveContextMenu(const QPoint& pos) {
    QMenu menu(this);
    QString path = getSelectedDrive();
    bool hasDrive = !path.isEmpty();
    bool mounted = hasDrive && drive_list_->getDriveInfo(path).mounted;
    
    QAction* mountAction = menu.addAction(tr("Mount"));
    QAction* unmountAction = menu.addAction(tr("Unmount"));
    QAction* ejectAction = menu.addAction(tr("Eject"));
    menu.addSeparator();
    QAction* settingsAction = menu.addAction(tr("Settings..."));
    
    mountAction->setEnabled(!mounted && hasDrive);
    unmountAction->setEnabled(mounted);
    ejectAction->setEnabled(hasDrive);
    settingsAction->setEnabled(hasDrive);
    
    mountAction->setIcon(actions_.mount->icon());
    unmountAction->setIcon(actions_.unmount->icon());
    ejectAction->setIcon(actions_.eject_drive->icon());
    settingsAction->setIcon(actions_.settings->icon());
    
    QAction* selectedAction = menu.exec(drive_list_->mapToGlobal(pos));
    if (!selectedAction) {
        return;
    }
    
    if (selectedAction == mountAction) {
        mountDrive(path);
    } else if (selectedAction == unmountAction) {
        unmountDrive(path);
    } else if (selectedAction == ejectAction) {
        unmountDrive(path, true);
    } else if (selectedAction == settingsAction) {
        onDriveSettings();
    }
}

void MainWindow::mountDrive(const QString& path, bool prompt) {
    // TODO: Implement mount logic
    Q_UNUSED(path);
    Q_UNUSED(prompt);
}

void MainWindow::unmountDrive(const QString& path, bool force) {
    // TODO: Implement unmount logic
    Q_UNUSED(path);
    Q_UNUSED(force);
}

void MainWindow::refreshDriveList() {
    drive_list_->refresh();
    updateActions();
}

void MainWindow::loadSettings() {
    QSettings settings;
    restoreGeometry(settings.value("MainWindow/geometry").toByteArray());
    QMainWindow::restoreState(settings.value("MainWindow/windowState").toByteArray());
    
    minimize_to_tray_ = settings.value("MainWindow/minimizeToTray", false).toBool();
    confirm_unmount_ = settings.value("MainWindow/confirmUnmount", true).toBool();
    auto_mount_ = settings.value("MainWindow/autoMount", false).toBool();
    show_notifications_ = settings.value("MainWindow/showNotifications", true).toBool();
    last_directory_ = settings.value("MainWindow/lastDirectory", QDir::homePath()).toString();
    
    bool showToolbar = settings.value("MainWindow/showToolbar", true).toBool();
    bool showStatusBar = settings.value("MainWindow/showStatusBar", true).toBool();
    
    actions_.show_toolbar->setChecked(showToolbar);
    actions_.show_statusbar->setChecked(showStatusBar);
    
    if (toolbar_) {
        toolbar_->setVisible(showToolbar);
    }
    if (statusBar()) {
        statusBar()->setVisible(showStatusBar);
    }
}

void MainWindow::saveSettings() {
    QSettings settings;
    settings.setValue("MainWindow/geometry", saveGeometry());
    settings.setValue("MainWindow/windowState", QMainWindow::saveState());
    settings.setValue("MainWindow/minimizeToTray", minimize_to_tray_);
    settings.setValue("MainWindow/confirmUnmount", confirm_unmount_);
    settings.setValue("MainWindow/autoMount", auto_mount_);
    settings.setValue("MainWindow/showNotifications", show_notifications_);
    settings.setValue("MainWindow/lastDirectory", last_directory_);
    settings.setValue("MainWindow/showToolbar", actions_.show_toolbar->isChecked());
    settings.setValue("MainWindow/showStatusBar", actions_.show_statusbar->isChecked());
}

void MainWindow::handleError(const QString& message, bool showDialog) {
    if (showDialog) {
        QMessageBox::critical(this, tr("Error"), message);
    }
    statusBar()->showMessage(message, 5000);
    logMessage(message);
}

void MainWindow::logMessage(const QString& message) {
    // TODO: Implement logging
    Q_UNUSED(message);
}

void MainWindow::updateWindowTitle() {
    QString title = tr("EncryptoDrive");
    QString path = getSelectedDrive();
    if (!path.isEmpty()) {
        title += QString(" - %1").arg(path);
    }
    setWindowTitle(title);
}

void MainWindow::updateStatusBar() {
    QString status = tr("Ready");
    QString path = getSelectedDrive();
    if (!path.isEmpty()) {
        const DriveList::DriveInfo& info = drive_list_->getDriveInfo(path);
        if (info.mounted) {
            status = tr("%1 (Mounted)").arg(path);
        } else {
            status = path;
        }
    }
    statusBar()->showMessage(status);
}

void MainWindow::updateTrayIcon() {
    int mounted = 0;
    for (const auto& drive : mounted_drives_) {
        if (drive && drive->isMounted()) {
            mounted++;
        }
    }
    
    QString tooltip = tr("EncryptoDrive - %n drive(s) mounted", "", mounted);
    tray_icon_->setToolTip(tooltip);
}

QString MainWindow::formatSize(qint64 size) const {
    constexpr qint64 KB = 1024;
    constexpr qint64 MB = KB * 1024;
    constexpr qint64 GB = MB * 1024;
    constexpr qint64 TB = GB * 1024;
    
    if (size >= TB) return QString("%1 TB").arg(size / TB);
    if (size >= GB) return QString("%1 GB").arg(size / GB);
    if (size >= MB) return QString("%1 MB").arg(size / MB);
    if (size >= KB) return QString("%1 KB").arg(size / KB);
    return QString("%1 B").arg(size);
}

} // namespace encrypto::gui
