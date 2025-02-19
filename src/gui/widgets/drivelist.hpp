#pragma once

#include <QTreeView>
#include <QWidget>
#include <QHeaderView>
#include <QStandardItemModel>
#include <QMouseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QIcon>
#include <QStringList>
#include <QDateTime>
#include <QSize>
#include <QPoint>
#include <QMimeData>
#include <QFileInfo>
#include <memory>
#include <vector>
#include <string>

namespace encrypto::gui {

class DriveList : public QTreeView {
    Q_OBJECT

public:
    // Drive information
    struct DriveInfo {
        QString path;              // Mount point path
        QString label;            // Volume label
        QString type;             // Filesystem type
        bool mounted;            // Whether drive is mounted
        bool encrypted;          // Whether drive is encrypted
        qint64 total_space;     // Total space in bytes
        qint64 free_space;      // Free space in bytes
        QStringList users;       // Users with access
        QString owner;           // Drive owner
        QDateTime last_mounted;  // Last mount time
    };

    // Column definitions
    enum Column {
        Name,
        Status,
        Size,
        Type,
        LastMounted,
        ColumnCount
    };

    // Constructor and destructor
    explicit DriveList(QWidget* parent = nullptr);
    ~DriveList();

    // Drive management
    void addDrive(const DriveInfo& info);
    void removeDrive(const QString& path);
    void updateDrive(const QString& path, const DriveInfo& info);
    void clear();

    // Selection
    QString selectedDrive() const;
    QString currentDrive() const { return selectedDrive(); }
    QStringList selectedDrives() const;
    DriveInfo getDriveInfo(const QString& path) const;

    // View options
    void setShowEncryptedOnly(bool show);
    void setShowMountedOnly(bool show);
    void setSortColumn(Column column, Qt::SortOrder order = Qt::AscendingOrder);
    void setStatusFilter(const QString& status);

public slots:
    // UI updates
    void refresh();
    void sort();

    // View options
    void setViewMode(int mode);
    void setIconSize(const QSize& size);
    void setShowHidden(bool show);

signals:
    // Selection signals
    void driveSelected(const QString& path);
    void driveDoubleClicked(const QString& path);
    void driveContextMenu(const QPoint& pos);

    // Status signals
    void driveStatusChanged(const QString& path, bool mounted);
    void driveError(const QString& path, const QString& error);
    void driveProgress(const QString& path, int progress);

protected:
    // Qt overrides
    void mousePressEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void contextMenuEvent(QContextMenuEvent* event) override;
    void dragEnterEvent(QDragEnterEvent* event) override;
    void dragMoveEvent(QDragMoveEvent* event) override;
    void dropEvent(QDropEvent* event) override;

private:
    // UI setup
    void setupModel();
    void setupView();
    void setupDelegate();
    void setupContextMenu();

    // Model helpers
    QStandardItem* findDriveItem(const QString& path) const;
    QList<QStandardItem*> createDriveRow(const DriveInfo& info) const;
    void updateDriveRow(QStandardItem* item, const DriveInfo& info);

    // Data formatting
    QString formatSize(qint64 size) const;
    QString formatDate(const QDateTime& date) const;
    QString formatStatus(bool mounted, bool encrypted) const;
    QIcon getDriveIcon(const DriveInfo& info) const;

    // Filtering
    bool matchesFilters(const DriveInfo& info) const;
    void applyFilters();

private:
    std::unique_ptr<QStandardItemModel> model_;
    std::vector<DriveInfo> drives_;

    // View options
    bool show_encrypted_only_;
    bool show_mounted_only_;
    QString status_filter_;
    int view_mode_;
};

} // namespace encrypto::gui
