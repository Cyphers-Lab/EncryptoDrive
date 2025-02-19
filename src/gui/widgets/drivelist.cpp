#include "drivelist.hpp"
#include <QContextMenuEvent>
#include <QMenu>
#include <QHeaderView>
#include <QFileIconProvider>
#include <QLocale>

namespace encrypto::gui {

DriveList::DriveList(QWidget* parent)
    : QTreeView(parent)
    , model_(std::make_unique<QStandardItemModel>())
    , show_encrypted_only_(false)
    , show_mounted_only_(false)
    , view_mode_(0) {
    setupModel();
    setupView();
    setupDelegate();
    setupContextMenu();
}

DriveList::~DriveList() = default;

void DriveList::setupModel() {
    QStringList headers;
    headers << tr("Name") << tr("Status") << tr("Size") << tr("Type") << tr("Last Mounted");
    model_->setHorizontalHeaderLabels(headers);
    setModel(model_.get());
}

void DriveList::setupView() {
    setSelectionMode(QAbstractItemView::SingleSelection);
    setSelectionBehavior(QAbstractItemView::SelectRows);
    setAlternatingRowColors(true);
    setRootIsDecorated(false);
    setSortingEnabled(true);
    setUniformRowHeights(true);
    
    header()->setStretchLastSection(false);
    header()->setSectionResizeMode(Name, QHeaderView::Stretch);
    header()->setSectionResizeMode(Status, QHeaderView::Fixed);
    header()->setSectionResizeMode(Size, QHeaderView::Fixed);
    header()->setSectionResizeMode(Type, QHeaderView::Fixed);
    header()->setSectionResizeMode(LastMounted, QHeaderView::Fixed);
    
    header()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
}

void DriveList::setupDelegate() {
    // TODO: Implement custom item delegate if needed
}

void DriveList::setupContextMenu() {
    setContextMenuPolicy(Qt::CustomContextMenu);
    connect(this, &QWidget::customContextMenuRequested,
            this, &DriveList::driveContextMenu);
}

void DriveList::addDrive(const DriveInfo& info) {
    if (!matchesFilters(info)) return;
    
    if (QStandardItem* existing = findDriveItem(info.path)) {
        updateDriveRow(existing, info);
    } else {
        model_->appendRow(createDriveRow(info));
    }
    
    drives_.push_back(info);
}

void DriveList::removeDrive(const QString& path) {
    if (QStandardItem* item = findDriveItem(path)) {
        model_->removeRow(item->row());
    }
    
    auto it = std::remove_if(drives_.begin(), drives_.end(),
        [&path](const DriveInfo& info) { return info.path == path; });
    drives_.erase(it, drives_.end());
}

void DriveList::updateDrive(const QString& path, const DriveInfo& info) {
    if (QStandardItem* item = findDriveItem(path)) {
        updateDriveRow(item, info);
    }
    
    auto it = std::find_if(drives_.begin(), drives_.end(),
        [&path](const DriveInfo& info) { return info.path == path; });
    if (it != drives_.end()) {
        *it = info;
    }
}

void DriveList::clear() {
    model_->removeRows(0, model_->rowCount());
    drives_.clear();
}

QString DriveList::selectedDrive() const {
    QModelIndexList selection = selectedIndexes();
    if (selection.isEmpty()) return QString();
    return model_->data(model_->index(selection.first().row(), 0), Qt::UserRole).toString();
}

QStringList DriveList::selectedDrives() const {
    QStringList result;
    QModelIndexList selection = selectedIndexes();
    for (const QModelIndex& index : selection) {
        if (index.column() == 0) {
            result << model_->data(index, Qt::UserRole).toString();
        }
    }
    return result;
}

DriveList::DriveInfo DriveList::getDriveInfo(const QString& path) const {
    auto it = std::find_if(drives_.begin(), drives_.end(),
        [&path](const DriveInfo& info) { return info.path == path; });
    return it != drives_.end() ? *it : DriveInfo();
}

void DriveList::setShowEncryptedOnly(bool show) {
    if (show_encrypted_only_ == show) return;
    show_encrypted_only_ = show;
    applyFilters();
}

void DriveList::setShowMountedOnly(bool show) {
    if (show_mounted_only_ == show) return;
    show_mounted_only_ = show;
    applyFilters();
}

void DriveList::setSortColumn(Column column, Qt::SortOrder order) {
    sortByColumn(column, order);
}

void DriveList::setStatusFilter(const QString& status) {
    if (status_filter_ == status) return;
    status_filter_ = status;
    applyFilters();
}

void DriveList::refresh() {
    // Re-apply filters and update all rows
    applyFilters();
}

void DriveList::sort() {
    model_->sort(header()->sortIndicatorSection(), header()->sortIndicatorOrder());
}

void DriveList::setViewMode(int mode) {
    view_mode_ = mode;
    // TODO: Implement different view modes
}

void DriveList::setIconSize(const QSize& size) {
    QTreeView::setIconSize(size);
}

void DriveList::setShowHidden(bool show) {
    setHidden(!show);
}

void DriveList::mousePressEvent(QMouseEvent* event) {
    QTreeView::mousePressEvent(event);
    
    if (event->button() == Qt::LeftButton) {
        QString path = selectedDrive();
        if (!path.isEmpty()) {
            emit driveSelected(path);
        }
    }
}

void DriveList::mouseDoubleClickEvent(QMouseEvent* event) {
    QTreeView::mouseDoubleClickEvent(event);
    
    if (event->button() == Qt::LeftButton) {
        QString path = selectedDrive();
        if (!path.isEmpty()) {
            emit driveDoubleClicked(path);
        }
    }
}

void DriveList::contextMenuEvent(QContextMenuEvent* event) {
    emit driveContextMenu(event->globalPos());
}

void DriveList::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void DriveList::dragMoveEvent(QDragMoveEvent* event) {
    event->acceptProposedAction();
}

void DriveList::dropEvent(QDropEvent* event) {
    event->acceptProposedAction();
    // TODO: Handle dropped files
}

QStandardItem* DriveList::findDriveItem(const QString& path) const {
    for (int row = 0; row < model_->rowCount(); ++row) {
        QStandardItem* item = model_->item(row, 0);
        if (item && item->data(Qt::UserRole).toString() == path) {
            return item;
        }
    }
    return nullptr;
}

QList<QStandardItem*> DriveList::createDriveRow(const DriveInfo& info) const {
    QList<QStandardItem*> row;
    
    auto* nameItem = new QStandardItem(getDriveIcon(info), info.label);
    nameItem->setData(info.path, Qt::UserRole);
    
    auto* statusItem = new QStandardItem(formatStatus(info.mounted, info.encrypted));
    auto* sizeItem = new QStandardItem(formatSize(info.total_space));
    auto* typeItem = new QStandardItem(info.type);
    auto* dateItem = new QStandardItem(formatDate(info.last_mounted));
    
    row << nameItem << statusItem << sizeItem << typeItem << dateItem;
    return row;
}

void DriveList::updateDriveRow(QStandardItem* item, const DriveInfo& info) {
    QStandardItem* nameItem = model_->item(item->row(), Name);
    QStandardItem* statusItem = model_->item(item->row(), Status);
    QStandardItem* sizeItem = model_->item(item->row(), Size);
    QStandardItem* typeItem = model_->item(item->row(), Type);
    QStandardItem* dateItem = model_->item(item->row(), LastMounted);
    
    nameItem->setText(info.label);
    nameItem->setIcon(getDriveIcon(info));
    statusItem->setText(formatStatus(info.mounted, info.encrypted));
    sizeItem->setText(formatSize(info.total_space));
    typeItem->setText(info.type);
    dateItem->setText(formatDate(info.last_mounted));
}

QString DriveList::formatSize(qint64 size) const {
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

QString DriveList::formatDate(const QDateTime& date) const {
    if (!date.isValid()) return tr("Never");
    return QLocale::system().toString(date, QLocale::ShortFormat);
}

QString DriveList::formatStatus(bool mounted, bool encrypted) const {
    if (encrypted) {
        return mounted ? tr("Mounted (Encrypted)") : tr("Not Mounted (Encrypted)");
    }
    return mounted ? tr("Mounted") : tr("Not Mounted");
}

QIcon DriveList::getDriveIcon(const DriveInfo& info) const {
    static QFileIconProvider iconProvider;
    if (info.mounted) {
        return QIcon(":/icons/drive-on.png");
    }
    return QIcon(":/icons/drive-off.png");
}

bool DriveList::matchesFilters(const DriveInfo& info) const {
    if (show_encrypted_only_ && !info.encrypted) return false;
    if (show_mounted_only_ && !info.mounted) return false;
    if (!status_filter_.isEmpty()) {
        QString status = formatStatus(info.mounted, info.encrypted);
        if (!status.contains(status_filter_, Qt::CaseInsensitive)) return false;
    }
    return true;
}

void DriveList::applyFilters() {
    clear();
    for (const DriveInfo& info : drives_) {
        if (matchesFilters(info)) {
            model_->appendRow(createDriveRow(info));
        }
    }
    sort();
}

} // namespace encrypto::gui
