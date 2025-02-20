#include "gui/windows/mainwindow.hpp"
#include <QApplication>
#include <QResource>
#include <QDir>
#include <QDirIterator>
#include <QDebug>
#include <QFile>

void dumpResourceTree(const QString& path = QLatin1String(":")) {
    qDebug() << "\nResource tree at" << path << ":";
    QDirIterator it(path, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        QString filePath = it.next();
        QFileInfo info(filePath);
        QFile file(filePath);
        qint64 size = file.exists() ? file.size() : -1;
        qDebug() << " -" << filePath 
                << "(exists:" << file.exists() 
                << "size:" << size << "bytes)";
    }
}

int main(int argc, char *argv[]) {
    qDebug() << "Starting application...";
    qDebug() << "Current directory:" << QDir::currentPath();

    QApplication app(argc, argv);

    // Initialize resources
    Q_INIT_RESOURCE(resources);

    qDebug() << "\nChecking resource paths:";
    qDebug() << "Application dir:" << QCoreApplication::applicationDirPath();
    qDebug() << "Library paths:" << QCoreApplication::libraryPaths();

    // Test loading a specific icon
    QString testIcon = QLatin1String(":/icons/new.png");
    QFile iconFile(testIcon);
    qDebug() << "\nTesting icon:" << testIcon;
    qDebug() << "File exists:" << iconFile.exists();
    if (iconFile.open(QIODevice::ReadOnly)) {
        qDebug() << "File size:" << iconFile.size() << "bytes";
        iconFile.close();
    }

    // Debug all available resources
    dumpResourceTree();

    // Create and show main window
    encrypto::gui::MainWindow window;
    window.show();

    return app.exec();
}
