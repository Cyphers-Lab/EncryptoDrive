#include <QApplication>
#include "gui/windows/mainwindow.hpp"
#include "core/encryptionengine.hpp"

int main(int argc, char* argv[]) {
    Q_UNUSED(argv);
    QApplication app(argc, argv);

    auto* window = new encrypto::gui::MainWindow();
    window->show();

    return app.exec();
}
