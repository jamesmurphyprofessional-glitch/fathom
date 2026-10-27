#include "main_window.hpp"

#include "theme.hpp"

#include <QApplication>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("Fathom"));
    QApplication::setOrganizationName(QStringLiteral("Fathom"));
    app.setStyleSheet(QString::fromUtf8(fathom::theme::kStyle));
    fathom::MainWindow window;
    window.resize(1440, 900);
    window.show();
    if (argc > 1) {
        window.open_path(QString::fromLocal8Bit(argv[1]));
    }
    return app.exec();
}
