#include "installer_core.hpp"
#include "main_window.hpp"

#include <QApplication>
#include <QCoreApplication>

#include <cstdint>

#if defined(Q_OS_WIN)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <cstdio>

namespace {

void connectConsoleHandle(HANDLE handle, FILE *stream) {
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE) {
        return;
    }
    const int descriptor = _open_osfhandle(reinterpret_cast<std::intptr_t>(handle), _O_TEXT);
    if (descriptor < 0) {
        return;
    }
    _dup2(descriptor, _fileno(stream));
    _close(descriptor);
}

void prepareCliConsole() {
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE error = GetStdHandle(STD_ERROR_HANDLE);
    const auto valid = [](HANDLE handle) {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    };
    if ((!valid(output) || !valid(error)) && GetConsoleWindow() == nullptr) {
        AttachConsole(ATTACH_PARENT_PROCESS);
        output = GetStdHandle(STD_OUTPUT_HANDLE);
        error = GetStdHandle(STD_ERROR_HANDLE);
    }
    if (valid(output) && output == error) {
        connectConsoleHandle(output, stdout);
        _dup2(_fileno(stdout), _fileno(stderr));
        return;
    }
    connectConsoleHandle(output, stdout);
    connectConsoleHandle(error, stderr);
}

} // namespace
#endif

#ifndef VPNGATE_INSTALLER_VERSION
#define VPNGATE_INSTALLER_VERSION "0.1.0"
#endif

namespace {

void setApplicationMetadata() {
    QCoreApplication::setApplicationName(QStringLiteral("VPN Gate Connect Installer"));
    QCoreApplication::setApplicationVersion(QStringLiteral(VPNGATE_INSTALLER_VERSION));
    QCoreApplication::setOrganizationName(QStringLiteral("VPN Gate Connect"));
}

} // namespace

int main(int argc, char **argv) {
    if (argc > 1) {
#if defined(Q_OS_WIN)
        prepareCliConsole();
#endif
        QCoreApplication app(argc, argv);
        setApplicationMetadata();
        return vpngate::installer::runCli(app.arguments().mid(1));
    }

    QApplication app(argc, argv);
    setApplicationMetadata();
    vpngate::installer::MainWindow window;
    window.show();
    return app.exec();
}
