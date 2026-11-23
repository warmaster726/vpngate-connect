#include "installer_core.hpp"
#include "host_integration.hpp"
#include "main_window.hpp"

#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QStandardPaths>
#include <QStringList>

#include <algorithm>
#include <cstdint>
#include <iterator>

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#endif

#if defined(Q_OS_WIN)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
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

QString quoteWindowsArgument(QString value) {
    QString quoted = QStringLiteral("\"");
    int backslashes = 0;
    for (const QChar ch : value) {
        if (ch == QLatin1Char('\\')) {
            ++backslashes;
        } else if (ch == QLatin1Char('"')) {
            quoted.append(QString(2 * backslashes + 1, QLatin1Char('\\')));
            quoted.append(ch);
            backslashes = 0;
        } else {
            quoted.append(QString(backslashes, QLatin1Char('\\')));
            quoted.append(ch);
            backslashes = 0;
        }
    }
    quoted.append(QString(2 * backslashes, QLatin1Char('\\')));
    quoted.append(QLatin1Char('"'));
    return quoted;
}

bool hasArgument(const QStringList &arguments, const QString &flag) {
    return std::any_of(arguments.cbegin(), arguments.cend(), [&](const QString &argument) {
        return argument.compare(flag, Qt::CaseInsensitive) == 0;
    });
}

bool shouldReexecuteWithUac(const QStringList &applicationArguments) {
    if (applicationArguments.size() < 2 || vpngate::installer::windowsAdministratorAvailable()) {
        return false;
    }
    const QString action = applicationArguments.at(1).toLower();
    const bool mutating = action == QStringLiteral("install") || action == QStringLiteral("uninstall")
        || action == QStringLiteral("--uninstall") || action == QStringLiteral("-u")
        || action == QStringLiteral("--remove") || action == QStringLiteral("-uninstall");
    if (!mutating) {
        return false;
    }
    const QStringList arguments = applicationArguments.mid(2);
    const bool userOnly = hasArgument(arguments, QStringLiteral("--user-only"));
    const bool dryRun = hasArgument(arguments, QStringLiteral("--dry-run"));
    const bool authorized = hasArgument(arguments, QStringLiteral("--yes"))
        || hasArgument(arguments, QStringLiteral("-y"));
    const bool elevatedChild = hasArgument(arguments, QStringLiteral("--elevated-child"));
    return !userOnly && !dryRun && authorized && !elevatedChild;
}

int reexecuteWithUac(const QStringList &applicationArguments) {
    QStringList arguments = applicationArguments.mid(1);
    if (!hasArgument(arguments, QStringLiteral("--prefix"))) {
        arguments.append(QStringLiteral("--prefix"));
        arguments.append(vpngate::installer::systemInstallPrefix());
    }
    if (!hasArgument(arguments, QStringLiteral("--target-home"))) {
        const QString home = qEnvironmentVariable("USERPROFILE");
        if (!home.isEmpty()) {
            arguments.append(QStringLiteral("--target-home"));
            arguments.append(home);
        }
    }
    if (!hasArgument(arguments, QStringLiteral("--cache-dir"))) {
        QString localAppData = qEnvironmentVariable("LOCALAPPDATA");
        const QString userProfile = qEnvironmentVariable("USERPROFILE");
        if (localAppData.isEmpty() && !userProfile.isEmpty()) {
            localAppData = QDir(userProfile).filePath(QStringLiteral("AppData/Local"));
        }
        if (!localAppData.isEmpty()) {
            arguments.append(QStringLiteral("--cache-dir"));
            arguments.append(QDir(localAppData).filePath(QStringLiteral("vpngate")));
        }
    }
    arguments.append(QStringLiteral("--elevated-child"));
    QStringList quotedArguments;
    for (const QString &argument : arguments) {
        quotedArguments.append(quoteWindowsArgument(argument));
    }
    const QString parameters = quotedArguments.join(QLatin1Char(' '));
    wchar_t executable[32768]{};
    const DWORD executableLength = GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable)));
    if (executableLength == 0 || executableLength >= std::size(executable)) {
        std::fprintf(stderr, "[-] Could not resolve the installer executable for UAC elevation.\n");
        return 1;
    }
    wchar_t workingDirectory[32768]{};
    const DWORD directoryLength = GetCurrentDirectoryW(static_cast<DWORD>(std::size(workingDirectory)), workingDirectory);
    if (directoryLength == 0 || directoryLength >= std::size(workingDirectory)) {
        workingDirectory[0] = L'\0';
    }
    SHELLEXECUTEINFOW launch{};
    launch.cbSize = sizeof(launch);
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = L"runas";
    launch.lpFile = executable;
    launch.lpParameters = reinterpret_cast<LPCWSTR>(parameters.utf16());
    launch.lpDirectory = workingDirectory[0] ? workingDirectory : nullptr;
    launch.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&launch)) {
        const DWORD code = GetLastError();
        std::fprintf(stderr, code == ERROR_CANCELLED
            ? "[-] Windows UAC elevation was cancelled.\n"
            : "[-] Could not start the elevated installer (Windows error %lu).\n", code);
        return 1;
    }
    DWORD exitCode = 1;
    if (launch.hProcess) {
        WaitForSingleObject(launch.hProcess, INFINITE);
        GetExitCodeProcess(launch.hProcess, &exitCode);
        CloseHandle(launch.hProcess);
    }
    return static_cast<int>(exitCode);
}

} // namespace
#endif

#ifndef VPNGATE_INSTALLER_VERSION
#define VPNGATE_INSTALLER_VERSION "0.1.0"
#endif

namespace {

#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
bool shouldReexecuteWithSudo(int argc, char **argv) {
    if (argc < 2 || ::geteuid() == 0) {
        return false;
    }
    const QString action = QString::fromLocal8Bit(argv[1]).toLower();
    const bool mutating = action == QStringLiteral("install") || action == QStringLiteral("uninstall")
        || action == QStringLiteral("--uninstall") || action == QStringLiteral("-u")
        || action == QStringLiteral("--remove") || action == QStringLiteral("-uninstall");
    if (!mutating) {
        return false;
    }
    bool userOnly = false;
    bool dryRun = false;
    bool authorized = false;
    for (int i = 2; i < argc; ++i) {
        const QString argument = QString::fromLocal8Bit(argv[i]).toLower();
        userOnly = userOnly || argument == QStringLiteral("--user-only");
        dryRun = dryRun || argument == QStringLiteral("--dry-run");
        authorized = authorized || argument == QStringLiteral("--yes") || argument == QStringLiteral("-y");
    }
    return !userOnly && !dryRun && authorized;
}

int reexecuteWithSudo(int argc, char **argv) {
    const QString executablePath = QStandardPaths::findExecutable(QString::fromLocal8Bit(argv[0]));
    if (executablePath.isEmpty()) {
        std::fprintf(stderr, "[-] Could not resolve the installer executable for sudo re-execution.\n");
        return 127;
    }
    const QByteArray executable = executablePath.toLocal8Bit();
    std::vector<char *> childArguments;
    childArguments.reserve(static_cast<std::size_t>(argc) + 3);
    childArguments.push_back(const_cast<char *>("sudo"));
    childArguments.push_back(const_cast<char *>("--"));
    childArguments.push_back(const_cast<char *>(executable.constData()));
    for (int i = 1; i < argc; ++i) {
        childArguments.push_back(argv[i]);
    }
    childArguments.push_back(nullptr);
    ::execvp("sudo", childArguments.data());
    std::fprintf(stderr, "[-] Could not start sudo: %s\n", std::strerror(errno));
    return 127;
}
#endif

void setApplicationMetadata() {
    QCoreApplication::setApplicationName(QStringLiteral("VPN Gate Connect Installer"));
    QCoreApplication::setApplicationVersion(QStringLiteral(VPNGATE_INSTALLER_VERSION));
    QCoreApplication::setOrganizationName(QStringLiteral("VPN Gate Connect"));
}

} // namespace

int main(int argc, char **argv) {
#if defined(Q_OS_WIN)
    if (argc > 1) {
        prepareCliConsole();
    }
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    if (shouldReexecuteWithSudo(argc, argv)) {
        return reexecuteWithSudo(argc, argv);
    }
#endif
    if (argc > 1) {
        QCoreApplication app(argc, argv);
        setApplicationMetadata();
#if defined(Q_OS_WIN)
        if (shouldReexecuteWithUac(app.arguments())) {
            return reexecuteWithUac(app.arguments());
        }
#endif
        return vpngate::installer::runCli(app.arguments().mid(1));
    }

    QApplication app(argc, argv);
    setApplicationMetadata();
    vpngate::installer::MainWindow window;
    window.show();
    return app.exec();
}
