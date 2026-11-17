/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff", derived from "Ostinato".

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#include "childjob.h"

#include <QDesktopServices>
#include <QDir>
#include <QProcess>

#ifdef Q_OS_WIN32
#include <windows.h>
#endif

void setupChildJob()
{
#ifdef Q_OS_WIN32
    // the handle is never closed: Windows closes it when Riff ends, which
    // kills every process still in the job
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (!job)
        return;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION info;
    memset(&info, 0, sizeof(info));
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                                          | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &info, sizeof(info))
            || !AssignProcessToJobObject(job, GetCurrentProcess())) {
        CloseHandle(job);
        return;
    }
    static UrlOpener opener;
    QDesktopServices::setUrlHandler("http", &opener, "openUrl");
    QDesktopServices::setUrlHandler("https", &opener, "openUrl");
    QDesktopServices::setUrlHandler("mailto", &opener, "openUrl");
#endif
}

#ifdef Q_OS_WIN32
static QString quoteArg(const QString &a)
{
    if (!a.isEmpty() && !a.contains(QRegExp("[\\s\"]")))
        return a;
    QString r = "\"";
    int bs = 0;
    for (QChar c : a) {
        if (c == '\\') {
            bs++;
            continue;
        }
        if (c == '"')
            r += QString(bs * 2 + 1, '\\');
        else
            r += QString(bs, '\\');
        bs = 0;
        r += c;
    }
    return r + QString(bs * 2, '\\') + "\"";
}
#endif

bool startOutsideJob(const QString &program, const QStringList &args)
{
#ifdef Q_OS_WIN32
    QString cmd = quoteArg(QDir::toNativeSeparators(program));
    foreach (const QString &a, args)
        cmd += " " + quoteArg(a);
    std::wstring wcmd = cmd.toStdWString();
    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    for (DWORD extra : {DWORD(CREATE_BREAKAWAY_FROM_JOB), DWORD(0)}) {
        // without a job (setupChildJob failed) breakaway is refused
        if (CreateProcessW(NULL, &wcmd[0], NULL, NULL, FALSE,
                           CREATE_UNICODE_ENVIRONMENT | extra, NULL, NULL,
                           &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return true;
        }
    }
    return false;
#else
    return QProcess::startDetached(program, args);
#endif
}

void UrlOpener::openUrl(const QUrl &url)
{
#ifdef Q_OS_WIN32
    // rundll32 hands the link to the default browser, outside Riff's job
    startOutsideJob("rundll32.exe", {"url.dll,FileProtocolHandler",
                                     url.toString(QUrl::FullyEncoded)});
#else
    Q_UNUSED(url);
#endif
}
