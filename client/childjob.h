/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff", derived from "Ostinato".

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#ifndef _CHILD_JOB_H
#define _CHILD_JOB_H

#include <QObject>
#include <QStringList>
#include <QUrl>

// Every process Riff starts (drone, wsl.exe, usbipd attach loops,
// riff-agent ...) runs in a Windows job object that is killed together with
// Riff - also when Riff is killed or crashes - so nothing is left holding
// the Wi-Fi dongles or the WSL distribution.
void setupChildJob();

// Starts a program that must outlive Riff (Wireshark, the web browser)
// outside that job.
bool startOutsideJob(const QString &program, const QStringList &args);

// Opens web links through startOutsideJob (registered as the URL handler
// for http/https/mailto by setupChildJob).
class UrlOpener : public QObject
{
    Q_OBJECT
public slots:
    void openUrl(const QUrl &url);
};

#endif
