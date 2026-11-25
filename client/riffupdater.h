/*
Riff - update check and in-place update
Copyright (C) 2026 UAJ-Studio

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#ifndef _RIFF_UPDATER_H
#define _RIFF_UPDATER_H

#include <QObject>
#include <QPointer>
#include <QUrl>

class QFile;
class QCryptographicHash;
class QNetworkAccessManager;
class QNetworkReply;

/*
 * Asks GitHub for the latest Riff release (only its version and file list -
 * nothing about the PC is sent), and on request downloads its setup,
 * checks the SHA-256 and runs it silently; the setup starts Riff again.
 */
class RiffUpdater : public QObject
{
    Q_OBJECT
public:
    explicit RiffUpdater(QObject *parent = nullptr);

    void check();
    void download();
    void cancelDownload();
    bool runInstaller(QString *error);

    QString latestVersion() const { return latest_; }
    QUrl notesUrl() const { return notesUrl_; }

    static bool isNewer(const QString &a, const QString &b);

signals:
    void checked(bool newer, QString latestVersion);
    void checkFailed(QString error);
    void progress(qint64 received, qint64 total);
    void downloaded();
    void downloadFailed(QString error);

private slots:
    void onCheckFinished();
    void onSumFinished();
    void onReadyRead();
    void onDownloadFinished();

private:
    void startSetupDownload();
    void failDownload(const QString &error);
    QNetworkReply* get(const QUrl &url);

    QNetworkAccessManager *net_;
    QPointer<QNetworkReply> reply_;
    QString latest_;
    QUrl notesUrl_;
    QUrl setupUrl_;
    QUrl sumUrl_;
    QString bodySum_;
    QString sum_;
    QString setupPath_;
    QFile *file_ = nullptr;
    QCryptographicHash *hash_ = nullptr;
};

#endif
