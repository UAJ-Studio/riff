/*
Riff - update check and in-place update
Copyright (C) 2026 UAJ-Studio

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

#include "riffupdater.h"
#include "childjob.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QStandardPaths>

extern const char* version;

static const char *kLatestApi =
    "https://api.github.com/repos/UAJ-Studio/riff/releases/latest";
static const char *kDownloadPrefix =
    "https://github.com/UAJ-Studio/riff/releases/download/";
static const qint64 kMaxSetupSize = 512LL * 1024 * 1024;

// GitHub itself and the hosts it redirects release downloads to
static bool allowedUrl(const QUrl &url)
{
    if (url.scheme() != "https")
        return false;
    const QString host = url.host().toLower();
    return host == "github.com" || host == "api.github.com"
        || host == "objects.githubusercontent.com"
        || host == "release-assets.githubusercontent.com"
        || host == "github-releases.githubusercontent.com";
}

RiffUpdater::RiffUpdater(QObject *parent)
    : QObject(parent), net_(new QNetworkAccessManager(this))
{
}

bool RiffUpdater::isNewer(const QString &a, const QString &b)
{
    const QStringList x = a.split('.'), y = b.split('.');
    for (int i = 0; i < qMax(x.size(), y.size()); i++) {
        const int p = i < x.size() ? x.at(i).toInt() : 0;
        const int q = i < y.size() ? y.at(i).toInt() : 0;
        if (p != q)
            return p > q;
    }
    return false;
}

QNetworkReply* RiffUpdater::get(const QUrl &url)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader,
                  QString("Riff/%1").arg(version));
    req.setRawHeader("Accept", url.host() == "api.github.com"
                     ? "application/vnd.github+json" : "*/*");
    req.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                     QNetworkRequest::UserVerifiedRedirectPolicy);
    QNetworkReply *reply = net_->get(req);
    connect(reply, &QNetworkReply::redirected, reply, [reply](const QUrl &to) {
        if (allowedUrl(to))
            emit reply->redirectAllowed();
        else
            reply->abort();
    });
    return reply;
}

void RiffUpdater::check()
{
    if (reply_)
        return;
    reply_ = get(QUrl(kLatestApi));
    connect(reply_, &QNetworkReply::finished,
            this, &RiffUpdater::onCheckFinished);
}

void RiffUpdater::onCheckFinished()
{
    QNetworkReply *reply = reply_;
    reply_ = nullptr;
    reply->deleteLater();
    if (reply->error() != QNetworkReply::NoError) {
        emit checkFailed(reply->errorString());
        return;
    }

    const QJsonObject rel = QJsonDocument::fromJson(reply->readAll()).object();
    const QString tag = rel.value("tag_name").toString();
    if (!tag.startsWith("riff-") || rel.value("draft").toBool()
            || rel.value("prerelease").toBool()) {
        emit checkFailed(tr("no Riff release found"));
        return;
    }
    const QString ver = tag.mid(5);
    const QString setupName = QString("Riff-%1-setup.exe").arg(ver);
    const QString prefix = QString(kDownloadPrefix) + tag + "/";

    setupUrl_.clear();
    sumUrl_.clear();
    const QJsonArray assets = rel.value("assets").toArray();
    for (const QJsonValue &v : assets) {
        const QJsonObject a = v.toObject();
        const QString name = a.value("name").toString();
        const QUrl url(a.value("browser_download_url").toString());
        if (!url.toString().startsWith(prefix))
            continue;
        if (name == setupName)
            setupUrl_ = url;
        else if (name == setupName + ".sha256")
            sumUrl_ = url;
    }
    // the release notes carry the SHA-256 too (older releases have no
    // .sha256 file)
    QRegularExpression re("SHA-256:\\s*`([0-9a-fA-F]{64})`");
    bodySum_ = re.match(rel.value("body").toString()).captured(1).toLower();

    latest_ = ver;
    notesUrl_ = QUrl(rel.value("html_url").toString());
    if (!notesUrl_.toString().startsWith("https://github.com/UAJ-Studio/riff/"))
        notesUrl_ = QUrl("https://github.com/UAJ-Studio/riff/releases/latest");
    emit checked(isNewer(ver, version) && setupUrl_.isValid(), ver);
}

void RiffUpdater::download()
{
    if (reply_ || !setupUrl_.isValid())
        return;
    sum_.clear();
    if (sumUrl_.isValid()) {
        reply_ = get(sumUrl_);
        connect(reply_, &QNetworkReply::finished,
                this, &RiffUpdater::onSumFinished);
    }
    else {
        sum_ = bodySum_;
        startSetupDownload();
    }
}

void RiffUpdater::onSumFinished()
{
    QNetworkReply *reply = reply_;
    reply_ = nullptr;
    reply->deleteLater();
    if (reply->error() == QNetworkReply::OperationCanceledError)
        return;
    if (reply->error() == QNetworkReply::NoError)
        sum_ = QString::fromLatin1(reply->read(200)).section(' ', 0, 0)
                   .trimmed().toLower();
    if (sum_.isEmpty())
        sum_ = bodySum_;
    startSetupDownload();
}

void RiffUpdater::startSetupDownload()
{
    if (!QRegularExpression("^[0-9a-f]{64}$").match(sum_).hasMatch()) {
        failDownload(tr("the release has no checksum"));
        return;
    }
    QDir dir(QStandardPaths::writableLocation(QStandardPaths::TempLocation)
             + "/Riff-update");
    dir.removeRecursively();
    if (!dir.mkpath(".")) {
        failDownload(tr("cannot create %1").arg(dir.path()));
        return;
    }
    setupPath_ = dir.filePath(QString("Riff-%1-setup.exe").arg(latest_));
    file_ = new QFile(setupPath_, this);
    if (!file_->open(QIODevice::WriteOnly)) {
        failDownload(tr("cannot write %1").arg(setupPath_));
        return;
    }
    hash_ = new QCryptographicHash(QCryptographicHash::Sha256);

    reply_ = get(setupUrl_);
    connect(reply_, &QNetworkReply::readyRead, this, &RiffUpdater::onReadyRead);
    connect(reply_, &QNetworkReply::downloadProgress,
            this, &RiffUpdater::progress);
    connect(reply_, &QNetworkReply::finished,
            this, &RiffUpdater::onDownloadFinished);
}

void RiffUpdater::onReadyRead()
{
    if (!reply_ || !file_)
        return;
    const QByteArray data = reply_->readAll();
    if (file_->size() + data.size() > kMaxSetupSize) {
        reply_->abort();
        return;
    }
    hash_->addData(data);
    if (file_->write(data) != data.size())
        reply_->abort();
}

void RiffUpdater::onDownloadFinished()
{
    QNetworkReply *reply = reply_;
    reply_ = nullptr;
    reply->deleteLater();
    if (reply->error() == QNetworkReply::NoError) {
        const QByteArray rest = reply->readAll();
        hash_->addData(rest);
        file_->write(rest);
    }
    const bool ok = reply->error() == QNetworkReply::NoError
                    && file_->error() == QFileDevice::NoError;
    const QString err = reply->errorString();
    file_->close();
    const QString got = QString::fromLatin1(hash_->result().toHex());
    delete hash_;
    hash_ = nullptr;
    file_->deleteLater();
    file_ = nullptr;

    if (!ok) {
        failDownload(reply->error() == QNetworkReply::OperationCanceledError
                     ? QString() : err);
        return;
    }
    if (got != sum_) {
        failDownload(tr("the downloaded file is damaged (checksum mismatch)"));
        return;
    }
    emit downloaded();
}

void RiffUpdater::cancelDownload()
{
    if (reply_)
        reply_->abort();
}

void RiffUpdater::failDownload(const QString &error)
{
    if (file_) {
        file_->close();
        file_->deleteLater();
        file_ = nullptr;
    }
    delete hash_;
    hash_ = nullptr;
    if (!setupPath_.isEmpty())
        QFile::remove(setupPath_);
    emit downloadFailed(error);
}

bool RiffUpdater::runInstaller(QString *error)
{
    // /SILENT shows only the progress; /RIFFUPDATE makes the setup leave
    // usbipd-win alone and start Riff again when it is done
    // (its log stays next to it, for when an update goes wrong)
    const QString log = QDir::toNativeSeparators(
            QFileInfo(setupPath_).path() + "/setup.log");
    const QStringList args = {"/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
                              "/CLOSEAPPLICATIONS", "/RIFFUPDATE",
                              "/LOG=" + log};
    // outside Riff's job, which would end the setup together with Riff
    if (startOutsideJob(setupPath_, args))
        return true;
    if (error)
        *error = tr("cannot start %1").arg(setupPath_);
    return false;
}
