/*
Copyright (C) 2021 Srivats P.
Copyright (C) 2026 Riff contributors

This file is part of "Riff", derived from "Ostinato"

This is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
*/

#include "thememanager.h"

#include "settings.h"

#include <QApplication>
#include <QDir>
#include <QFile>
#include <QMap>
#include <QResource>
#include <QStyle>
#include <QStyleFactory>

ThemeManager *ThemeManager::instance_{nullptr};

namespace {

struct RiffColors {
    const char *window, *base, *alt, *header, *text, *mutedText, *border,
               *grid, *hover, *accent, *accentStrong, *accentSoft,
               *accentText, *scroll, *tooltip, *indicatorBorder;
};

const RiffColors kLight = {
    "#F3F5F8", "#FFFFFF", "#F7F9FB", "#EBEFF4", "#1D2733", "#6B7785",
    "#D3DAE3", "#E6EBF1", "#E3F1F0", "#0F8B8D", "#0B6E70", "#CDEDEA",
    "#FFFFFF", "#C2CBD6", "#FFFFFF", "#8A95A3"
};

const RiffColors kDark = {
    "#1C2026", "#232830", "#282E37", "#2B313A", "#E4E8EE", "#9AA5B1",
    "#3A424D", "#313842", "#2C3A3E", "#2CB8AA", "#5FD3C6", "#1F4A48",
    "#0E1B1A", "#4A5360", "#2B313A", "#8691A0"
};

} // namespace

ThemeManager::ThemeManager()
{
    themeDir_ = QCoreApplication::applicationDirPath() + "/themes/";
    nativeStyle_ = qApp->style()->objectName();
    nativePalette_ = qApp->palette();
    qDebug("Themes directory: %s", qPrintable(themeDir_));
}

QStringList ThemeManager::themeList()
{
    QStringList themes;
    themes << "riff-dark" << "riff-light" << "default";

    QDir themeDir(themeDir_);
    themeDir.setFilter(QDir::Files);
    themeDir.setNameFilters(QStringList() << "*.qss");
    themeDir.setSorting(QDir::Name);
    for (QString theme : themeDir.entryList())
        themes.append(theme.remove(".qss"));

    return themes;
}

QString ThemeManager::displayName(const QString &theme) const
{
    if (theme == "riff-light")
        return QCoreApplication::translate("ThemeManager", "Riff Light");
    if (theme == "riff-dark")
        return QCoreApplication::translate("ThemeManager", "Riff Dark");
    if (theme == "default" || theme.isEmpty())
        return QCoreApplication::translate("ThemeManager", "Classic (system)");
    return theme;
}

void ThemeManager::setTheme(QString theme)
{
    if (theme.isEmpty())
        theme = "default";

    // Undo whatever the current theme changed
    qApp->setStyleSheet("");
    if (!registeredRcc_.isEmpty()) {
        if (!QResource::unregisterResource(registeredRcc_))
            qDebug("Unable to unregister theme rccFile %s",
                   qPrintable(registeredRcc_));
        registeredRcc_.clear();
    }
    if (QStyle *style = QStyleFactory::create(nativeStyle_))
        qApp->setStyle(style);
    qApp->setPalette(nativePalette_);
    dark_ = false;

    // Remember the choice - "default" too, so that it survives a restart
    appSettings->setValue(kThemeKey, theme);

    if (theme == "riff-light" || theme == "riff-dark") {
        applyRiffTheme(theme == "riff-dark");
        return;
    }

    if (theme == "default")
        return;

    // External theme from the themes directory
    QFile qssFile(themeDir_ + theme + ".qss");
    if (!qssFile.open(QFile::ReadOnly)) {
        qDebug("Unable to open theme qssFile %s",
               qPrintable(qssFile.fileName()));
        return;
    }

    // Register theme resource before applying theme style sheet
    QString rccFile = themeDir_ + theme + ".rcc";
    if (QResource::registerResource(rccFile))
        registeredRcc_ = rccFile;
    else
        qDebug("Unable to register theme rccFile %s", qPrintable(rccFile));

    qApp->setStyleSheet(QString(qssFile.readAll()));
}

void ThemeManager::applyRiffTheme(bool dark)
{
    const RiffColors &c = dark ? kDark : kLight;
    dark_ = dark;

    qApp->setStyle(QStyleFactory::create("Fusion"));

    QPalette p;
    p.setColor(QPalette::Window, QColor(c.window));
    p.setColor(QPalette::WindowText, QColor(c.text));
    p.setColor(QPalette::Base, QColor(c.base));
    p.setColor(QPalette::AlternateBase, QColor(c.alt));
    p.setColor(QPalette::ToolTipBase, QColor(c.tooltip));
    p.setColor(QPalette::ToolTipText, QColor(c.text));
    p.setColor(QPalette::Text, QColor(c.text));
    p.setColor(QPalette::Button, QColor(c.base));
    p.setColor(QPalette::ButtonText, QColor(c.text));
    p.setColor(QPalette::BrightText, QColor("#E5484D"));
    p.setColor(QPalette::Highlight, QColor(c.accent));
    p.setColor(QPalette::HighlightedText, QColor(c.accentText));
    p.setColor(QPalette::Link, QColor(c.accentStrong));
    p.setColor(QPalette::LinkVisited, QColor(c.accentStrong));
    p.setColor(QPalette::PlaceholderText, QColor(c.mutedText));
    p.setColor(QPalette::Light, QColor(c.base));
    p.setColor(QPalette::Midlight, QColor(c.alt));
    p.setColor(QPalette::Mid, QColor(c.border));
    p.setColor(QPalette::Dark, QColor(c.border));
    p.setColor(QPalette::Shadow, QColor(dark ? "#0B0D10" : "#AEB7C2"));
    for (QPalette::ColorRole role : {QPalette::WindowText, QPalette::Text,
                                     QPalette::ButtonText}) {
        p.setColor(QPalette::Disabled, role, QColor(c.mutedText));
    }
    p.setColor(QPalette::Disabled, QPalette::Base, QColor(c.window));
    p.setColor(QPalette::Disabled, QPalette::Button, QColor(c.window));
    qApp->setPalette(p);

    QFile qssFile(":/riff/theme.qss");
    if (!qssFile.open(QFile::ReadOnly)) {
        qDebug("Riff theme stylesheet missing from resources");
        return;
    }
    QString qss = QString::fromUtf8(qssFile.readAll());

    // Replace longest tokens first so that @accent doesn't clobber
    // @accentSoft etc.
    QMap<QString, QString> tokens {
        {"@window", c.window}, {"@base", c.base}, {"@alt", c.alt},
        {"@header", c.header}, {"@text", c.text},
        {"@mutedText", c.mutedText}, {"@border", c.border},
        {"@grid", c.grid}, {"@hover", c.hover}, {"@accent", c.accent},
        {"@accentStrong", c.accentStrong}, {"@accentSoft", c.accentSoft},
        {"@accentText", c.accentText}, {"@scroll", c.scroll},
        {"@indicatorBorder", c.indicatorBorder},
    };
    QStringList keys = tokens.keys();
    std::sort(keys.begin(), keys.end(),
              [](const QString &a, const QString &b) {
                  return a.size() > b.size();
              });
    for (const QString &key : keys)
        qss.replace(key, tokens.value(key));

    qApp->setStyleSheet(qss);
}

ThemeManager* ThemeManager::instance()
{
    if (!instance_)
        instance_ = new ThemeManager();
    return instance_;
}
