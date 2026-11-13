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

#ifndef _THEME_MANAGER_H
#define _THEME_MANAGER_H

#include <QPalette>
#include <QString>
#include <QStringList>

/*
 * Themes are identified by an id string -
 *   "riff-light", "riff-dark" : built-in Riff themes (Fusion + palette + qss)
 *   "default"                 : the platform's native look
 *   anything else             : <appdir>/themes/<id>.qss (+ optional .rcc)
 */
class ThemeManager
{
public:
    ThemeManager();

    QStringList themeList();
    QString displayName(const QString &theme) const;
    void setTheme(QString theme);
    bool isDark() const { return dark_; }

    // Text colours for errors/warnings that are readable on the
    // current theme's background
    QString errorColor() const { return dark_ ? "#FFB4AB" : "#B3261E"; }
    QString warningColor() const { return dark_ ? "#F2CC60" : "#8A5300"; }

    static ThemeManager* instance();

private:
    void applyRiffTheme(bool dark);

    QString themeDir_;
    QString nativeStyle_;
    QPalette nativePalette_;
    QString registeredRcc_;
    bool dark_{false};

    static ThemeManager *instance_;
};

#endif
