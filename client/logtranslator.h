/*
Copyright (C) 2026 Riff contributors

This file is part of "Riff"

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

#ifndef _LOG_TRANSLATOR_H
#define _LOG_TRANSLATOR_H

#include <QCoreApplication>
#include <QString>

/*
 * Translates log/notification text into the UI language.
 *
 * Messages from the agent (riff-agent) arrive as plain English text over
 * RPC - possibly from an agent on another machine - so they are matched
 * against known patterns here, on the controller, and re-phrased with
 * tr(). Unknown text is returned unchanged.
 */
class LogTranslator
{
    Q_DECLARE_TR_FUNCTIONS(LogTranslator)

public:
    static QString translate(const QString &message);
};

#endif
