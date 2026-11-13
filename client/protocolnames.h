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

#ifndef _PROTOCOL_NAMES_H
#define _PROTOCOL_NAMES_H

#include <QString>

// Protocol long names (AbstractProtocol::name()) come from the protocol
// library, which is shared with the agent and not translated - translate
// them for display on the controller
QString translatedProtocolName(const QString &name);

#endif
