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

#ifndef _VARIABLE_FIELDS_H
#define _VARIABLE_FIELDS_H

#include "abstractprotocol.h"

#include <QtEndian>

/*
 * Applies a protocol's variable fields to its frame bytes - for protocols
 * that build protocolFrameValue() themselves instead of using
 * AbstractProtocol's generic implementation (which does this itself).
 * Same semantics as AbstractProtocol's varyCounter().
 */
namespace VariableFields {

template <typename T>
inline void vary(QByteArray &buf, int frameIndex,
                 const OstProto::VariableField &vf)
{
    if (vf.offset() + sizeof(T) > uint(buf.size()) || vf.count() == 0)
        return;

    uchar *p = reinterpret_cast<uchar*>(buf.data()) + vf.offset();
    T oldValue = (sizeof(T) > 1) ? qFromBigEndian<T>(p) : T(*p);
    quint32 x = (quint32(frameIndex) % vf.count()) * vf.step();
    quint32 v;
    switch (vf.mode()) {
    case OstProto::VariableField::kDecrement:
        v = vf.value() - x;
        break;
    case OstProto::VariableField::kRandom:
        v = vf.value() + quint32(qrand());
        break;
    case OstProto::VariableField::kIncrement:
    default:
        v = vf.value() + x;
        break;
    }
    T newValue = T((oldValue & ~vf.mask()) | (v & vf.mask()));
    if (sizeof(T) > 1)
        qToBigEndian<T>(newValue, p);
    else
        *p = uchar(newValue);
}

inline void apply(const AbstractProtocol *proto, QByteArray &buf,
                  int frameIndex)
{
    for (int i = 0; i < proto->variableFieldCount(); i++) {
        const OstProto::VariableField &vf = proto->variableField(i);
        switch (vf.type()) {
        case OstProto::VariableField::kCounter8:
            vary<quint8>(buf, frameIndex, vf);
            break;
        case OstProto::VariableField::kCounter16:
            vary<quint16>(buf, frameIndex, vf);
            break;
        case OstProto::VariableField::kCounter32:
            vary<quint32>(buf, frameIndex, vf);
            break;
        default:
            break;
        }
    }
}

} // namespace VariableFields

#endif
