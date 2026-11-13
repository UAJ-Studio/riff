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

#include "logtranslator.h"

#include <QList>
#include <QRegularExpression>
#include <QStringList>

namespace {

struct Rule {
    QRegularExpression pattern;   // English text, captures -> %1, %2 ...
    QString translation;          // already tr()'d
};

QString applyRules(const QList<Rule> &rules, const QString &line)
{
    for (const Rule &rule : rules) {
        QRegularExpressionMatch m = rule.pattern.match(line);
        if (!m.hasMatch())
            continue;
        QString out = rule.translation;
        for (int i = 1; i <= m.lastCapturedIndex(); i++)
            out = out.arg(m.captured(i));
        return out;
    }
    return line;
}

} // namespace

QString LogTranslator::translate(const QString &message)
{
    // Built on first use, i.e. after the UI translator was installed
    static const QList<Rule> rules = [] {
        auto rx = [](const char *p) {
            return QRegularExpression(QString("^%1$").arg(p));
        };
        return QList<Rule> {
            // ---- from the agent ----
            {rx("Port (\\d+): Source mac resolve failed for one or more "
                "streams - Device matching stream's source IP not found"),
             tr("Port %1: Could not resolve the source MAC of one or more "
                "streams - no device has the stream's source IP. Set the "
                "source MAC mode to \"Self\" to use the port's own MAC, or "
                "add a device with that IP on the Devices tab.")},
            {rx("Port (\\d+): Destination mac resolve failed for one or "
                "more streams - possible ARP/ND failure"),
             tr("Port %1: Could not resolve the destination MAC of one or "
                "more streams - no ARP/ND reply. Check the destination IP "
                "(or the default gateway for other subnets).")},
            {rx("Port (\\d+): Error building packet buffers - out of "
                "buffer memory"),
             tr("Port %1: Could not build the packets - out of buffer "
                "memory. Reduce the number of streams or packets.")},
            {rx("Port (\\d+) (.+): operation disallowed on transmitting "
                "port"),
             tr("Port %1 (%2): not allowed while the port is transmitting "
                "- stop transmit and try again")},
            {rx("Port (\\d+) Stream (\\d+) (.+): invalid stream id"),
             tr("Port %1 stream %2 (%3): invalid stream ID")},
            {rx("Port (\\d+) (.+): invalid port"),
             tr("Port %1 (%2): invalid port")},
            {rx("Drone needs controller version (.+)"),
             tr("The agent needs controller version %1")},

            // ---- from the controller itself ----
            {rx("PortGroup connected"), tr("Connected to the port group")},
            {rx("PortGroup disconnected"),
             tr("Disconnected from the port group")},
            {rx("Reconnect attempt after (\\d+)s"),
             tr("Reconnecting in %1 s")},
            {rx("Bad data received from portgroup, aborting connection; "
                "who is listening on (.+):(\\d+)\\s+- is it riff-agent or "
                "some other process\\?"),
             tr("Unexpected data from the port group - connection closed. "
                "Is the program listening on %1:%2 really riff-agent?")},
            {rx("Port configuration changed notification"),
             tr("Port configuration was changed")},
            {rx("No ports in portlist"), tr("The port list is empty")},
            {rx("Port is reserved by (.+)\\. Skipping reconfiguration"),
             tr("Port is reserved by %1 - not reconfigured")},
            {rx("Deleting old DeviceGroups"),
             tr("Deleting old device groups")},
            {rx("Creating new DeviceGroups"),
             tr("Creating new device groups")},
            {rx("Modifying changed DeviceGroups"),
             tr("Updating changed device groups")},
            {rx("Deleting old Streams"), tr("Deleting old streams")},
            {rx("Creating new Streams"), tr("Creating new streams")},
            {rx("Modifying changed Streams"),
             tr("Updating changed streams")},
            {rx("Resolving device neighbors"),
             tr("Resolving neighbors (ARP/ND)")},
            {rx("Re-building packets"), tr("Rebuilding packets")},
            {rx("All port changes applied - in (.+)s"),
             tr("All port changes applied (%1 s)")},
            {rx("Modifying port configuration"),
             tr("Updating port configuration")},
            {rx("Wireshark does not exist at (.+)"),
             tr("Wireshark was not found at %1")},
            {rx("Failed to start (.+)"), tr("Could not start %1")},
            {rx("Port is still transmitting - stream stats may be "
                "unavailable or incomplete"),
             tr("Port is still transmitting - stream statistics may be "
                "missing or incomplete")},
            {rx("checkVersion RPC failed: (.*)"),
             tr("Version check failed: %1")},
            {rx("checkVersion failed: (.*)"),
             tr("Version check failed: %1")},
        };
    }();

    // Agent notes may hold several messages, one per line
    QStringList lines = message.split('\n');
    for (QString &line : lines)
        line = applyRules(rules, line.trimmed());
    while (!lines.isEmpty() && lines.last().isEmpty())
        lines.removeLast();
    return lines.join('\n');
}
