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

#include "etheripconfig.h"

#include "etherip.h"

#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QSpinBox>
#include <QVBoxLayout>

EtherIpConfigForm::EtherIpConfigForm(QWidget *parent)
    : AbstractProtocolConfigForm(parent)
{
    QVBoxLayout *layout = new QVBoxLayout(this);

    QGroupBox *box = new QGroupBox(tr("EtherIP header"), this);
    QFormLayout *form = new QFormLayout(box);

    version_ = new QSpinBox(box);
    version_->setRange(0, 15);
    version_->setToolTip(tr("RFC 3378 defines version 3"));
    form->addRow(tr("Version"), version_);

    reserved_ = new QSpinBox(box);
    reserved_->setRange(0, 0xFFF);
    reserved_->setDisplayIntegerBase(16);
    reserved_->setPrefix("0x");
    reserved_->setToolTip(tr("12 reserved bits - normally 0"));
    form->addRow(tr("Reserved"), reserved_);
    layout->addWidget(box);

    QLabel *hint = new QLabel(tr(
        "EtherIP carries a whole Ethernet frame inside IP (IP protocol 97, "
        "set automatically).<br>"
        "In <b>Protocol Selection &gt; Advanced</b>, add the inner frame "
        "after EtherIP - e.g. <i>MAC, Ethernet II, IPv4, UDP</i>."), this);
    hint->setWordWrap(true);
    hint->setEnabled(false); // secondary text
    layout->addWidget(hint);
    layout->addStretch();
}

EtherIpConfigForm::~EtherIpConfigForm()
{
}

EtherIpConfigForm* EtherIpConfigForm::createInstance()
{
    return new EtherIpConfigForm;
}

void EtherIpConfigForm::loadWidget(AbstractProtocol *proto)
{
    version_->setValue(proto->fieldData(EtherIpProtocol::etherip_version,
            AbstractProtocol::FieldValue).toInt());
    reserved_->setValue(proto->fieldData(EtherIpProtocol::etherip_reserved,
            AbstractProtocol::FieldValue).toInt());
}

void EtherIpConfigForm::storeWidget(AbstractProtocol *proto)
{
    proto->setFieldData(EtherIpProtocol::etherip_version, version_->value());
    proto->setFieldData(EtherIpProtocol::etherip_reserved,
                        reserved_->value());
}
