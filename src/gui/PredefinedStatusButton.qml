/*
 * Copyright (C) by Claudio Cambra <claudio.cambra@nextcloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

import QtQuick 2.15
import QtQuick.Dialogs 1.3
import QtQuick.Layouts 1.15
import QtQuick.Controls 2.15

import Style 1.0

AbstractButton {
    id: root

    hoverEnabled: true
    topPadding: Style.standardSpacing
    bottomPadding: Style.standardSpacing
    leftPadding: Style.standardSpacing / 2
    rightPadding: Style.standardSpacing / 2

    property int emojiWidth: -1
    property int internalSpacing: Style.standardSpacing
    property string emoji: ""
    property string statusText: ""
    property string clearAtText: ""

    background: Rectangle {
        color: root.hovered || root.checked ? Style.lightHover : "transparent"
        radius: Style.slightlyRoundedButtonRadius
    }

    contentItem: Row {
        spacing: root.internalSpacing

        Label {
            width: root.emojiWidth > 0 ? root.emojiWidth : implicitWidth
            text: emoji
            textFormat: Text.PlainText
            horizontalAlignment: Image.AlignHCenter
            verticalAlignment: Image.AlignVCenter
        }

        Row {
            spacing: Style.smallSpacing
            Label {
                text: root.statusText
                textFormat: Text.PlainText
                color: Style.ncTextColor
                verticalAlignment: Text.AlignVCenter
                font.bold: true
            }

            Label {
                text: "-"
                color: Style.ncTextColor
                verticalAlignment: Text.AlignVCenter
            }

            Label {
                text: root.clearAtText
                textFormat: Text.PlainText
                color: Style.ncTextColor
                verticalAlignment: Text.AlignVCenter
            }
        }
    }
}
