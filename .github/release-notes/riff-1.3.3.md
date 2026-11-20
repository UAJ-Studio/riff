# Riff 1.3.3
**Riff** is a packet and traffic generator for Windows — **made by [UAJ-Studio](https://uaj-studio.com)** · [Riff page](https://uaj-studio.com/riff)

Riff は Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。有線 LAN と USB Wi-Fi ドングルから自由に作ったパケットを送信でき、ドングルで受信した無線（802.11）を Wireshark でライブキャプチャすることもできます。

## Download / ダウンロード

`Riff-1.3.3-setup.exe` (below; `Riff-setup.exe` is the same file). It installs Riff for the current user (no administrator rights needed) and updates an older Riff in place, keeping its settings.

インストーラー `Riff-1.3.3-setup.exe` を実行してください（`Riff-setup.exe` は同じファイルです）。管理者権限なしでインストールされ、古い Riff は設定を残したまま更新されます。

SHA-256: `@SHA256@`

## What's new / 変更点

- **Fixed: an AirPcap adapter could keep the USB Wi-Fi dongles from working.** AirPcap is a Windows capture adapter (Riff uses it as an AirPcap port), but it was listed as a supported dongle, could be checked and taken for Riff, and then failed again and again because Windows uses it. It is now shown as a Windows capture adapter and is never used as a dongle.
  **修正：AirPcap があると USB Wi-Fi ドングルが使えなくなることがありました。** AirPcap は Windows のキャプチャ機器（Riff では AirPcap のポートとして使えます）ですが、対応ドングルとして一覧に出て選べてしまい、Windows が使っているため準備の失敗を繰り返していました。今後は「Windows のキャプチャ機器」と表示し、ドングルとしては使いません。
- **One dongle that cannot be used no longer stops the others**, and it is not retried again and again.
  **使えないドングルが 1 台あっても、ほかのドングルは使えます。** 失敗したドングルを何度も準備し直すこともしません。
- With no earlier choice, the dongle list checks only the dongles already registered for Riff, not every supported device.
  前回の選択がないとき、ドングルの一覧では Riff に登録済みのドングルだけにチェックを付けます（対応する機器すべてではありません）。
- Riff writes what happens with the dongles to `%LOCALAPPDATA%\Riff\wireless.log`, which helps when something goes wrong.
  ドングルまわりの記録を `%LOCALAPPDATA%\Riff\wireless.log` に残すようにしました。うまくいかないときの原因調べに使えます。

If an AirPcap is shown as "give it back to Windows" in Tools > Wireless Dongle, select it and press **Give back to Windows** once.
「ツール ＞ 無線ドングル」で AirPcap に「Windows に戻してください」と表示されている場合は、選んで「Windows に戻す」を一度押してください。

## Requirements / 必要なもの

- Windows 10 / 11 (64-bit)
- [Npcap](https://npcap.com/) (free; not bundled because it may not be redistributed)
- For USB Wi-Fi dongles: WSL 2 and usbipd-win (bundled with the setup). Supported chips: see the [list](https://github.com/UAJ-Studio/riff#supported-usb-wi-fi-dongles).

## Known limitations / 注意

- **Not code-signed yet.** Windows SmartScreen shows a warning on first start (More info → Run anyway). On PCs with **Smart App Control** turned on, Riff does not start until a signed release is available.
  コード署名がまだないため、初回起動時に Windows の警告が出ます（「詳細情報」→「実行」）。スマート アプリ コントロールがオンの PC では、署名入りの版が出るまで起動できません。
- Use Riff only on networks and radio environments you own or are allowed to test, with certified equipment, and do not disturb other people's communication.
  自分が管理している、または許可を得た環境でのみ使い、技適マークのある機器で、他人の通信を妨害しないでください。

Riff is free and open source (GPLv3). It is derived from [Ostinato](https://ostinato.org) 1.3.0 by Srivats P.; it is not affiliated with or endorsed by the Ostinato project.
