# Riff 1.3.4
**Riff** is a packet and traffic generator for Windows — **made by [UAJ-Studio](https://uaj-studio.com)** · [Riff page](https://uaj-studio.com/riff)

Riff は Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。有線 LAN と USB Wi-Fi ドングルから自由に作ったパケットを送信でき、ドングルで受信した無線（802.11）を Wireshark でライブキャプチャすることもできます。

## Download / ダウンロード

`Riff-1.3.4-setup.exe` (below; `Riff-setup.exe` is the same file). It installs Riff for the current user (no administrator rights needed) and updates an older Riff in place, keeping its settings.

インストーラー `Riff-1.3.4-setup.exe` を実行してください（`Riff-setup.exe` は同じファイルです）。管理者権限なしでインストールされ、古い Riff は設定を残したまま更新されます。

SHA-256: `@SHA256@`

## What's new / 変更点

- **Update notification with an Update button.** About once a day Riff asks GitHub whether a newer version is out. If there is one, it says so; **Update** downloads it, checks its checksum, closes Riff, updates it and starts Riff again, keeping the settings. **Help > Check for Updates** checks right away; turn the check off with **Help > Check for Updates at Start**. Only the version number of the latest release is asked for; nothing about you or the PC is sent.
  **更新の通知と「更新」ボタン。** Riff は 1 日 1 回ほど、新しい版が出ていないかを GitHub に確かめます。出ていれば知らせ、「更新」を押すとダウンロード、チェックサムの確認、Riff を閉じての更新、再起動まで自動で進みます（設定はそのまま）。「ヘルプ ＞ 更新を確認」ですぐに確かめられ、「ヘルプ ＞ 起動時に更新を確認する」で止められます。問い合わせるのは最新版の版番号だけで、利用者や PC の情報は送りません。
- **User manual** in Japanese and English: **Help > User Manual (Online)** opens it.
  **使い方マニュアル**（日本語・英語）を用意しました。「ヘルプ ＞ 使い方マニュアル（オンライン）」で開きます。
- The dongle list in Tools > Wireless Dongle can be scrolled while the dongles are transmitting.
  「ツール ＞ 無線ドングル」のドングル一覧を、送信中でもスクロールできるようにしました。
- If only devices Riff cannot use were checked before, the dongles registered for Riff are checked again.
  前回チェックしていたのが Riff で使えない機器だけだった場合は、Riff に登録済みのドングルにチェックを付けるようにしました。
- USB Wi-Fi dongle drivers for more WSL kernels (6.18.26, 6.18.33 and 6.18.35).
  USB Wi-Fi ドングルのドライバーを、より多くの WSL のカーネル（6.18.26・6.18.33・6.18.35）に用意しました。

From this version on, Riff tells you about new versions by itself. Users of 1.3.3 or older need to install this version once by hand.
この版からは、新しい版が出ると Riff が知らせます。1.3.3 以前を使っている方は、この版だけ手動で入れてください。

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
