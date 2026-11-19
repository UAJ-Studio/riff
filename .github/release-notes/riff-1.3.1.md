# Riff 1.3.1
**Riff** is a packet and traffic generator for Windows — **made by [UAJ-Studio](https://uaj-studio.com)** · [Riff page](https://uaj-studio.com/riff)

Riff は Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。有線 LAN と USB Wi-Fi ドングルから自由に作ったパケットを送信でき、ドングルで受信した無線（802.11）を Wireshark でライブキャプチャすることもできます。

## Download / ダウンロード

`Riff-1.3.1-setup.exe` (below; `Riff-setup.exe` is the same file). It installs Riff for the current user (no administrator rights needed) and updates an older Riff in place, keeping its settings.

インストーラー `Riff-1.3.1-setup.exe` を実行してください（`Riff-setup.exe` は同じファイルです）。管理者権限なしで現在のユーザーにインストールされ、古い Riff は設定を残したまま更新されます。

SHA-256: `@SHA256@`

## What's new / 変更点

- **New installer**: a regular setup wizard (Japanese / English) instead of the console window. It offers to close a running Riff, can install usbipd-win for USB Wi-Fi dongles, and tells you when Npcap or WSL is missing. Uninstall from Settings → Apps; it asks whether to give USB Wi-Fi dongles back to Windows and whether to remove Riff's WSL environment and settings.
  **インストーラーを一新**：黒い画面ではなく、一般的なセットアップ ウィザード（日本語/英語）になりました。起動中の Riff の終了、usbipd-win のインストール、Npcap や WSL がない場合の案内を行います。アンインストールは「設定 → アプリ」から行え、ドングルを Windows に戻すか、Riff 専用の WSL 環境や設定を削除するかを確認します。
- **Fixed**: Riff's window did not appear when Riff was started from the installer.
  **修正**：インストーラーから起動したときに Riff の画面が表示されない不具合を直しました。
- **Fixed**: the program icon was still Ostinato's; it is Riff's own now.
  **修正**：プログラムのアイコンが Ostinato のものになっていたのを、Riff のアイコンに直しました。
- Qt is now built into `riff.exe`: no Qt DLLs in the install folder anymore.
  Qt を `riff.exe` に組み込み、インストール先に Qt の DLL がなくなりました。
- Every file of this release is built from this repository's source by [GitHub Actions](https://github.com/UAJ-Studio/riff/actions).
  このリリースのファイルは、すべてこのリポジトリのソースから GitHub Actions で作っています。

## Requirements / 必要なもの

- Windows 10 / 11 (64-bit)
- [Npcap](https://npcap.com/) (free; not bundled because it may not be redistributed)
- For USB Wi-Fi dongles: WSL 2 and usbipd-win (bundled with the setup). Supported chips include Realtek rtw89/rtw88, MediaTek mt76 and Atheros ath9k_htc.

## Known limitations / 注意

- **Not code-signed yet.** Windows SmartScreen shows a warning on first start (More info → Run anyway). On PCs with **Smart App Control** turned on, Riff does not start until a signed release is available.
  コード署名がまだないため、初回起動時に Windows の警告が出ます（「詳細情報」→「実行」）。スマート アプリ コントロールがオンの PC では、署名入りの版が出るまで起動できません。
- Use Riff only on networks and radio environments you own or are allowed to test, with certified equipment, and do not disturb other people's communication.
  自分が管理している、または許可を得た環境でのみ使い、技適マークのある機器で、他人の通信を妨害しないでください。

Riff is free and open source (GPLv3). It is derived from [Ostinato](https://ostinato.org) 1.3.0 by Srivats P.; it is not affiliated with or endorsed by the Ostinato project.
