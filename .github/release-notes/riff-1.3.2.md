# Riff 1.3.2
**Riff** is a packet and traffic generator for Windows — **made by [UAJ-Studio](https://uaj-studio.com)** · [Riff page](https://uaj-studio.com/riff)

Riff は Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。有線 LAN と USB Wi-Fi ドングルから自由に作ったパケットを送信でき、ドングルで受信した無線（802.11）を Wireshark でライブキャプチャすることもできます。

## Download / ダウンロード

`Riff-1.3.2-setup.exe` (below; `Riff-setup.exe` is the same file). It installs Riff for the current user (no administrator rights needed) and updates an older Riff in place, keeping its settings.

インストーラー `Riff-1.3.2-setup.exe` を実行してください（`Riff-setup.exe` は同じファイルです）。管理者権限なしでインストールされ、古い Riff は設定を残したまま更新されます。

SHA-256: `@SHA256@`

## What's new / 変更点

- **USB Wi-Fi dongles work with WSL 3.0** (kernel 6.18): WSL 3.0.5 moved to a new kernel, and the dongle drivers of 1.3.1 did not load there. 1.3.2 includes drivers for the 6.18 kernels.
  **WSL 3.0 でもドングルが使えるようになりました**：WSL 3.0.5 でカーネルが 6.18 系に変わり、1.3.1 のドングル用ドライバーが読み込めなくなっていました。1.3.2 には 6.18 系用のドライバーが入っています。
- **Future WSL updates are followed automatically**: when Microsoft updates the WSL kernel again, GitHub Actions builds the drivers for it within a day, and Riff downloads them by itself (checked before use). If they cannot be downloaded, Riff offers to build them on the PC (about 10 minutes).
  **今後の WSL の更新にも自動で追従します**：Microsoft が WSL のカーネルを更新すると、GitHub Actions が 1 日以内にそのカーネル用のドライバーを自動で作り、Riff が自動でダウンロードします（使う前に確認します）。取得できない場合は、PC 上で作ることもできます（10 分ほど）。
- **Fixed**: when no drivers matched the WSL kernel, a message appeared again and again and Riff closed after OK. It now shows once, and the wired ports keep working.
  **修正**：WSL のカーネルに合うドライバーがないとき、メッセージが何度も表示され、OK を押すと Riff が終了していました。表示は 1 回だけになり、有線 LAN のポートはそのまま使えます。

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
