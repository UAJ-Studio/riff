; Riff installer (Inno Setup 6.3 or later). Built by wireless/build-installer.sh:
;   ISCC /DAppVersion=1.3.0 /DDistDir=..\dist\Riff /DHelperExe=... /DUsbipdMsi=... riff.iss
; Installs per user (no administrator rights) in %LOCALAPPDATA%\Programs\Riff,
; the same folder the older console installer used, so it updates those
; installs in place. Only installing usbipd-win and giving USB Wi-Fi dongles
; back to Windows show a UAC prompt.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef DistDir
  #define DistDir "..\dist\Riff"
#endif
#ifndef HelperExe
  #define HelperExe "..\dist\riff-maintenance.exe"
#endif
#ifndef UsbipdMsi
  #define UsbipdMsi "..\dist\usbipd.msi"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

[Setup]
AppId={{5ED30487-FE11-409C-8493-9A1EDF918C2B}
AppName=Riff
AppVersion={#AppVersion}
AppVerName=Riff {#AppVersion}
AppPublisher=UAJ-Studio
AppPublisherURL=https://uaj-studio.com/riff
AppSupportURL=https://github.com/UAJ-Studio/riff
AppUpdatesURL=https://github.com/UAJ-Studio/riff/releases
AppComments=Packet and traffic generator for Windows (derived from Ostinato)
DefaultDirName={autopf}\Riff
DisableProgramGroupPage=yes
; the welcome page says what Riff is
DisableWelcomePage=no
DisableDirPage=auto
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=Riff-{#AppVersion}-setup
SetupIconFile=..\client\icons\logo.ico
UninstallDisplayIcon={app}\riff.exe
UninstallDisplayName=Riff
WizardStyle=modern
WizardImageFile=installer\wizard.bmp,installer\wizard-2x.bmp
WizardSmallImageFile=installer\small.bmp,installer\small-2x.bmp
ShowLanguageDialog=no
LanguageDetectionMethod=uilanguage
Compression=lzma2/max
SolidCompression=yes
; files in use (Riff running): offer to close it
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}.0
VersionInfoProductName=Riff
VersionInfoCompany=UAJ-Studio
VersionInfoDescription=Riff installer
VersionInfoCopyright=GPLv3. Derived from Ostinato (c) 2007-2023 Srivats P.

[Languages]
Name: "ja"; MessagesFile: "compiler:Languages\Japanese.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Messages]
ja.WelcomeLabel2=[name/ver] をインストールします。%n%nRiff は Windows 用のパケット/トラフィックジェネレーターです（Ostinato 1.3.0 からの派生）。有線 LAN と USB Wi-Fi ドングルから自由に作ったパケットを送信でき、ドングルで受信した無線（802.11）を Wireshark でライブキャプチャすることもできます。%n%n管理者権限は必要ありません。続ける前に、ほかのアプリケーションを閉じることをお勧めします。
en.WelcomeLabel2=This will install [name/ver] on your computer.%n%nRiff is a packet and traffic generator for Windows (derived from Ostinato 1.3.0). It sends packets you build from wired Ethernet ports and USB Wi-Fi dongles, and captures 802.11 traffic from the dongles live in Wireshark.%n%nNo administrator rights are needed. It is recommended that you close all other applications before continuing.

[CustomMessages]
ja.DongleGroup=USB Wi-Fi ドングル（使わない場合は不要です）:
en.DongleGroup=USB Wi-Fi dongles (not needed if you do not use them):
ja.UsbipdTask=usbipd-win（同梱版）をインストールする（管理者の確認画面が出ます）
en.UsbipdTask=Install usbipd-win (bundled; shows an administrator prompt)
ja.InstallingUsbipd=usbipd-win をインストールしています...
en.InstallingUsbipd=Installing usbipd-win...
ja.UsbipdFailed=usbipd-win をインストールできませんでした。あとで Riff の「ツール ＞ 無線ドングル」から入れられます。
en.UsbipdFailed=usbipd-win was not installed. You can install it later from Riff (Tools > Wireless Dongles).
ja.CheckTitle=動作に必要なもの
en.CheckTitle=What Riff needs
ja.CheckSubtitle=次のものが見つかりませんでした。Riff のインストールはこのまま続けられます。
en.CheckSubtitle=The following was not found. You can continue installing Riff.
ja.NpcapMissing=■ Npcap がインストールされていません%nNpcap がないと Riff はパケットを送受信できません。Npcap は再配布できないため同梱していません。インストールの最後に、公式サイトのダウンロードページを開けます（https://npcap.com/）。
en.NpcapMissing=■ Npcap is not installed%nRiff cannot send or receive packets without Npcap. It may not be redistributed, so it is not bundled. You can open its download page at the end of the setup (https://npcap.com/).
ja.WslMissing=■ WSL がインストールされていません（USB Wi-Fi ドングルを使う場合のみ必要）%nドングルを使うときは、管理者の PowerShell で「wsl --install --no-distribution」を実行して PC を再起動してください。
en.WslMissing=■ WSL is not installed (only needed for USB Wi-Fi dongles)%nTo use dongles, run "wsl --install --no-distribution" in an administrator PowerShell and restart the PC.
ja.OpenNpcapPage=Npcap のダウンロードページを開く（パケットの送受信に必要です）
en.OpenNpcapPage=Open the Npcap download page (needed to send and receive packets)
ja.GiveBackDongles=Riff 専用に登録した USB Wi-Fi ドングル（%1）を Windows に戻しますか?%n管理者の確認画面が出ます。
en.GiveBackDongles=Give the USB Wi-Fi dongles registered for Riff (%1) back to Windows?%nAn administrator prompt will appear.
ja.RemoveDistro=Riff 専用の WSL 環境（RiffWireless）も削除しますか?
en.RemoveDistro=Also remove Riff's own WSL environment (RiffWireless)?
ja.RemoveSettings=Riff の設定（ウィンドウ配置、登録済みドングルの記録など）も削除しますか?
en.RemoveSettings=Also remove Riff's settings (window layout, registered dongles, ...)?

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "usbipd"; Description: "{cm:UsbipdTask}"; GroupDescription: "{cm:DongleGroup}"; Check: not UsbipdInstalled

[InstallDelete]
; left over from the older shared-Qt builds (Riff now has Qt built in)
Type: files; Name: "{app}\*.dll"
Type: filesandordirs; Name: "{app}\bearer"
Type: filesandordirs; Name: "{app}\iconengines"
Type: filesandordirs; Name: "{app}\imageformats"
Type: filesandordirs; Name: "{app}\platforms"
Type: filesandordirs; Name: "{app}\styles"
; state file of the older console installer
Type: files; Name: "{app}\install.json"

[Files]
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#HelperExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#UsbipdMsi}"; DestName: "usbipd.msi"; Flags: dontcopy

[Icons]
Name: "{autoprograms}\Riff"; Filename: "{app}\riff.exe"; WorkingDir: "{app}"; Comment: "Riff - packet generator"
Name: "{autodesktop}\Riff"; Filename: "{app}\riff.exe"; WorkingDir: "{app}"; Comment: "Riff - packet generator"; Tasks: desktopicon

[Run]
Filename: "https://npcap.com/#download"; Description: "{cm:OpenNpcapPage}"; Flags: shellexec postinstall nowait skipifsilent; Check: not NpcapInstalled
Filename: "{app}\riff.exe"; WorkingDir: "{app}"; Description: "{cm:LaunchProgram,Riff}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; settings files Riff may create next to itself
Type: filesandordirs; Name: "{app}"

[Code]
var
  CheckPage: TOutputMsgWizardPage;

function NpcapInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\wpcap.dll'));
end;

function UsbipdInstalled: Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\usbipd-win\usbipd.exe'));
end;

function WslAvailable: Boolean;
var
  rc: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\wsl.exe'), '--status', '', SW_HIDE,
                 ewWaitUntilTerminated, rc) and (rc = 0);
end;

procedure InitializeWizard;
var
  msg: String;
begin
  msg := '';
  if not NpcapInstalled then
    msg := CustomMessage('NpcapMissing');
  if not WslAvailable then begin
    if msg <> '' then
      msg := msg + #13#10#13#10;
    msg := msg + CustomMessage('WslMissing');
  end;
  if msg <> '' then
    CheckPage := CreateOutputMsgPage(wpSelectTasks, CustomMessage('CheckTitle'),
                                     CustomMessage('CheckSubtitle'), msg);
end;

procedure InstallUsbipd;
var
  rc: Integer;
begin
  WizardForm.StatusLabel.Caption := CustomMessage('InstallingUsbipd');
  ExtractTemporaryFile('usbipd.msi');
  if not ShellExec('runas', ExpandConstant('{sys}\msiexec.exe'),
                   '/i "' + ExpandConstant('{tmp}\usbipd.msi') + '" /passive /norestart',
                   '', SW_SHOWNORMAL, ewWaitUntilTerminated, rc) or not UsbipdInstalled then
    SuppressibleMsgBox(CustomMessage('UsbipdFailed'), mbInformation, MB_OK, IDOK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    { the older console installer registered itself under this key }
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Riff');
    if WizardIsTaskSelected('usbipd') then
      InstallUsbipd;
  end;
end;

{ ---- uninstall: Riff's dongles, WSL distro, extcap and settings ---- }

function Helper: String;
begin
  Result := ExpandConstant('{app}\riff-maintenance.exe');
end;

{ silent uninstall (scripts): remove Riff itself only - no dongles, WSL
  environment or settings without someone saying so }
function Ask(const msg: String; defYes: Boolean): Boolean;
var
  flags: Integer;
begin
  if UninstallSilent then begin
    Result := False;
    exit;
  end;
  flags := MB_YESNO;
  if not defYes then
    flags := flags or MB_DEFBUTTON2;
  Result := MsgBox(msg, mbConfirmation, flags) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  rc, i: Integer;
  output: TExecOutput;
  ids: String;
begin
  if (CurUninstallStep <> usUninstall) or not FileExists(Helper) then
    exit;
  Exec(Helper, '--close-riff', '', SW_HIDE, ewWaitUntilTerminated, rc);

  ids := '';
  if ExecAndCaptureOutput(Helper, '--riff-dongles', '', SW_HIDE, ewWaitUntilTerminated, rc, output) then
    for i := 0 to GetArrayLength(output.StdOut) - 1 do
      ids := ids + Trim(output.StdOut[i]);
  if (ids <> '') and Ask(FmtMessage(CustomMessage('GiveBackDongles'), [ids]), True) then
    ShellExec('runas', Helper, '--elevated-unbind --busids=' + ids, '', SW_HIDE,
              ewWaitUntilTerminated, rc);

  if Exec(Helper, '--distro-exists', '', SW_HIDE, ewWaitUntilTerminated, rc) and (rc = 0) and
     Ask(CustomMessage('RemoveDistro'), True) then
    Exec(Helper, '--unregister-distro', '', SW_HIDE, ewWaitUntilTerminated, rc);

  Exec(Helper, '--remove-extcap', '', SW_HIDE, ewWaitUntilTerminated, rc);

  if Ask(CustomMessage('RemoveSettings'), False) then
    Exec(Helper, '--remove-settings', '', SW_HIDE, ewWaitUntilTerminated, rc);
end;
