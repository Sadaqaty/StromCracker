; Inno Setup Script for StormCracker GPU Engine
; Compiles the standalone EXE, Hashcat, and Wordlist into a professional Setup.exe installer

[Setup]
AppName=StormCracker
AppVersion=1.0
AppPublisher=Storm Labs
AppPublisherURL=https://github.com/
DefaultDirName={localappdata}\StormCracker
DefaultGroupName=StormCracker
DisableProgramGroupPage=yes
OutputBaseFilename=StormCracker_Setup
Compression=lzma2/ultra
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
; The compiled GUI executable (you must compile this first using PyInstaller)
Source: "dist\win_cracker.exe"; DestDir: "{app}"; Flags: ignoreversion

; The Hashcat folder and its contents
Source: "hashcat.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "OpenCL\*"; DestDir: "{app}\OpenCL"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "modules\*"; DestDir: "{app}\modules"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "charsets\*"; DestDir: "{app}\charsets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "hashcat.hcstat2"; DestDir: "{app}"; Flags: ignoreversion

; The Wordlist
Source: "rockyou.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\StormCracker"; Filename: "{app}\win_cracker.exe"
Name: "{autodesktop}\StormCracker"; Filename: "{app}\win_cracker.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\win_cracker.exe"; Description: "Launch StormCracker"; Flags: nowait postinstall skipifsilent
