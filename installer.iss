[Setup]
AppName=Smart Notebook
AppVersion=1.0
DefaultDirName={autopf}\SmartNotebook
DefaultGroupName=Smart Notebook
OutputDir=dist
OutputBaseFilename=SmartNotebook-Setup
Compression=lzma
SolidCompression=yes
MinVersion=6.1
PrivilegesRequired=lowest
UninstallDisplayIcon={app}\SmartNotebook.exe

[Files]
Source: "dist\SmartNotebook.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Smart Notebook"; Filename: "{app}\SmartNotebook.exe"
Name: "{autodesktop}\Smart Notebook"; Filename: "{app}\SmartNotebook.exe"

[Run]
Filename: "{app}\SmartNotebook.exe"; Description: "Launch Smart Notebook"; Flags: nowait postinstall skipifsilent
