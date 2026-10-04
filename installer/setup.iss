; ThreatGuard Windows Endpoint Agent Inno Setup Script
; Generates ThreatGuard-Agent-Setup.exe

#define MyAppName "ThreatGuard Endpoint Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ThreatGuard Security"
#define MyAppExeName "threatguard-agent.exe"

[Setup]
AppId={{9F7B16E4-5A2C-4A2B-831E-14D5771A1234}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\ThreatGuard Agent
DefaultGroupName=ThreatGuard
OutputDir=..\dist
OutputBaseFilename=ThreatGuard-Agent-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\threatguard-agent.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.template.json"; DestDir: "{commonappdata}\ThreatGuard"; DestName: "config.json"; Flags: onlyifdoesntexist

[Dirs]
Name: "{commonappdata}\ThreatGuard"
Name: "{commonappdata}\ThreatGuard\logs"

[Run]
; Register and start Windows Service after installation
Filename: "sc.exe"; Parameters: "create ThreatGuardAgent binPath= ""\""{app}\{#MyAppExeName}\"" --service-run"" start= auto DisplayName= ""ThreatGuard Endpoint Security Agent"""; Flags: runhidden
Filename: "sc.exe"; Parameters: "description ThreatGuardAgent ""ThreatGuard endpoint security telemetry and monitoring agent service."""; Flags: runhidden
Filename: "sc.exe"; Parameters: "failure ThreatGuardAgent reset= 86400 actions= restart/60000/restart/60000/restart/60000"; Flags: runhidden
Filename: "sc.exe"; Parameters: "start ThreatGuardAgent"; Flags: runhidden

[UninstallRun]
; Stop and remove service upon uninstallation
Filename: "sc.exe"; Parameters: "stop ThreatGuardAgent"; Flags: runhidden; RunOnceId: "StopTGService"
Filename: "sc.exe"; Parameters: "delete ThreatGuardAgent"; Flags: runhidden; RunOnceId: "DeleteTGService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
