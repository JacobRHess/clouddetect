# ATT&CK coverage

Generated from `detections.yaml`. Regenerate after manifest changes:

```bash
uv run python -m clouddetect.attackdoc > docs/ATTACK.md
```

| Technique | Name | Detection | Source |
|-----------|------|-----------|--------|
| T1098.003 | Account Manipulation: Additional Cloud Roles | iam-attach-admin-policy | cloudtrail |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | cloudtrail-logging-disabled | cloudtrail |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | guardduty-disabled | cloudtrail |
| T1078.004 | Valid Accounts: Cloud Accounts | root-account-activity | cloudtrail |
| T1098 | Account Manipulation | iam-login-profile-created | cloudtrail |
| T1098.003 | Account Manipulation: Additional Cloud Roles | iam-user-added-to-admin-group | cloudtrail |
| T1485 | Data Destruction | kms-key-scheduled-deletion | cloudtrail |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | aws-config-recorder-stopped | cloudtrail |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | okta-api-token-created | okta |
| T1556.006 | Modify Authentication Process: Multi-Factor Authentication | okta-mfa-factor-reset | okta |
| T1098.003 | Account Manipulation: Additional Cloud Roles | okta-super-admin-granted | okta |
| T1528 | Steal Application Access Token | entra-oauth-consent-grant | entra |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | entra-sp-credential-added | entra |
| T1556 | Modify Authentication Process | entra-conditional-access-deleted | entra |
| T1484.002 | Domain or Tenant Policy Modification: Trust Modification | entra-federation-domain-set | entra |
| T1556 | Modify Authentication Process | entra-strong-auth-disabled | entra |
