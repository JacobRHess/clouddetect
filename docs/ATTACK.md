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
