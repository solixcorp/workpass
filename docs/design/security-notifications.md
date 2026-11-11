# Security notifications

Security notices are in-app messages for the affected account, including when the actor and target are the same person. A plain sign-in is not itself a security notice; a previously unseen device and country combination is the exception. Notices are best effort and never make the operation fail. They contain no credentials, tokens, IP addresses or administrator-supplied reasons.

| Kind | Title | Link | Triggers |
| --- | --- | --- | --- |
| `security_password` | 비밀번호가 변경되었습니다 | `/security` | Activation, OPAQUE registration, password change or administrator reset, account recovery |
| `security_mfa` | 2차 인증 수단이 등록되었습니다 | `/security` | Confirmed TOTP, HOTP enrollment or administrator attachment, passkey registration |
| `security_mfa` | 2차 인증 수단이 삭제되었습니다 | `/security` | TOTP or passkey removal, HOTP removal, administrator MFA reset |
| `security_account` | 계정이 비활성화되었습니다 | `/security` | Administrator disables an account |
| `security_account` | 계정이 활성화되었습니다 | `/security` | Administrator enables an account |
| `security_account` | 계정 역할이 변경되었습니다 | `/security` | Administrator changes a role |
| `security_account` | 모든 세션이 해제되었습니다 | `/security` | Administrator revokes all sessions |
| `security_account` | 신뢰 기기가 해제되었습니다 | `/security` | Administrator revokes trusted devices |
| `security_account` | 계정이 잠겼습니다 | `/security` | Self-service or administrator lockdown |
| `security_account` | 계정 잠금이 해제되었습니다 | `/security` | Administrator lifts lockdown |
| `security_location` | 허용되지 않은 위치에서 로그인이 시도되었습니다 | `/activity` | Enforced place-policy denial after a password or passkey proof |
| `security_new_device` | 새 기기에서 로그인했습니다 | `/activity` | A device label and country combination not seen in the previous 90 days, except the first recorded login |

A single atomic insert suppresses another notice with the same user, kind and title within 60 seconds, regardless of whether it has been read. Different titles are independent. The new-device comparison uses the existing user-agent description and country, including unknown values; it checks prior history before recording the current login. History and notification failures are ignored. Place-policy observation and authorization checks do not produce location notices. The passkey denial path deletes the newly issued session before returning the existing 403 response.

Most mutation notices are emitted when their successful audit event is finalized; activation and post-proof location denials have explicit hooks. Authentication failures and intermediate MFA verification attempts do not trigger mutation notices.
