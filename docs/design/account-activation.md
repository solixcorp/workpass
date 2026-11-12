# 계정 활성화 (첫 로그인 / 비밀번호 설정)

상태: 구현됨. 아래 문제·구현 순서·결정 항목은 초기 설계 배경이며, 현재 관리자 화면의 동작은 다음과 같다.

## 현재 관리자 화면

- 사용자 추가 시 **이메일 발송** 또는 **링크 직접 전달**을 선택한다. 직접 전달은 메일 설정 여부와 관계없이 `sendEmail: false`로 요청하므로 이메일을 보내지 않는다.
- 사용자 목록의 링크 버튼과 사용자 상세의 **비밀번호 설정 링크**에서도 같은 전달 방법을 선택해 재발급할 수 있다. 잠금 해제 후에도 이 화면에서 전달 방법을 선택한다.
- 직접 전달 결과에서 **링크 복사**를 눌러 메신저·문자로 전달한다. 브라우저가 지원하면 **공유**로 기기의 공유 창을 열 수도 있다. 복사가 실패하면 링크 입력란을 선택해 수동 복사할 수 있다.
- 링크와 만료 시각은 발급 결과 화면에 표시한다. 기본 유효 기간은 24시간이며 한 번만 사용 가능하다. 재발급하면 이전 미사용 링크는 무효화된다.
- 활성화 화면은 서버가 내려준 길이·대문자·소문자·숫자·기호 조건을 입력 중에 확인한다. 충족한 항목은 초록색 체크로 표시하며, 제출 시에도 같은 검사 결과를 사용한다. 이는 브라우저의 입력 안내이며 OPAQUE 기록에서 서버가 비밀번호 복잡도를 검증한다는 뜻은 아니다.

## 문제

OPAQUE 로그인은 비밀번호 서버 기록(credential record)이 있어야 하고, 기록 등록(`/api/opaque/register/*`)은 세션이 있어야 한다. 평문 로그인이 막혀 있으므로 다음 계정은 처음 들어올 방법이 없다.

- 관리자·SCIM이 만든 계정
- 비밀번호를 잃어버렸거나 OPAQUE 등록을 안 한 계정
- 기존 평문 비밀번호만 있는 계정

관리자 콘솔 "사용자" 화면에도 사용자 만들기·초대 동작이 없다.

## 재사용할 것

| 있는 것 | 위치 | 쓰임 |
| --- | --- | --- |
| 1회용 토큰 패턴 (256비트, 다이제스트만 저장, 단일 사용, IP 속도 제한) | `src/security/account-recovery.ts` | 활성화 토큰 |
| 메일 발송 (SMTP·Resend 등, 개발용 웹훅) | `src/mail/send.ts` | 활성화 링크 발송 |
| 사용자 생성 | SCIM `POST /Users`, Better Auth `admin/create-user` | 계정 만들기 |
| OPAQUE 등록 | `/api/opaque/register/*` | 비밀번호 설정 |
| 서버가 내려주는 화면 정의 | `src/auth/idx-routes.ts` | 활성화 화면 |

복구 토큰은 "잠긴 계정 전용"이라 그대로 쓰지 않는다. 같은 구조로 목적만 다른 테이블을 만든다.

## 흐름

```
관리자: 사용자 생성 또는 "활성화 링크 보내기"
  └ 토큰 발급 (24시간, 1회용) → 메일 발송
사용자: 링크 /activate#<토큰> 열기
  1. 프론트가 토큰을 서버로 보내 확인 (POST /api/activation/inspect)
       → { email, ui } 또는 만료/사용됨 (구분 없이 같은 응답)
  2. 사용자가 새 비밀번호 입력
  3. 브라우저에서 OPAQUE 등록 (비밀번호는 서버로 가지 않음)
       POST /api/activation/register/start  { token, registrationRequest }
       POST /api/activation/register/finish { token, record }
  4. 서버가 기록 저장 → 토큰 소진 → 기존 세션 폐기
  5. 일반 로그인 화면으로 이동 (이메일은 채워 둠)
```

활성화로는 로그인되지 않는다. 비밀번호만 설정하고, 로그인은 기존 경로(기기 위험도, 2차 인증)를 그대로 탄다. 링크를 가진 사람이 곧바로 세션을 얻는 일을 막는다.

## 보안 조건

- 토큰: 256비트 랜덤, DB에는 `HMAC(AUTH_SECRET, "activation:"+token)`만 저장. 평문은 메일 본문과 한 번 보이는 관리자 응답에만 있다.
- URL 조각(`#`)에 담아 서버 로그와 Referer로 새지 않게 한다. 프론트가 조각을 읽어 요청 본문으로 보낸다.
- 만료·사용됨·없음은 같은 응답이다. 계정 존재 여부가 드러나지 않는다.
- 등록 요청은 토큰에 묶인 이메일로만 `credential_identifier`를 만든다. 요청 본문의 이메일은 받지 않는다.
- IP당 분당 속도 제한 (`fingerprint_lookup_limits` 재사용). 확인·시작·마침 합쳐서 제한.
- 활성화 후 해당 사용자의 기존 세션과 신뢰 기기를 폐기한다.
- 이미 비밀번호가 있는 계정에는 "다시 설정"으로 새 토큰을 발급할 수 있다. 이 경우 로그인 중인 세션을 모두 끊는다. (복구와 같은 위험이므로 관리자만 발급 가능, 감사 이벤트 기록)
- 감사 이벤트: `identity.user.activation_link.issued`, `identity.user.activation.completed`, `.failed`.

## 데이터

```sql
CREATE TABLE account_activation_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_digest TEXT NOT NULL UNIQUE,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  delivered_to TEXT,
  delivered_at TEXT
);
```

D1 쓰기는 발급 때 1회, 완료 때 2회(기록 저장, 토큰 소진)다. 만료 행은 기존 정리 작업(cron)에서 지운다.

## API

관리자 (`requireAdministrator`, 같은 오리진 POST):

- `POST /api/admin/users` `{email, name, sendEmail}` 사용자 생성 + 활성화 링크 발급. 이메일 발송이 꺼져 있으면 링크를 응답에 한 번만 돌려준다.
- `POST /api/admin/users/{id}/activation-link` `{ttlMinutes?, sendEmail?}` 다시 발급.

공개 (속도 제한, 토큰 필수):

- `POST /api/activation/inspect` `{token}` → `{email, ui}`
- `POST /api/activation/register/start` `{token, registrationRequest}` → OPAQUE 응답
- `POST /api/activation/register/finish` `{token, record}` → `{activated: true}`

화면 문구는 로그인과 같은 방식으로 서버 응답의 `ui`에 담는다.

## 프론트

- `/activate` 라우트 (로그인 없이 접근). 로딩 → 비밀번호 두 번 입력 → 완료 후 로그인으로 이동.
- 관리자 "사용자" 화면에 "사용자 추가"와 행별 "활성화 링크 보내기".
- 비밀번호 규칙은 기존 비밀번호 정책(`src/policies/password.ts`)을 서버에서 검사해 `ui.messages`로 돌려준다. 클라이언트는 규칙을 모른다.

## 구현 순서

1. 테이블과 토큰 발급·소진 로직 (복구 토큰을 본뜸) + 단위 테스트
2. 공개 API 3개 + 통합 테스트 (만료·재사용·타 계정 이메일 시도·속도 제한)
3. 관리자 API 2개 + 메일 발송 연결
4. `/activate` 화면과 관리자 화면
5. 브라우저 확인, API 문서 갱신

## 결정이 필요한 것

1. **발송 방식.** 메일 제공자가 설정돼 있지 않으면 관리자가 링크를 직접 전달해야 한다. 지금 어떤 메일 제공자를 쓸지 정해야 한다. (선택: 설정된 제공자 / 링크를 관리자 화면에 표시만)
2. **비밀번호 규칙.** 기존 정책 엔진의 규칙을 그대로 쓸지, 활성화에만 따로 둘지.
3. **유효 기간.** 기본 24시간으로 제안. 더 짧게 할지.
4. **기존 계정 처리.** 평문 비밀번호만 있는 기존 계정에 일괄로 링크를 보낼지, 관리자가 하나씩 보낼지.
5. **첫 로그인 후 2차 인증 등록 강제 여부.** 이번 범위에는 넣지 않았다.
