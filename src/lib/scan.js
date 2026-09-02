// 점검 체크 ID를 사람이 읽는 이름으로.
//
// Prowler 체크 ID(ec2_networkacl_allow_ingress_any_port)를 그대로 제목에 쓰면
// 목록을 훑을 때 무엇이 문제인지 읽히지 않는다. 자주 나오는 것만 옮겨 적고,
// 없는 것은 ID를 다듬어 보여준다.
//
// 전부 옮기지 않는 이유: Prowler 체크가 640개고 계속 늘어난다. 손으로 적은 표가
// 원본보다 뒤처지면 틀린 이름이 남는다. 여기 있는 것은 실제로 걸린 적 있는 것들이다.
//
// 문장 규칙 — 새로 추가할 때도 지킬 것:
//   1. "무엇이 어떤 상태인지"를 끝맺는 문장으로 쓴다. 화면의 다른 안내문과 같은 '-습니다'.
//      명사로 끊으면("암호화되지 않은 EBS 볼륨") 목록이 딱딱하고 무엇이 문제인지도 흐리다.
//   2. 영어 용어를 글자 그대로 옮기지 않는다. 무슨 뜻인지 먼저 쓰고 원어는 괄호에 넣는다.
//      'confused deputy'를 "혼동된 대리인"으로 옮겼다가 무슨 말인지 알 수 없다는 지적을 받았다.
//   3. 30자 안팎으로. 길면 목록에서 잘린다. 체크 ID와 리소스 종류는 제목 아래 따로 나오므로
//      여기서 되풀이하지 않는다.

export const CHECK_LABEL = {
  // EC2 / 네트워크
  ec2_networkacl_allow_ingress_any_port: '모든 포트가 인터넷에 열려 있습니다',
  ec2_networkacl_allow_ingress_tcp_port_22: 'SSH 포트(22)가 인터넷에 열려 있습니다',
  ec2_networkacl_allow_ingress_tcp_port_3389: '원격 접속 포트(3389)가 인터넷에 열려 있습니다',
  ec2_securitygroup_allow_ingress_from_internet_to_any_port: '모든 포트가 인터넷에 열려 있습니다',
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: 'SSH 포트(22)가 인터넷에 열려 있습니다',
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389: '원격 접속 포트(3389)가 인터넷에 열려 있습니다',
  ec2_securitygroup_not_used: '어디에도 쓰이지 않고 남아 있습니다',
  ec2_securitygroup_default_restrict_traffic: '기본 보안 그룹이 트래픽을 막지 않습니다',
  ec2_securitygroup_with_many_ingress_egress_rules: '규칙이 너무 많아 검토하기 어렵습니다',
  ec2_instance_public_ip: '인터넷에서 바로 닿는 주소가 붙어 있습니다',
  ec2_instance_imdsv2_enabled: '메타데이터 보호(IMDSv2)가 꺼져 있습니다',
  ec2_ebs_volume_encryption: '디스크가 암호화되어 있지 않습니다',
  ec2_ebs_default_encryption: '새 디스크를 자동으로 암호화하지 않습니다',
  ec2_elastic_ip_shodan: '인터넷 스캔 사이트(Shodan)에서 검색됩니다',

  // VPC
  vpc_flow_logs_enabled: '통신 기록(Flow Logs)을 남기지 않습니다',
  vpc_different_regions: 'VPC가 여러 리전에 흩어져 있습니다',
  vpc_endpoint_connections_trust_boundaries: '다른 계정에서도 접근할 수 있습니다',
  vpc_subnet_no_public_ip_by_default: '만들어지는 서버에 공인 IP가 자동으로 붙습니다',
  vpc_subnet_different_az: '서브넷이 한 곳(가용 영역)에만 몰려 있습니다',

  // IAM
  iam_user_mfa_enabled_console_access: '추가 인증(MFA) 없이 콘솔에 로그인합니다',
  iam_root_mfa_enabled: '루트 계정에 추가 인증(MFA)이 없습니다',
  iam_root_hardware_mfa_enabled: '루트 계정에 하드웨어 인증 기기가 없습니다',
  iam_user_accesskey_unused: '오랫동안 쓰지 않은 액세스 키가 남아 있습니다',
  iam_rotate_access_key_90_days: '액세스 키를 90일 넘게 바꾸지 않았습니다',
  iam_policy_allows_privilege_escalation: '이 정책으로 더 큰 권한을 얻어낼 수 있습니다',
  iam_policy_attached_only_to_group_or_roles: '그룹이 아니라 사용자에게 직접 붙어 있습니다',
  iam_no_root_access_key: '루트 계정에 액세스 키가 있습니다',
  iam_user_no_setup_initial_access_key: '한 번도 쓰지 않은 최초 액세스 키가 있습니다',
  iam_user_hardware_mfa_enabled: '하드웨어 인증 기기를 쓰지 않습니다',
  iam_avoid_root_usage: '최근에 루트 계정으로 작업했습니다',
  iam_user_administrator_access_policy: '관리자 권한이 그대로 붙어 있습니다',
  iam_aws_attached_policy_no_administrative_privileges: '모든 권한을 주는 정책이 붙어 있습니다',
  iam_inline_policy_allows_privilege_escalation: '인라인 정책으로 더 큰 권한을 얻어낼 수 있습니다',
  iam_user_with_temporary_credentials: '만료 없는 액세스 키로 여러 서비스를 씁니다',
  // 'confused deputy'를 글자 그대로 옮기면 무슨 말인지 알 수 없다.
  // 신뢰 정책에 조건이 없어 남이 이 역할을 대신 쓰게 만들 수 있다는 뜻이다.
  iam_role_cross_service_confused_deputy_prevention: '다른 서비스가 이 역할을 몰래 쓸 수 있습니다',
  iam_check_saml_providers_sts: '회사 계정으로 로그인하는 연동(SAML)이 없습니다',
  iam_securityaudit_role_created: '보안 점검 전용 역할이 없습니다',
  iam_support_role_created: 'AWS에 지원을 요청할 역할이 없습니다',
  iam_user_access_not_stale_to_bedrock: 'Bedrock 권한을 받아두고 쓰지 않습니다',
  iam_role_access_not_stale_to_bedrock: 'Bedrock 권한을 받아두고 쓰지 않습니다',
  iam_user_access_not_stale_to_sagemaker: 'SageMaker 권한을 받아두고 쓰지 않습니다',

  // IAM — 비밀번호 정책
  iam_password_policy_minimum_length_14: '비밀번호를 14자 미만으로 쓸 수 있습니다',
  iam_password_policy_uppercase: '비밀번호에 대문자를 넣지 않아도 됩니다',
  iam_password_policy_lowercase: '비밀번호에 소문자를 넣지 않아도 됩니다',
  iam_password_policy_number: '비밀번호에 숫자를 넣지 않아도 됩니다',
  iam_password_policy_symbol: '비밀번호에 특수문자를 넣지 않아도 됩니다',
  iam_password_policy_reuse_24: '예전에 쓰던 비밀번호를 다시 쓸 수 있습니다',
  iam_password_policy_expires_passwords_within_90_days_or_less: '비밀번호를 90일 안에 바꾸지 않아도 됩니다',

  // S3
  s3_bucket_public_access: '누구나 볼 수 있게 공개되어 있습니다',
  s3_bucket_default_encryption: '저장되는 파일을 암호화하지 않습니다',
  s3_bucket_server_access_logging_enabled: '누가 접근했는지 기록하지 않습니다',
  s3_bucket_object_versioning: '이전 버전을 남기지 않아 되돌릴 수 없습니다',
  s3_account_level_public_access_blocks: '계정 전체의 공개 차단이 꺼져 있습니다',

  // CloudTrail
  cloudtrail_multi_region_enabled: '일부 리전의 활동이 기록되지 않습니다',
  cloudtrail_log_file_validation_enabled: '로그가 위변조됐는지 확인할 수 없습니다',
  cloudtrail_logs_s3_bucket_access_logging_enabled: '로그 보관함에 누가 접근했는지 남지 않습니다',
  cloudtrail_kms_encryption_enabled: '로그가 암호화되어 있지 않습니다',
  cloudtrail_multi_region_enabled_logging_management_events: '읽기·쓰기 활동 중 일부만 기록합니다',
  cloudtrail_bedrock_logging_enabled: 'Bedrock 호출 기록이 남지 않습니다',
}

// 점검에서 걸린 항목이 ISMS-P 인증기준 중 무엇에 닿는지.
//
// Prowler는 "AWS가 권하는 설정"을 본다. 여기에 국내 인증기준을 이어 두면
// "AWS 기준에 어긋난다"에서 "2.6.1 네트워크 접근에 걸린다"까지 말할 수 있다.
// 조치의 근거가 권고에서 규제로 올라간다.
//
// 손으로 적는 이유: 임베딩 유사도로 붙여 봤더니 관련 있는 것과 없는 것이 같은
// 점수 구간(0.29~0.36)에 섞여 나왔다. 규제 항목을 그 정확도로 붙이면 틀린 근거를
// 확신에 차서 말하게 된다. 자동화할 자리가 아니다.
//
// 붙이는 기준 — **인증기준의 '주요 확인사항'에 직접 대응하는 문장이 있을 때만 붙인다.**
// 영역이 얼추 맞는다고 붙이지 않는다. 첫판에 그렇게 했다가 이런 것들이 섞였다:
//   · 인바운드 개방에 2.6.7(인터넷 접속 통제) — 그 항목은 내부에서 밖으로 나가는 통제다
//   · SecurityAudit 역할에 1.4.2(관리체계 점검) — 그 항목은 점검할 '조직'을 꾸리라는 요구다
//   · confused deputy에 2.3.2(외부자 계약) — 그 항목은 계약서에 명시하라는 문서 요구다
// 그 결과 2.6.1에 12건이 몰렸는데, 항목이 넓어서가 아니라 부풀린 것이었다.
//
// 나머지 원칙:
//   1. **하나만 붙인다.** 둘을 대면 "그래서 어느 쪽 결함이냐"가 되어 근거로서 힘이 빠진다.
//      예외는 조치가 실제로 갈릴 때뿐이다 — EC2 퍼블릭 IP는 안 써도 되면 떼는 것이고(2.6.1)
//      공개가 목적이면 DMZ로 분리하는 것이라(2.10.3) 할 일이 달라진다.
//      반대로 SSH 개방은 2.6.6과 2.6.1에 다 걸리지만 할 일은 '접근 범위 축소' 하나다.
//   2. 대응이 없으면 빈 배열로 둔다. 목록에서 지우지는 않는다 —
//      지우면 새 체크가 늘었을 때 '아직 안 본 것'과 '보고 뺀 것'이 구별되지 않는다.
//
// 항목 번호와 제목은 「ISMS-P 인증기준 안내서」(2023.11) 기준이다.
export const ISMSP_MAP = {
  // 인터넷에서 들어오는 경로를 막는 것 — 2.6.1의 "모든 경로를 식별하고 인가된
  // 사용자만이 접근할 수 있도록 통제"에 곧바로 걸린다.
  ec2_networkacl_allow_ingress_any_port: ['2.6.1'],
  ec2_securitygroup_allow_ingress_from_internet_to_any_port: ['2.6.1'],
  ec2_securitygroup_default_restrict_traffic: ['2.6.1'],

  // 원격 관리 포트를 인터넷에 여는 것은 2.6.6이다 —
  // "인터넷과 같은 외부 네트워크를 통한 정보시스템 원격운영은 원칙적으로 금지"가 그대로 이 상황이다.
  // 2.6.1에도 걸리지만 할 일은 '접근 범위 축소' 하나라 붙이지 않는다.
  ec2_networkacl_allow_ingress_tcp_port_22: ['2.6.6'],
  ec2_networkacl_allow_ingress_tcp_port_3389: ['2.6.6'],
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: ['2.6.6'],
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389: ['2.6.6'],

  // "외부 연결이 필요하지 않은 경우 사설 IP로 할당하는 등의 대책"에 대응한다.
  vpc_subnet_no_public_ip_by_default: ['2.6.1'],
  // 둘을 남기는 유일한 자리. 안 써도 되면 떼는 것이고(2.6.1),
  // 공개가 목적이면 DMZ로 분리하고 보호대책을 세우는 것이라(2.10.3) 할 일이 갈린다.
  ec2_instance_public_ip: ['2.6.1', '2.10.3'],

  // 암호화
  ec2_ebs_volume_encryption: ['2.7.1'],
  ec2_ebs_default_encryption: ['2.7.1'],
  s3_bucket_default_encryption: ['2.7.1'],
  // 대상이 로그일 뿐 할 일은 암호화 적용이다.
  cloudtrail_kms_encryption_enabled: ['2.7.1'],

  // 계정과 인증
  iam_user_mfa_enabled_console_access: ['2.5.3'],
  iam_user_hardware_mfa_enabled: ['2.5.3'],
  // 외부 인증 공급자가 등록돼 있는지 — 누가 우리 계정에 들어올 수 있는지를 가리는 문제라 식별이다.
  iam_check_saml_providers_sts: ['2.5.2'],
  // MFA는 인증 수단이므로 2.5.3이다. 루트가 특수 계정인 것은 그다음 얘기이고
  // (2.5.5는 "권한을 최소 인원에게" "별도 목록으로 관리"를 요구하지 인증 방식을 다루지 않는다),
  // 어느 쪽으로 보든 할 일은 'MFA를 켠다' 하나다.
  iam_root_mfa_enabled: ['2.5.3'],
  iam_root_hardware_mfa_enabled: ['2.5.3'],
  // 반면 이 둘은 특수 계정 자체를 어떻게 쓰느냐의 문제다.
  iam_no_root_access_key: ['2.5.5'],
  iam_avoid_root_usage: ['2.5.5'],
  iam_user_no_setup_initial_access_key: ['2.5.1'],
  iam_user_with_temporary_credentials: ['2.5.1'],
  iam_policy_attached_only_to_group_or_roles: ['2.5.1'],

  // 비밀번호 정책은 전부 2.5.4 하나로 모인다.
  iam_password_policy_minimum_length_14: ['2.5.4'],
  iam_password_policy_uppercase: ['2.5.4'],
  iam_password_policy_lowercase: ['2.5.4'],
  iam_password_policy_number: ['2.5.4'],
  iam_password_policy_symbol: ['2.5.4'],
  iam_password_policy_reuse_24: ['2.5.4'],
  iam_password_policy_expires_passwords_within_90_days_or_less: ['2.5.4'],
  // 액세스 키도 "개인정보취급자의 인증수단을 안전하게 적용하고 관리"에 걸린다.
  iam_rotate_access_key_90_days: ['2.5.4'],

  // 과도한 권한 — "관리자 권한 등 특수권한은 최소한의 인원에게만"이 그대로 대응한다.
  // 2.5.6(정기 검토)은 재발을 막는 얘기고, 지금 할 일은 권한 회수 하나다.
  iam_user_administrator_access_policy: ['2.5.5'],
  iam_aws_attached_policy_no_administrative_privileges: ['2.5.5'],
  iam_policy_allows_privilege_escalation: ['2.5.5'],
  iam_inline_policy_allows_privilege_escalation: ['2.5.5'],

  // 안 쓰는 권한이 남아 있는 것 — 정기 검토(2.5.6)가 잡아내야 할 일이다.
  iam_user_accesskey_unused: ['2.5.6'],
  iam_user_access_not_stale_to_bedrock: ['2.5.6'],
  iam_role_access_not_stale_to_bedrock: ['2.5.6'],
  iam_user_access_not_stale_to_sagemaker: ['2.5.6'],

  // 공개 노출 — "조직의 중요정보가 웹을 통하여 노출되고 있는지 주기적으로 확인"에 대응.
  // 2.6.1(네트워크 접근)은 붙이지 않는다. S3는 네트워크 영역을 나누는 얘기가 아니다.
  s3_bucket_public_access: ['2.10.3'],
  s3_account_level_public_access_blocks: ['2.10.3'],

  // 로그
  vpc_flow_logs_enabled: ['2.9.4'],
  s3_bucket_server_access_logging_enabled: ['2.9.4'],
  cloudtrail_multi_region_enabled: ['2.9.4'],
  cloudtrail_multi_region_enabled_logging_management_events: ['2.9.4'],
  cloudtrail_logs_s3_bucket_access_logging_enabled: ['2.9.4'],
  cloudtrail_bedrock_logging_enabled: ['2.9.4'],
  // 위변조 확인 기능을 켜는 일이라 기록 관리 쪽이다. 2.9.5는 '주기적으로 검토하라'는
  // 운영 요구여서 설정 하나로 끝나지 않는다.
  cloudtrail_log_file_validation_enabled: ['2.9.4'],

  // 백업 — "백업 대상, 주기, 방법, 보관장소"에 대응한다.
  s3_bucket_object_versioning: ['2.9.3'],

  // ── 대응하는 인증기준이 없는 것들 ──
  // 목록에서 빼지 않고 빈 배열로 남긴다. 빼 버리면 체크가 늘었을 때
  // '아직 안 본 것'과 '보고 나서 뺀 것'을 구별할 수 없다. 이유도 함께 적는다.

  // AWS 고유의 구현·서비스라 대응 개념이 없다.
  ec2_instance_imdsv2_enabled: [],   // 인스턴스 메타데이터 서비스 버전
  ec2_elastic_ip_shodan: [],         // 외부 검색엔진(Shodan) 노출 여부

  // 영역은 비슷해 보이지만 확인사항이 요구하는 것이 다르다.
  ec2_securitygroup_not_used: [],                      // 2.1.3은 취급절차·책임자 지정을 요구
  ec2_securitygroup_with_many_ingress_egress_rules: [], // 규칙 수를 다루는 확인사항이 없음
  vpc_endpoint_connections_trust_boundaries: [],        // 2.6.1의 '영역 분리'에 억지로 붙였던 것
  iam_role_cross_service_confused_deputy_prevention: [], // 2.3.2는 계약서 명시 요구

  // 설정 하나가 아니라 조직·절차를 갖추라는 항목들이라 체크와 층위가 맞지 않는다.
  iam_securityaudit_role_created: [],  // 1.4.2는 점검할 조직을 꾸리라는 요구
  iam_support_role_created: [],        // 2.11.1은 사고 대응 절차·조직
  vpc_subnet_different_az: [],         // 2.12.1은 재해 유형 식별과 복구목표(RTO/RPO) 정의를
  vpc_different_regions: [],           // 요구한다. AZ·리전 분산은 그 계획의 구현 수단일 뿐
}

// 화면과 설명에 쓸 이름표. 매핑에 등장하는 것만 둔다 —
// 101개를 다 적으면 쓰지도 않는 표를 손으로 관리하게 된다.
export const ISMSP_LABEL = {
  '2.5.1': '사용자 계정 관리',
  '2.5.2': '사용자 식별',
  '2.5.3': '사용자 인증',
  '2.5.4': '비밀번호 관리',
  '2.5.5': '특수 계정 및 권한관리',
  '2.5.6': '접근권한 검토',
  '2.6.1': '네트워크 접근',
  '2.6.6': '원격접근 통제',
  '2.7.1': '암호정책 적용',
  '2.9.3': '백업 및 복구관리',
  '2.9.4': '로그 및 접속기록 관리',
  '2.10.3': '공개서버 보안',
}

// 체크 하나가 닿는 인증기준을 [{ no, title }]로. 없으면 빈 배열.
export function ismspFor(checkId) {
  return (ISMSP_MAP[checkId] || []).map((no) => ({ no, title: ISMSP_LABEL[no] || '' }))
}

// 표에 없으면 ID를 다듬어 보여준다.
// ec2_securitygroup_not_used → EC2 · securitygroup not used
export function checkLabel(checkId) {
  const known = CHECK_LABEL[checkId]
  if (known) return known

  const parts = String(checkId || '').split('_')
  if (parts.length < 2) return checkId || '-'
  const service = parts[0].toUpperCase()
  return `${service} · ${parts.slice(1).join(' ')}`
}

// 어떤 리소스에 대한 점검인지. 제목에는 상태만 쓰고 종류는 체크 ID 옆에 둔다.
// "SSH(22) 인바운드가 열려 있음"만 보면 NACL 얘긴지 SG 얘긴지 알 수 없다.
const KIND_RULES = [
  [/networkacl/, 'Network ACL'],
  [/securitygroup/, 'Security Group'],
  [/^ec2_instance/, 'EC2 인스턴스'],
  [/^ec2_ebs/, 'EBS'],
  [/^ec2_elastic_ip/, 'Elastic IP'],
  [/^ec2_ami/, 'AMI'],
  [/^vpc_subnet/, '서브넷'],
  [/^vpc_endpoint/, 'VPC 엔드포인트'],
  [/^vpc_/, 'VPC'],
  [/^iam_root/, '루트 계정'],
  [/^iam_avoid_root/, '루트 계정'],
  [/^iam_password_policy/, '비밀번호 정책'],
  [/^iam_inline_policy/, 'IAM 정책'],
  [/^iam_user/, 'IAM 사용자'],
  [/^iam_policy/, 'IAM 정책'],
  [/^iam_role/, 'IAM 역할'],
  [/^iam_/, 'IAM'],
  [/^s3_bucket/, 'S3 버킷'],
  [/^s3_/, 'S3'],
  [/^cloudtrail_/, 'CloudTrail'],
  [/^cloudwatch_/, 'CloudWatch'],
  [/^rds_/, 'RDS'],
  [/^kms_/, 'KMS'],
]

// 점검에서 걸린 항목을 어떤 신청으로 고칠 수 있는지.
//
// 없으면 null. 앱이 실제로 실행할 수 있는 조치만 이어준다 —
// MFA 등록이나 비밀번호 정책처럼 콘솔에서 사람이 해야 하는 건 버튼을 만들지 않는다.
// 있지도 않은 길을 열어두면 눌러본 사람이 헤맨다.
//
// 포트는 체크 ID에 들어 있다: ec2_securitygroup_..._tcp_port_22 → 22
export function remedyFor(checkId, resourceId) {
  const id = String(checkId || '')
  if (!resourceId) return null

  const portMatch = /_tcp_port_(\d+)$/.exec(id)
  const port = portMatch ? Number(portMatch[1]) : null
  const anyPort = /_to_any_port$/.test(id) || /_allow_ingress_any_port$/.test(id)

  // 보안 그룹이 인터넷에 열려 있는 경우 — 그 규칙을 지우는 신청
  if (/^ec2_securitygroup_allow_ingress_from_internet/.test(id)) {
    const rule = anyPort
      ? { direction: 'ingress', protocol: '-1', from_port: null, to_port: null, cidr: '0.0.0.0/0' }
      : port
        ? { direction: 'ingress', protocol: 'tcp', from_port: port, to_port: port, cidr: '0.0.0.0/0' }
        : null
    if (!rule) return null
    return {
      to: '/request/sg',
      label: 'SG 규칙 삭제 신청',
      state: {
        prefill: {
          mode: 'delete',
          check_id: id,
          sg_id: resourceId,
          rules: [rule],
          reason: `보안 점검에서 걸린 규칙 제거 (${id})`,
        },
      },
    }
  }

  // 네트워크 ACL에 특정 포트가 열려 있는 경우 — 앞 번호에 거부 규칙을 넣는 신청.
  //
  // 모든 포트가 열린 경우(_any_port)는 버튼을 만들지 않는다. 기본 NACL의 전체 허용을
  // 어떻게 좁힐지는 그 VPC에서 무엇이 오가는지 알아야 정할 수 있다.
  if (/^ec2_networkacl_allow_ingress_tcp_port_/.test(id) && port) {
    return {
      to: '/request/nacl',
      label: 'NACL 거부 규칙 신청',
      state: {
        prefill: {
          mode: 'create',
          check_id: id,
          nacl_id: resourceId,
          rules: [{
            rule_no: '70', direction: 'ingress', action: 'deny',
            protocol: 'tcp', port: String(port), cidr: '0.0.0.0/0',
          }],
          reason: `보안 점검에서 걸린 포트 차단 (${id})`,
        },
      },
    }
  }

  return null
}

export function checkKind(checkId) {
  const id = String(checkId || '')
  for (const [re, label] of KIND_RULES) if (re.test(id)) return label
  return id.split('_')[0]?.toUpperCase() || '-'
}
