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
