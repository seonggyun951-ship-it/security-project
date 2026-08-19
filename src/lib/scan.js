// 점검 체크 ID를 사람이 읽는 이름으로.
//
// Prowler 체크 ID(ec2_networkacl_allow_ingress_any_port)를 그대로 제목에 쓰면
// 목록을 훑을 때 무엇이 문제인지 읽히지 않는다. 자주 나오는 것만 옮겨 적고,
// 없는 것은 ID를 다듬어 보여준다.
//
// 전부 옮기지 않는 이유: Prowler 체크가 640개고 계속 늘어난다. 손으로 적은 표가
// 원본보다 뒤처지면 틀린 이름이 남는다. 여기 있는 것은 실제로 걸린 적 있는 것들이다.

export const CHECK_LABEL = {
  // EC2 / 네트워크
  ec2_networkacl_allow_ingress_any_port: '모든 포트 인바운드가 열려 있음',
  ec2_networkacl_allow_ingress_tcp_port_22: 'SSH(22) 인바운드가 열려 있음',
  ec2_networkacl_allow_ingress_tcp_port_3389: 'RDP(3389) 인바운드가 열려 있음',
  ec2_securitygroup_allow_ingress_from_internet_to_any_port: '모든 포트가 인터넷에 열려 있음',
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22: 'SSH(22)가 인터넷에 열려 있음',
  ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389: 'RDP(3389)가 인터넷에 열려 있음',
  ec2_securitygroup_not_used: '어디에도 연결되지 않은 보안 그룹',
  ec2_securitygroup_default_restrict_traffic: '기본 보안 그룹이 트래픽을 막고 있지 않음',
  ec2_securitygroup_with_many_ingress_egress_rules: '규칙이 너무 많은 보안 그룹',
  ec2_instance_public_ip: '퍼블릭 IP가 붙어 있는 인스턴스',
  ec2_instance_imdsv2_enabled: 'IMDSv2가 강제되지 않은 인스턴스',
  ec2_ebs_volume_encryption: '암호화되지 않은 EBS 볼륨',
  ec2_ebs_default_encryption: 'EBS 기본 암호화가 꺼져 있음',
  ec2_elastic_ip_shodan: '외부 스캔 서비스에 노출된 Elastic IP',

  // VPC
  vpc_flow_logs_enabled: 'Flow Logs가 꺼져 있음',
  vpc_different_regions: 'VPC가 여러 리전에 흩어져 있음',
  vpc_endpoint_connections_trust_boundaries: '신뢰 경계를 벗어난 VPC 엔드포인트',
  vpc_subnet_no_public_ip_by_default: '퍼블릭 IP를 자동 할당하는 서브넷',
  vpc_subnet_different_az: '한 가용 영역에만 있는 서브넷',

  // IAM
  iam_user_mfa_enabled_console_access: 'MFA 없이 콘솔을 쓰는 사용자',
  iam_root_mfa_enabled: '루트 계정에 MFA가 없음',
  iam_root_hardware_mfa_enabled: '루트 계정에 하드웨어 MFA가 없음',
  iam_user_accesskey_unused: '오래 쓰지 않은 액세스 키',
  iam_rotate_access_key_90_days: '90일 넘게 교체하지 않은 액세스 키',
  iam_password_policy_minimum_length_14: '비밀번호 최소 길이가 14자 미만',
  iam_policy_allows_privilege_escalation: '권한 상승이 가능한 정책',
  iam_policy_attached_only_to_group_or_roles: '사용자에게 직접 붙은 정책',
  iam_no_root_access_key: '루트 계정에 액세스 키가 있음',
  iam_user_no_setup_initial_access_key: '사용하지 않은 초기 액세스 키',

  // S3
  s3_bucket_public_access: '공개된 S3 버킷',
  s3_bucket_default_encryption: '기본 암호화가 꺼진 S3 버킷',
  s3_bucket_server_access_logging_enabled: '접근 로깅이 꺼진 S3 버킷',
  s3_bucket_object_versioning: '버전 관리가 꺼진 S3 버킷',
  s3_account_level_public_access_blocks: '계정 수준 퍼블릭 차단이 꺼져 있음',

  // CloudTrail
  cloudtrail_multi_region_enabled: '여러 리전을 기록하지 않는 CloudTrail',
  cloudtrail_log_file_validation_enabled: '로그 파일 검증이 꺼진 CloudTrail',
  cloudtrail_logs_s3_bucket_access_logging_enabled: '로그 버킷에 접근 로깅이 없음',
  cloudtrail_kms_encryption_enabled: 'KMS로 암호화되지 않은 CloudTrail 로그',
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

export function checkKind(checkId) {
  const id = String(checkId || '')
  for (const [re, label] of KIND_RULES) if (re.test(id)) return label
  return id.split('_')[0]?.toUpperCase() || '-'
}
