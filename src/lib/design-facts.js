// 자동 생성 파일 — 손으로 고치지 말 것.
// scripts/rag/build-design-facts.mjs 가 design/virtual-company.yaml에서 만든다.
export default {
  "_generated": "scripts/rag/build-design-facts.mjs (design/virtual-company.yaml에서)",
  "account": "170420138507",
  "region": "ap-northeast-2",
  "cidrs": [
    {
      "cidr": "172.16.0.0/16",
      "vpc": "vpc-prod",
      "env": "prod",
      "class": "app",
      "internet_facing": true,
      "direct_access_forbidden": false,
      "pii": false,
      "subnets": [
        {
          "cidr": "172.16.1.0/24",
          "tier": "public"
        },
        {
          "cidr": "172.16.2.0/24",
          "tier": "public"
        },
        {
          "cidr": "172.16.11.0/24",
          "tier": "private"
        },
        {
          "cidr": "172.16.12.0/24",
          "tier": "private"
        }
      ]
    },
    {
      "cidr": "10.10.0.0/16",
      "vpc": "vpc-dev",
      "env": "dev",
      "class": "env",
      "internet_facing": false,
      "direct_access_forbidden": false,
      "pii": false,
      "subnets": [
        {
          "cidr": "10.10.1.0/24",
          "tier": "public"
        },
        {
          "cidr": "10.10.2.0/24",
          "tier": "public"
        },
        {
          "cidr": "10.10.11.0/24",
          "tier": "private"
        },
        {
          "cidr": "10.10.12.0/24",
          "tier": "private"
        }
      ]
    },
    {
      "cidr": "10.20.0.0/16",
      "vpc": "vpc-qa",
      "env": "qa",
      "class": "env",
      "internet_facing": false,
      "direct_access_forbidden": false,
      "pii": false,
      "subnets": [
        {
          "cidr": "10.20.1.0/24",
          "tier": "public"
        },
        {
          "cidr": "10.20.2.0/24",
          "tier": "public"
        },
        {
          "cidr": "10.20.11.0/24",
          "tier": "private"
        },
        {
          "cidr": "10.20.12.0/24",
          "tier": "private"
        }
      ]
    },
    {
      "cidr": "192.168.0.0/16",
      "vpc": "vpc-db",
      "env": "db",
      "class": "general_db",
      "internet_facing": false,
      "direct_access_forbidden": true,
      "pii": false,
      "subnets": [
        {
          "cidr": "192.168.1.0/24",
          "tier": "data"
        },
        {
          "cidr": "192.168.2.0/24",
          "tier": "data"
        }
      ]
    },
    {
      "cidr": "10.99.0.0/16",
      "vpc": "vpc-pii",
      "env": "pii",
      "class": "pii_db",
      "internet_facing": false,
      "direct_access_forbidden": true,
      "pii": true,
      "subnets": [
        {
          "cidr": "10.99.1.0/24",
          "tier": "data"
        },
        {
          "cidr": "10.99.2.0/24",
          "tier": "data"
        }
      ]
    }
  ],
  "internal_cidrs": [
    "172.16.0.0/16",
    "10.10.0.0/16",
    "10.20.0.0/16",
    "192.168.0.0/16",
    "10.99.0.0/16"
  ],
  "general_db_allowed_sources": [
    "172.16.11.0/24",
    "172.16.12.0/24"
  ],
  "nat_egress_ips": {
    "dev": "43.201.10.21",
    "qa": "43.201.10.22",
    "prod": "43.201.10.23"
  }
}
