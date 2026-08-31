export const dashboardStats = {
  totalRequests: 12540,
  threatsDetected: 127,
  criticalThreats: 12,
  blockedThreats: 45
};
export const threats = [
  {
    id: "T001",
    timestamp: "18:30:12",
    sourceIp: "192.168.1.10",
    attackType: "DoS",
    riskScore: 92,
    severity: "CRITICAL",
    action: "BLOCK"
  },
  {
    id: "T002",
    timestamp: "18:25:43",
    sourceIp: "10.0.0.24",
    attackType: "Port Scan",
    riskScore: 71,
    severity: "HIGH",
    action: "ALERT"
  },
  {
    id: "T003",
    timestamp: "18:20:18",
    sourceIp: "172.16.0.15",
    attackType: "Brute Force",
    riskScore: 85,
    severity: "CRITICAL",
    action: "BLOCK"
  },
  {
    id: "T004",
    timestamp: "18:16:05",
    sourceIp: "192.168.1.45",
    attackType: "API Abuse",
    riskScore: 64,
    severity: "HIGH",
    action: "RATE LIMIT"
  },
  {
    id: "T005",
    timestamp: "18:10:31",
    sourceIp: "10.0.0.52",
    attackType: "Normal",
    riskScore: 12,
    severity: "LOW",
    action: "ALLOW"
  }
];
export const attackStatistics = [
  {
    name: "DoS",
    count: 35
  },
  {
    name: "Port Scan",
    count: 25
  },
  {
    name: "Brute Force",
    count: 20
  },
  {
    name: "API Abuse",
    count: 15
  },
  {
    name: "Other",
    count: 5
  }
];
export const riskDistribution = [
  {
    name: "LOW",
    count: 35
  },
  {
    name: "MEDIUM",
    count: 28
  },
  {
    name: "HIGH",
    count: 42
  },
  {
    name: "CRITICAL",
    count: 22
  }
];