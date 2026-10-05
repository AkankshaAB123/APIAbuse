/* =========================================================
   MOCK DATA
   AI-Based API Abuse Threat Detection System
========================================================= */


/* =========================================================
   DASHBOARD STATISTICS
========================================================= */

export const dashboardStats = {
  totalRequests: 12540,
  threatsDetected: 127,
  criticalThreats: 12,
  blockedThreats: 45
};


/* =========================================================
   RECENT THREATS
========================================================= */

export const threats = [
  {
    id: "THREAT-001",
    time: "18:30:12",
    sourceIp: "192.168.1.10",
    attackType: "SQL Injection",
    riskScore: 96,
    severity: "CRITICAL",
    action: "BLOCK",
    endpoint: "/api/users",
    method: "GET",
    detection: "Boolean-based SQL injection detected",
    anomaly: false
  },

  {
    id: "THREAT-002",
    time: "18:25:43",
    sourceIp: "10.0.0.24",
    attackType: "BOLA / IDOR",
    riskScore: 97,
    severity: "CRITICAL",
    action: "BLOCK",
    endpoint: "/api/users/456",
    method: "GET",
    detection: "Resource owner mismatch detected",
    anomaly: false
  },

  {
    id: "THREAT-003",
    time: "18:20:18",
    sourceIp: "172.16.0.15",
    attackType: "Credential Attack",
    riskScore: 85,
    severity: "CRITICAL",
    action: "BLOCK",
    endpoint: "/api/login",
    method: "POST",
    detection: "Multiple failed authentication attempts",
    anomaly: true
  },

  {
    id: "THREAT-004",
    time: "18:16:05",
    sourceIp: "192.168.1.45",
    attackType: "Resource Exhaustion",
    riskScore: 64,
    severity: "HIGH",
    action: "RATE LIMIT",
    endpoint: "/api/search",
    method: "GET",
    detection: "Abnormally high request frequency",
    anomaly: true
  },

  {
    id: "THREAT-005",
    time: "18:10:31",
    sourceIp: "10.0.0.52",
    attackType: "Normal",
    riskScore: 12,
    severity: "LOW",
    action: "ALLOW",
    endpoint: "/api/products",
    method: "GET",
    detection: "Normal API activity",
    anomaly: false
  }
];


/* =========================================================
   ATTACK STATISTICS
========================================================= */

export const attackStatistics = [
  {
    name: "SQL Injection",
    value: 24
  },
  {
    name: "BOLA / IDOR",
    value: 19
  },
  {
    name: "Credential Attack",
    value: 18
  },
  {
    name: "SSRF",
    value: 15
  },
  {
    name: "Account Takeover",
    value: 12
  },
  {
    name: "Resource Exhaustion",
    value: 10
  },
  {
    name: "Privilege Escalation",
    value: 9
  },
  {
    name: "Business Flow Abuse",
    value: 8
  },
  {
    name: "Endpoint Enumeration",
    value: 7
  },
  {
    name: "Misconfiguration",
    value: 5
  }
];


/* =========================================================
   RISK DISTRIBUTION
========================================================= */

export const riskDistribution = [
  {
    name: "Critical",
    value: 18
  },
  {
    name: "High",
    value: 31
  },
  {
    name: "Medium",
    value: 42
  },
  {
    name: "Low",
    value: 36
  }
];


/* =========================================================
   ATTACK SIMULATION SCENARIOS
========================================================= */

export const attacks = [

  /* -------------------------------------------------------
     1. BOLA / IDOR
  ------------------------------------------------------- */

  {
    id: "bola",
    name: "BOLA / IDOR",
    description:
      "Attempts to access a resource belonging to another user.",
    method: "GET",
    endpoint: "/api/users/456",

    payload: {
      source_ip: "192.168.1.20",
      user_id: "user_17",
      object_id: "456",
      target_user_id: "user_99"
    }
  },


  /* -------------------------------------------------------
     2. BROKEN FUNCTION LEVEL AUTHORIZATION
  ------------------------------------------------------- */

  {
    id: "privilege",
    name: "Privilege Escalation",
    description:
      "A normal user attempts to access an administrative API function.",
    method: "GET",
    endpoint: "/api/admin/users",

    payload: {
      source_ip: "192.168.1.21",
      user_id: "user_17",
      object_id: "admin-users",
      target_user_id: "admin"
    }
  },


  /* -------------------------------------------------------
     3. CREDENTIAL ATTACK
  ------------------------------------------------------- */

  {
    id: "credential",
    name: "Credential Attack",
    description:
      "Simulates repeated failed login attempts.",
    method: "POST",
    endpoint: "/api/login",

    payload: {
      source_ip: "10.0.0.24",
      user_id: "user_42",
      object_id: "login",
      failed_attempts: 15,
      action: "login",
      status_code: 401
    }
  },


  /* -------------------------------------------------------
     4. ACCOUNT TAKEOVER
  ------------------------------------------------------- */

  {
    id: "account-takeover",
    name: "Account Takeover",
    description:
      "Simulates suspicious access to a sensitive account.",
    method: "POST",
    endpoint: "/api/account/settings",

    payload: {
      source_ip: "172.16.0.15",
      user_id: "user_88",
      object_id: "account-88",
      target_user_id: "user_88",
      failed_attempts: 8,
      action: "password_change",
      status_code: 200
    }
  },


  /* -------------------------------------------------------
     5. SQL INJECTION
  ------------------------------------------------------- */

  {
    id: "sql-injection",
    name: "SQL Injection",
    description:
      "Attempts to inject a malicious SQL condition through an API parameter.",
    method: "GET",
    endpoint: "/api/users",

    payload: {
      source_ip: "192.168.1.10",
      user_id: "user_17",

      /*
       * IMPORTANT:
       * This value is intentionally malicious so that the
       * backend SQL injection detector can identify it.
       */
      suspicious_pattern: "' OR 1=1",

      object_id: "1"
    }
  },


  /* -------------------------------------------------------
     6. SSRF
  ------------------------------------------------------- */

  {
    id: "ssrf",
    name: "SSRF",
    description:
      "Attempts to make the API request a restricted internal URL.",
    method: "GET",
    endpoint: "/api/fetch",

    payload: {
      source_ip: "192.168.1.30",
      user_id: "user_17",
      object_id: "metadata",

      suspicious_url:
        "http://169.254.169.254/latest/meta-data/"
    }
  },


  /* -------------------------------------------------------
     7. RESOURCE EXHAUSTION
  ------------------------------------------------------- */

  {
    id: "resource-exhaustion",
    name: "Resource Exhaustion",
    description:
      "Simulates excessive API requests intended to consume server resources.",
    method: "GET",
    endpoint: "/api/search",

    payload: {
      source_ip: "192.168.1.40",
      user_id: "user_50",
      object_id: "search",
      request_count: 25
    }
  },


  /* -------------------------------------------------------
     8. BUSINESS FLOW ABUSE
  ------------------------------------------------------- */

  {
    id: "business-flow",
    name: "Business Flow Abuse",
    description:
      "Simulates automated abuse of a sensitive business operation.",
    method: "POST",
    endpoint: "/api/orders",

    payload: {
      source_ip: "192.168.1.50",
      user_id: "user_60",
      object_id: "order",
      action: "purchase",
      action_count: 15
    }
  },


  /* -------------------------------------------------------
     9. API RECONNAISSANCE / ENDPOINT ENUMERATION
  ------------------------------------------------------- */

  {
    id: "recon",
    name: "API Reconnaissance",
    description:
      "Simulates a user probing multiple API endpoints.",
    method: "GET",
    endpoint: "/api/admin",

    payload: {
      source_ip: "10.0.0.50",
      user_id: "user_70",
      object_id: "recon",

      endpoints_requested: [
        "/api/users",
        "/api/admin",
        "/api/orders",
        "/api/payments",
        "/api/config",
        "/api/internal"
      ]
    }
  },


  /* -------------------------------------------------------
     10. SECURITY MISCONFIGURATION
  ------------------------------------------------------- */

  {
    id: "misconfiguration",
    name: "Security Misconfiguration",
    description:
      "Simulates access to an exposed or improperly secured API endpoint.",
    method: "GET",
    endpoint: "/api/internal/config",

    payload: {
      source_ip: "10.0.0.60",
      user_id: null,
      object_id: "config",

      exposed_endpoint: true,
      is_authenticated: false
    }
  }

];


/* =========================================================
   ALIAS
   =========================================================
   Some components may use attackScenarios instead of
   attacks. Both point to the same simulation data.
========================================================= */

export const attackScenarios = attacks;


/* =========================================================
   DEFAULT EXPORT
========================================================= */

export default {
  dashboardStats,
  threats,
  attackStatistics,
  riskDistribution,
  attacks,
  attackScenarios
};