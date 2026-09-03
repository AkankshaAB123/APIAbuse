import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { processEvent } from "../services/api";


/* =========================================================
   ATTACK SCENARIOS
========================================================= */

const attackScenarios = [
  {
    id: "bola",
    name: "BOLA / IDOR",
    description:
      "Simulates unauthorized access to another user's resource by manipulating an object ID.",
    method: "GET",
    endpoint: "/api/orders/42",
    payload: {
      user_id: "user_17",
      target_user_id: "user_42",
      object_id: "42",
    },
  },

  {
    id: "privilege",
    name: "Privilege Escalation",
    description:
      "Simulates a non-privileged user attempting to access a privileged API function.",
    method: "POST",
    endpoint: "/api/admin/users",
    payload: {
      user_id: "user_17",
      role: "user",
      requested_role: "admin",
    },
  },

  {
    id: "credential",
    name: "Credential Attack",
    description:
      "Simulates repeated failed authentication attempts against an API account.",
    method: "POST",
    endpoint: "/api/login",
    payload: {
      username: "demo_user",
      user_id: "demo_user",
      failed_attempts: 5,
      source_ip: "192.168.1.20",
      action: "login",
      status_code: 401,
    },
  },

  {
    id: "account-takeover",
    name: "Account Takeover",
    description:
      "Simulates multiple failed logins followed by a successful authentication from the same source.",
    method: "POST",
    endpoint: "/api/login",
    payload: {
      user_id: "user_17",
      username: "user_17",
      source_ip: "192.168.1.25",
      action: "login",
    },
  },

  {
    id: "sql-injection",
    name: "SQL Injection",
    description:
      "Simulates a suspicious API request containing an SQL injection pattern.",
    method: "GET",
    endpoint: "/api/users",
    payload: {
      parameter: "id",
      suspicious_pattern: "' OR 1=1",
      object_id: "1",
      source_ip: "192.168.1.10",
      user_id: "user_17",
    },
  },

  {
    id: "ssrf",
    name: "SSRF",
    description:
      "Simulates an API request attempting to make the server access a restricted resource.",
    method: "GET",
    endpoint: "/api/fetch",
    payload: {
      url: "http://169.254.169.254/latest/meta-data/",
      source_ip: "192.168.1.30",
      user_id: "user_17",
    },
  },

  {
    id: "resource",
    name: "Resource Exhaustion",
    description:
      "Simulates high-volume requests targeting the same resource-intensive API endpoint.",
    method: "GET",
    endpoint: "/api/search",
    payload: {
      request_count: 10,
      time_window: "60 seconds",
      source_ip: "192.168.1.40",
      user_id: "user_50",
      object_id: "search",
    },
  },

  {
    id: "misconfiguration",
    name: "Security Misconfiguration",
    description:
      "Simulates access to an exposed or improperly protected configuration endpoint.",
    method: "GET",
    endpoint: "/api/debug",
    payload: {
      authentication: "missing",
      exposed_endpoint: true,
      source_ip: "192.168.1.60",
      user_id: null,
      object_id: "debug",
    },
  },

  {
    id: "business-flow",
    name: "Business Flow Abuse",
    description:
      "Simulates abnormal repetition of a legitimate sensitive business operation.",
    method: "POST",
    endpoint: "/api/checkout",
    payload: {
      user_id: "user_17",
      quantity: 1000,
      repeated_requests: true,
      action: "checkout",
      source_ip: "192.168.1.50",
      object_id: "checkout",
    },
  },

  {
    id: "recon",
    name: "API Reconnaissance",
    description:
      "Simulates requests used to discover multiple available API endpoints.",
    method: "GET",
    endpoint: "/api/",
    payload: {
      endpoints_requested: 5,
      time_window: "30 seconds",
      source_ip: "192.168.1.70",
      user_id: "user_70",
    },
  },
];


/* =========================================================
   CREATE UNIQUE EVENT ID
========================================================= */

function createEventId() {
  return `SIM-${Date.now()}-${Math.random()
    .toString(36)
    .slice(2, 8)}`;
}


/* =========================================================
   CREATE UNIQUE SIMULATION IDENTITY
========================================================= */

/*
   Every time the user starts a new simulation, we create
   a new source IP and user ID.

   This prevents events from an earlier simulation from
   interfering with the current simulation's detector
   windows in MongoDB.
*/

function createSimulationIdentity() {

  const randomPart =
    Math.floor(
      Math.random() * 200
    ) + 20;

  const randomUserPart =
    Math.random()
      .toString(36)
      .slice(2, 7);

  return {
    sourceIp: `10.250.${randomPart}.${Math.floor(
      Math.random() * 200
    ) + 20}`,

    userId: `sim_user_${Date.now()}_${randomUserPart}`,
  };
}


/* =========================================================
   BUILD BACKEND EVENT
========================================================= */

function buildBackendEvent(
  attack,
  overrides = {}
) {

  const payload = {
    ...attack.payload,
    ...overrides,
  };


  const sourceIp =
    payload.source_ip ||
    "10.250.1.100";


  const userId =
    payload.user_id ||
    "sim_user";


  const resourceId =
    payload.object_id ||
    "42";


  /* =======================================================
     REQUEST BODY
  ======================================================= */

  let body = null;

  if (attack.method !== "GET") {
    body = payload;
  }


  /* =======================================================
     QUERY PARAMETERS
  ======================================================= */

  let queryParams = {};


  if (attack.id === "sql-injection") {

    queryParams = {
      id:
        payload.suspicious_pattern,
    };
  }


  if (attack.id === "ssrf") {

    queryParams = {
      url:
        payload.url,
    };
  }


  /* =======================================================
     RESOURCE INFORMATION
  ======================================================= */

  const resource = {

    resource_type:
      attack.id === "bola"
        ? "user"
        : "api_resource",

    resource_id:
      resourceId,

    owner_id:
      attack.id === "bola"
        ? payload.target_user_id
        : userId,

    is_sensitive:
      attack.id === "bola" ||
      attack.id === "account-takeover",
  };


  /* =======================================================
     RESPONSE STATUS
  ======================================================= */

  let statusCode = 200;


  if (
    attack.id === "credential" ||
    overrides.failed_login === true
  ) {

    statusCode = 401;
  }


  if (
    overrides.successful_login === true
  ) {

    statusCode = 200;
  }


  /* =======================================================
     AUTHENTICATION
  ======================================================= */

  let isAuthenticated =
    attack.id !==
    "misconfiguration";


  if (
    overrides.successful_login === true
  ) {

    isAuthenticated = true;
  }


  if (
    overrides.failed_login === true
  ) {

    isAuthenticated = false;
  }


  /* =======================================================
     USER ROLES
  ======================================================= */

  let roles = ["user"];


  if (overrides.roles) {

    roles =
      overrides.roles;
  }


  /* =======================================================
     SESSION
  ======================================================= */

  const sessionId =
    overrides.session_id ||
    `session-${userId}`;


  /* =======================================================
     FINAL EVENT
  ======================================================= */

  return {

    schema_version: "1.0",

    event_id:
      createEventId(),

    timestamp:
      new Date().toISOString(),

    network: {

      source_ip:
        sourceIp,

      user_agent:
        "ThreatGuard-Simulator",
    },

    identity: {

      user_id:
        userId,

      session_id:
        sessionId,

      roles:
        roles,

      is_authenticated:
        isAuthenticated,
    },

    request: {

      method:
        attack.method,

      endpoint:
        overrides.endpoint ||
        attack.endpoint,

      path_params: {

        object_id:
          resourceId,
      },

      query_params:
        queryParams,

      headers: {

        "X-Simulation":
          "true",

      },

      body:
        body,
    },

    response: {

      status_code:
        statusCode,

      latency_ms:
        120,
    },

    resource:
      resource,
  };
}


/* =========================================================
   DISPLAY ENDPOINT
========================================================= */

function getDisplayEndpoint(
  attack
) {

  if (
    attack.id ===
    "sql-injection"
  ) {

    return `/api/users?id=${encodeURIComponent(
      attack.payload.suspicious_pattern
    )}`;
  }


  if (
    attack.id ===
    "ssrf"
  ) {

    return `/api/fetch?url=${encodeURIComponent(
      attack.payload.url
    )}`;
  }


  return attack.endpoint;
}


/* =========================================================
   SEND EVENT
========================================================= */

async function sendEvent(
  attack,
  overrides = {}
) {

  const event =
    buildBackendEvent(
      attack,
      overrides
    );


  return processEvent(
    event
  );
}


/* =========================================================
   ATTACK SIMULATION
========================================================= */

function AttackSimulation() {

  const navigate =
    useNavigate();


  /* =======================================================
     STATE
  ======================================================= */

  const [
    selectedAttack,
    setSelectedAttack
  ] = useState(
    attackScenarios[0]
  );


  const [
    logs,
    setLogs
  ] = useState([

    "> Attack Simulation Console initialized.",

    "> Controlled local demonstration mode.",

    "> Select an attack scenario to begin.",

  ]);


  const [
    running,
    setRunning
  ] = useState(false);


  const [
    latestResult,
    setLatestResult
  ] = useState(null);


  /* =======================================================
     RUN SIMULATION
  ======================================================= */

  const runSimulation =
    async () => {

      if (running) {
        return;
      }


      setRunning(true);


      /*
         Remove the previous result while the new
         simulation is running.
      */

      setLatestResult(null);


      /*
         IMPORTANT:

         Generate ONE unique identity for this
         complete simulation.

         Every request inside this simulation
         uses the same IP and user.

         A new simulation gets a new IP/user.
      */

      const simulationIdentity =
        createSimulationIdentity();


      const simulationIp =
        simulationIdentity.sourceIp;


      const simulationUser =
        simulationIdentity.userId;


      const displayEndpoint =
        getDisplayEndpoint(
          selectedAttack
        );


      setLogs([

        "> Simulation started.",

        `> Attack: ${selectedAttack.name}`,

        `> Method: ${selectedAttack.method}`,

        `> Endpoint: ${displayEndpoint}`,

        `> Simulation Source IP: ${simulationIp}`,

        `> Simulation User: ${simulationUser}`,

        "> Preparing controlled attack sequence...",

      ]);


      try {

        let result = null;


        /* =================================================
           BOLA / IDOR
        ================================================= */

        if (
          selectedAttack.id ===
          "bola"
        ) {

          setLogs(
            previous => [

              ...previous,

              "> Sending BOLA request...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                user_id:
                  simulationUser,

                /*
                   Keep target owner different from
                   authenticated user so BOLA detector
                   correctly identifies the mismatch.
                */

                target_user_id:
                  "protected_owner",

                object_id:
                  "42",

              }

            );
        }


        /* =================================================
           PRIVILEGE ESCALATION
        ================================================= */

        else if (
          selectedAttack.id ===
          "privilege"
        ) {

          setLogs(
            previous => [

              ...previous,

              "> Authenticated USER role requesting ADMIN endpoint...",

              "> Sending privilege escalation request...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                user_id:
                  simulationUser,

                roles:
                  ["user"],

              }

            );
        }


        /* =================================================
           SQL INJECTION
        ================================================= */

        else if (
          selectedAttack.id ===
          "sql-injection"
        ) {

          setLogs(
            previous => [

              ...previous,

              "> Sending SQL injection request...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                user_id:
                  simulationUser,

              }

            );
        }


        /* =================================================
           SSRF
        ================================================= */

        else if (
          selectedAttack.id ===
          "ssrf"
        ) {

          setLogs(
            previous => [

              ...previous,

              "> Sending SSRF request targeting cloud metadata...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                user_id:
                  simulationUser,

              }

            );
        }


        /* =================================================
           SECURITY MISCONFIGURATION
        ================================================= */

        else if (
          selectedAttack.id ===
          "misconfiguration"
        ) {

          setLogs(
            previous => [

              ...previous,

              "> Accessing exposed configuration endpoint...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                user_id:
                  simulationUser,

              }

            );
        }


        /* =================================================
           CREDENTIAL ATTACK
        ================================================= */

        else if (
          selectedAttack.id ===
          "credential"
        ) {

          const username =
            simulationUser;


          /*
             Send five failed login attempts
             from the SAME unique IP.
          */

          for (
            let i = 1;
            i <= 5;
            i++
          ) {

            setLogs(
              previous => [

                ...previous,

                `> Failed login attempt ${i}/5...`,

              ]
            );


            result =
              await sendEvent(

                selectedAttack,

                {

                  source_ip:
                    simulationIp,

                  username:
                    username,

                  user_id:
                    simulationUser,

                  failed_login:
                    true,

                }

              );
          }
        }


        /* =================================================
           ACCOUNT TAKEOVER
        ================================================= */

        else if (
          selectedAttack.id ===
          "account-takeover"
        ) {

          const username =
            simulationUser;


          const sessionId =
            `session-ato-${Date.now()}`;


          /*
             THREE FAILED LOGINS
          */

          for (
            let i = 1;
            i <= 3;
            i++
          ) {

            setLogs(
              previous => [

                ...previous,

                `> Failed authentication ${i}/3...`,

              ]
            );


            result =
              await sendEvent(

                selectedAttack,

                {

                  source_ip:
                    simulationIp,

                  username:
                    username,

                  user_id:
                    simulationUser,

                  failed_login:
                    true,

                  session_id:
                    sessionId,

                }

              );
          }


          /*
             SUCCESSFUL LOGIN
          */

          setLogs(
            previous => [

              ...previous,

              "> Suspicious successful login detected in sequence...",

              "> Sending successful authentication...",

            ]
          );


          result =
            await sendEvent(

              selectedAttack,

              {

                source_ip:
                  simulationIp,

                username:
                  username,

                user_id:
                  simulationUser,

                successful_login:
                  true,

                session_id:
                  sessionId,

              }

            );
        }


        /* =================================================
           RESOURCE EXHAUSTION
        ================================================= */

        else if (
          selectedAttack.id ===
          "resource"
        ) {

          const endpoint =
            selectedAttack.endpoint;


          /*
             Send ten requests to the SAME endpoint
             from the SAME unique IP.

             This is exactly what the detector needs.
          */

          for (
            let i = 1;
            i <= 10;
            i++
          ) {

            setLogs(
              previous => [

                ...previous,

                `> Request ${i}/10 → ${endpoint}`,

              ]
            );


            result =
              await sendEvent(

                selectedAttack,

                {

                  source_ip:
                    simulationIp,

                  user_id:
                    simulationUser,

                  endpoint:
                    endpoint,

                }

              );
          }
        }


        /* =================================================
           BUSINESS FLOW ABUSE
        ================================================= */

        else if (
          selectedAttack.id ===
          "business-flow"
        ) {

          const endpoint =
            selectedAttack.endpoint;


          /*
             Five business actions from the SAME
             user and SAME IP.
          */

          for (
            let i = 1;
            i <= 5;
            i++
          ) {

            setLogs(
              previous => [

                ...previous,

                `> Business action ${i}/5 → ${endpoint}`,

              ]
            );


            result =
              await sendEvent(

                selectedAttack,

                {

                  source_ip:
                    simulationIp,

                  user_id:
                    simulationUser,

                  endpoint:
                    endpoint,

                }

              );
          }
        }


        /* =================================================
           API RECONNAISSANCE
        ================================================= */

        else if (
          selectedAttack.id ===
          "recon"
        ) {

          const endpoints = [

            "/api/users",

            "/api/orders",

            "/api/products",

            "/api/payments",

            "/api/profile",

          ];


          /*
             Five DIFFERENT endpoints from the SAME
             unique source IP.

             This should trigger ONLY the
             Endpoint Enumeration detector,
             assuming no other detector condition
             is satisfied.
          */

          for (
            let i = 0;
            i < endpoints.length;
            i++
          ) {

            setLogs(
              previous => [

                ...previous,

                `> Endpoint ${i + 1}/5 → ${endpoints[i]}`,

              ]
            );


            result =
              await sendEvent(

                selectedAttack,

                {

                  source_ip:
                    simulationIp,

                  user_id:
                    simulationUser,

                  endpoint:
                    endpoints[i],

                }

              );
          }
        }


        /* =================================================
           VALIDATE BACKEND RESULT
        ================================================= */

        if (!result) {

          throw new Error(
            "No backend result was returned."
          );
        }


        /* =================================================
           SAVE FINAL RESULT
        ================================================= */

        /*
           IMPORTANT:

           Store the final response in React state.

           This makes the View Threat Details
           button appear.
        */

        setLatestResult(
          result
        );


        /*
           Save the same result in localStorage.

           ThreatDetails.jsx uses this information
           when the user opens the details page.
        */

        localStorage.setItem(

          "latestThreat",

          JSON.stringify(
            result
          )

        );


        /* =================================================
           EXTRACT RESULT INFORMATION
        ================================================= */

        const threatDetected =
          result
            .risk_assessment
            ?.threat_detected;


        const riskScore =
          result
            .risk_assessment
            ?.risk_score;


        const riskLevel =
          result
            .risk_assessment
            ?.risk_level;


        const attackTypes =
          result
            .risk_assessment
            ?.attack_types ||
          [];


        const detectorResults =
          result
            .detector_results ||
          [];


        /* =================================================
           FINAL LOG OUTPUT
        ================================================= */

        setLogs([

          "> Simulation started.",

          `> Attack: ${selectedAttack.name}`,

          `> Method: ${selectedAttack.method}`,

          `> Endpoint: ${displayEndpoint}`,

          `> Simulation Source IP: ${simulationIp}`,

          `> Simulation User: ${simulationUser}`,

          "> Event sequence completed successfully.",

          "> Detection system response received.",

          `> Backend Status: ${
            result.status ||
            "processed"
          }`,

          `> Message: ${
            result.message ||
            "Event processed successfully"
          }`,

          `> Event ID: ${
            result.event_id ||
            "N/A"
          }`,

          "",

          `> Detector Results: ${
            detectorResults.length
          }`,

          `> Threat Detected: ${
            threatDetected
              ? "YES"
              : "NO"
          }`,

          `> Risk Score: ${
            riskScore ??
            "N/A"
          }`,

          `> Risk Level: ${
            riskLevel ??
            "N/A"
          }`,

          `> Attack Types: ${
            attackTypes.length
              ? attackTypes.join(
                  ", "
                )
              : "None"
          }`,

          `> Mitigation Action: ${
            result.mitigation_action ||
            "N/A"
          }`,

          "",

          "> Simulation completed successfully.",

        ]);

      }

      catch (error) {

        console.error(
          "Simulation error:",
          error
        );


        setLogs([

          "> Simulation started.",

          `> Attack: ${selectedAttack.name}`,

          `> Method: ${selectedAttack.method}`,

          `> Endpoint: ${displayEndpoint}`,

          "",

          "> ERROR: Backend request failed.",

          `> ${error.message}`,

          "",

          "> Make sure the FastAPI backend is running.",

        ]);


        setLatestResult(
          null
        );

      }

      finally {

        setRunning(
          false
        );

      }

    };


  /* =======================================================
     UI
  ======================================================= */

  return (

    <div className="attack-simulation-page">


      {/* =================================================
          HEADER
      ================================================= */}

      <div className="attack-simulation-header">

        <div>

          <div className="page-kicker">
            API ABUSE SECURITY LAB
          </div>


          <h1>
            Attack Simulation Console
          </h1>


          <p>
            Controlled API security testing
            environment for local demonstration.
          </p>

        </div>


        <div className="demo-status">

          <span className="status-dot"></span>

          LOCAL DEMO MODE

        </div>

      </div>


      {/* =================================================
          SIMULATION LAYOUT
      ================================================= */}

      <div className="simulation-layout">


        {/* =================================================
            ATTACK LIST
        ================================================= */}

        <div className="attack-list-panel">

          <div className="panel-title">

            <span>
              ATTACK SCENARIOS
            </span>


            <span className="attack-count">

              {
                attackScenarios.length
              }

            </span>

          </div>


          <div className="attack-list">

            {
              attackScenarios.map(
                attack => (

                  <button

                    key={
                      attack.id
                    }

                    className={`
                      attack-item
                      ${
                        selectedAttack.id ===
                        attack.id
                          ? "active"
                          : ""
                      }
                    `}

                    onClick={() => {

                      if (running) {
                        return;
                      }


                      setSelectedAttack(
                        attack
                      );


                      setLatestResult(
                        null
                      );


                      setLogs([

                        "> Attack selected.",

                        `> Scenario: ${attack.name}`,

                        "> Ready for simulation.",

                      ]);

                    }}

                  >

                    <span className="attack-indicator">
                      ›
                    </span>


                    <span>
                      {attack.name}
                    </span>

                  </button>

                )
              )
            }

          </div>

        </div>


        {/* =================================================
            MAIN SIMULATION AREA
        ================================================= */}

        <div className="simulation-main">


          {/* =================================================
              SELECTED ATTACK
          ================================================= */}

          <div className="selected-attack-card">


            <div className="selected-attack-top">

              <div>

                <div className="section-label">
                  SELECTED ATTACK
                </div>


                <h2>
                  {selectedAttack.name}
                </h2>

              </div>


              <div className="attack-tag">
                SIMULATION
              </div>

            </div>


            <p className="attack-description">

              {
                selectedAttack.description
              }

            </p>


            {/* REQUEST */}

            <div className="request-section">

              <div className="section-label">
                PREDEFINED REQUEST
              </div>


              <div className="request-box">

                <div className="request-line">

                  <span className="method">

                    {
                      selectedAttack.method
                    }

                  </span>


                  <span>

                    {
                      getDisplayEndpoint(
                        selectedAttack
                      )
                    }

                  </span>

                </div>


                <div className="request-user">

                  Controlled demonstration payload

                </div>


                <pre>

                  {
                    JSON.stringify(
                      selectedAttack.payload,
                      null,
                      2
                    )
                  }

                </pre>

              </div>

            </div>


            {/* EXECUTE BUTTON */}

            <button

              className="execute-button"

              onClick={
                runSimulation
              }

              disabled={
                running
              }

            >

              {
                running
                  ? "RUNNING SIMULATION..."
                  : "▶  EXECUTE SIMULATION"
              }

            </button>

          </div>


          {/* =================================================
              SIMULATION OUTPUT
          ================================================= */}

          <div className="console-panel">


            <div className="console-header">

              <div className="console-title">

                <span className="terminal-icon">
                  ●
                </span>

                SIMULATION OUTPUT

              </div>


              <div className="console-status">

                {
                  running
                    ? "PROCESSING"
                    : "READY"
                }

              </div>

            </div>


            <div className="console-body">

              {
                logs.map(
                  (log, index) => (

                    <div

                      key={
                        `${log}-${index}`
                      }

                      className={

                        log.includes(
                          "Threat Detected:"
                        )

                          ? "log-detection"

                          : log.includes(
                              "Risk Score:"
                            )

                          ? "log-risk"

                          : log.includes(
                              "Mitigation Action:"
                            )

                          ? "log-detection"

                          : log.startsWith(
                              "> ERROR:"
                            )

                          ? "log-detection"

                          : "log-line"

                      }

                    >

                      {
                        log ||
                        "\u00A0"
                      }

                    </div>

                  )
                )
              }


              <span className="cursor">
                _
              </span>

            </div>

          </div>


          {/* =================================================
              VIEW THREAT DETAILS
          ================================================= */}

          {
            latestResult && (

              <div

                className="threat-details-action"

                style={{

                  display:
                    "flex",

                  justifyContent:
                    "flex-end",

                  marginTop:
                    "18px",

                }}

              >

                <button

                  className="view-threat-button"

                  onClick={() =>

                    navigate(
                      `/threat/${latestResult.event_id}`
                    )

                  }

                >

                  VIEW THREAT DETAILS

                </button>

              </div>

            )
          }

        </div>

      </div>

    </div>

  );
}


export default AttackSimulation;