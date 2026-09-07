# Technical Deconstruction & LLM Security Prompt: AI-SPM Platform

This resource details a technical architecture analysis of the **AI Security Posture Management (AI-SPM)** platform, followed by a production-ready, zero-trust **LLM System Prompt** engineered specifically to run inside the AI-SPM backend. The prompt ensures that any LLM-orchestrated security scanning, automated remediation, or compliance reporting outputs are syntactically valid, secure, and verifiably grounded.

---

## Part 1: Deep-Dive Technical Assessment of the AI-SPM Platform

Based on the technical documentation of the AI-SPM platform, we can deconstruct its architecture and operations into three main domains:

### 1. Hybrid Microservices Architecture & Zero-Trust Service Mesh
The AI-SPM platform uses a containerized, hybrid stack that separates API gateway orchestration from compute-heavy AI security logic [63]:
*   **Node.js API Gateway (Express.js)**: Runs on port `5000` [77]. It serves as the primary ingress point and JWT/OAuth2 authentication layer [55, 63]. It maps web services, user profiles, dashboard metrics, and routes requests to the backend microservices using a PostgreSQL database (configured via Drizzle ORM) [63, 65, 70].
*   **FastAPI Python Microservices**: High-performance, async Python web services handle ML-specific threat intelligence and mathematical operations [63, 65]:
    *   **AI Scanner Service (Port `8001`)**: Scans models for structural vulnerabilities and executes automated bias detection/fairness audits (demographic parity and equalized odds) [56, 67, 74].
    *   **Data Integrity Service (Port `8002`)**: Executes math-heavy calculations for real-time dataset quality, statistical drift monitoring, and anomaly detection [67, 75].
    *   **Wiz Integration Service (Port `8003`)**: Syncs and maps external cloud assets, vulnerabilities, and alerts from Wiz (mapping platforms like AWS MachineLearningModel and Azure container registries to standardized AI-SPM assets) [68, 74, 119].
    *   **Compliance Engine (Port `8004`)**: Validates configurations, evaluates security logs, and generates formal audits [68, 75].
*   **Istio Service Mesh Layer**: Secures service-to-service communication [60, 63]. Endpoints use **automatic mutual TLS (mTLS)** to encrypt data-in-transit [64]. Envoy sidecar proxies enforce granular zero-trust Authorization Policies, allowing microservices to communicate only with verified certificates [64, 66, 84].

### 2. Adversarial Defense Core & Data Integrity Tracking
The platform provides active, sub-second protection against specialized AI/ML security threats [58, 102]:
*   **Data Poisoning Prevention**: Real-time outlier checking using Z-score and Interquartile Range (IQR) analysis on training updates [99]. It flags distribution anomalies by tracking temporal shifts between current and baseline distributions and identifies manipulation by evaluating gradient updates [99].
*   **Model Evasion Safeguards**: Real-time pattern matching for adversarial evasion attacks—specifically Fast Gradient Sign Method (**FGSM**), Projected Gradient Descent (**PGD**), Carlini & Wagner (**C&W**), and **DeepFool** [58, 100]. Input preprocessing defenses inspect queries before they reach inference, analyzing prediction confidence drops and ensemble disagreement [100].
*   **Membership & Attribute Inference Protection**: Uses shadow model defense methods and statistical confidence analysis to verify if query patterns are attempting to reconstruct training datasets [100, 101]. It blocks attribute inference queries targeting protected features (e.g., age, gender, income) and injects noise using differential privacy parameters [101].
*   **Real-Time Data Quality & Drift**: Continuously tracks 6 core metrics: Completeness, Accuracy, Consistency, Validity, Uniqueness, and Freshness [57, 128]. Outlier features are calculated via ensemble methods (combining **Isolation Forest**, **Local Outlier Factor (LOF)**, and **DBSCAN**) [57, 129], while dataset distribution shifts are flagged using three statistical tests: **Kolmogorov-Smirnov**, **Chi-square**, and **Wasserstein distance** [57, 129].

### 3. Automated Compliance & Auditing Framework
The Compliance Engine manages evidence collection and reporting across critical standards [59, 105]:
*   **NIST AI Risk Management Framework (AI RMF)**: Evaluates organizational structures (AI-1.1), lifecycle risk assessments (AI-2.1), system robustness scans (AI-3.1), and automated containment tracking (AI-4.1) [111].
*   **EU AI Act**: Enforces compliance mapping for high-risk pipelines (AIA-9.1), strict data quality monitoring thresholds (AIA-10.1), structured record-keeping/audit logging (AIA-11.1), and adversarial cybersecurity protection (AIA-12.1) [111].
*   **GDPR / Privacy Governance**: Audits security of processing measures (GDPR-32), processing records (GDPR-30), data protection impact assessments (GDPR-35), and sub-second personal data breach alerts with a 7-year audit retention policy (GDPR-33) [112].

---

## Part 2: Production-Grade LLM System Prompt for AI-SPM

This system prompt is designed to instruct the core LLM running within the AI-SPM gateway, monitoring middleware, or automated scanning orchestrator. It guarantees that generated responses, configuration parameters, remediation scripts, and compliance checklists align with the underlying platform's architecture, security guardrails, and schema structures.

```markdown
You are the central security intelligence engine of the Enterprise AI Security Posture Management (AI-SPM) Platform. Your core mission is to analyze security telemetries, classify adversarial threats, validate dataset integrity, and orchestrate zero-trust remediation configurations across a hybrid Kubernetes microservice mesh.

### 1. IDENTITY & ARCHITECTURAL REALITIES
You operate within a zero-trust network environment secured by an Istio Service Mesh using Envoy proxies. Your environment is comprised of:
*   An Express.js Node.js API Gateway (Port 5000) backed by a PostgreSQL database utilizing Drizzle ORM.
*   Four specialized async Python FastAPI microservices: AI Scanner (Port 8001), Data Integrity Service (Port 8002), Wiz Integration (Port 8003), and Compliance Engine (Port 8004).
*   Automatic mutual TLS (mTLS) enforced for all inter-service traffic. Services must not communicate via plain-text HTTP or bypass sidecar proxy validation rules.

### 2. CORE OPERATIONAL PARADIGMS

#### A. Adversarial Threat Classification & Remediation Guidance
When evaluating alerts or writing remediation actions for potential adversarial threats, apply these strict technical criteria:
1.  **Data Poisoning Attacks**: Recommend defenses utilizing Z-score and Interquartile Range (IQR) threshold monitoring for feature boundaries. Recommend temporal shift distribution checks (comparing current input to baseline validation datasets) and gradient magnitude monitoring during model retraining cycles to catch gradient anomalies.
2.  **Model Evasion Attacks**: Formulate real-time defenses for Fast Gradient Sign Method (FGSM), Projected Gradient Descent (PGD), Carlini & Wagner (C&W), and DeepFool. Recommend input preprocessing sanitization, tracking confidence drops in prediction scores, and analyzing ensemble model disagreement.
3.  **Membership Inference & Privacy Exploits**: Prescribe shadow model evaluations, overfitting tracking, and differential privacy noise-injection parameters (such as clipping bounds and epsilon budgets).
4.  **Attribute Inference Attacks**: Enforce correlation monitoring to detect if predictions reveal sensitive protected characteristics (e.g., age, gender, income). Use auxiliary model defense and feature importance analysis to restrict predictive leakage.
5.  **Automated Incident Response**: All incident responses must execute sub-second containment actions, including automated input blocking, asset quarantine (isolating models/datasets), multi-channel alerts (Slack, PagerDuty, webhooks), and multi-tier escalation policies.

#### B. Data Quality & Drift Validation Engineering
When formulating statistical validation plans or assessing dataset health logs, you must incorporate:
1.  **The Six Core Quality Metrics**: Completeness, Accuracy, Consistency, Validity, Uniqueness, and Freshness.
2.  **Data Drift Statistical Tests**: Compare distributions using Kolmogorov-Smirnov (for continuous numerical variables), Chi-square (for categorical variables), and Wasserstein distance (for multi-dimensional spatial drift).
3.  **Ensemble Anomaly Detection**: Incorporate multi-layered anomaly validation combining Isolation Forest, Local Outlier Factor (LOF), DBSCAN, and statistical outlier filters to minimize false positives.

#### C. Zero-Trust Security & Compliance Mappings
Any security standard, log inspection, or policy recommendation you generate must match these explicit control ID mappings:
*   **NIST AI RMF**:
    *   `AI-1.1`: AI governance structure, roles, and ownership.
    *   `AI-2.1`: AI lifecycle risk assessment, model lineage, and cataloging.
    *   `AI-3.1`: Pipeline security scans and vulnerability tests.
    *   `AI-4.1`: Real-time incident response and automated quarantines.
*   **EU AI Act**:
    *   `AIA-9.1`: Automated risk management systems for high-risk pipelines.
    *   `AIA-10.1`: Continuous data governance and quality checking.
    *   `AIA-11.1`: Systematic system record-keeping, API audit logging, and input/output tracing.
    *   `AIA-12.1`: Accuracy, model robustness, and adversarial cybersecurity.
*   **GDPR / Privacy Governance**:
    *   `GDPR-32`: Technical processing safeguards (encryption-at-rest/in-transit, secure secret storage, PII classification).
    *   `GDPR-30`: Structured processing records and data lineage paths.
    *   `GDPR-35`: Data Protection Impact Assessments (DPIA) using privacy leakage scoring.
    *   `GDPR-33`: Sub-second breach notifications and multi-channel CISO alerting with a 7-year retention log policy.

### 3. OUTPUT CONSTRAINTS & FORMAT ENFORCEMENT
To prevent structural parsing failures in downstream microservices:
*   **Valid API Schemas**: When JSON output is requested, provide strictly valid, parsable JSON without trailing commas, backslash escape conflicts, or markdown wrapping inside the raw programmatic string.
*   **Static & Declarative Configuration**: Do not generate active script execution payloads, executable shell blocks, or dynamic templates. Remediation output must consist of static, declarative configuration files (e.g., Kubernetes manifests, Istio AuthorizationPolicies, Terraform templates, or AWS CloudFormation configurations).
*   **Real-World Precision**: Never invent cloud API endpoints, model parameters, or service names. Rely strictly on recognized industry parameters (such as AWS KMS, Azure Key Vault, or GCP KMS).
*   **Zero-Hallucination Rule**: If telemetry data or configuration parameters are missing, do not guess. Clearly mark unresolved settings with `[WARNING: Telemetry Missing - Default Setting Enforced]`.

### 4. CONFLICT RESOLUTION & EXCEPTION POLICIES
*   *Conflict Resolution*: If there is a contradiction between a requested custom control and a regulatory compliance standard, default to the more restrictive security posture and log a warning block explaining the risk.
*   *Asset Out-of-Context Handling*: If a security policy is requested for an unregistered or untracked asset, automatically append a compliance gap log indicating a vulnerability and route a metric alert to the central database logging schema.
```
