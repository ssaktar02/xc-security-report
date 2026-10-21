"""
Curated per-rule recommendation text and reference links.

Source: "XC Security Report - Recommendations & Best-Practice Review" doc.
Keyed by rule ID. These values REPLACE whatever remediation / referenceUrl the
auditor JSON carries, so reports always show the reviewed wording and links.

Format: rule_id -> (recommendation, reference_url)
An empty string blanks that field. Rules not listed keep the JSON values
(with legacy URL fixes from finding_corrections._URL_REPLACEMENTS).
"""

RULE_RECOMMENDATIONS = {
    # --- ACCESS_CONTROL ---
    "AC-01": (  # Service Policy Applied
        "Apply an active service policy (or inherit the namespace service policy set) on the load balancer.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/app-security/service-policy",
    ),
    "AC-02": (  # IP Reputation Enabled
        "Enable IP Reputation on the load balancer (Security Configuration → enable IP Reputation).",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/configure-ip-reputation",
    ),
    "AC-03": (  # Threat Mesh Enabled
        "Enable Threat Mesh in the load balancer Security Configuration to share cross-tenant threat intelligence.",
        "https://docs.cloud.f5.com/docs/how-to/advanced-security",
    ),
    "AC-04": (  # No Broad WAF Bypass for Trusted Clients
        "Scope trusted-client WAF-skip rules to specific, justified IP prefixes — never 0.0.0.0/0.",
        "https://my.f5.com/manage/s/article/K000146814",
    ),
    "AC-05": (  # Trusted Client IP Headers Where Behind CDN/Proxy
        "Configure Trusted Client IP Headers with the exact header the fronting tier sets; verify that tier overwrites any client-supplied value before forwarding.",
        "https://my.f5.com/manage/s/article/K000147809",
    ),
    "AC-06": (  # Challenge Posture Defined
        "Prefer policy-based challenge for granular per-source rules; coordinate with Bot Defense to avoid double-challenging legitimate users.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/adv-security/js-challenge",
    ),
    "CORS-01": (  # CORS Not Over-Permissive
        "Restrict CORS Allow-Origin to specific trusted origins; never combine \"*\" with Allow-Credentials.",
        "https://docs.cloud.f5.com/docs/how-to/app-security",
    ),
    "SP-01": (  # Service Policy No Allow-All
        "Review rule order; remove or constrain any top-level ALLOW rule matching all clients so deny/restriction rules are evaluated.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/app-security/service-policy",
    ),
    "SP-02": (  # No Allow-All IP Prefix
        "Replace 0.0.0.0/0 in ALLOW rules with the specific trusted prefixes.",
        "https://docs.cloud.f5.com/docs/how-to/app-security/service-policy",
    ),
    # --- ALERTING ---
    "object-20": (  # Alert Policies Configured
        "Create alert policies (and alert receivers) covering error rate, origin health, and certificate expiry.",
        "https://docs.cloud.f5.com/docs-v2/shared-configuration/how-tos/alerting/alerts-email-sms",
    ),
    # --- API_SECURITY ---
    "API-01": (  # API Discovery Enabled
        "Enable API Discovery on the load balancer and review the discovered inventory periodically.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/quickstart/api-security",
    ),
    "API-02": (  # API Definition / Schema Attached
        "Upload an OpenAPI spec and attach it as an API Definition for schema-based validation.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/import-openapi-spec",
    ),
    "API-03": (  # OpenAPI Validation Enforced (Block + Fall-Through)
        "Set OpenAPI Validation → All Endpoints, Request Processing = Validate, Enforcement = Block; define custom fall-through; enable response validation where schemas are reliable.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/import-openapi-spec",
    ),
    "API-04": (  # JWT Validation on Authenticated APIs
        "Configure JWT Validation: target the authenticated API groups/base paths, attach the IdP JWKS, validate reserved claims (exp, nbf), action = Block. Keep JWKS in sync with IdP key rotation.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    ),
    "API-05": (  # API Protection Rules Gate Sensitive Groups
        "Define API groups from the discovered inventory; add deny rules with narrow allow exceptions for admin and internal groups.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/api-security/configure-api-protection-rules",
    ),
    "API-06": (  # Sensitive Data Discovery Aligned to Compliance Scope
        "Define a sensitive data discovery policy for the relevant frameworks; review flagged endpoints in API inventory; apply DG-01 masking or schema fixes on confirmed leaks.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/api-security/sensitive-data",
    ),
    "API-07": (  # GraphQL Inspection Where GraphQL Is Served
        "Add a GraphQL rule on the GraphQL route; disable introspection in production; set max depth and max batched queries to observed application norms.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/apiep-discovery-control",
    ),
    "DG-01": (  # Data Guard (Response Masking)
        "Configure Data Guard rules on pages/paths that may expose sensitive data.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    # --- BOT_DEFENSE ---
    "BOT-01": (  # Bot Defense Attached
        "Attach a Bot Defense policy to the load balancer (requires Bot Defense Standard/Advanced license).",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection",
    ),
    "BOT-02": (  # Malicious User Detection
        "Enable Malicious User Detection on the load balancer (and configure a mitigation policy / user identifier).",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users",
    ),
    "BOT-03": (  # Malicious User Mitigation Wired to Actions
        "Attach a malicious-user mitigation policy (the default ladder is a sane start); ensure user identification is policy-based (UID-01) so actions hit users, not NAT pools.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/adv-security/malicious-users",
    ),
    "BOT-04": (  # Known & AI Bot Policy Reviewed
        "Set per-bot actions for AI bots in the Bot Defense policy; review the known-bot dashboard on a regular cadence.",
        "https://docs.cloud.f5.com/docs-v2/bot-defense/configure-advanced/endpoint-policy",
    ),
    # --- CLIENT_SECURITY ---
    "COOKIE-01": (  # Cookie Protection (Secure/HttpOnly)
        "Add Protected Cookies with Secure, HttpOnly, and SameSite for session cookies.",
        "https://my.f5.com/manage/s/article/K000148047",
    ),
    "CSD-01": (  # Client-Side Defense
        "Enable Client-Side Defense on load balancers serving payment / sensitive forms (requires license).",
        "https://docs.cloud.f5.com/docs-v2/client-side-defense/concepts/about-csd",
    ),
    "CSD-02": (  # CSD New-Script Alerting & PCI Compliance Status
        "Enable new-script alerting; assign and review per-script compliance status on release cadence.",
        "https://docs.cloud.f5.com/docs-v2/client-side-defense/how-tos/configure-csd",
    ),
    "CSRF-01": (  # CSRF Protection
        "Enable CSRF protection on the load balancer and set the allowed source-origin domains.",
        "https://community.f5.com/t/how-to-protect-your-applications-from-cross-site-request-forgery-csrf-with-f5-distributed-cloud/71522",
    ),
    "HDR-01": (  # Security Response Headers
        "Add response headers on the LB: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options: nosniff, Referrer-Policy.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    "HDR-02": (  # Server Header Suppression
        "Add \"server\" to Remove Response Headers (or overwrite it) on the load balancer.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/adv-security/manipulate-server-header-in-https-response",
    ),
    "HDR-03": (  # x-volterra-location Header Disabled
        "Leave \"Add Location\" disabled in production unless actively used for debugging.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    "WAFP-07": (  # WAF Cookie Protection
        "Enable cookie protection (Secure / HttpOnly / SameSite) in the App Firewall policy.",
        "https://my.f5.com/manage/s/article/K000148047",
    ),
    # --- DDOS ---
    "DDOS-01": (  # L7 DDoS Protection
        "Configure L7 DDoS protection (auto-mitigation) or DDoS mitigation rules on the load balancer. See step 10 in the reference documentation.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/create-http-load-balancer",
    ),
    "DDOS-02": (  # Slow-Request (Slowloris) Mitigation
        "Keep the request-headers / request timeout (or system defaults); do not select \"No Request Timeout\" unless required. See step 10 in the reference documentation.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/create-http-load-balancer",
    ),
    "DDOS-03": (  # Request Size Limit
        "Set a maximum request size (buffer policy) appropriate to the application. See step 10 in the reference documentation.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/create-http-load-balancer",
    ),
    # --- DNS ---
    "object-23": (  # DNSSEC on XC-Hosted Primary Zones
        "Enable DNSSEC on the primary zone; publish the DS record at the registrar; verify the chain (dig +dnssec / DNSViz).",
        "https://docs.cloud.f5.com/docs-v2/dns-management/how-to/manage-dns-zones",
    ),
    # --- EXPOSURE ---
    "EXP-01": (  # VIP Advertisement Scope Matches Exposure Intent
        "For internal apps use Custom advertisement to CE sites/inside networks; reserve the public VIP for genuinely public apps.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-tos/advanced-app-nwg/disable-advertising-on-public-network",
    ),
    "EXP-02": (  # No Overly-Broad Domain Match
        "Split distinct apps/subdomains onto separate LBs with right-sized WAF, API, and bot policies.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    # --- IAM ---
    "object-22": (  # SSO + MFA Enforcement
        "Configure SSO (SAML/OIDC); enable MFA on every remaining local account; document and test the break-glass procedure.",
        "https://docs.cloud.f5.com/docs/how-to/user-mgmt",
    ),
    "object-24": (  # Credential Expiry Policy Enforced
        "Administration → Tenant Settings → Credential Expiry Policy: set maximum expiry ≤ 90 days for tokens, certificates and kubeconfigs.",
        "https://docs.cloud.f5.com/docs/how-to/user-mgmt",
    ),
    "object-25": (  # Console Session Timeouts Configured
        "Administration → Tenant Configuration → set idle and absolute session timeouts (e.g. idle ≤ 30 min for admin roles).",
        "https://docs.cloud.f5.com/docs/how-to/user-mgmt",
    ),
    "object-26": (  # No Stale or Over-Privileged Credentials
        "Revoke stale credentials; migrate automation to Service Credentials with namespace-scoped least-privilege roles; review quarterly.",
        "https://docs.cloud.f5.com/docs/how-to/user-mgmt",
    ),
    # --- LOGGING ---
    "object-21": (  # SIEM / Global Log Receiver Configured
        "Configure a Global Log Receiver (shared namespace) to stream logs to your SIEM (Splunk, S3, Datadog, etc.).",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-tos/others/global-log-streaming",
    ),
    "object-27": (  # Security Events + Audit Logs Streamed to SIEM
        "Add Global Log Receivers in the shared/system namespace for each missing event type, pointed at the SIEM.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-tos/others/global-log-streaming",
    ),
    # --- ORIGIN ---
    "HC-01": (  # HTTP(S) Health Check with Expected Codes
        "Use an HTTP/HTTPS health check with an expected status code (e.g. 200) and a health path, not TCP-only.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-02": (  # Origin Certificate Validation
        "Disable \"Skip Server Verification\" and use Volterra Trusted CA or upload the origin CA for verification.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-03": (  # Origin Pool High Availability
        "Add a second origin server (different AZ / failure domain) to provide failover.",
        "https://my.f5.com/manage/s/article/K000147769",
    ),
    "OP-04": (  # Health Check Configured
        "Attach an active HTTP/HTTPS health check (with an expected response code) to the origin pool.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-06": (  # Outlier Detection
        "Enable outlier detection in the origin pool advanced options.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-07": (  # Circuit Breaker
        "Configure a circuit breaker (or enable the default) in the origin pool advanced options.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-09": (  # mTLS to Origin for Internet-Reachable Origins
        "Issue a client cert for the XC→origin leg, attach under origin pool TLS, and configure the origin to require it (accept only XC).",
        "https://my.f5.com/manage/s/article/K000147231",
    ),
    "OP-10": (  # Origin Cloaking / Private Connectivity
        "Prefer CE/site private connectivity for origins; otherwise allowlist the published F5 XC IP ranges at the origin firewall and enable OP-09 mTLS.",
        "https://docs.cloud.f5.com/docs-v2/platform/reference/network-cloud-ref",
    ),
    # --- RATE_LIMITING ---
    "RL-01": (  # Rate Limiting Configured
        "Configure a rate limiter (with an appropriate user identifier) on the load balancer.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/adv-security/user-rate-limit",
    ),
    "RL-02": (  # API Endpoint Rate Limits on Sensitive Endpoints
        "Add api_endpoint_rules for login, OTP, password reset and expensive read endpoints; key on the UID-01 identifier, not bare client IP.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/api-security/configure-api-rate-limiting",
    ),
    # --- TLS_SSL ---
    "CERT-01": (  # Certificate Expiry
        "Renew the certificate before expiry (upload new cert + full chain), or migrate to XC auto-managed certificates.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/manage-multiple-custom-certificates",
    ),
    "CERT-02": (  # Certificate Key Blindfolded
        "Re-import the certificate using a Blindfold-encrypted private key or a Vault reference; never store the key as plaintext.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-to/adv-security/blindfold-tls-certs",
    ),
    "CERT-03": (  # Certificate Key Strength
        "Reissue the certificate with an RSA ≥ 2048-bit or ECDSA P-256 key.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/manage-multiple-custom-certificates",
    ),
    "OP-01": (  # TLS to Origin Enabled
        "Enable TLS to the origin in the origin pool (Origin Servers → TLS).",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/origin-pools",
    ),
    "OP-05": (  # Origin TLS Version (Medium+)
        "Set the origin TLS security level to Medium or High in the origin pool TLS settings.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/reference/tls-reference",
    ),
    "OP-08": (  # SNI Set When Verifying Origin TLS
        "Enable Use Host Header as SNI (or set an explicit SNI value) on TLS origin pools that verify server certs.",
        "https://my.f5.com/manage/s/article/K000146682",
    ),
    "TLS-01": (  # Load Balancer Serves HTTPS
        "Edit the load balancer and set the listener type to \"HTTPS with Automatic Certificate\" (or a custom certificate), then enable HTTP redirect to HTTPS.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    "TLS-02": (  # HTTP to HTTPS Redirect
        "In the load balancer HTTPS settings, enable \"HTTP Redirect to HTTPS\".",
        "https://my.f5.com/manage/s/article/K000147743",
    ),
    "TLS-03": (  # HSTS Header Enabled
        "In the load balancer HTTPS settings, enable \"Add HSTS Header\".",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    "TLS-04": (  # TLS Security Level (Medium+)
        "In the load balancer HTTPS / TLS settings, set the TLS Security Level to Default/High (TLS 1.2+). Avoid the Medium and Low presets, which permit TLS 1.0/1.1.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/reference/tls-reference",
    ),
    "TLS-05": (  # mTLS Client Cert Revocation (CRL)
        "Create a CRL object (Manage → Load Balancers → Certificate Revocation List) with an appropriate refresh interval and attach it under the LB mTLS settings.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/load-balance/configure-certificate-revocation-list",
    ),
    "TLS-06": (  # mTLS Not Silently Optional
        "Disable \"client certificate optional\" once all clients hold certs; forward XFCC so the origin can apply its own check during the transition.",
        "https://my.f5.com/manage/s/article/K000147231",
    ),
    # --- USER_IDENTIFICATION ---
    "UID-01": (  # User Identification Policy
        "Attach a user identification policy (cookie/header based) instead of relying on client-IP only for authenticated applications.",
        "https://docs.cloud.f5.com/docs-v2/multi-cloud-app-connect/how-to/adv-security/user-rate-limit",
    ),
    # --- WAF ---
    "WAF-01": (  # WAF (App Firewall) Attached
        "Attach an Application Firewall policy to the load balancer (Security Configuration → Web Application Firewall → Enable).",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAF-02": (  # No Broad WAF Exclusions
        "Replace any \"any domain / any path\" exclusion (or \".*\" path regex) with narrow exclusions scoped to the exact signature and path.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAF-03": (  # Malware Protection Enabled
        "Enable Malware Protection (licensed add-on) on load balancers that accept file uploads.",
        "https://docs.cloud.f5.com/docs/how-to/app-security",
    ),
    "WAF-04": (  # No Route Disabling WAF
        "Remove per-route \"disable WAF\" overrides, or confirm they are intentional and on non-sensitive paths.",
        "https://my.f5.com/manage/s/article/K000160940",
    ),
    "WAF-05": (  # Path Normalization
        "Enable path normalization in the load balancer HTTP/HTTPS settings.",
        "https://docs.cloud.f5.com/docs/how-to/app-networking/http-load-balancer",
    ),
    "WAFP-01": (  # WAF Enforcement Mode (Blocking)
        "Set the App Firewall enforcement mode to Blocking for production policies.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-02": (  # Threat Campaigns Enabled
        "Enable Threat Campaigns in the App Firewall policy detection settings.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-03": (  # High/Medium Accuracy Signatures
        "Enable the high & medium accuracy signature set in the App Firewall policy signature selection settings.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-04": (  # WAF Bot Signature Protection
        "Set the WAF bot protection malicious-bot action to Block in the App Firewall policy.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-05": (  # No Attack Types Disabled
        "Re-enable any disabled attack-type categories in the App Firewall signature settings.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-06": (  # No Violation Types Disabled
        "Re-enable any disabled violation types in the App Firewall policy.",
        "https://docs.cloud.f5.com/docs-v2/web-app-and-api-protection/how-to/app-security/application-firewall",
    ),
    "WAFP-REF": (  # WAF policy retrievable
        "Ensure the WAF policy namespace is included in the audit, or verify the policy (blocking mode, signatures, tuning) directly in the console.",
        "",
    ),
}
