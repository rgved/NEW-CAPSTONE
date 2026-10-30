"""
backend/models/finding.py

Pydantic model for a Phase 6 security finding.
"""
from __future__ import annotations

from typing import Annotated, Literal, Optional

from pydantic import BaseModel, Field

FindingCategory = Literal[
    "missing_csrf",
    "weak_authentication",
    "exposed_endpoint",
    "file_upload_risk",
    "missing_security_headers",
    "admin_surface",
    "sensitive_input",
    "vulnerable_dependency",
    "missing_subresource_integrity",
    "verbose_error_leak",
    "unknown",
]

# I2: Added "critical" as the highest severity tier.
FindingSeverity = Literal["informational", "low", "medium", "high", "critical"]

# I6: Evidence is capped at 10 items to prevent unbounded LLM output.
BoundedEvidenceList = Annotated[list[str], Field(default_factory=list, max_length=10)]


class Finding(BaseModel):
    finding_id: Optional[str] = None
    type: FindingCategory
    title: str
    feature: str
    severity: FindingSeverity
    # ML second opinion from the Nuclei-trained TF-IDF + linear SVM.
    # Additive only: never replaces the LLM-assigned severity above.
    model_severity: Optional[FindingSeverity] = None
    security_confidence: float = Field(ge=0.0, le=1.0)
    evidence: BoundedEvidenceList = Field(default_factory=list)
    description: str = ""
    reasoning: str = ""
    route_id: Optional[int] = None


_DEFAULT_REASONINGS: dict[str, str] = {
    "missing_csrf": "State-changing POST request submission identified on an interactive form without anti-CSRF token verification or nonce validation, enabling unauthorized cross-site action execution on behalf of authenticated users.",
    "weak_authentication": "Authentication endpoint transmits credentials without sufficient transport encryption, lockout protections, or strict complexity requirements, creating high risk for brute-force and credential intercept attacks.",
    "exposed_endpoint": "Sensitive internal or API endpoint is exposed directly to unauthenticated clients without role-based access control or network isolation.",
    "file_upload_risk": "File ingestion boundary allows multipart/form-data upload without strict server-side MIME type or extension whitelist enforcement, creating potential for arbitrary file execution.",
    "missing_security_headers": "HTTP response headers lack essential defensive policies (such as HSTS, Content-Security-Policy, or X-Frame-Options), leaving the client browser exposed to framing, downgrade, and injection attacks.",
    "admin_surface": "Administrative interface components are reachable from public network routes without multi-factor authentication or source IP filtering.",
    "sensitive_input": "Form inputs accept unconstrained user data without input sanitization or validation, increasing the likelihood of injection attacks.",
    "vulnerable_dependency": "Third-party client library with known public CVEs is embedded directly without version pinning or security patching, exposing the application to client-side exploitation.",
    "missing_subresource_integrity": "External script or stylesheet is fetched from an untrusted third-party CDN without cryptographic subresource integrity (SRI) hash verification, allowing arbitrary script injection if the CDN is compromised.",
    "verbose_error_leak": "Server responses or unhandled exceptions leak stack traces, database schema details, or environment diagnostics, enabling targeted exploit generation.",
}


def get_default_reasoning(category: str, description: str = "") -> str:
    if category in _DEFAULT_REASONINGS:
        return _DEFAULT_REASONINGS[category]
    return description or "Security finding identified based on contextual analysis of response headers, form structures, and input boundaries."


_DEFAULT_RECOMMENDATIONS: dict[str, str] = {
    "missing_csrf": "Implement state-changing anti-CSRF token check on all state-changing endpoints.",
    "weak_authentication": "Strengthen authentication parameters, use HTTPS, lockout mechanisms, and complexity requirements.",
    "exposed_endpoint": "Restrict access to sensitive pathways with proper IP filtering and role checks.",
    "file_upload_risk": "Enforce server-side file ext validations, upload size constraints, and change filename on save.",
    "missing_security_headers": "Ensure modern security headers (HSTS, CSP, X-Frame-Options, XSS protection) are present.",
    "admin_surface": "Block public routing to administration components, enforce MFA and audit logging.",
    "sensitive_input": "Ensure input forms validate parameters strictly, sanitizing special chars before handling.",
    "vulnerable_dependency": "Upgrade outdated client-side libraries to modern patched releases.",
    "missing_subresource_integrity": "Add integrity and crossorigin attributes to external third-party CDN scripts.",
    "verbose_error_leak": "Disable verbose debugging and configure generic error pages in production.",
}


def get_default_recommendation(category: str) -> str:
    """R8: Centralized recommendation lookup shared across API endpoints."""
    return _DEFAULT_RECOMMENDATIONS.get(
        category,
        "Review the capability structure and enforce strict access authorization."
    )

