"""
Prompt helpers for analyst reasoning tasks.

These helpers build structured prompts for triage, remediation suggestions,
and finding-cluster summaries.  They are provider-agnostic — they return plain
LangChain ``HumanMessage`` / ``SystemMessage`` lists that can be fed directly
to any ``BaseChatModel``.
"""

from __future__ import annotations

from typing import Any


def triage_prompt(finding: dict[str, Any]) -> list[dict[str, str]]:
    """
    Build a triage prompt for a single finding.

    Parameters
    ----------
    finding:
        A dict with at least ``name``, ``severity``, ``url``, and optionally
        ``description`` and ``matched_at`` keys — as produced by nuclei JSON
        output.

    Returns
    -------
    List of ``{role, content}`` dicts ready for ``model.invoke(messages)``.
    """
    name = finding.get("name", "Unknown")
    severity = finding.get("severity", "unknown")
    url = finding.get("url", finding.get("matched-at", "N/A"))
    desc = finding.get("description", "No description provided.")
    template_id = finding.get("template-id", "")

    system = (
        "You are a senior application security analyst performing authorized "
        "defensive security assessments.  Your job is to triage vulnerability "
        "findings accurately and without exaggeration."
    )
    user = (
        f"Triage the following security finding found during an authorized scan:\n\n"
        f"- **Finding name**: {name}\n"
        f"- **Template ID**: {template_id}\n"
        f"- **Severity**: {severity}\n"
        f"- **URL**: {url}\n"
        f"- **Description**: {desc}\n\n"
        "Provide:\n"
        "1. A brief assessment of whether this is likely a true positive.\n"
        "2. The potential business impact (1-2 sentences).\n"
        "3. Suggested immediate mitigation steps (bullet list).\n"
        "Keep your response concise and technical."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def remediation_prompt(finding: dict[str, Any]) -> list[dict[str, str]]:
    """
    Build a detailed remediation suggestion prompt.
    """
    name = finding.get("name", "Unknown")
    severity = finding.get("severity", "unknown")
    url = finding.get("url", finding.get("matched-at", "N/A"))
    desc = finding.get("description", "")
    cwe = finding.get("classification", {}).get("cwe-id", [])
    cvss = finding.get("classification", {}).get("cvss-score", "N/A")

    cwe_str = ", ".join(cwe) if cwe else "N/A"

    system = (
        "You are a defensive application security consultant.  "
        "Provide practical, developer-friendly remediation guidance."
    )
    user = (
        f"Provide a remediation plan for the following vulnerability finding:\n\n"
        f"- **Name**: {name}\n"
        f"- **Severity**: {severity} (CVSS: {cvss})\n"
        f"- **URL**: {url}\n"
        f"- **CWE**: {cwe_str}\n"
        f"- **Description**: {desc}\n\n"
        "Provide:\n"
        "1. Root cause explanation (1 paragraph).\n"
        "2. Short-term fix (code snippet or config change if applicable).\n"
        "3. Long-term architectural recommendation.\n"
        "4. Verification steps to confirm the fix.\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def cluster_summary_prompt(findings: list[dict[str, Any]], target: str) -> list[dict[str, str]]:
    """
    Build a cluster/summary prompt for a set of findings against one target.
    """
    total = len(findings)
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    sev_summary = ", ".join(f"{k}: {v}" for k, v in sorted(severity_counts.items()))

    # List top-10 finding names to keep prompt size bounded
    names = list({f.get("name", "") for f in findings})[:10]
    names_str = "\n".join(f"- {n}" for n in names)

    system = (
        "You are a security team lead reviewing automated scan results.  "
        "Your goal is to produce an executive-readable risk summary."
    )
    user = (
        f"Summarize the following scan results for target **{target}**:\n\n"
        f"- Total findings: {total}\n"
        f"- Severity breakdown: {sev_summary}\n"
        f"- Finding types (sample):\n{names_str}\n\n"
        "Provide:\n"
        "1. Overall risk rating (Critical / High / Medium / Low / Informational).\n"
        "2. Top 3 most impactful findings and why.\n"
        "3. Recommended prioritisation order for remediation.\n"
        "4. Any patterns or systemic weaknesses observed.\n"
        "Keep the summary to 300 words or less."
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]
