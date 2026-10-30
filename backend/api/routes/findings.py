from fastapi import APIRouter, Query, Header
from typing import Optional, List
import json
import logging
from backend.models.finding import get_default_reasoning, get_default_recommendation
from backend.memory.sqlite.database import get_connection
from backend.api.routes.missions import get_missions

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/findings")
def get_findings_list(
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, informational, all"),
    category: Optional[str] = Query(None, description="Filter by category"),
    search: Optional[str] = Query(None, description="Search term in title or description"),
    authorization: Optional[str] = Header(None)
):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        findings_map = {}

        # Determine user scope
        is_authenticated = (authorization and isinstance(authorization, str) and authorization.startswith("Bearer "))
        user_missions = get_missions(authorization)
        user_mission_ids = {m["mission_id"] for m in user_missions if m.get("mission_id")}

        if is_authenticated and not user_mission_ids:
            return []
        
        # 1. Fetch reports to build findings and mission mapping
        cursor.execute("SELECT mission_id, generated_at, target_url, report_json FROM reports")
        reports = cursor.fetchall()
        for r in reports:
            m_id = r["mission_id"]
            if user_mission_ids and m_id not in user_mission_ids:
                continue
            date_str = r["generated_at"]
            try:
                rep_data = json.loads(r["report_json"])
                for f in rep_data.get("findings", []):
                    fid = f.get("finding_id")
                    if fid and fid not in findings_map:
                        reasoning_val = f.get("reasoning") or get_default_reasoning(f.get("category", ""), f.get("description", ""))
                        findings_map[fid] = {
                            "finding_id": fid,
                            "title": f.get("title", ""),
                            "category": f.get("category", "unknown"),
                            "severity": f.get("severity", "medium").lower(),
                            "model_severity": f.get("model_severity"),
                            "confidence": f.get("confidence", 0.0),
                            "evidence": f.get("evidence", []),
                            "description": f.get("description", ""),
                            "reasoning": reasoning_val,
                            "mission": m_id,
                            "date": date_str,
                            "recommendation": get_default_recommendation(f.get("category", ""))
                        }
            except Exception:
                pass
                
        # 2. Query any findings from the findings table that might not be in reports
        if user_mission_ids:
            placeholders = ",".join("?" for _ in user_mission_ids)
            cursor.execute(f"""
                SELECT f.id, f.finding_id, f.type, f.title, f.feature, f.severity, 
                       f.security_confidence, f.evidence, f.description, f.reasoning, f.route_id, f.mission_id,
                       f.model_severity,
                       r.url, r.discovered_at
                FROM findings f
                LEFT JOIN routes r ON f.route_id = r.id
                WHERE f.mission_id IN ({placeholders})
                ORDER BY f.id DESC
            """, list(user_mission_ids))
        else:
            cursor.execute("""
                SELECT f.id, f.finding_id, f.type, f.title, f.feature, f.severity, 
                       f.security_confidence, f.evidence, f.description, f.reasoning, f.route_id, f.mission_id,
                       f.model_severity,
                       r.url, r.discovered_at
                FROM findings f
                LEFT JOIN routes r ON f.route_id = r.id
                ORDER BY f.id DESC
            """)
        finding_rows = cursor.fetchall()
        for row in finding_rows:
            fid = row["finding_id"] or f"FIND-{row['id']:03d}"
            if fid not in findings_map:
                try:
                    evidence_list = json.loads(row["evidence"])
                except Exception:
                    evidence_list = []
                    
                reasoning_text = row["reasoning"] if "reasoning" in row.keys() and row["reasoning"] else ""
                if not reasoning_text:
                    reasoning_text = get_default_reasoning(row["type"], row["description"])

                m_id = row["mission_id"] if "mission_id" in row.keys() and row["mission_id"] else ("MISSION-004" if "testfire" in (row["url"] or "") else "MISSION-001")
                findings_map[fid] = {
                    "finding_id": fid,
                    "title": row["title"],
                    "category": row["type"],
                    "severity": row["severity"].lower(),
                    "model_severity": row["model_severity"] if "model_severity" in row.keys() else None,
                    "confidence": row["security_confidence"],
                    "evidence": evidence_list,
                    "description": row["description"],
                    "reasoning": reasoning_text,
                    "mission": m_id,
                    "date": row["discovered_at"],
                    "recommendation": get_default_recommendation(row["type"])
                }

        findings = list(findings_map.values())
            
        # 3. Apply Filters
        filtered_findings = []
        for f in findings:
            # Severity filter
            if isinstance(severity, str) and severity.lower() != "all":
                if f["severity"] != severity.lower():
                    continue
                    
            # Category filter
            if isinstance(category, str) and category.lower() != "all":
                if f["category"].lower() != category.lower():
                    continue
                    
            # Search filter
            if isinstance(search, str) and search.strip():
                query = search.strip().lower()
                title_match = query in f["title"].lower()
                desc_match = query in f["description"].lower()
                id_match = query in f["finding_id"].lower()
                if not (title_match or desc_match or id_match):
                    continue
                    
            filtered_findings.append(f)
            
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        filtered_findings.sort(
            key=lambda f: sev_order.get((f.get("severity") or "").lower(), 0),
            reverse=True,
        )
        return filtered_findings
    finally:
        conn.close()
