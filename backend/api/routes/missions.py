from fastapi import APIRouter, HTTPException, BackgroundTasks, Header
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import json
import logging
import contextvars
import re

from backend.orchestrator.orchestrator import Orchestrator
from backend.services.storage_service import current_mission_id, current_username, save_mission
from backend.memory.sqlite.database import get_connection
from backend.api.routes.auth import get_current_user_from_header
from backend.services.risk_scorer import prioritize_routes
from backend.models.finding import get_default_reasoning, get_default_recommendation

logger = logging.getLogger(__name__)

router = APIRouter()

CATEGORY_TO_CAPABILITY = {
    "missing_csrf": "authentication",
    "weak_authentication": "authentication",
    "vulnerable_dependency": "client_side_libraries",
    "missing_subresource_integrity": "cdn_subresources",
    "missing_security_headers": "security_headers",
    "verbose_error_leak": "error_handling",
    "sensitive_input": "input_handling",
    "file_upload_risk": "file_upload",
    "exposed_endpoint": "api",
    "admin_surface": "admin_panel",
}


def normalize_confidence(val: float | int | None) -> float:
    """F3: Safely normalize confidence to a 0.0 - 100.0 scale without compounding."""
    if val is None:
        return 0.0
    try:
        f = float(val)
    except (ValueError, TypeError):
        return 0.0
    if f <= 1.0:
        f = f * 100.0
    return min(100.0, max(0.0, round(f, 1)))


class ScanRequest(BaseModel):
    url: str
    max_pages: Optional[int] = 5


class ScanResponse(BaseModel):
    mission_id: str


async def run_scan_background(url: str, mission_id: str, offset: int, max_pages: int = 5, username: Optional[str] = None):
    # Set coroutine context var for mission_id and username
    current_mission_id.set(mission_id)
    if username:
        current_username.set(username)
    
    crawl_limit = max(1, min(max_pages, 20))
    orchestrator = Orchestrator(max_crawl_routes=crawl_limit)
    orchestrator._mission_counter = offset
    try:
        logger.info(f"Starting background scan for {mission_id} on target {url} (max_pages={crawl_limit}, user={username})")
        await orchestrator.run(url)
        logger.info(f"Completed background scan for {mission_id}")
    except Exception as e:
        logger.error(f"Error running background scan for {mission_id}: {e}", exc_info=True)


def get_max_mission_counter() -> int:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Get from missions table
        cursor.execute("SELECT mission_id FROM missions")
        missions_ids = [row["mission_id"] for row in cursor.fetchall() if row["mission_id"]]

        # Get from reports
        cursor.execute("SELECT mission_id FROM reports")
        reports_ids = [row["mission_id"] for row in cursor.fetchall() if row["mission_id"]]
        
        # Get from tasks
        cursor.execute("SELECT mission_id FROM tasks WHERE mission_id IS NOT NULL")
        tasks_ids = [row["mission_id"] for row in cursor.fetchall()]
        
        all_ids = set(missions_ids).union(reports_ids).union(tasks_ids)
        
        max_counter = 0
        for m_id in all_ids:
            match = re.match(r"MISSION-(\d+)", m_id)
            if match:
                val = int(match.group(1))
                if val > max_counter:
                    max_counter = val
        return max_counter
    except Exception as e:
        logger.error(f"Error getting max mission counter: {e}")
        return 0
    finally:
        conn.close()


@router.post("/scan", response_model=ScanResponse)
def start_scan(payload: ScanRequest, background_tasks: BackgroundTasks, authorization: Optional[str] = Header(None)):
    url = payload.url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")
        
    user = get_current_user_from_header(authorization)
    username = user["username"] if user else None

    # Ownership gate: real targets require verified control; demo is confined to the local mock
    from backend.services.ownership import is_demo_url, is_verified, get_strong_user
    if not is_demo_url(url):
        strong, code = get_strong_user(authorization)
        if not strong:
            status = 403 if code == "AUTH_WEAK_IDENTITY" else 401
            raise HTTPException(status_code=status, detail={"code": code, "message": "Sign in with a password account to scan real targets. Ownership verification is required."})
        allowed, reason = is_verified(url, strong["username"])
        if not allowed:
            raise HTTPException(status_code=403, detail={"code": "OWNERSHIP_VERIFICATION_REQUIRED", "message": reason})

    # I4: Prevent concurrent scans that collide or overload resources
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT mission_id FROM missions WHERE status = 'running' LIMIT 1")
        active = cursor.fetchone()
        if active:
            raise HTTPException(
                status_code=429,
                detail=f"A mission ({active['mission_id']}) is already in progress. Please wait for it to finish."
            )
    finally:
        conn.close()

    # Determine next mission ID
    max_counter = get_max_mission_counter()
    next_counter = max_counter + 1
    next_mission_id = f"MISSION-{next_counter:03d}"
    
    # Save running mission with user ownership immediately
    save_mission(next_mission_id, url, status="running", username=username)

    # Launch in background with configured max_pages (I8) and username
    pages = payload.max_pages or 5
    background_tasks.add_task(run_scan_background, url, next_mission_id, max_counter, pages, username)
    
    return {"mission_id": next_mission_id}

@router.get("/missions")
def get_missions(authorization: Optional[str] = Header(None)):
    user = get_current_user_from_header(authorization)
    username = user["username"] if user else None

    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # I1: Read missions table as source of truth
        if username:
            cursor.execute(
                "SELECT mission_id, target_url, status, started_at, finished_at, username FROM missions WHERE username = ? ORDER BY id DESC",
                (username,)
            )
            db_missions = {row["mission_id"]: dict(row) for row in cursor.fetchall()}
            all_ids = set(db_missions.keys())
        else:
            cursor.execute("SELECT mission_id, target_url, status, started_at, finished_at, username FROM missions ORDER BY id DESC")
            db_missions = {row["mission_id"]: dict(row) for row in cursor.fetchall()}
            cursor.execute("SELECT mission_id FROM reports")
            rep_ids = {r["mission_id"] for r in cursor.fetchall() if r["mission_id"]}
            cursor.execute("SELECT mission_id FROM tasks WHERE mission_id IS NOT NULL")
            task_ids = {t["mission_id"] for t in cursor.fetchall() if t["mission_id"]}
            cursor.execute("SELECT DISTINCT mission_id FROM routes WHERE mission_id IS NOT NULL")
            route_ids = {row["mission_id"] for row in cursor.fetchall() if row["mission_id"]}
            all_ids = set(db_missions.keys()).union(rep_ids).union(task_ids).union(route_ids)

        if not all_ids:
            return []

        # Get all reports
        cursor.execute("SELECT mission_id, target_url, generated_at, report_json FROM reports")
        reports_rows = cursor.fetchall()
        reports_map = {r["mission_id"]: r for r in reports_rows if r["mission_id"]}
            
        # Get all tasks grouped by mission_id
        cursor.execute("SELECT mission_id, action, status, created_at, target FROM tasks ORDER BY id ASC")
        tasks_rows = cursor.fetchall()
        
        missions_tasks = {}
        for t in tasks_rows:
            m_id = t["mission_id"] or "MISSION-001"
            if m_id not in missions_tasks:
                missions_tasks[m_id] = []
            missions_tasks[m_id].append(t)
        
        missions = []
        for m_id in sorted(all_ids, reverse=True):
            status = "completed"
            target = ""
            created_at = None
            findings_count = 0
            
            # If mission is in missions table (I1 / F1)
            if m_id in db_missions:
                target = db_missions[m_id]["target_url"] or ""
                status = db_missions[m_id]["status"] or "running"
                created_at = db_missions[m_id]["started_at"]

            # If report exists, mission is definitively completed and we have exact findings count
            if m_id in reports_map:
                r = reports_map[m_id]
                try:
                    rep_data = json.loads(r["report_json"])
                    findings_count = len(rep_data.get("findings", []))
                    if not target:
                        target = r["target_url"] or rep_data.get("target_url", "")
                except Exception:
                    findings_count = 0
                    if not target:
                        target = r["target_url"] or ""
                if not created_at:
                    created_at = r["generated_at"]
                status = "completed"
            
            # Fallback checks from tasks if not in missions table or report
            if m_id in missions_tasks:
                m_tasks = missions_tasks[m_id]
                if not target:
                    target = next((t["target"] for t in m_tasks if t["target"]), "")
                if not created_at and m_tasks:
                    created_at = m_tasks[0]["created_at"]
                if m_id not in reports_map and m_id not in db_missions:
                    has_stop_completed = any(t["action"] == "STOP" and t["status"] == "completed" for t in m_tasks)
                    has_failed = any(t["status"] == "failed" for t in m_tasks)
                    if has_failed:
                        status = "failed"
                    elif has_stop_completed:
                        status = "completed"
                    else:
                        status = "running"
            
            # Fallback target from routes if still blank
            if not target:
                cursor.execute("SELECT url, discovered_at FROM routes WHERE mission_id = ? ORDER BY id ASC LIMIT 1", (m_id,))
                m_r = cursor.fetchone()
                if m_r:
                    target = m_r["url"]
                    if not created_at and "discovered_at" in m_r.keys():
                        created_at = str(m_r["discovered_at"])
                    # F7: If only routes exist and no tasks, reports, or mission entry, it's failed, not ghost completed
                    if m_id not in reports_map and m_id not in db_missions and m_id not in missions_tasks:
                        status = "failed"
                        
            if not target:
                cursor.execute("SELECT url FROM routes ORDER BY id ASC LIMIT 1")
                first_r = cursor.fetchone()
                if first_r:
                    target = first_r["url"]

            # Formulate the response item
            missions.append({
                "mission_id": m_id,
                "target": target or "https://target-app.local",
                "target_url": target or "https://target-app.local",
                "status": status,
                "created_at": created_at,
                "findings_count": findings_count
            })
            
        return missions
    finally:
        conn.close()

from urllib.parse import urlparse, urljoin

def get_mission_routes(target: str, rep_data: dict, cursor, mission_id: str = "") -> list[str]:
    target_netloc = urlparse(target).netloc.lower() if target else ""
    routes_set = set()
    if target:
        routes_set.add(target)
        
    # 1. Check routes explicitly recorded in report
    for r in rep_data.get("routes", []):
        u = r.get("url") if isinstance(r, dict) else str(r)
        if u:
            if u.startswith("/"):
                u = urljoin(target, u)
            if not target_netloc or urlparse(u).netloc.lower() == target_netloc:
                routes_set.add(u)
                
    # 2. Check form actions or links extracted in findings evidence
    for f in rep_data.get("findings", []):
        for ev in f.get("evidence", []):
            if "action:" in ev.lower():
                parts = ev.split("action:", 1)[1].split(",")[0].strip()
                if parts:
                    joined = urljoin(target, parts)
                    if not target_netloc or urlparse(joined).netloc.lower() == target_netloc:
                        routes_set.add(joined)

    # 3. Check SQLite routes table for routes matching THIS mission_id and domain
    if mission_id:
        cursor.execute("SELECT url FROM routes WHERE mission_id = ?", (mission_id,))
        m_routes = cursor.fetchall()
        if not m_routes and mission_id == "MISSION-001":
            cursor.execute("SELECT url FROM routes WHERE mission_id IS NULL")
            m_routes = cursor.fetchall()
        for r_row in m_routes:
            u = r_row["url"]
            if u and target_netloc and urlparse(u).netloc.lower() == target_netloc:
                routes_set.add(u)
    else:
        cursor.execute("SELECT url FROM routes")
        for r_row in cursor.fetchall():
            u = r_row["url"]
            if u and target_netloc and urlparse(u).netloc.lower() == target_netloc:
                routes_set.add(u)
            
    return list(routes_set)

@router.get("/missions/{id}")
def get_mission_detail(id: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Check if mission exists in missions table (I1 / F1)
        cursor.execute("SELECT status, target_url, started_at, finished_at FROM missions WHERE mission_id = ?", (id,))
        mission_row = cursor.fetchone()

        # Check if report exists
        cursor.execute("SELECT report_id, target_url, generated_at, report_json FROM reports WHERE mission_id = ?", (id,))
        report_row = cursor.fetchone()
        
        # Get tasks for this mission
        cursor.execute("SELECT action, status, created_at, target FROM tasks WHERE mission_id = ? ORDER BY id ASC", (id,))
        task_rows = cursor.fetchall()
        
        # Fallback to legacy default for MISSION-001 if task_rows is empty and it matches
        if not task_rows and id == "MISSION-001":
            cursor.execute("SELECT action, status, created_at, target FROM tasks WHERE mission_id IS NULL ORDER BY id ASC")
            task_rows = cursor.fetchall()
            
        if not task_rows and not report_row and not mission_row:
            cursor.execute("SELECT url, discovered_at FROM routes WHERE mission_id = ?", (id,))
            m_routes = cursor.fetchall()
            if not m_routes:
                raise HTTPException(status_code=404, detail="Mission not found")
            
        target = ""
        created_at = None
        
        if mission_row:
            target = mission_row["target_url"] or ""
            created_at = mission_row["started_at"]

        if report_row:
            try:
                rep_data = json.loads(report_row["report_json"])
                if not target:
                    target = report_row["target_url"] or rep_data.get("target_url", "")
            except Exception:
                rep_data = {}
                if not target:
                    target = report_row["target_url"] or ""
            if not created_at:
                created_at = report_row["generated_at"]
        else:
            rep_data = {}
            
        if not target and task_rows:
            target = next((t["target"] for t in task_rows if t["target"]), "")
            if not created_at:
                created_at = task_rows[0]["created_at"]
                
        if not target and id:
            cursor.execute("SELECT url, discovered_at FROM routes WHERE mission_id = ? ORDER BY id ASC LIMIT 1", (id,))
            first_m_r = cursor.fetchone()
            if first_m_r:
                target = first_m_r["url"]
                if not created_at and "discovered_at" in first_m_r.keys():
                    created_at = str(first_m_r["discovered_at"])

        if not target:
            cursor.execute("SELECT url FROM routes ORDER BY id ASC LIMIT 1")
            first_r = cursor.fetchone()
            if first_r:
                target = first_r["url"]
                
        target = target or "https://target-app.local"
            
        # Determine status: missions table and reports are authoritative (F1 / F7)
        if report_row:
            status = "completed"
        elif mission_row:
            status = mission_row["status"] or "running"
        elif task_rows:
            has_stop_completed = any(t["action"] == "STOP" and t["status"] == "completed" for t in task_rows)
            has_failed = any(t["status"] == "failed" for t in task_rows)
            if has_failed:
                status = "failed"
            elif has_stop_completed:
                status = "completed"
            else:
                status = "running"
        else:
            status = "completed"
                    
        runtime_str = "0s"
        if task_rows:
            try:
                start_time = datetime.fromisoformat(task_rows[0]["created_at"])
                if status == "running":
                    end_time = datetime.now(timezone.utc)
                else:
                    end_time = datetime.fromisoformat(task_rows[-1]["created_at"])
                diff = max(0.1, (end_time - start_time).total_seconds())
                runtime_str = f"{diff:.1f}s"
            except Exception:
                runtime_str = "unknown"
                
        # If completed, extract everything from the report!
        if report_row:
            stats = rep_data.get("statistics", {})
            original_tokens = stats.get("token_count_naive", 0)
            reduced_tokens = stats.get("token_count_efficient", 0)
            reduction_percentage = 0.0
            if original_tokens > 0:
                reduction_percentage = ((original_tokens - reduced_tokens) / original_tokens) * 100
                
            features_list = []
            if rep_data.get("features"):
                for f in rep_data.get("features", []):
                    conf = normalize_confidence(f.get("confidence") or f.get("classification_confidence", 0.0))
                    features_list.append({
                        "name": f.get("name", "unknown"),
                        "confidence": conf
                    })
            if not features_list:
                target_netloc = urlparse(target).netloc.lower() if target else ""
                cursor.execute("SELECT name, classification_confidence, routes, mission_id FROM features WHERE mission_id = ?", (id,))
                feat_rows = cursor.fetchall()
                if not feat_rows:
                    cursor.execute("SELECT name, classification_confidence, routes, mission_id FROM features")
                    all_feat = cursor.fetchall()
                    feat_rows = [
                        r for r in all_feat 
                        if (r["mission_id"] == id) or 
                           (target_netloc and target_netloc in (r["routes"] or "").lower())
                    ]
                for row in feat_rows:
                    conf = normalize_confidence(row["classification_confidence"])
                    features_list.append({
                        "name": row["name"],
                        "confidence": conf
                    })
                
            findings_list = []
            for f in rep_data.get("findings", []):
                findings_list.append({
                    "finding_id": f.get("finding_id", ""),
                    "title": f.get("title", ""),
                    "category": f.get("category", ""),
                    "severity": f.get("severity", ""),
                    "model_severity": f.get("model_severity"),
                    "confidence": f.get("confidence", 0.0),
                    "evidence": f.get("evidence", []),
                    "description": f.get("description", ""),
                    "reasoning": f.get("reasoning") or get_default_reasoning(f.get("category", ""), f.get("description", "")),
                    "recommendation": f.get("recommendation", "") or get_default_recommendation(f.get("category", ""))
                })

            # Enrich report-stored findings with persisted ML verdicts (report JSON predates the severity merge)
            try:
                cursor.execute("SELECT finding_id, model_severity FROM findings WHERE mission_id = ?", (id,))
                _db_ms = {r["finding_id"]: r["model_severity"] for r in cursor.fetchall()}
                for _f in findings_list:
                    if not _f.get("model_severity"):
                        _f["model_severity"] = _db_ms.get(_f.get("finding_id", ""))
            except Exception:
                pass
                
            sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
            findings_list.sort(
                key=lambda item: sev_order.get((item.get("severity") or "").lower(), 0),
                reverse=True,
            )

            # Ensure capabilities reflect all evaluated functional surfaces from findings
            feature_names = {feat["name"].lower() for feat in features_list}
            for f in findings_list:
                cat = f.get("category", "").lower()
                cap = CATEGORY_TO_CAPABILITY.get(cat)
                if cap and cap not in feature_names:
                    features_list.append({
                        "name": cap,
                        "confidence": 100.0
                    })
                    feature_names.add(cap)

            # Compute prioritized attack surface strictly for this target and mission
            route_urls = get_mission_routes(target, rep_data, cursor, mission_id=id)
            prioritized_surface = [
                item.model_dump() for item in prioritize_routes(route_urls, seed_url=target)
            ]
                
            return {
                "mission_id": id,
                "target_url": target,
                "status": status,
                "runtime": runtime_str,
                "generated_at": report_row["generated_at"],
                "recon_summary": {
                    "routes": stats.get("routes_discovered", len(route_urls)) or 1,
                    "forms": stats.get("forms_count", 0),
                    "inputs": stats.get("inputs_count", 0),
                    "buttons": stats.get("buttons_count", 0),
                    "scripts": stats.get("scripts_count", 0),
                    "links": stats.get("links_count", len(route_urls) or 1),
                    "meta_tags": stats.get("meta_tags_count", 0),
                    "is_spa": bool(stats.get("is_spa", False))
                },
                "features": features_list,
                "token_reduction": {
                    "original_tokens": original_tokens,
                    "reduced_tokens": reduced_tokens,
                    "reduction_percentage": round(reduction_percentage, 1)
                },
                "findings": findings_list,
                "prioritized_attack_surface": prioritized_surface,
                "report_id": report_row["report_id"]
            }
            
        # If running or failed
        # Retrieve routes and findings strictly related to this mission target and mission_id
        target_netloc = urlparse(target).netloc.lower() if target else ""
        if id:
            cursor.execute("SELECT id, url FROM routes WHERE mission_id = ?", (id,))
            m_routes = cursor.fetchall()
            if not m_routes and id == "MISSION-001":
                cursor.execute("SELECT id, url FROM routes WHERE mission_id IS NULL")
                m_routes = cursor.fetchall()
            all_routes = m_routes
        else:
            cursor.execute("SELECT id, url FROM routes")
            all_routes = cursor.fetchall()

        mission_route_rows = [r for r in all_routes if target_netloc and urlparse(r["url"]).netloc.lower() == target_netloc]
        mission_route_ids = [r["id"] for r in mission_route_rows]
        route_urls = [r["url"] for r in mission_route_rows] or ([target] if target else [])
        
        prioritized_surface = [
            item.model_dump() for item in prioritize_routes(route_urls, seed_url=target)
        ]

        features_list = []
        if id:
            cursor.execute("SELECT name, classification_confidence, routes, mission_id FROM features WHERE mission_id = ?", (id,))
            feat_rows = cursor.fetchall()
            if not feat_rows:
                cursor.execute("SELECT name, classification_confidence, routes, mission_id FROM features")
                all_feat = cursor.fetchall()
                feat_rows = [
                    r for r in all_feat 
                    if (r["mission_id"] == id) or 
                       (target_netloc and target_netloc in (r["routes"] or "").lower())
                ]
            for row in feat_rows:
                conf = normalize_confidence(row["classification_confidence"])
                features_list.append({
                    "name": row["name"],
                    "confidence": conf
                })
        
        findings_list = []
        finding_rows = []
        if id:
            cursor.execute("SELECT * FROM findings WHERE mission_id = ?", (id,))
            finding_rows = cursor.fetchall()
            if not finding_rows and id == "MISSION-001":
                cursor.execute("SELECT * FROM findings WHERE mission_id IS NULL")
                finding_rows = cursor.fetchall()
        elif mission_route_ids:
            placeholders = ",".join("?" for _ in mission_route_ids)
            cursor.execute(f"SELECT * FROM findings WHERE route_id IN ({placeholders})", mission_route_ids)
            finding_rows = cursor.fetchall()

        for f in finding_rows:
            try:
                ev = json.loads(f["evidence"])
            except Exception:
                ev = []
            reasoning_val = f["reasoning"] if "reasoning" in f.keys() and f["reasoning"] else ""
            if not reasoning_val:
                reasoning_val = get_default_reasoning(f["type"], f["description"])
            findings_list.append({
                "finding_id": f["finding_id"] or f"FIND-{f['id']:03d}",
                "title": f["title"],
                "category": f["type"],
                "severity": f["severity"],
                "model_severity": f["model_severity"] if "model_severity" in f.keys() else None,
                "confidence": f["security_confidence"],
                "evidence": ev,
                "description": f["description"],
                "reasoning": reasoning_val,
                "recommendation": get_default_recommendation(f["type"])
            })
            
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
        findings_list.sort(
            key=lambda item: sev_order.get((item.get("severity") or "").lower(), 0),
            reverse=True,
        )

        # Ensure capabilities reflect all evaluated functional surfaces from findings
        feature_names = {feat["name"].lower() for feat in features_list}
        for f in findings_list:
            cat = f.get("category", "").lower()
            cap = CATEGORY_TO_CAPABILITY.get(cat)
            if cap and cap not in feature_names:
                features_list.append({
                    "name": cap,
                    "confidence": 100.0
                })
                feature_names.add(cap)

        return {
            "mission_id": id,
            "target_url": target,
            "status": status,
            "runtime": runtime_str,
            "generated_at": created_at,
            "recon_summary": {
                "routes": len(mission_route_ids) or 1,
                "forms": 0,
                "inputs": 0,
                "buttons": 0,
                "scripts": 0,
                "links": 0,
                "meta_tags": 0,
                "is_spa": False
            },
            "features": features_list,
            "token_reduction": {
                "original_tokens": 0,
                "reduced_tokens": 0,
                "reduction_percentage": 0.0
            },
            "findings": findings_list,
            "prioritized_attack_surface": prioritized_surface,
            "report_id": None
        }
    finally:
        conn.close()

@router.get("/missions/{id}/timeline")
def get_mission_timeline(id: str):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        
        # Get tasks for this mission
        cursor.execute("SELECT action, status, created_at FROM tasks WHERE mission_id = ? ORDER BY id ASC", (id,))
        rows = cursor.fetchall()
        
        # Fallback to legacy default for MISSION-001 if empty
        if not rows and id == "MISSION-001":
            cursor.execute("SELECT action, status, created_at FROM tasks WHERE mission_id IS NULL ORDER BY id ASC")
            rows = cursor.fetchall()
            
        timeline = []
        for r in rows:
            timeline.append({
                "task": r["action"],
                "status": r["status"],
                "timestamp": r["created_at"]
            })
            
        return timeline
    finally:
        conn.close()
