"""
Local Threat Intelligence Engine
Stores and correlates indicators of compromise (IOCs) across analyses.
"""
from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional

# Database lives in the phish_analyzer config directory
DB_PATH = Path(__file__).resolve().parent / "config" / "threat_intel.db"


def get_connection() -> sqlite3.Connection:
    """
    Open a connection to the local threat intel database.
    Creates the database file if it doesn't exist yet.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row  # lets us access columns by name
    conn.execute("PRAGMA journal_mode=WAL")  # safer for concurrent access
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def initialize_database() -> None:
    """
    Create all tables if they don't already exist.
    Safe to call on every startup — won't overwrite existing data.
    """
    conn = get_connection()

    with conn:
        # Master analysis log — one row per email analyzed
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name       TEXT,
                analyzed_at     TEXT NOT NULL,
                risk_score      INTEGER,
                se_score        INTEGER,
                verdict         TEXT,
                campaign_tag    TEXT
            )
        """)

        # IP addresses seen in analyses
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_ips (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
                ip              TEXT NOT NULL,
                context         TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)

        # Domains seen in analyses
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_domains (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
                domain          TEXT NOT NULL,
                context         TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)

        # Attachment hashes seen in analyses
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_hashes (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
                md5             TEXT,
                sha1            TEXT,
                sha256          TEXT NOT NULL,
                filename        TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)

        # URLs seen in analyses
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_urls (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
                url             TEXT NOT NULL,
                final_url       TEXT,
                context         TEXT,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)

        # X-Mailer / User-Agent strings seen
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ioc_mailers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id     INTEGER NOT NULL REFERENCES analyses(id),
                mailer_value    TEXT NOT NULL,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)

        # Indexes for fast lookups on the fields we'll query most
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_ips_ip ON ioc_ips(ip)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_domains_domain ON ioc_domains(domain)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_hashes_sha256 ON ioc_hashes(sha256)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc_urls_url ON ioc_urls(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_campaign ON analyses(campaign_tag)")

    conn.close()

def save_analysis(
    file_name:   str,
    risk_score:  Optional[int] = None,
    se_score:    Optional[int] = None,
    verdict:     Optional[str] = None,
) -> int:
    """
    Create a new analysis record and return its ID.
    This ID ties all IOCs from this run together.
    """
    conn = get_connection()
    now = datetime.utcnow().isoformat()

    with conn:
        cursor = conn.execute("""
            INSERT INTO analyses (file_name, analyzed_at, risk_score, se_score, verdict)
            VALUES (?, ?, ?, ?, ?)
        """, (file_name, now, risk_score, se_score, verdict))
        analysis_id = cursor.lastrowid

    conn.close()
    return analysis_id


def save_ioc_ip(analysis_id: int, ip: str, context: str = None) -> None:
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        conn.execute("""
            INSERT INTO ioc_ips (analysis_id, ip, context, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
        """, (analysis_id, ip.strip(), context, now, now))
    conn.close()


def save_ioc_domain(analysis_id: int, domain: str, context: str = None) -> None:
    if not domain:
        return
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        conn.execute("""
            INSERT INTO ioc_domains (analysis_id, domain, context, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
        """, (analysis_id, domain.strip().lower(), context, now, now))
    conn.close()


def save_ioc_hash(
    analysis_id: int,
    sha256:      str,
    md5:         str = None,
    sha1:        str = None,
    filename:    str = None,
) -> None:
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        conn.execute("""
            INSERT INTO ioc_hashes (analysis_id, md5, sha1, sha256, filename, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (analysis_id, md5, sha1, sha256, filename, now, now))
    conn.close()


def save_ioc_url(
    analysis_id: int,
    url:         str,
    final_url:   str = None,
    context:     str = None,
) -> None:
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        conn.execute("""
            INSERT INTO ioc_urls (analysis_id, url, final_url, context, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (analysis_id, url, final_url, context, now, now))
    conn.close()


def save_ioc_mailer(analysis_id: int, mailer_value: str) -> None:
    conn = get_connection()
    now = datetime.utcnow().isoformat()
    with conn:
        conn.execute("""
            INSERT INTO ioc_mailers (analysis_id, mailer_value, first_seen, last_seen)
            VALUES (?, ?, ?, ?)
        """, (analysis_id, mailer_value, now, now))
    conn.close()


def extract_and_save_iocs(
    analysis_id:  int,
    from_domain:  Optional[str]       = None,
    reply_domain: Optional[str]       = None,
    return_domain: Optional[str]      = None,
    client_ip:    Optional[str]       = None,
    urls:         Optional[list]      = None,
    attachments:  Optional[list]      = None,
    mailer:       Optional[str]       = None,
) -> dict:
    """
    Central IOC extraction function. Call this once per analysis with
    whatever indicators you have available. Returns a summary of what
    was saved so you can log it or display it.

    attachments should be a list of dicts like:
        {"filename": "...", "payload": b"..."}
    urls should be a list of normalized URL strings.
    """
    saved = {
        "domains": [],
        "ips":     [],
        "hashes":  [],
        "urls":    [],
        "mailers": [],
    }

    # --- Domains ---
    for domain, ctx in [
        (from_domain,   "from_header"),
        (reply_domain,  "reply_to_header"),
        (return_domain, "return_path_header"),
    ]:
        if domain:
            save_ioc_domain(analysis_id, domain, context=ctx)
            saved["domains"].append(domain)

    # --- Sending IP ---
    if client_ip:
        save_ioc_ip(analysis_id, client_ip, context="spf_client_ip")
        saved["ips"].append(client_ip)

    # --- URLs ---
    for url in (urls or []):
        save_ioc_url(analysis_id, url)
        saved["urls"].append(url)

    # --- Attachment hashes ---
    for att in (attachments or []):
        payload = att.get("payload")
        if not payload:
            continue

        hashes = {
            "md5":    __import__("hashlib").md5(payload).hexdigest(),
            "sha1":   __import__("hashlib").sha1(payload).hexdigest(),
            "sha256": __import__("hashlib").sha256(payload).hexdigest(),
        }

        save_ioc_hash(
            analysis_id,
            sha256=hashes["sha256"],
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            filename=att.get("filename"),
        )
        saved["hashes"].append(hashes["sha256"])

    # --- Mailer ---
    if mailer:
        save_ioc_mailer(analysis_id, mailer)
        saved["mailers"].append(mailer)

    return saved

def correlate_ip(ip: str) -> Optional[dict]:
    """
    Look up an IP against historical analyses.
    Returns match data if seen before, None if first time seeing it.
    """
    if not ip:
        return None

    conn = get_connection()
    row = conn.execute("""
        SELECT
            ip,
            COUNT(*)                                    AS seen_count,
            MIN(first_seen)                             AS first_seen,
            MAX(last_seen)                              AS last_seen,
            GROUP_CONCAT(DISTINCT a.campaign_tag)       AS campaigns,
            ROUND(AVG(a.risk_score), 1)                 AS avg_risk_score,
            COUNT(DISTINCT ioc_ips.analysis_id)         AS analysis_count
        FROM ioc_ips
        LEFT JOIN analyses a ON a.id = ioc_ips.analysis_id
        WHERE ip = ?
        GROUP BY ip
    """, (ip,)).fetchone()
    conn.close()

    if not row or row["seen_count"] == 0:
        return None

    return {
        "indicator":      row["ip"],
        "type":           "ip",
        "seen_count":     row["seen_count"],
        "analysis_count": row["analysis_count"],
        "first_seen":     row["first_seen"],
        "last_seen":      row["last_seen"],
        "avg_risk_score": row["avg_risk_score"],
        "campaigns":      [c for c in (row["campaigns"] or "").split(",") if c],
    }


def correlate_domain(domain: str) -> Optional[dict]:
    """
    Look up a domain against historical analyses.
    """
    if not domain:
        return None

    conn = get_connection()
    row = conn.execute("""
        SELECT
            domain,
            COUNT(*)                                    AS seen_count,
            MIN(first_seen)                             AS first_seen,
            MAX(last_seen)                              AS last_seen,
            GROUP_CONCAT(DISTINCT a.campaign_tag)       AS campaigns,
            ROUND(AVG(a.risk_score), 1)                 AS avg_risk_score,
            COUNT(DISTINCT ioc_domains.analysis_id)     AS analysis_count,
            GROUP_CONCAT(DISTINCT ioc_domains.context)  AS contexts
        FROM ioc_domains
        LEFT JOIN analyses a ON a.id = ioc_domains.analysis_id
        WHERE domain = ?
        GROUP BY domain
    """, (domain,)).fetchone()
    conn.close()

    if not row or row["seen_count"] == 0:
        return None

    return {
        "indicator":      row["domain"],
        "type":           "domain",
        "seen_count":     row["seen_count"],
        "analysis_count": row["analysis_count"],
        "first_seen":     row["first_seen"],
        "last_seen":      row["last_seen"],
        "avg_risk_score": row["avg_risk_score"],
        "campaigns":      [c for c in (row["campaigns"] or "").split(",") if c],
        "contexts":       [c for c in (row["contexts"] or "").split(",") if c],
    }


def correlate_hash(sha256: str) -> Optional[dict]:
    """
    Look up an attachment SHA256 against historical analyses.
    """
    if not sha256:
        return None

    conn = get_connection()
    row = conn.execute("""
        SELECT
            sha256,
            COUNT(*)                                    AS seen_count,
            MIN(first_seen)                             AS first_seen,
            MAX(last_seen)                              AS last_seen,
            GROUP_CONCAT(DISTINCT filename)             AS filenames,
            GROUP_CONCAT(DISTINCT a.campaign_tag)       AS campaigns,
            ROUND(AVG(a.risk_score), 1)                 AS avg_risk_score,
            COUNT(DISTINCT ioc_hashes.analysis_id)      AS analysis_count
        FROM ioc_hashes
        LEFT JOIN analyses a ON a.id = ioc_hashes.analysis_id
        WHERE sha256 = ?
        GROUP BY sha256
    """, (sha256,)).fetchone()
    conn.close()

    if not row or row["seen_count"] == 0:
        return None

    return {
        "indicator":      row["sha256"],
        "type":           "sha256",
        "seen_count":     row["seen_count"],
        "analysis_count": row["analysis_count"],
        "first_seen":     row["first_seen"],
        "last_seen":      row["last_seen"],
        "avg_risk_score": row["avg_risk_score"],
        "campaigns":      [c for c in (row["campaigns"] or "").split(",") if c],
        "filenames":      [f for f in (row["filenames"] or "").split(",") if f],
    }


def correlate_url(url: str) -> Optional[dict]:
    """
    Look up a URL against historical analyses.
    """
    if not url:
        return None

    conn = get_connection()
    row = conn.execute("""
        SELECT
            url,
            COUNT(*)                                    AS seen_count,
            MIN(first_seen)                             AS first_seen,
            MAX(last_seen)                              AS last_seen,
            GROUP_CONCAT(DISTINCT a.campaign_tag)       AS campaigns,
            ROUND(AVG(a.risk_score), 1)                 AS avg_risk_score,
            COUNT(DISTINCT ioc_urls.analysis_id)        AS analysis_count
        FROM ioc_urls
        LEFT JOIN analyses a ON a.id = ioc_urls.analysis_id
        WHERE url = ?
        GROUP BY url
    """, (url,)).fetchone()
    conn.close()

    if not row or row["seen_count"] == 0:
        return None

    return {
        "indicator":      row["url"],
        "type":           "url",
        "seen_count":     row["seen_count"],
        "analysis_count": row["analysis_count"],
        "first_seen":     row["first_seen"],
        "last_seen":      row["last_seen"],
        "avg_risk_score": row["avg_risk_score"],
        "campaigns":      [c for c in (row["campaigns"] or "").split(",") if c],
    }


def correlate_all(
    from_domain:   Optional[str] = None,
    reply_domain:  Optional[str] = None,
    return_domain: Optional[str] = None,
    client_ip:     Optional[str] = None,
    urls:          Optional[list] = None,
    attachments:   Optional[list] = None,
) -> dict:
    """
    Run correlation checks across all indicator types in a single call.
    Returns a structured dict of all matches found.

    This is the main function to call from core.py before saving new IOCs.
    """
    import hashlib

    matches = {
        "domains": [],
        "ips":     [],
        "hashes":  [],
        "urls":    [],
        "total":   0,
    }

    # --- Domains ---
    for domain in filter(None, [from_domain, reply_domain, return_domain]):
        result = correlate_domain(domain)
        if result:
            matches["domains"].append(result)

    # --- IP ---
    if client_ip:
        result = correlate_ip(client_ip)
        if result:
            matches["ips"].append(result)

    # --- URLs ---
    for url in (urls or []):
        result = correlate_url(url)
        if result:
            matches["urls"].append(result)

    # --- Attachment hashes ---
    for att in (attachments or []):
        payload = att.get("payload")
        if not payload:
            continue
        sha256 = hashlib.sha256(payload).hexdigest()
        result = correlate_hash(sha256)
        if result:
            matches["hashes"].append(result)

    matches["total"] = (
        len(matches["domains"]) +
        len(matches["ips"]) +
        len(matches["hashes"]) +
        len(matches["urls"])
    )

    return matches

def print_correlation_results(matches: dict, colors: dict) -> None:
    """
    Pretty-print correlation results to the terminal.
    Pass in your colors dict from colors.py.
    """
    RED         = colors.get("RED", "")
    YELLOW      = colors.get("YELLOW", "")
    CYAN        = colors.get("CYAN", "")
    BRIGHT_RED  = colors.get("BRIGHT_RED", "")
    BRIGHT_GREEN= colors.get("BRIGHT_GREEN", "")
    RESET       = colors.get("RESET", "")

    print(f"{CYAN}=== Threat Intelligence Correlation ==={RESET}")

    if matches["total"] == 0:
        print(f"{BRIGHT_GREEN}[+] No matches found in local threat intel database{RESET}")
        print()
        return

    print(f"{BRIGHT_RED}[!] {matches['total']} known indicator match(es) found in local database{RESET}")
    print()

    def _print_match(match: dict) -> None:
        indicator = match["indicator"]
        ioc_type  = match["type"].upper()
        count     = match["analysis_count"]
        first     = match["first_seen"][:10]   # date only
        last      = match["last_seen"][:10]
        avg_risk  = match.get("avg_risk_score")
        campaigns = match.get("campaigns", [])
        filenames = match.get("filenames", [])
        contexts  = match.get("contexts", [])

        # Pick color based on how many times seen
        if count >= 5:
            color = BRIGHT_RED
        elif count >= 2:
            color = RED
        else:
            color = YELLOW

        print(f"  {color}[{ioc_type}] {indicator}{RESET}")
        print(f"      Seen in {count} previous analysis/analyses")
        print(f"      First seen: {first}  |  Last seen: {last}")

        if avg_risk is not None:
            print(f"      Avg risk score when seen: {avg_risk}/100")

        if campaigns:
            clean = [c for c in campaigns if c and c != "None"]
            if clean:
                print(f"      Campaigns: {', '.join(clean)}")

        if filenames:
            clean = [f for f in filenames if f and f != "None"]
            if clean:
                print(f"      Seen filenames: {', '.join(clean[:5])}")

        if contexts:
            clean = [c for c in contexts if c and c != "None"]
            if clean:
                print(f"      Seen in: {', '.join(clean)}")

        print()

    for match in matches["domains"]:
        _print_match(match)

    for match in matches["ips"]:
        _print_match(match)

    for match in matches["hashes"]:
        _print_match(match)

    for match in matches["urls"]:
        _print_match(match)

def tag_campaign(analysis_id: int, campaign_tag: str) -> bool:
    """
    Tag an existing analysis with a campaign name.
    Returns True if successful, False if analysis_id not found.
    """
    conn = get_connection()

    with conn:
        cursor = conn.execute("""
            UPDATE analyses
            SET campaign_tag = ?
            WHERE id = ?
        """, (campaign_tag.strip(), analysis_id))

    conn.close()
    return cursor.rowcount > 0


def tag_campaign_by_indicator(indicator: str, campaign_tag: str) -> int:
    """
    Tag ALL analyses that contain a specific indicator (IP, domain, hash, or URL)
    with a campaign name. Useful for retroactively labeling a campaign after
    you identify the common thread.

    Returns the number of analyses tagged.
    """
    conn = get_connection()
    tagged = set()

    # Find all analysis IDs associated with this indicator across all IOC tables
    for table, column in [
        ("ioc_ips",     "ip"),
        ("ioc_domains", "domain"),
        ("ioc_hashes",  "sha256"),
        ("ioc_urls",    "url"),
    ]:
        rows = conn.execute(f"""
            SELECT DISTINCT analysis_id FROM {table}
            WHERE {column} = ?
        """, (indicator,)).fetchall()

        for row in rows:
            tagged.add(row["analysis_id"])

    count = 0
    if tagged:
        with conn:
            for analysis_id in tagged:
                cursor = conn.execute("""
                    UPDATE analyses
                    SET campaign_tag = ?
                    WHERE id = ?
                """, (campaign_tag.strip(), analysis_id))
                count += cursor.rowcount

    conn.close()
    return count


def list_analyses(limit: int = 20, campaign_tag: str = None) -> list:
    """
    List recent analyses from the database.
    Optionally filter by campaign tag.
    """
    conn = get_connection()

    if campaign_tag:
        rows = conn.execute("""
            SELECT
                id, file_name, analyzed_at,
                risk_score, se_score, verdict, campaign_tag
            FROM analyses
            WHERE campaign_tag = ?
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (campaign_tag, limit)).fetchall()
    else:
        rows = conn.execute("""
            SELECT
                id, file_name, analyzed_at,
                risk_score, se_score, verdict, campaign_tag
            FROM analyses
            ORDER BY analyzed_at DESC
            LIMIT ?
        """, (limit,)).fetchall()

    conn.close()
    return [dict(r) for r in rows]


def list_campaigns() -> list:
    """
    List all unique campaign tags and how many analyses are tagged with each.
    """
    conn = get_connection()
    rows = conn.execute("""
        SELECT
            campaign_tag,
            COUNT(*)            AS analysis_count,
            MIN(analyzed_at)    AS first_seen,
            MAX(analyzed_at)    AS last_seen
        FROM analyses
        WHERE campaign_tag IS NOT NULL
        GROUP BY campaign_tag
        ORDER BY analysis_count DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_campaign_iocs(campaign_tag: str) -> dict:
    """
    Pull all IOCs associated with a campaign tag across all analyses
    tagged with it. Useful for building a full campaign profile.
    """
    conn = get_connection()

    analysis_ids = [
        row["id"] for row in conn.execute("""
            SELECT id FROM analyses WHERE campaign_tag = ?
        """, (campaign_tag,)).fetchall()
    ]

    if not analysis_ids:
        conn.close()
        return {}

    placeholders = ",".join("?" * len(analysis_ids))

    ips = conn.execute(f"""
        SELECT DISTINCT ip FROM ioc_ips
        WHERE analysis_id IN ({placeholders})
    """, analysis_ids).fetchall()

    domains = conn.execute(f"""
        SELECT DISTINCT domain, context FROM ioc_domains
        WHERE analysis_id IN ({placeholders})
    """, analysis_ids).fetchall()

    hashes = conn.execute(f"""
        SELECT DISTINCT sha256, md5, sha1, filename FROM ioc_hashes
        WHERE analysis_id IN ({placeholders})
    """, analysis_ids).fetchall()

    urls = conn.execute(f"""
        SELECT DISTINCT url FROM ioc_urls
        WHERE analysis_id IN ({placeholders})
    """, analysis_ids).fetchall()

    mailers = conn.execute(f"""
        SELECT DISTINCT mailer_value FROM ioc_mailers
        WHERE analysis_id IN ({placeholders})
    """, analysis_ids).fetchall()

    conn.close()

    return {
        "campaign_tag":    campaign_tag,
        "analysis_count":  len(analysis_ids),
        "ips":             [r["ip"] for r in ips],
        "domains":         [{"domain": r["domain"], "context": r["context"]} for r in domains],
        "hashes":          [dict(r) for r in hashes],
        "urls":            [r["url"] for r in urls],
        "mailers":         [r["mailer_value"] for r in mailers],
    }

def export_iocs_json(campaign_tag: str = None) -> str:
    """
    Export all IOCs as a JSON string.
    Optionally filter by campaign tag.
    """
    conn = get_connection()

    if campaign_tag:
        analysis_filter = """
            WHERE analysis_id IN (
                SELECT id FROM analyses WHERE campaign_tag = ?
            )
        """
        params = (campaign_tag,)
    else:
        analysis_filter = ""
        params = ()

    ips = conn.execute(
        f"SELECT DISTINCT ip, context FROM ioc_ips {analysis_filter}", params
    ).fetchall()

    domains = conn.execute(
        f"SELECT DISTINCT domain, context FROM ioc_domains {analysis_filter}", params
    ).fetchall()

    hashes = conn.execute(
        f"SELECT DISTINCT sha256, md5, sha1, filename FROM ioc_hashes {analysis_filter}", params
    ).fetchall()

    urls = conn.execute(
        f"SELECT DISTINCT url FROM ioc_urls {analysis_filter}", params
    ).fetchall()

    mailers = conn.execute(
        f"SELECT DISTINCT mailer_value FROM ioc_mailers {analysis_filter}", params
    ).fetchall()

    conn.close()

    export = {
        "exported_at":  datetime.utcnow().isoformat(),
        "campaign_tag": campaign_tag or "all",
        "iocs": {
            "ips":      [{"ip": r["ip"], "context": r["context"]} for r in ips],
            "domains":  [{"domain": r["domain"], "context": r["context"]} for r in domains],
            "hashes":   [{"sha256": r["sha256"], "md5": r["md5"],
                          "sha1": r["sha1"], "filename": r["filename"]} for r in hashes],
            "urls":     [{"url": r["url"]} for r in urls],
            "mailers":  [{"mailer_value": r["mailer_value"]} for r in mailers],
        },
        "counts": {
            "ips":     len(ips),
            "domains": len(domains),
            "hashes":  len(hashes),
            "urls":    len(urls),
            "mailers": len(mailers),
        }
    }

    return json.dumps(export, indent=2)


def export_iocs_csv(campaign_tag: str = None) -> dict:
    """
    Export all IOCs as CSV strings, one per indicator type.
    Returns a dict of {type: csv_string}.
    Optionally filter by campaign tag.
    """
    import csv
    import io

    conn = get_connection()

    if campaign_tag:
        analysis_filter = """
            WHERE analysis_id IN (
                SELECT id FROM analyses WHERE campaign_tag = ?
            )
        """
        params = (campaign_tag,)
    else:
        analysis_filter = ""
        params = ()

    exports = {}

    # IPs
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ip", "context"])
    for row in conn.execute(
        f"SELECT DISTINCT ip, context FROM ioc_ips {analysis_filter}", params
    ).fetchall():
        writer.writerow([row["ip"], row["context"]])
    exports["ips"] = buf.getvalue()

    # Domains
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["domain", "context"])
    for row in conn.execute(
        f"SELECT DISTINCT domain, context FROM ioc_domains {analysis_filter}", params
    ).fetchall():
        writer.writerow([row["domain"], row["context"]])
    exports["domains"] = buf.getvalue()

    # Hashes
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["sha256", "md5", "sha1", "filename"])
    for row in conn.execute(
        f"SELECT DISTINCT sha256, md5, sha1, filename FROM ioc_hashes {analysis_filter}", params
    ).fetchall():
        writer.writerow([row["sha256"], row["md5"], row["sha1"], row["filename"]])
    exports["hashes"] = buf.getvalue()

    # URLs
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["url"])
    for row in conn.execute(
        f"SELECT DISTINCT url FROM ioc_urls {analysis_filter}", params
    ).fetchall():
        writer.writerow([row["url"]])
    exports["urls"] = buf.getvalue()

    conn.close()
    return exports


def export_iocs_stix(campaign_tag: str = None) -> str:
    """
    Export IOCs as a STIX 2.1 Bundle (JSON format).
    No external libraries required — builds the JSON structure manually.
    Optionally filter by campaign tag.
    """
    import uuid

    conn = get_connection()

    if campaign_tag:
        analysis_filter = """
            WHERE analysis_id IN (
                SELECT id FROM analyses WHERE campaign_tag = ?
            )
        """
        params = (campaign_tag,)
    else:
        analysis_filter = ""
        params = ()

    ips = conn.execute(
        f"SELECT DISTINCT ip FROM ioc_ips {analysis_filter}", params
    ).fetchall()

    domains = conn.execute(
        f"SELECT DISTINCT domain FROM ioc_domains {analysis_filter}", params
    ).fetchall()

    hashes = conn.execute(
        f"SELECT DISTINCT sha256, md5, sha1, filename FROM ioc_hashes {analysis_filter}", params
    ).fetchall()

    urls = conn.execute(
        f"SELECT DISTINCT url FROM ioc_urls {analysis_filter}", params
    ).fetchall()

    conn.close()

    now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    objects = []

    # --- IP indicators ---
    for row in ips:
        objects.append({
            "type":             "indicator",
            "spec_version":     "2.1",
            "id":               f"indicator--{uuid.uuid4()}",
            "created":          now,
            "modified":         now,
            "name":             f"Malicious IP: {row['ip']}",
            "pattern":          f"[ipv4-addr:value = '{row['ip']}']",
            "pattern_type":     "stix",
            "valid_from":       now,
            "indicator_types":  ["malicious-activity"],
            "labels":           ["phishing"],
        })

    # --- Domain indicators ---
    for row in domains:
        objects.append({
            "type":             "indicator",
            "spec_version":     "2.1",
            "id":               f"indicator--{uuid.uuid4()}",
            "created":          now,
            "modified":         now,
            "name":             f"Malicious Domain: {row['domain']}",
            "pattern":          f"[domain-name:value = '{row['domain']}']",
            "pattern_type":     "stix",
            "valid_from":       now,
            "indicator_types":  ["malicious-activity"],
            "labels":           ["phishing"],
        })

    # --- File hash indicators ---
    for row in hashes:
        hashes_obj = {"SHA-256": row["sha256"]}
        if row["md5"]:
            hashes_obj["MD5"] = row["md5"]
        if row["sha1"]:
            hashes_obj["SHA-1"] = row["sha1"]

        objects.append({
            "type":             "indicator",
            "spec_version":     "2.1",
            "id":               f"indicator--{uuid.uuid4()}",
            "created":          now,
            "modified":         now,
            "name":             f"Malicious File: {row['filename'] or 'unknown'}",
            "pattern":          f"[file:hashes.'SHA-256' = '{row['sha256']}']",
            "pattern_type":     "stix",
            "valid_from":       now,
            "indicator_types":  ["malicious-activity"],
            "labels":           ["phishing"],
            "extensions": {
                "file": {
                    "hashes": hashes_obj,
                    "name":   row["filename"] or "unknown",
                }
            }
        })

    # --- URL indicators ---
    for row in urls:
        objects.append({
            "type":             "indicator",
            "spec_version":     "2.1",
            "id":               f"indicator--{uuid.uuid4()}",
            "created":          now,
            "modified":         now,
            "name":             f"Malicious URL: {row['url'][:80]}",
            "pattern":          f"[url:value = '{row['url']}']",
            "pattern_type":     "stix",
            "valid_from":       now,
            "indicator_types":  ["malicious-activity"],
            "labels":           ["phishing"],
        })

    # --- STIX Bundle ---
    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "created":      now,
        "objects":      objects,
    }

    if campaign_tag:
        bundle["name"] = f"Phish Analyzer Export - {campaign_tag}"

    return json.dumps(bundle, indent=2)