"""
StaffWatch Server v4.1
Flask + Flask-SocketIO + Flask-SQLAlchemy

New in v4.1:
  - OrgSettings model (org name, logo, timezone, contact, address)
  - /api/admin/settings  GET / POST
  - /api/admin/change_password  POST  (current + new password)
  - /api/admin/report/<mid>  GET  (per-machine PDF-ready JSON report with date filter)
  - Real-time push: browser_update now ships latest event payload
  - Real-time push: app_update now ships latest event payload
  - Real-time push: network_update now ships connection count
"""
from flask import (Flask, render_template, request, jsonify,
                   Response, session, redirect, url_for)
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta, timezone
import csv, io, json, os, secrets

# ─── Admin password — stored in module-level variable so change_password works
_ADMIN_PASSWORD = "admin123"   # ← change before first deploy

# ─── App ──────────────────────────────────────────────────────────────────────
UTC = timezone.utc

import os
BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE, "../dashboard/templates"),
    static_folder=os.path.join(BASE, "../dashboard/static"),
)
app.config.update(
    SECRET_KEY=secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI="sqlite:////opt/render/project/src/staffwatch.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

db      = SQLAlchemy(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    max_http_buffer_size=10 * 1024 * 1024,
)

# ─── UTC helpers ──────────────────────────────────────────────────────────────

def _now():
    return datetime.now(UTC).replace(tzinfo=None)

def _ago(days=0, minutes=0):
    return _now() - timedelta(days=days, minutes=minutes)

def _parse_ts(raw):
    if not raw:
        return _now()
    s = str(raw).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.astimezone(UTC).replace(tzinfo=None)
        return dt
    except (ValueError, TypeError):
        return _now()

def _iso(dt):
    return dt.isoformat() + "Z" if dt else None

# ─── Auth ─────────────────────────────────────────────────────────────────────

def _logged_in():
    return session.get("admin_logged_in") is True

# ─── Models ───────────────────────────────────────────────────────────────────

class Machine(db.Model):
    id            = db.Column(db.String(64),  primary_key=True)
    hostname      = db.Column(db.String(128), nullable=False)
    os_type       = db.Column(db.String(32),  default="")
    ip_address    = db.Column(db.String(64),  default="")
    mac_address   = db.Column(db.String(64),  default="")
    employee_name = db.Column(db.String(128), default="")
    department    = db.Column(db.String(128), default="")
    agent_version = db.Column(db.String(16),  default="4.1")
    first_seen    = db.Column(db.DateTime,    default=_now)
    last_seen     = db.Column(db.DateTime,    default=_now)
    is_online     = db.Column(db.Boolean,     default=False)
    consent_given = db.Column(db.Boolean,     default=False)
    agent_locked  = db.Column(db.Boolean,     default=True)


class BrowserEvent(db.Model):
    id           = db.Column(db.Integer,     primary_key=True)
    machine_id   = db.Column(db.String(64),  db.ForeignKey("machine.id"))
    timestamp    = db.Column(db.DateTime,    default=_now)
    browser      = db.Column(db.String(32),  default="unknown")
    url          = db.Column(db.Text,        default="")
    title        = db.Column(db.Text,        default="")
    domain       = db.Column(db.String(256), default="")
    duration_sec = db.Column(db.Integer,     default=0)


class AppEvent(db.Model):
    id           = db.Column(db.Integer,     primary_key=True)
    machine_id   = db.Column(db.String(64),  db.ForeignKey("machine.id"))
    timestamp    = db.Column(db.DateTime,    default=_now)
    app_name     = db.Column(db.String(256), default="")
    window_title = db.Column(db.Text,        default="")
    duration_sec = db.Column(db.Integer,     default=0)
    category     = db.Column(db.String(64),  default="Other")


class Screenshot(db.Model):
    id         = db.Column(db.Integer,    primary_key=True)
    machine_id = db.Column(db.String(64), db.ForeignKey("machine.id"))
    timestamp  = db.Column(db.DateTime,  default=_now)
    image_b64  = db.Column(db.Text,      default="")
    width      = db.Column(db.Integer,   default=0)
    height     = db.Column(db.Integer,   default=0)
    ocr_text   = db.Column(db.Text,      default="")


class NetworkEvent(db.Model):
    id         = db.Column(db.Integer,     primary_key=True)
    machine_id = db.Column(db.String(64),  db.ForeignKey("machine.id"))
    timestamp  = db.Column(db.DateTime,   default=_now)
    dest_host  = db.Column(db.String(256), default="")
    dest_port  = db.Column(db.Integer,    default=0)
    protocol   = db.Column(db.String(16),  default="TCP")
    bytes_sent = db.Column(db.Integer,    default=0)
    bytes_recv = db.Column(db.Integer,    default=0)


class AlertLog(db.Model):
    id           = db.Column(db.Integer,    primary_key=True)
    machine_id   = db.Column(db.String(64), db.ForeignKey("machine.id"))
    rule_id      = db.Column(db.Integer,    db.ForeignKey("alert_rule.id"), nullable=True)
    timestamp    = db.Column(db.DateTime,   default=_now)
    alert_type   = db.Column(db.String(64), default="")
    detail       = db.Column(db.Text,       default="")
    severity     = db.Column(db.String(16), default="info")
    acknowledged = db.Column(db.Boolean,    default=False)
    ack_at       = db.Column(db.DateTime,   nullable=True)


class AlertRule(db.Model):
    id               = db.Column(db.Integer,     primary_key=True)
    name             = db.Column(db.String(128),  nullable=False)
    rule_type        = db.Column(db.String(32),   nullable=False)
    enabled          = db.Column(db.Boolean,      default=True)
    severity         = db.Column(db.String(16),   default="warning")
    applies_to       = db.Column(db.String(512),  default="all")
    config           = db.Column(db.Text,         default="{}")
    notify_dashboard = db.Column(db.Boolean,      default=True)
    notify_sound     = db.Column(db.Boolean,      default=False)
    cooldown_min     = db.Column(db.Integer,      default=15)
    created_at       = db.Column(db.DateTime,     default=_now)
    updated_at       = db.Column(db.DateTime,     default=_now)


class OrgSettings(db.Model):
    """Single-row table — always id=1."""
    id           = db.Column(db.Integer,     primary_key=True)
    org_name     = db.Column(db.String(256),  default="My Organisation")
    org_logo_b64 = db.Column(db.Text,         default="")   # base64 data URL
    timezone     = db.Column(db.String(64),   default="UTC")
    contact_name = db.Column(db.String(128),  default="")
    contact_email= db.Column(db.String(256),  default="")
    address      = db.Column(db.Text,         default="")
    updated_at   = db.Column(db.DateTime,     default=_now)
    # Comma-separated keyword lists for each app category (admin-configurable)
    cat_productive    = db.Column(db.Text, default="code,vscode,excel,word,powerpoint,outlook,teams,slack,zoom,notepad,terminal,pycharm,intellij,xcode,android studio,vim,emacs")
    cat_entertainment = db.Column(db.Text, default="youtube,netflix,spotify,vlc,steam,discord,twitch,prime video,hulu,disneyplus")
    cat_communication = db.Column(db.Text, default="teams,slack,zoom,skype,telegram,whatsapp,outlook,thunderbird,mail,gmail")


def _get_org():
    o = db.session.get(OrgSettings, 1)
    if not o:
        o = OrgSettings(id=1)
        db.session.add(o)
        db.session.commit()
    return o


# ─── App categorisation ───────────────────────────────────────────────────────

def _get_cat_keywords():
    """Return (productive, entertainment, communication) keyword sets from DB."""
    o = _get_org()
    def _parse(text, default):
        kws = [k.strip().lower() for k in (text or "").split(",") if k.strip()]
        return set(kws) if kws else default
    default_p = {"code","vscode","excel","word","powerpoint","outlook","teams",
                 "slack","zoom","notepad","terminal","pycharm","intellij","xcode",
                 "android studio","vim","emacs"}
    default_e = {"youtube","netflix","spotify","vlc","steam","discord",
                 "twitch","prime video","hulu","disneyplus"}
    default_c = {"teams","slack","zoom","skype","telegram","whatsapp",
                 "outlook","thunderbird","mail","gmail"}
    return (
        _parse(o.cat_productive,    default_p),
        _parse(o.cat_entertainment, default_e),
        _parse(o.cat_communication, default_c),
    )

def _categorise(app_name):
    n = app_name.lower()
    productive, entertainment, communication = _get_cat_keywords()
    if any(a in n for a in productive):    return "Productive"
    if any(a in n for a in entertainment): return "Entertainment"
    if any(a in n for a in communication): return "Communication"
    return "Other"


# ─── Alert engine ─────────────────────────────────────────────────────────────

def _cooldown_ok(rule, machine_id):
    since = _ago(minutes=rule.cooldown_min)
    return not AlertLog.query.filter_by(
        rule_id=rule.id, machine_id=machine_id
    ).filter(AlertLog.timestamp >= since).first()


def _rule_applies(rule, machine_id):
    if rule.applies_to == "all":
        return True
    return machine_id in [x.strip() for x in rule.applies_to.split(",")]


def _fire(rule, machine_id, detail):
    m     = db.session.get(Machine, machine_id)
    entry = AlertLog(
        machine_id=machine_id, rule_id=rule.id,
        alert_type=rule.rule_type, detail=detail, severity=rule.severity,
    )
    db.session.add(entry)
    db.session.commit()
    payload = {
        "id": entry.id, "machine_id": machine_id,
        "hostname": m.hostname if m else machine_id[:12],
        "rule_name": rule.name, "alert_type": rule.rule_type,
        "detail": detail, "severity": rule.severity,
        "sound": rule.notify_sound, "timestamp": _iso(entry.timestamp),
    }
    if rule.notify_dashboard:
        socketio.emit("new_alert", payload, room="admin")


def eval_browser_rules(machine_id, url, domain, title):
    for rule in AlertRule.query.filter_by(enabled=True).all():
        if not _rule_applies(rule, machine_id):
            continue
        cfg = json.loads(rule.config or "{}")
        if rule.rule_type == "BLOCKED_SITE":
            kws    = [k.strip().lower() for k in cfg.get("keywords", "").split(",") if k.strip()]
            target = (url + " " + domain + " " + (title or "")).lower()
            for kw in kws:
                if kw in target and _cooldown_ok(rule, machine_id):
                    _fire(rule, machine_id, f"Visited blocked site: {domain} (keyword: {kw})")
                    break
        elif rule.rule_type == "NONPROD_TIME_LIMIT":
            threshold = cfg.get("threshold_min", 30) * 60
            nonprod   = ["youtube.com","facebook.com","instagram.com","tiktok.com",
                         "twitter.com","x.com","reddit.com","netflix.com","twitch.tv"]
            today = _now().date()
            total = sum(
                e.duration_sec
                for e in BrowserEvent.query.filter_by(machine_id=machine_id)
                                           .filter(BrowserEvent.timestamp >= today).all()
                if any(nd in (e.domain or "") for nd in nonprod)
            )
            if total >= threshold and _cooldown_ok(rule, machine_id):
                _fire(rule, machine_id,
                      f"Non-productive browsing: {total // 60} min today "
                      f"(limit: {cfg.get('threshold_min', 30)} min)")


def eval_app_rules(machine_id, app_name, duration_sec):
    for rule in AlertRule.query.filter_by(enabled=True).all():
        if not _rule_applies(rule, machine_id):
            continue
        cfg = json.loads(rule.config or "{}")
        if rule.rule_type == "FLAGGED_APP":
            kws = [k.strip().lower() for k in cfg.get("keywords", "").split(",") if k.strip()]
            for kw in kws:
                if kw in app_name.lower() and _cooldown_ok(rule, machine_id):
                    _fire(rule, machine_id, f"Flagged app used: {app_name}")
                    break
        elif rule.rule_type == "APP_TIME_LIMIT":
            target = cfg.get("app_name", "").lower()
            limit  = cfg.get("threshold_min", 60) * 60
            if target and target in app_name.lower():
                today = _now().date()
                total = db.session.query(db.func.sum(AppEvent.duration_sec)).filter(
                    AppEvent.machine_id == machine_id,
                    AppEvent.timestamp  >= today,
                    AppEvent.app_name.ilike(f"%{target}%"),
                ).scalar() or 0
                if total >= limit and _cooldown_ok(rule, machine_id):
                    _fire(rule, machine_id,
                          f"App time limit: {app_name} — {total // 60} min today "
                          f"(limit: {cfg.get('threshold_min', 60)} min)")
        elif rule.rule_type == "AFTER_HOURS":
            ws    = cfg.get("work_start", "09:00")
            we    = cfg.get("work_end",   "18:00")
            now_t = _now().strftime("%H:%M")
            if (now_t < ws or now_t > we) and _cooldown_ok(rule, machine_id):
                _fire(rule, machine_id,
                      f"After-hours activity: {app_name} at {now_t} UTC "
                      f"(work hours: {ws}–{we})")


def eval_idle_rules(machine_id):
    for rule in AlertRule.query.filter_by(enabled=True, rule_type="IDLE").all():
        if not _rule_applies(rule, machine_id):
            continue
        cfg      = json.loads(rule.config or "{}")
        idle_min = cfg.get("idle_min", 15)
        recent   = AppEvent.query.filter_by(machine_id=machine_id) \
                                 .filter(AppEvent.timestamp >= _ago(minutes=idle_min)).first()
        if recent is None and _cooldown_ok(rule, machine_id):
            _fire(rule, machine_id, f"Machine idle for {idle_min}+ minutes")


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    global _ADMIN_PASSWORD
    data = request.json or {}
    if data.get("password") == _ADMIN_PASSWORD:
        session.permanent = True
        session["admin_logged_in"] = True
        return jsonify({"status": "ok"})
    return jsonify({"error": "Invalid password"}), 401


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "ok"})


@app.route("/api/auth/check", methods=["GET"])
def api_auth_check():
    return jsonify({"logged_in": _logged_in()})


# ─── Agent endpoints ──────────────────────────────────────────────────────────

@app.route("/api/agent/register", methods=["POST"])
def agent_register():
    data = request.json or {}
    mid  = data.get("machine_guid", "")
    if not mid:
        return jsonify({"error": "missing machine_guid"}), 400
    m = db.session.get(Machine, mid)
    if not m:
        m = Machine(id=mid)
        db.session.add(m)
    m.hostname      = data.get("hostname",      "unknown")
    m.os_type       = data.get("os_type",        "unknown")
    m.ip_address    = request.remote_addr
    m.mac_address   = data.get("mac_address",   "")
    m.agent_version = data.get("agent_version", "4.1")
    m.last_seen     = _now()
    m.is_online     = True
    m.consent_given = bool(data.get("consent_given", False))
    db.session.commit()
    socketio.emit("machine_status",
                  {"machine_id": mid, "status": "online", "hostname": m.hostname,
                   "ip_address": m.ip_address, "os_type": m.os_type},
                  room="admin")
    return jsonify({"status": "registered", "machine_id": mid,
                    "agent_locked": m.agent_locked})


@app.route("/api/agent/heartbeat", methods=["POST"])
def agent_heartbeat():
    data = request.json or {}
    m    = db.session.get(Machine, data.get("machine_guid", ""))
    if m:
        m.last_seen  = _now()
        m.is_online  = True
        m.ip_address = request.remote_addr
        db.session.commit()
        eval_idle_rules(m.id)
        # Push updated machine status
        socketio.emit("machine_heartbeat",
                      {"machine_id": m.id, "last_seen": _iso(m.last_seen),
                       "is_online": True},
                      room="admin")
    return jsonify({"status": "ok",
                    "agent_locked": m.agent_locked if m else True})


@app.route("/api/agent/browser", methods=["POST"])
def ingest_browser():
    data   = request.json or {}
    mid    = data.get("machine_guid", "")
    latest = None
    for ev in data.get("events", []):
        url    = ev.get("url", "")
        domain = url.split("/")[2] if "//" in url else url
        ts     = _parse_ts(ev.get("timestamp"))
        row    = BrowserEvent(
            machine_id=mid, timestamp=ts, browser=ev.get("browser", "unknown"),
            url=url, title=ev.get("title", ""), domain=domain,
            duration_sec=ev.get("duration_sec", 0),
        )
        db.session.add(row)
        eval_browser_rules(mid, url, domain, ev.get("title", ""))
        latest = row
    db.session.commit()
    # Real-time push with latest event payload
    if latest:
        socketio.emit("browser_update", {
            "machine_id": mid,
            "domain": latest.domain, "title": latest.title,
            "browser": latest.browser, "timestamp": _iso(latest.timestamp),
        }, room="admin")
    return jsonify({"status": "ok"})


@app.route("/api/agent/apps", methods=["POST"])
def ingest_apps():
    data   = request.json or {}
    mid    = data.get("machine_guid", "")
    latest = None
    for ev in data.get("events", []):
        name = ev.get("app_name", "")
        ts   = _parse_ts(ev.get("timestamp"))
        row  = AppEvent(
            machine_id=mid, timestamp=ts, app_name=name,
            window_title=ev.get("window_title", ""),
            duration_sec=ev.get("duration_sec", 0),
            category=_categorise(name),
        )
        db.session.add(row)
        eval_app_rules(mid, name, ev.get("duration_sec", 0))
        latest = row
    db.session.commit()
    if latest:
        socketio.emit("app_update", {
            "machine_id": mid,
            "app_name": latest.app_name, "category": latest.category,
            "duration_sec": latest.duration_sec, "timestamp": _iso(latest.timestamp),
        }, room="admin")
    return jsonify({"status": "ok"})


@app.route("/api/agent/screenshot", methods=["POST"])
def ingest_screenshot():
    data = request.json or {}
    mid  = data.get("machine_guid", "")
    ss   = Screenshot(
        machine_id=mid, image_b64=data.get("image_b64", ""),
        width=data.get("width", 0), height=data.get("height", 0),
        ocr_text=data.get("ocr_text", ""),
    )
    db.session.add(ss)
    # Keep only last 50 screenshots per machine
    old = Screenshot.query.filter_by(machine_id=mid) \
                          .order_by(Screenshot.timestamp.desc()).offset(50).all()
    for o in old:
        db.session.delete(o)
    db.session.commit()
    socketio.emit("live_screen",
                  {"machine_id": mid, "image_b64": data.get("image_b64", ""),
                   "timestamp": _iso(ss.timestamp),
                   "width": ss.width, "height": ss.height},
                  room="admin")
    return jsonify({"status": "ok"})


@app.route("/api/agent/network", methods=["POST"])
def ingest_network():
    data  = request.json or {}
    mid   = data.get("machine_guid", "")
    count = 0
    for ev in data.get("events", []):
        db.session.add(NetworkEvent(
            machine_id=mid, timestamp=_parse_ts(ev.get("timestamp")),
            dest_host=ev.get("dest_host", ""), dest_port=ev.get("dest_port", 0),
            protocol=ev.get("protocol", "TCP"),
            bytes_sent=ev.get("bytes_sent", 0), bytes_recv=ev.get("bytes_recv", 0),
        ))
        count += 1
    db.session.commit()
    if count:
        socketio.emit("network_update",
                      {"machine_id": mid, "new_connections": count},
                      room="admin")
    return jsonify({"status": "ok"})


# ─── Admin: machines ──────────────────────────────────────────────────────────

@app.route("/api/admin/machines", methods=["GET"])
def get_machines():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cutoff   = _ago(minutes=2)
    machines = Machine.query.all()
    result   = []
    for m in machines:
        if m.last_seen and m.last_seen < cutoff and m.is_online:
            m.is_online = False
            db.session.commit()
        result.append({
            "id": m.id, "hostname": m.hostname, "os_type": m.os_type,
            "ip_address": m.ip_address, "employee_name": m.employee_name,
            "department": m.department, "is_online": m.is_online,
            "last_seen": _iso(m.last_seen), "first_seen": _iso(m.first_seen),
            "consent_given": m.consent_given, "agent_locked": m.agent_locked,
            "mac_address": m.mac_address, "agent_version": m.agent_version,
        })
    return jsonify(result)


@app.route("/api/admin/machine/<mid>/update", methods=["POST"])
def update_machine(mid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    m = db.session.get(Machine, mid)
    if not m:
        return jsonify({"error": "not found"}), 404
    data = request.json or {}
    if "employee_name" in data: m.employee_name = data["employee_name"]
    if "department"    in data: m.department    = data["department"]
    db.session.commit()
    return jsonify({"status": "updated"})


@app.route("/api/admin/machine/<mid>/disable", methods=["POST"])
def disable_agent(mid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    m = db.session.get(Machine, mid)
    if not m:
        return jsonify({"error": "not found"}), 404
    data = request.json or {}
    if data.get("password") == _ADMIN_PASSWORD:
        m.agent_locked = False
        db.session.commit()
        socketio.emit("agent_command", {"command": "disable"}, room=f"machine_{mid}")
        return jsonify({"status": "agent_disabled"})
    return jsonify({"error": "invalid password"}), 403


# ─── Admin: statistics ────────────────────────────────────────────────────────

@app.route("/api/admin/stats/overview", methods=["GET"])
def stats_overview():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    machines = Machine.query.all()
    online   = sum(1 for m in machines if m.is_online)
    today    = _now().date()
    return jsonify({
        "total_machines":       len(machines),
        "online_machines":      online,
        "offline_machines":     len(machines) - online,
        "total_browser_events": BrowserEvent.query.count(),
        "total_app_events":     AppEvent.query.count(),
        "today_browser_events": BrowserEvent.query.filter(BrowserEvent.timestamp >= today).count(),
        "today_app_events":     AppEvent.query.filter(AppEvent.timestamp >= today).count(),
        "unacked_alerts":       AlertLog.query.filter_by(acknowledged=False).count(),
    })


@app.route("/api/admin/stats/browser", methods=["GET"])
def stats_browser():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mid    = request.args.get("machine_id", "")
    days   = int(request.args.get("days", 7))
    since  = _ago(days=days)
    q      = BrowserEvent.query.filter(BrowserEvent.timestamp >= since)
    if mid:
        q = q.filter_by(machine_id=mid)
    events = q.order_by(BrowserEvent.timestamp.desc()).limit(500).all()
    domain_counts, by_day = {}, {}
    for e in events:
        domain_counts[e.domain] = domain_counts.get(e.domain, 0) + 1
        day = e.timestamp.date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1
    return jsonify({
        "total": len(events),
        "top_domains": [{"domain": d, "count": c}
                        for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:20]],
        "by_day":  [{"date": d, "count": c} for d, c in sorted(by_day.items())],
        "recent": [{"id": e.id, "machine_id": e.machine_id, "browser": e.browser,
                    "url": e.url, "title": e.title, "domain": e.domain,
                    "timestamp": _iso(e.timestamp), "duration_sec": e.duration_sec}
                   for e in events[:100]],
    })


@app.route("/api/admin/stats/apps", methods=["GET"])
def stats_apps():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mid    = request.args.get("machine_id", "")
    days   = int(request.args.get("days", 7))
    since  = _ago(days=days)
    q      = AppEvent.query.filter(AppEvent.timestamp >= since)
    if mid:
        q = q.filter_by(machine_id=mid)
    events = q.order_by(AppEvent.timestamp.desc()).limit(1000).all()
    app_counts, cat_counts, by_day = {}, {}, {}
    for e in events:
        app_counts[e.app_name] = app_counts.get(e.app_name, 0) + e.duration_sec
        cat_counts[e.category] = cat_counts.get(e.category, 0) + e.duration_sec
        day = e.timestamp.date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1
    return jsonify({
        "total": len(events),
        "top_apps": [{"app": a, "duration_sec": d}
                     for a, d in sorted(app_counts.items(), key=lambda x: -x[1])[:20]],
        "by_category": [{"category": c, "duration_sec": d} for c, d in cat_counts.items()],
        "by_day":  [{"date": d, "count": c} for d, c in sorted(by_day.items())],
        "recent": [{"id": e.id, "machine_id": e.machine_id, "app_name": e.app_name,
                    "window_title": e.window_title, "category": e.category,
                    "timestamp": _iso(e.timestamp), "duration_sec": e.duration_sec}
                   for e in events[:100]],
    })


@app.route("/api/admin/stats/network", methods=["GET"])
def stats_network():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mid    = request.args.get("machine_id", "")
    days   = int(request.args.get("days", 7))
    since  = _ago(days=days)
    q      = NetworkEvent.query.filter(NetworkEvent.timestamp >= since)
    if mid:
        q = q.filter_by(machine_id=mid)
    events = q.order_by(NetworkEvent.timestamp.desc()).limit(2000).all()
    host_counts, port_counts, by_day = {}, {}, {}
    bs_total = br_total = 0
    for e in events:
        if e.dest_host:
            host_counts[e.dest_host] = host_counts.get(e.dest_host, 0) + 1
        if e.dest_port:
            port_counts[e.dest_port] = port_counts.get(e.dest_port, 0) + 1
        day = e.timestamp.date().isoformat()
        by_day[day] = by_day.get(day, 0) + 1
        bs_total   += e.bytes_sent or 0
        br_total   += e.bytes_recv or 0
    mmap = {m.id: m for m in Machine.query.all()}
    return jsonify({
        "total": len(events),
        "bytes_sent": bs_total, "bytes_recv": br_total,
        "top_hosts": [{"host": h, "count": c}
                      for h, c in sorted(host_counts.items(), key=lambda x: -x[1])[:20]],
        "top_ports": [{"port": p, "count": c}
                      for p, c in sorted(port_counts.items(), key=lambda x: -x[1])[:15]],
        "by_day": [{"date": d, "count": c} for d, c in sorted(by_day.items())],
        "recent": [{"id": e.id, "machine_id": e.machine_id,
                    "hostname": mmap[e.machine_id].hostname if e.machine_id in mmap else e.machine_id[:12],
                    "timestamp": _iso(e.timestamp),
                    "dest_host": e.dest_host, "dest_port": e.dest_port,
                    "protocol": e.protocol}
                   for e in events[:200]],
    })


@app.route("/api/admin/machine/<mid>/screenshots", methods=["GET"])
def get_screenshots(mid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    shots = Screenshot.query.filter_by(machine_id=mid) \
                            .order_by(Screenshot.timestamp.desc()).limit(10).all()
    return jsonify([{"id": s.id, "timestamp": _iso(s.timestamp),
                     "image_b64": s.image_b64, "width": s.width, "height": s.height}
                    for s in shots])


# ─── Admin: org settings ──────────────────────────────────────────────────────

@app.route("/api/admin/settings", methods=["GET"])
def get_settings():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    o = _get_org()
    return jsonify({
        "org_name":           o.org_name,
        "org_logo_b64":       o.org_logo_b64,
        "timezone":           o.timezone,
        "contact_name":       o.contact_name,
        "contact_email":      o.contact_email,
        "address":            o.address,
        "updated_at":         _iso(o.updated_at),
        "cat_productive":     o.cat_productive    or "",
        "cat_entertainment":  o.cat_entertainment or "",
        "cat_communication":  o.cat_communication or "",
    })


@app.route("/api/admin/settings", methods=["POST"])
def save_settings():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    o    = _get_org()
    data = request.json or {}
    for f in ["org_name", "org_logo_b64", "timezone",
              "contact_name", "contact_email", "address",
              "cat_productive", "cat_entertainment", "cat_communication"]:
        if f in data:
            setattr(o, f, data[f])
    o.updated_at = _now()
    db.session.commit()
    return jsonify({"status": "saved"})


@app.route("/api/admin/change_password", methods=["POST"])
def change_password():
    global _ADMIN_PASSWORD
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    current = data.get("current_password", "")
    new_pw  = data.get("new_password", "")
    if current != _ADMIN_PASSWORD:
        return jsonify({"error": "Current password incorrect"}), 403
    if len(new_pw) < 6:
        return jsonify({"error": "New password must be at least 6 characters"}), 400
    _ADMIN_PASSWORD = new_pw
    return jsonify({"status": "password_changed"})


# ─── Admin: per-machine report ────────────────────────────────────────────────

@app.route("/api/admin/report/<mid>", methods=["GET"])
def machine_report(mid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    m = db.session.get(Machine, mid)
    if not m:
        return jsonify({"error": "not found"}), 404

    fmt     = request.args.get("format", "json")   # json | csv
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to",   "")

    try:
        since = datetime.fromisoformat(date_from) if date_from else _ago(days=30)
    except ValueError:
        since = _ago(days=30)
    try:
        until = datetime.fromisoformat(date_to) if date_to else _now()
    except ValueError:
        until = _now()

    # ── Gather data ──────────────────────────────────────────────────────────
    browser_events = BrowserEvent.query.filter_by(machine_id=mid) \
        .filter(BrowserEvent.timestamp >= since, BrowserEvent.timestamp <= until) \
        .order_by(BrowserEvent.timestamp.desc()).limit(2000).all()

    app_events = AppEvent.query.filter_by(machine_id=mid) \
        .filter(AppEvent.timestamp >= since, AppEvent.timestamp <= until) \
        .order_by(AppEvent.timestamp.desc()).limit(2000).all()

    net_events = NetworkEvent.query.filter_by(machine_id=mid) \
        .filter(NetworkEvent.timestamp >= since, NetworkEvent.timestamp <= until) \
        .order_by(NetworkEvent.timestamp.desc()).limit(2000).all()

    alerts = AlertLog.query.filter_by(machine_id=mid) \
        .filter(AlertLog.timestamp >= since, AlertLog.timestamp <= until) \
        .order_by(AlertLog.timestamp.desc()).all()

    # ── Summaries ────────────────────────────────────────────────────────────
    domain_counts  = {}
    for e in browser_events:
        domain_counts[e.domain] = domain_counts.get(e.domain, 0) + 1

    app_totals = {}
    cat_totals = {}
    for e in app_events:
        app_totals[e.app_name] = app_totals.get(e.app_name, 0) + e.duration_sec
        cat_totals[e.category] = cat_totals.get(e.category, 0) + e.duration_sec

    alert_breakdown = {"info": 0, "warning": 0, "critical": 0}
    for a in alerts:
        alert_breakdown[a.severity] = alert_breakdown.get(a.severity, 0) + 1

    org = _get_org()

    if fmt == "csv":
        out = io.StringIO()
        w   = csv.writer(out)

        # --- Machine summary ---
        w.writerow(["=== STAFFWATCH REPORT ==="])
        w.writerow(["Organisation", org.org_name])
        w.writerow(["Generated", _iso(_now())])
        w.writerow(["Period", f"{_iso(since)} → {_iso(until)}"])
        w.writerow([])
        w.writerow(["=== MACHINE INFO ==="])
        w.writerow(["Hostname",       m.hostname])
        w.writerow(["Employee",       m.employee_name or "—"])
        w.writerow(["Department",     m.department or "—"])
        w.writerow(["OS",             m.os_type])
        w.writerow(["IP Address",     m.ip_address])
        w.writerow(["MAC Address",    m.mac_address])
        w.writerow(["Agent Version",  m.agent_version])
        w.writerow(["First Seen",     _iso(m.first_seen)])
        w.writerow(["Last Seen",      _iso(m.last_seen)])
        w.writerow([])

        # --- Browser ---
        w.writerow(["=== BROWSER HISTORY ==="])
        w.writerow(["Timestamp","Browser","Domain","URL","Title","Duration (s)"])
        for e in browser_events:
            w.writerow([_iso(e.timestamp), e.browser, e.domain, e.url, e.title, e.duration_sec])
        w.writerow([])

        # --- Apps ---
        w.writerow(["=== APPLICATION USAGE ==="])
        w.writerow(["Timestamp","Application","Category","Window Title","Duration (s)"])
        for e in app_events:
            w.writerow([_iso(e.timestamp), e.app_name, e.category, e.window_title, e.duration_sec])
        w.writerow([])

        # --- Network ---
        w.writerow(["=== NETWORK CONNECTIONS ==="])
        w.writerow(["Timestamp","Destination","Port","Protocol"])
        for e in net_events:
            w.writerow([_iso(e.timestamp), e.dest_host, e.dest_port, e.protocol])
        w.writerow([])

        # --- Alerts ---
        w.writerow(["=== ALERTS ==="])
        w.writerow(["Timestamp","Type","Severity","Detail","Acknowledged"])
        for a in alerts:
            w.writerow([_iso(a.timestamp), a.alert_type, a.severity, a.detail,
                        "Yes" if a.acknowledged else "No"])

        out.seek(0)
        filename = f"staffwatch_report_{m.hostname}_{_now().date()}.csv"
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={filename}"})

    # ── JSON report ───────────────────────────────────────────────────────────
    return jsonify({
        "report_meta": {
            "generated_at": _iso(_now()),
            "period_from": _iso(since),
            "period_to":   _iso(until),
            "org_name":    org.org_name,
        },
        "machine": {
            "id": m.id, "hostname": m.hostname, "os_type": m.os_type,
            "ip_address": m.ip_address, "mac_address": m.mac_address,
            "employee_name": m.employee_name, "department": m.department,
            "agent_version": m.agent_version,
            "first_seen": _iso(m.first_seen), "last_seen": _iso(m.last_seen),
            "is_online": m.is_online,
        },
        "summary": {
            "total_browser_events":  len(browser_events),
            "total_app_events":      len(app_events),
            "total_network_events":  len(net_events),
            "total_alerts":          len(alerts),
            "alert_breakdown":       alert_breakdown,
            "top_domains":  [{"domain": d, "count": c}
                             for d, c in sorted(domain_counts.items(), key=lambda x: -x[1])[:15]],
            "top_apps":     [{"app": a, "duration_sec": d}
                             for a, d in sorted(app_totals.items(), key=lambda x: -x[1])[:15]],
            "app_categories": [{"category": c, "duration_sec": d}
                               for c, d in sorted(cat_totals.items(), key=lambda x: -x[1])],
        },
        "browser_events": [{"timestamp": _iso(e.timestamp), "browser": e.browser,
                             "domain": e.domain, "url": e.url, "title": e.title,
                             "duration_sec": e.duration_sec}
                           for e in browser_events],
        "app_events": [{"timestamp": _iso(e.timestamp), "app_name": e.app_name,
                        "category": e.category, "duration_sec": e.duration_sec,
                        "window_title": e.window_title}
                       for e in app_events],
        "network_events": [{"timestamp": _iso(e.timestamp), "dest_host": e.dest_host,
                             "dest_port": e.dest_port, "protocol": e.protocol}
                           for e in net_events],
        "alerts": [{"timestamp": _iso(a.timestamp), "alert_type": a.alert_type,
                    "severity": a.severity, "detail": a.detail,
                    "acknowledged": a.acknowledged}
                   for a in alerts],
    })


# ─── Admin: alert log ─────────────────────────────────────────────────────────

@app.route("/api/admin/alerts", methods=["GET"])
def get_alerts():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mid   = request.args.get("machine_id", "")
    sev   = request.args.get("severity", "")
    acked = request.args.get("acknowledged", "")
    days  = int(request.args.get("days", 7))
    since = _ago(days=days)
    q     = AlertLog.query.filter(AlertLog.timestamp >= since)
    if mid:   q = q.filter_by(machine_id=mid)
    if sev:   q = q.filter_by(severity=sev)
    if acked != "":
        q = q.filter_by(acknowledged=(acked.lower() == "true"))
    alerts    = q.order_by(AlertLog.timestamp.desc()).limit(500).all()
    breakdown = {"info": 0, "warning": 0, "critical": 0}
    for a in alerts:
        breakdown[a.severity] = breakdown.get(a.severity, 0) + 1
    return jsonify({
        "total": len(alerts), "breakdown": breakdown,
        "alerts": [{"id": a.id, "machine_id": a.machine_id, "rule_id": a.rule_id,
                    "timestamp": _iso(a.timestamp), "alert_type": a.alert_type,
                    "detail": a.detail, "severity": a.severity,
                    "acknowledged": a.acknowledged, "ack_at": _iso(a.ack_at)}
                   for a in alerts],
    })


@app.route("/api/admin/alerts/<int:aid>/acknowledge", methods=["POST"])
def acknowledge_alert(aid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    a = db.session.get(AlertLog, aid)
    if not a:
        return jsonify({"error": "not found"}), 404
    a.acknowledged = True
    a.ack_at       = _now()
    db.session.commit()
    socketio.emit("alert_acked", {"id": aid}, room="admin")
    return jsonify({"status": "acknowledged"})


@app.route("/api/admin/alerts/acknowledge_all", methods=["POST"])
def acknowledge_all_alerts():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    AlertLog.query.filter_by(acknowledged=False).update(
        {"acknowledged": True, "ack_at": _now()})
    db.session.commit()
    socketio.emit("alerts_all_acked", {}, room="admin")
    return jsonify({"status": "ok"})


@app.route("/api/admin/alerts/export", methods=["GET"])
def export_alerts():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    days   = int(request.args.get("days", 30))
    alerts = AlertLog.query.filter(AlertLog.timestamp >= _ago(days=days)) \
                           .order_by(AlertLog.timestamp.desc()).all()
    mmap   = {m.id: m for m in Machine.query.all()}
    out    = io.StringIO()
    w      = csv.writer(out)
    w.writerow(["ID","Timestamp (UTC)","Machine","Employee","Alert Type",
                "Severity","Detail","Acknowledged","Ack Time (UTC)"])
    for a in alerts:
        m = mmap.get(a.machine_id)
        w.writerow([a.id, _iso(a.timestamp),
                    m.hostname if m else a.machine_id,
                    m.employee_name if m else "",
                    a.alert_type, a.severity, a.detail,
                    "Yes" if a.acknowledged else "No", _iso(a.ack_at)])
    out.seek(0)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=staffwatch_alerts.csv"})


# ─── Admin: alert rules CRUD ──────────────────────────────────────────────────

def _rule_dict(r):
    return {
        "id": r.id, "name": r.name, "rule_type": r.rule_type,
        "enabled": r.enabled, "severity": r.severity, "applies_to": r.applies_to,
        "config": json.loads(r.config or "{}"),
        "notify_dashboard": r.notify_dashboard, "notify_sound": r.notify_sound,
        "cooldown_min": r.cooldown_min,
        "created_at": _iso(r.created_at), "updated_at": _iso(r.updated_at),
    }


@app.route("/api/admin/alert_rules", methods=["GET"])
def get_alert_rules():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify([_rule_dict(r) for r in AlertRule.query.order_by(AlertRule.created_at.desc()).all()])


@app.route("/api/admin/alert_rules", methods=["POST"])
def create_alert_rule():
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    r = AlertRule(
        name=data.get("name", "New Rule"),
        rule_type=data.get("rule_type", "BLOCKED_SITE"),
        enabled=data.get("enabled", True),
        severity=data.get("severity", "warning"),
        applies_to=data.get("applies_to", "all"),
        config=json.dumps(data.get("config", {})),
        notify_dashboard=data.get("notify_dashboard", True),
        notify_sound=data.get("notify_sound", False),
        cooldown_min=data.get("cooldown_min", 15),
    )
    db.session.add(r)
    db.session.commit()
    return jsonify(_rule_dict(r)), 201


@app.route("/api/admin/alert_rules/<int:rid>", methods=["PUT"])
def update_alert_rule(rid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    r = db.session.get(AlertRule, rid)
    if not r:
        return jsonify({"error": "not found"}), 404
    data = request.json or {}
    for f in ["name","rule_type","enabled","severity","applies_to",
              "notify_dashboard","notify_sound","cooldown_min"]:
        if f in data: setattr(r, f, data[f])
    if "config" in data:
        r.config = json.dumps(data["config"])
    r.updated_at = _now()
    db.session.commit()
    return jsonify(_rule_dict(r))


@app.route("/api/admin/alert_rules/<int:rid>", methods=["DELETE"])
def delete_alert_rule(rid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    r = db.session.get(AlertRule, rid)
    if not r: return jsonify({"error": "not found"}), 404
    db.session.delete(r)
    db.session.commit()
    return jsonify({"status": "deleted"})


@app.route("/api/admin/alert_rules/<int:rid>/toggle", methods=["POST"])
def toggle_alert_rule(rid):
    if not _logged_in():
        return jsonify({"error": "unauthorized"}), 401
    r = db.session.get(AlertRule, rid)
    if not r: return jsonify({"error": "not found"}), 404
    r.enabled    = not r.enabled
    r.updated_at = _now()
    db.session.commit()
    return jsonify({"enabled": r.enabled})


# ─── Dashboard & SocketIO ─────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    if not _logged_in():
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")


@socketio.on("join_admin")
def on_join_admin():
    join_room("admin")
    emit("joined", {"room": "admin"})


@socketio.on("join_machine")
def on_join_machine(data):
    join_room(f"machine_{data['machine_id']}")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        _get_org()   # ensure OrgSettings row exists
        print("✅ StaffWatch v4.2 — http://0.0.0.0:5000")
        print(f"   Admin password: {_ADMIN_PASSWORD}")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
