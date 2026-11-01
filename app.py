"""أرشيف مدرسة أم المؤمنين — server-only Supabase access, private storage."""
import csv
import hashlib
import io
import tempfile
import httpx
import zipfile
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from functools import lru_cache, wraps
from pathlib import Path
from uuid import UUID, uuid4

import cv2
import numpy as np
from flask import Flask, Response, jsonify, request, send_file, send_from_directory, session, stream_with_context
from openpyxl import load_workbook
from PIL import Image, ImageEnhance, ImageFilter, ImageOps
from pypdf import PdfReader, PdfWriter
from supabase import create_client
from werkzeug.security import check_password_hash, generate_password_hash
from zipstream import ZIP_STORED, ZipStream

ROOT = Path(__file__).resolve().parent
KINDS = {
    "start": "مباشرة العمل",
    "appointment": "قرار التعيين",
    "birth": "شهادة الميلاد",
    "service": "استمرارية العمل",
    "qualification": "المؤهل العلمي",
}
BUCKET = "teacher-archive-private"
MAX_IMAGE = 12 * 1024 * 1024
MAX_REQUEST = 75 * 1024 * 1024
LOGIN_ATTEMPTS = {}  # basic in-process throttle (single Gunicorn worker)
Image.MAX_IMAGE_PIXELS = 32_000_000
app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_REQUEST,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(os.environ.get("COOKIE_SECURE", "1") == "1"),
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,
    JSON_AS_ASCII=False,
)
logging.basicConfig(level=logging.INFO)


class UserError(Exception):
    def __init__(self, message, code=400):
        self.message, self.code = message, code


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(UserError)
def handle_user_error(exc):
    return jsonify(error=exc.message), exc.code


@app.errorhandler(413)
def handle_large(_):
    return jsonify(error="الملف كبير جدًا. صغّر الصور أو أرسلها على دفعتين."), 413


@app.errorhandler(Exception)
def handle_error(exc):
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return jsonify(error=exc.description), exc.code
    app.logger.exception("Unexpected server failure")
    return jsonify(error="تعذّر إكمال العملية. راجع سجل Render للتفاصيل."), 500


@lru_cache(maxsize=1)
def db():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not url or not key:
        raise UserError("أضف SUPABASE_URL وSUPABASE_SERVICE_ROLE_KEY في Render أولًا.", 503)
    return create_client(url, key)


def table(name):
    return db().table("archive_" + name)


def clean(s, limit=120):
    return re.sub(r"[\\/:*?\"<>|\r\n\x00-\x1f]", "_", str(s)).strip(" ._")[:limit] or "غير_مسمى"


def uid(value):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise UserError("معرّف غير صحيح")


def read_with_retry(fn, attempts=3):
    """Retry SELECT requests only. Never blindly repeat writes."""
    for attempt in range(attempts):
        try:
            return fn()
        except (httpx.TransportError, TimeoutError, OSError) as exc:
            app.logger.warning("Temporary Supabase read transport error: %s (%s/%s)",
                               type(exc).__name__, attempt + 1, attempts)
            if attempt == attempts - 1:
                raise UserError("تعذر الاتصال بالتخزين مؤقتًا. لم تُحذف البيانات؛ أعد المحاولة.", 503) from exc
            time.sleep((0.35, 1.0, 2.0)[min(attempt, 2)])


def all_records(name, fields="*", order="created_at"):
    result = []
    for offset in range(0, 10000, 500):
        part = read_with_retry(lambda: table(name).select(fields).order(order).range(
            offset, offset + 499).execute()).data or []
        result.extend(part)
        if len(part) < 500:
            break
    return result


def login_required(roles=None):
    def inner(fn):
        @wraps(fn)
        def wrapped(*a, **kw):
            user_id = session.get("uid")
            if not user_id:
                raise UserError("سجّل الدخول أولًا", 401)
            users = read_with_retry(lambda: table("users").select("id,username,full_name,role,active").eq("id", user_id).limit(1).execute()).data
            if not users or not users[0]["active"]:
                session.clear()
                raise UserError("الحساب غير نشط", 401)
            request.current_user = users[0]
            if roles and users[0]["role"] not in roles:
                raise UserError("ليس لديك صلاحية لهذا الإجراء", 403)
            return fn(*a, **kw)
        return wrapped
    return inner


@app.before_request
def csrf_protection():
    if request.path.startswith("/api/") and request.method in ("POST", "PATCH", "PUT", "DELETE") and request.path != "/api/login":
        expected = session.get("csrf")
        received = request.headers.get("X-CSRF-Token", "")
        if not expected or not secrets.compare_digest(expected, received):
            raise UserError("انتهت صلاحية الجلسة؛ حدّث الصفحة وأعد المحاولة.", 403)


def audit(action, info=""):
    try:
        table("logs").insert({
            "actor_id": session.get("uid"),
            "actor_name": (getattr(request, "current_user", {}) or {}).get("full_name", "النظام"),
            "action": action,
            "details": str(info)[:300],
        }).execute()
    except Exception:
        app.logger.warning("Audit write failed", exc_info=True)


def audit_document(action, doc, extra=""):
    """Include teacher name AND national ID in audit trail; no schema changes."""
    teacher = teacher_by_id(doc["teacher_id"])
    details = (
        f"معلم: {teacher['full_name']} | وطني: {teacher['national_id']} | "
        f"مستند: {KINDS.get(doc['kind'], doc['kind'])} | "
        f"ID:{teacher['id']}"
    )
    if extra:
        details += f" | {extra}"
    audit(action, details)


def audit_new_document(action, teacher, kind):
    audit(action, f"معلم: {teacher['full_name']} | وطني: {teacher['national_id']} | "
                  f"مستند: {KINDS[kind]} | ID:{teacher['id']}")


def boot_admin():
    existing = table("users").select("id").limit(1).execute().data
    if existing:
        return
    username = os.environ.get("FIRST_ADMIN_USERNAME", "").strip()
    password = os.environ.get("FIRST_ADMIN_PASSWORD", "")
    if not username or len(password) < 12:
        raise UserError("حدد FIRST_ADMIN_USERNAME وكلمة FIRST_ADMIN_PASSWORD من 12 خانة على الأقل في Render.", 503)
    table("users").insert({
        "username": username,
        "full_name": "مدير الأرشيف",
        "password_hash": generate_password_hash(password),
        "role": "admin",
        "active": True,
    }).execute()


@app.get("/")
def home():
    response = send_from_directory(ROOT, "index.html")
    # Android browsers may otherwise keep showing the older interface after
    # GitHub + Render deployment. The archive data itself is unaffected.
    response.headers["Cache-Control"] = "no-store, max-age=0, must-revalidate"
    return response


@app.get("/health")
def health():
    return jsonify(ok=True, version="V10-DARK-20261101")


@app.get("/api/version")
def public_version():
    """Deployment health indicator only; never expose customer records or keys."""
    return jsonify(version="V10-DARK-20261101", theme="dark", download="native-zip")


@app.post("/api/login")
def login():
    ip = request.remote_addr or "unknown"
    now = time.monotonic()
    recent = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 900]
    if len(recent) >= 12:
        raise UserError("محاولات دخول كثيرة. أعد المحاولة بعد 15 دقيقة.", 429)
    boot_admin()
    data = request.get_json(silent=True) or {}
    name = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    users = table("users").select("*").eq("username", name).limit(1).execute().data or []
    user = users[0] if users else None
    if not user or not user["active"] or not check_password_hash(user["password_hash"], password):
        LOGIN_ATTEMPTS[ip] = (recent + [now])[-12:]
        raise UserError("اسم المستخدم أو كلمة المرور غير صحيحة", 401)
    LOGIN_ATTEMPTS.pop(ip, None)
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    audit("دخول", name)
    return jsonify(user={k: user[k] for k in ("id", "username", "full_name", "role")}, csrf=session["csrf"])


@app.post("/api/logout")
@login_required()
def logout():
    audit("خروج")
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
@login_required()
def me():
    return jsonify(user=request.current_user, csrf=session.get("csrf"))


@app.get("/api/state")
@login_required()
def state():
    role = request.current_user["role"]
    # Scanner can search existing teachers and correct his/her own scans, but
    # cannot access national IDs, other users' PDFs, exports or management.
    teacher_fields = "id,full_name,position" if role == "scanner" else "id,full_name,national_id,position,created_at"
    document_fields = ("id,teacher_id,kind,pages,version,uploaded_by" if role == "scanner"
                       else "id,teacher_id,kind,pages,version,uploaded_by,created_at,updated_at")
    teachers = all_records("teachers", teacher_fields)
    docs = all_records("documents", document_fields, "created_at")
    logs = []
    users = []
    if role == "admin":
        logs = read_with_retry(lambda: table("logs").select("actor_name,action,details,created_at").order("created_at", desc=True).limit(30).execute()).data or []
        users = read_with_retry(lambda: table("users").select("id,username,full_name,role,active,created_at").order("created_at").execute()).data or []
    return jsonify(teachers=teachers, documents=docs, logs=logs, users=users)


def teacher_by_id(id_):
    rows = read_with_retry(lambda: table("teachers").select("*").eq("id", uid(id_)).limit(1).execute()).data or []
    if not rows:
        raise UserError("لم يتم العثور على المعلم", 404)
    return rows[0]


def validated_teacher(data):
    full_name = str(data.get("full_name", "")).strip()
    national_id = str(data.get("national_id", "")).strip().translate(str.maketrans("٠١٢٣٤٥٦٧٨٩", "0123456789"))
    position = str(data.get("position", "")).strip()
    if len(full_name) < 4 or len(full_name) > 180 or not re.fullmatch(r"\d{6,25}", national_id) or not position or len(position) > 100:
        raise UserError("أدخل اسم المعلم، ورقمًا وطنيًا من 6 إلى 25 رقمًا، والوظيفة.")
    return {"full_name": full_name, "national_id": national_id, "position": position}


@app.post("/api/teachers")
@login_required(roles=("admin",))
def add_teacher():
    values = validated_teacher(request.get_json(silent=True) or {})
    if table("teachers").select("id").eq("national_id", values["national_id"]).limit(1).execute().data:
        raise UserError("هذا الرقم الوطني موجود بالفعل", 409)
    result = table("teachers").insert(values).execute().data[0]
    audit("إضافة معلم", result["full_name"])
    return jsonify(teacher=result), 201


@app.patch("/api/teachers/<id_>")
@login_required(roles=("admin",))
def change_teacher(id_):
    teacher_by_id(id_)
    values = validated_teacher(request.get_json(silent=True) or {})
    table("teachers").update(values).eq("id", uid(id_)).execute()
    audit("تعديل معلم", values["full_name"])
    return jsonify(ok=True)


@app.delete("/api/teachers/<id_>")
@login_required(roles=("admin",))
def remove_teacher(id_):
    teacher = teacher_by_id(id_)
    docs = table("documents").select("storage_path").eq("teacher_id", uid(id_)).execute().data or []
    table("teachers").delete().eq("id", uid(id_)).execute()
    if docs:
        try:
            db().storage.from_(BUCKET).remove([x["storage_path"] for x in docs])
        except Exception:
            app.logger.exception("Storage cleanup pending for deleted teacher")
    audit("حذف معلم", teacher["full_name"])
    return jsonify(ok=True)


def parse_spreadsheet(file):
    name = file.filename.lower()
    blob = file.read(3 * 1024 * 1024 + 1)
    if len(blob) > 3 * 1024 * 1024:
        raise UserError("ملف Excel أكبر من 3 ميغابايت")
    if name.endswith(".xlsx"):
        wb = load_workbook(io.BytesIO(blob), read_only=True, data_only=True)
        rows = wb.active.iter_rows(values_only=True)
        values = [list(x) for x in rows]
        wb.close()
    elif name.endswith(".csv"):
        values = list(csv.reader(io.StringIO(blob.decode("utf-8-sig"))))
    else:
        raise UserError("استخدم ملف .xlsx أو .csv فقط")
    if not values:
        raise UserError("الملف فارغ")
    first = [str(v or "").lower().strip() for v in values[0]]
    header = any("الوطني" in x or "national" in x for x in first) or (
        bool(first) and first[0] in ("الاسم", "اسم المعلم", "name", "full_name"))
    def col(words, fallback):
        for i, val in enumerate(first):
            if any(w in val for w in words):
                return i
        return fallback
    name_col = col(("الاسم", "name", "المعلم"), 0) if header else 0
    nid_col = col(("الوطني", "national", "القومي"), 1) if header else 1
    job_col = col(("الوظيفة", "position", "الصفة", "المسمى"), 2) if header else 2
    result, seen = [], set()
    for ix, row in enumerate(values[1:] if header else values, start=2 if header else 1):
        if not any(v is not None and str(v).strip() for v in row):
            continue
        try:
            vals = validated_teacher({
                "full_name": row[name_col] or "",
                "national_id": str(row[nid_col] or "").removesuffix(".0"),
                "position": row[job_col] or "",
            })
        except (IndexError, UserError) as ex:
            raise UserError(f"خطأ في صف Excel رقم {ix}: {getattr(ex, 'message', 'الأعمدة غير مكتملة')}")
        if vals["national_id"] in seen:
            raise UserError(f"الرقم الوطني مكرر في صف Excel رقم {ix}")
        result.append(vals)
        seen.add(vals["national_id"])
        if len(result) > 2000:
            raise UserError("الحد الأقصى للاستيراد 2000 معلم")
    if not result:
        raise UserError("لا توجد بيانات صالحة للاستيراد")
    return result


@app.post("/api/teachers/import")
@login_required(roles=("admin",))
def import_teachers():
    file = request.files.get("file")
    if not file:
        raise UserError("اختَر ملف Excel")
    values = parse_spreadsheet(file)
    # Update existing names/positions based on national ID, keeping teacher IDs and PDFs intact.
    for start in range(0, len(values), 200):
        table("teachers").upsert(values[start:start+200], on_conflict="national_id").execute()
    audit("استيراد Excel", f"{len(values)} معلم")
    return jsonify(ok=True, count=len(values))


def storage():
    return db().storage.from_(BUCKET)


def find_doc(teacher_id, kind):
    if kind not in KINDS:
        raise UserError("نوع المستند غير معروف")
    found = read_with_retry(lambda: table("documents").select("*").eq("teacher_id", uid(teacher_id)).eq("kind", kind).limit(1).execute()).data or []
    return found[0] if found else None


def get_doc(id_):
    found = read_with_retry(lambda: table("documents").select("*").eq("id", uid(id_)).limit(1).execute()).data or []
    if not found:
        raise UserError("المستند غير موجود", 404)
    return found[0]


@app.get("/api/teachers/<teacher_id>/documents/<kind>/version")
@login_required(roles=("admin", "scanner"))
def current_document_version(teacher_id, kind):
    """Lightweight version check before phone uploads (no PDF download).

    The client uses this to reconcile its outdated screen. The server still
    enforces compare-and-swap on save to prevent lost updates between devices.
    """
    item = find_doc(teacher_id, kind)
    return jsonify(exists=bool(item), id=item["id"] if item else None,
                   version=int(item["version"]) if item else 0,
                   pages=int(item["pages"]) if item else 0)


def require_document_editor(doc):
    """Staff photographers may correct any saved teacher document.

    Removing an image/PDF or replacing it always requires a current version;
    concurrent edits fail safely rather than silently overwriting one another.
    All actions are logged. Teacher deletion/export and account management
    remain admin-only.
    """
    if request.current_user["role"] in ("admin", "scanner"):
        return
    raise UserError("ليس لديك صلاحية تعديل مستندات PDF", 403)


def check_document_version(doc, raw, required=False):
    if raw in (None, ""):
        if required:
            raise UserError("حدّث الصفحة أولًا قبل تعديل هذا المستند.", 409)
        return
    try:
        expected = int(raw)
    except (ValueError, TypeError):
        raise UserError("رقم نسخة المستند غير صحيح")
    if doc["version"] != expected:
        raise UserError("المستند تغيّر من جهاز آخر. حدّث قائمة المعلمين ثم أعد المحاولة.", 409)

def detect_page(im):
    """Attempt 4-corner perspective correction. Fallback retains full image."""
    rgb = np.array(im.convert("RGB"))
    height, width = rgb.shape[:2]
    scale = min(1., 1100 / max(width, height))
    small = cv2.resize(rgb, None, fx=scale, fy=scale) if scale < 1 else rgb
    gray = cv2.cvtColor(small, cv2.COLOR_RGB2GRAY)
    edged = cv2.Canny(cv2.GaussianBlur(gray, (5, 5), 0), 45, 140)
    contours, _ = cv2.findContours(edged, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    for cnt in sorted(contours, key=cv2.contourArea, reverse=True)[:8]:
        perimeter = cv2.arcLength(cnt, True)
        pts = cv2.approxPolyDP(cnt, .025 * perimeter, True)
        if (len(pts) != 4 or not cv2.isContourConvex(pts)
                or cv2.contourArea(pts) < .38 * small.shape[0] * small.shape[1]):
            continue
        p = pts.reshape(4, 2).astype("float32") / scale
        sums, diffs = p.sum(axis=1), np.diff(p, axis=1).flatten()
        src = np.array([p[np.argmin(sums)], p[np.argmin(diffs)], p[np.argmax(sums)], p[np.argmax(diffs)]], dtype="float32")
        tl, tr, br, bl = src
        destw = max(int(np.linalg.norm(tr-tl)), int(np.linalg.norm(br-bl)))
        desth = max(int(np.linalg.norm(bl-tl)), int(np.linalg.norm(br-tr)))
        if (destw < 250 or desth < 250 or destw * desth > 32_000_000
                or not .52 <= destw / desth <= 1.9):
            continue
        dst = np.array([[0,0],[destw-1,0],[destw-1,desth-1],[0,desth-1]], dtype="float32")
        warped = cv2.warpPerspective(rgb, cv2.getPerspectiveTransform(src, dst), (destw, desth))
        return Image.fromarray(warped), True
    return im, False


def manual_crop_image(image, corners):
    """Crop and straighten a page from four normalized corners [TL,TR,BR,BL].

    The points come from the authenticated browser after the employee positions
    draggable handles. The original image pixels are processed on the server.
    """
    if not isinstance(corners, list) or len(corners) != 4:
        raise UserError("حدد زوايا الورقة الأربع بصورة صحيحة")
    try:
        pts = np.asarray(corners, dtype=np.float32)
    except (TypeError, ValueError):
        raise UserError("إحداثيات قص الورقة غير صحيحة")
    if pts.shape != (4, 2) or not np.isfinite(pts).all() or (pts < 0).any() or (pts > 1).any():
        raise UserError("إحداثيات القص خارج حدود الصورة")
    width, height = image.size
    pts *= np.array([width - 1, height - 1], dtype=np.float32)
    # Reorder points after any 90-degree rotation performed by the browser.
    sm = pts.sum(axis=1)
    df = np.diff(pts, axis=1).reshape(-1)
    tl, tr, br, bl = pts[np.argmin(sm)], pts[np.argmin(df)], pts[np.argmax(sm)], pts[np.argmax(df)]
    ordered = np.array([tl, tr, br, bl], dtype=np.float32)
    area = abs(cv2.contourArea(ordered))
    if area < width * height * .015:
        raise UserError("منطقة القص صغيرة جدًا، حدّد حدود الورقة كاملة")
    new_width = round(max(np.linalg.norm(tr-tl), np.linalg.norm(br-bl)))
    new_height = round(max(np.linalg.norm(bl-tl), np.linalg.norm(br-tr)))
    if min(new_width, new_height) < 300:
        raise UserError("منطقة القص صغيرة جدًا لقراءة المستند")
    # Bound memory on free Render, keep good native resolution for print.
    sf = min(1., 3000 / max(new_width, new_height))
    new_width, new_height = round(new_width * sf), round(new_height * sf)
    dest = np.float32([[0, 0], [new_width - 1, 0],
                       [new_width - 1, new_height - 1], [0, new_height - 1]])
    matrix = cv2.getPerspectiveTransform(ordered, dest)
    result = cv2.warpPerspective(np.asarray(image.convert('RGB')), matrix,
                                 (new_width, new_height), flags=cv2.INTER_LINEAR,
                                 borderMode=cv2.BORDER_CONSTANT,
                                 borderValue=(255, 255, 255))
    return Image.fromarray(result)


def pdf_from_image(image, mode="scan", automatic_crop=True, manual_points=None):
    """Create a legible, compact A4 PDF quickly, avoiding dark page output.

    The paper is corrected using a background illumination map. Ink is kept
    dark, but faint handwritten strokes are not blindly thresholded away.
    An A4-size raster does not magically increase optical camera detail.
    """
    if mode not in ("scan", "clear", "color", "bw"):
        raise UserError("نمط التحسين غير صحيح")
    image = ImageOps.exif_transpose(image).convert("RGB")
    if min(image.size) < 500:
        raise UserError("الصورة صغيرة أو بعيدة جدًا؛ قرّب الهاتف وأعد التصوير")
    if max(image.size) > 3200:
        image.thumbnail((3200, 3200), Image.Resampling.LANCZOS)
    cropped = False
    if manual_points is not None:
        image = manual_crop_image(image, manual_points)
        cropped = True
    elif automatic_crop:
        image, cropped = detect_page(image)
    rgb = np.asarray(image)
    if mode == "color":
        # Gentle correction keeps coloured stamps and ink visible.
        lab = cv2.cvtColor(rgb, cv2.COLOR_RGB2LAB)
        l, a, b = cv2.split(lab)
        l = cv2.createCLAHE(clipLimit=1.5, tileGridSize=(8, 8)).apply(l)
        processed = Image.fromarray(cv2.cvtColor(cv2.merge((l, a, b)), cv2.COLOR_LAB2RGB))
    else:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        h, w = gray.shape
        # Estimate page lighting at low resolution: fast even on free Render.
        factor = min(1.0, 850 / max(h, w))
        small = cv2.resize(gray, (max(50, round(w*factor)), max(50, round(h*factor))),
                           interpolation=cv2.INTER_AREA) if factor < 1 else gray
        kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (33, 33))
        background = cv2.morphologyEx(small, cv2.MORPH_CLOSE, kernel)
        background = cv2.GaussianBlur(background, (0, 0), sigmaX=13)
        bg = cv2.resize(background, (w, h), interpolation=cv2.INTER_LINEAR)
        # Remove shadows even on very dark mobile photos.
        norm = cv2.divide(gray, np.maximum(bg, 15), scale=253)
        if mode == "bw":
            result = cv2.adaptiveThreshold(norm, 255,
                        cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 35, 13)
        else:
            # Normalize background to paper white, preserve pale text.
            strength = 1.18 if mode == "scan" else 1.07
            result = np.clip((norm.astype(np.float32) - 215) * strength + 226,
                             0, 255).astype(np.uint8)
            # A gentle sharpen avoids black bands and crushed handwriting.
        processed = Image.fromarray(result).filter(
            ImageFilter.UnsharpMask(radius=.55, percent=75, threshold=3))
    # 230 dpi A4 gives clear text with faster conversion, smaller uploads and
    # smaller PDFs than re-encoding every sheet at 300 dpi and quality 96.
    sheet_w, sheet_h = 1748, 2479  # A4 ~210 DPI, lighter to render and transfer
    margin = 28
    if processed.width > processed.height:
        processed = processed.rotate(90, expand=True)
    avail_w, avail_h = sheet_w - 2*margin, sheet_h - 2*margin
    s = min(avail_w / processed.width, avail_h / processed.height)
    new_size = (max(1, round(processed.width*s)), max(1, round(processed.height*s)))
    processed = processed.resize(new_size, Image.Resampling.LANCZOS if s < 1 else Image.Resampling.BICUBIC)
    sheet = Image.new("RGB" if mode == "color" else "L", (sheet_w, sheet_h), "white")
    sheet.paste(processed, ((sheet_w-new_size[0])//2, (sheet_h-new_size[1])//2))
    out = io.BytesIO()
    sheet.save(out, format="PDF", resolution=210, quality=82)
    return out.getvalue(), cropped


def image_pdf(data, mode="scan", points=None):
    if len(data) > MAX_IMAGE:
        raise UserError("حجم الصورة يتجاوز 12 ميغابايت")
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
        return pdf_from_image(im, mode, manual_points=points,
                              automatic_crop=points is None)
    except (ValueError, OSError, Image.DecompressionBombError):
        raise UserError("تعذر فتح الصورة؛ استخدم JPG أو PNG")


def images_as_pdf(files, mode="scan", points_json=None):
    if not files or len(files) > 20:
        raise UserError("اختَر من 1 إلى 20 صورة في كل مرة")
    try:
        points_list = json.loads(points_json) if points_json else [None] * len(files)
    except (json.JSONDecodeError, TypeError):
        raise UserError("تعذر قراءة حدود قص الصورة")
    if not isinstance(points_list, list) or len(points_list) != len(files):
        raise UserError("عدد حدود القص لا يطابق عدد الصور")
    # Fast path for the common case: one photo = one PDF page. Avoid reading
    # and rewriting the PDF a second time just to copy one page.
    if len(files) == 1:
        f = files[0]
        if not (f.mimetype or "").startswith("image/"):
            raise UserError("يُسمح برفع الصور فقط")
        result, cropped = image_pdf(f.read(MAX_IMAGE + 1), mode, points_list[0])
        return result, int(cropped)
    writer, cropped_count = PdfWriter(), 0
    for f, points in zip(files, points_list):
        if not (f.mimetype or "").startswith("image/"):
            raise UserError("يُسمح برفع الصور فقط")
        pdf, cropped = image_pdf(f.read(MAX_IMAGE + 1), mode, points)
        cropped_count += int(cropped)
        writer.append(io.BytesIO(pdf))
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue(), cropped_count


def merge_pdfs(existing_pdf, new_pdf, mode, page_index=None):
    old = PdfReader(io.BytesIO(existing_pdf))
    fresh = PdfReader(io.BytesIO(new_pdf))
    writer = PdfWriter()
    if mode == "replace":
        writer.append(fresh)
    elif mode == "append":
        writer.append(old)
        writer.append(fresh)
    elif mode == "replace_page":
        if page_index is None or not 0 <= page_index < len(old.pages) or len(fresh.pages) != 1:
            raise UserError("رقم الصفحة غير صحيح")
        for n, page in enumerate(old.pages):
            writer.add_page(fresh.pages[0] if n == page_index else page)
    else:
        raise UserError("عملية غير معروفة")
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def save_doc(teacher_id, kind, contents, pages, old=None):
    path = f"{uid(teacher_id)}/{kind}/{uuid4().hex}.pdf"
    storage().upload(path, contents, {"content-type": "application/pdf", "upsert": "false"})
    # Verify new bytes are reachable BEFORE pointing the database at this path.
    # Keep the uploaded object on failure for later recovery; never delete user scans.
    try:
        check = None
        for attempt in range(3):
            try:
                check = _direct_private_pdf(path)
                break
            except StorageFetchError as exc:
                # The SDK offers a second authenticated route if direct GET
                # is unavailable on this Supabase Storage deployment.
                try:
                    check = storage().download(path)
                    if isinstance(check, bytes) and check.startswith(b"%PDF"):
                        break
                except Exception:
                    pass
                if attempt == 2:
                    raise UserError("تم رفع PDF لكن تعذر التحقق من وصوله للتخزين. احتفظ بالصورة وأعد المحاولة؛ لن تُستبدل النسخة الحالية.", 503) from exc
                time.sleep((0.35, 1.0)[attempt])
        if check is None or hashlib.sha256(check).digest() != hashlib.sha256(contents).digest():
            raise UserError("النسخة المرفوعة لا تطابق المستند؛ لم نغيّر الملف القديم.", 503)
    except UserError:
        app.logger.error("Upload not verified, original database reference retained: %s", path)
        raise
    try:
        if old:
            resp = table("documents").update({
                "storage_path": path, "pages": pages, "version": old["version"] + 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "uploaded_by": session.get("uid"),
            }).eq("id", old["id"]).eq("version", old["version"]).execute()
            if not resp.data:
                raise UserError("تم تعديل المستند من مستخدم آخر. حدّث الشاشة وأعد المحاولة.", 409)
        else:
            resp = table("documents").insert({
                "teacher_id": uid(teacher_id), "kind": kind, "pages": pages,
                "version": 1, "storage_path": path, "uploaded_by": session.get("uid"),
            }).execute()
    except Exception:
        # Never remove a freshly uploaded file after a database conflict.
        # It can contain the only recoverable scan if a request is interrupted.
        app.logger.warning("Uploaded PDF retained for recovery after DB write conflict: %s", path)
        # Two authorized devices may scan the same missing document at once.
        # Preserve the first save and ask the second device to refresh, instead
        # of presenting a generic internal error or replacing another scan.
        if old is None:
            try:
                if find_doc(teacher_id, kind):
                    raise UserError("هذا المستند حُفظ من جهاز آخر. حدّث الصفحة لمشاهدة الحالة.", 409)
            except UserError:
                raise
            except Exception:
                app.logger.warning("Could not verify simultaneous upload", exc_info=True)
        raise
    # Critical data-safety policy: NEVER auto-delete an older PDF version.
    # Versions live under teacher_id/kind and can recover missing references.
    return resp.data[0]


def safe_doc_pdf(doc):
    """Read the newest recoverable PDF for the SAME teacher and document type."""
    data, resolved = _export_pdf_with_retries({
        "kind": doc["kind"], "path": doc["storage_path"],
        "version": int(doc.get("version") or 1),
        "pages": int(doc.get("pages") or 0),
    }, "مستند المعلم", doc["teacher_id"])
    return data, resolved


@app.post("/api/teachers/<teacher_id>/documents/<kind>")
@login_required(roles=("admin", "scanner"))
def upload_doc(teacher_id, kind):
    teacher = teacher_by_id(teacher_id)
    if kind not in KINDS:
        raise UserError("نوع المستند غير معروف")
    mode = request.form.get("mode", "append")
    if mode not in ("append", "replace"):
        raise UserError("اختر إضافة صفحات أو استبدال المستند")

    # Check replacement conflicts BEFORE image processing. The browser also
    # checks freshness before starting the upload, but that alone is not safe
    # when multiple phones are scanning at the same time.
    expected = request.form.get("expected_version", "0")
    old = find_doc(teacher_id, kind)
    if old:
        require_document_editor(old)
        if mode == "replace":
            check_document_version(old, expected, required=True)
    elif mode == "replace" and expected not in ("", "0"):
        raise UserError("المستند حُذف من جهاز آخر. أعد مراجعة الملف قبل حفظ البديل.", 409)

    files = request.files.getlist("images")
    new_pdf, cropped = images_as_pdf(
        files, request.form.get("quality", "scan"), request.form.get("crop_points"))

    # Appending new pages is non-destructive. If two phones append together,
    # fetch the newer PDF and retry with the same new pages; conditional DB
    # writes inside save_doc make sure neither phone can silently erase work.
    # Full replacement, unlike append, must never auto-rebase.
    for attempt in range(3 if mode == "append" else 1):
        current = find_doc(teacher_id, kind)
        if current:
            require_document_editor(current)
        if mode == "replace":
            if current:
                check_document_version(current, expected, required=True)
            elif expected not in ("", "0"):
                raise UserError("المستند حُذف من جهاز آخر. حدّث قائمة المعلمين.", 409)
        final = new_pdf
        if current and mode == "append":
            final = merge_pdfs(safe_doc_pdf(current)[0], new_pdf, "append")
        page_count = (current["pages"] if current and mode == "append" else 0) + len(files)
        try:
            saved = save_doc(teacher_id, kind, final, page_count, current)
            break
        except UserError as exc:
            if mode != "append" or exc.code != 409 or attempt == 2:
                raise
            app.logger.info("Concurrent page append, rebasing once more: teacher=%s kind=%s",
                            teacher_id, kind)
    audit_new_document("تعديل مستند" if old else "تصوير مستند", teacher, kind)
    return jsonify(document=saved, auto_crop_count=cropped)


@app.post("/api/documents/<doc_id>/pages/<int:page>/replace")
@login_required(roles=("admin", "scanner"))
def replace_page(doc_id, page):
    doc = get_doc(doc_id)
    require_document_editor(doc)
    check_document_version(doc, request.form.get("expected_version"), required=True)
    imgs = request.files.getlist("images")
    if len(imgs) != 1:
        raise UserError("اختَر صورة واحدة للاستبدال")
    pdf, cropped = images_as_pdf(imgs, request.form.get("quality", "scan"), request.form.get("crop_points"))
    updated = merge_pdfs(safe_doc_pdf(doc)[0], pdf, "replace_page", page)
    saved = save_doc(doc["teacher_id"], doc["kind"], updated, doc["pages"], doc)
    audit_document("استبدال صفحة", doc, f"صفحة {page+1}")
    return jsonify(document=saved, auto_crop_count=cropped)


@app.delete("/api/documents/<doc_id>/pages/<int:page>")
@login_required(roles=("admin", "scanner"))
def remove_page(doc_id, page):
    doc = get_doc(doc_id)
    require_document_editor(doc)
    check_document_version(doc, request.args.get("expected_version"), required=True)
    old = PdfReader(io.BytesIO(safe_doc_pdf(doc)[0]))
    if len(old.pages) < 2:
        raise UserError("هذه آخر صفحة؛ استخدم زر حذف المستند كاملًا")
    if not 0 <= page < len(old.pages):
        raise UserError("رقم الصفحة غير صحيح")
    writer = PdfWriter()
    for idx, p in enumerate(old.pages):
        if idx != page:
            writer.add_page(p)
    out = io.BytesIO()
    writer.write(out)
    saved = save_doc(doc["teacher_id"], doc["kind"], out.getvalue(), len(old.pages)-1, doc)
    audit_document("حذف صفحة", doc, f"صفحة {page+1}")
    return jsonify(document=saved)


@app.delete("/api/documents/<doc_id>")
@login_required(roles=("admin", "scanner"))
def remove_doc(doc_id):
    doc = get_doc(doc_id)
    require_document_editor(doc)
    check_document_version(doc, request.args.get("expected_version"), required=True)
    deleted = table("documents").delete().eq("id", doc["id"]).eq("version",doc["version"]).execute()
    if not deleted.data:
        raise UserError("هذا المستند تغير من جهاز آخر. حدّث الصفحة أولًا.", 409)
    try:
        storage().remove([doc["storage_path"]])
    except Exception:
        app.logger.exception("File cleanup after deletion failed")
    audit_document("حذف مستند", doc)
    return jsonify(ok=True)


@app.post("/api/documents/<doc_id>/enhance")
@login_required(roles=("admin", "scanner"))
def enhance_existing_pdf(doc_id):
    """Explicitly improve older archived raster PDFs. Never run on existing files silently."""
    doc = get_doc(doc_id)
    require_document_editor(doc)
    check_document_version(doc, (request.get_json(silent=True) or {}).get("expected_version"), required=True)
    # Existing archived documents in this application are one raster image per PDF page.
    old_pdf = safe_doc_pdf(doc)[0]
    pdf = PdfReader(io.BytesIO(old_pdf))
    if not 1 <= len(pdf.pages) <= 20:
        raise UserError("ملفات PDF الكبيرة تحتاج إعادة تصوير على دفعات")
    writer = PdfWriter()
    for page in pdf.pages:
        images = page.images
        if len(images) != 1:
            raise UserError("هذا الملف ليس صورة ممسوحة واحدة لكل صفحة؛ استخدم إعادة التصوير بدل التحسين الآلي")
        # Avoid camera-edge auto-crop for an already A4-formatted page.
        improved, _ = pdf_from_image(images[0].image, mode="scan", automatic_crop=False)
        writer.append(io.BytesIO(improved))
    result = io.BytesIO()
    writer.write(result)
    saved = save_doc(doc["teacher_id"], doc["kind"], result.getvalue(), len(pdf.pages), doc)
    audit_document("تحسين وضوح PDF", doc, f"{len(pdf.pages)} صفحة")
    return jsonify(document=saved)


@app.post("/api/documents/<doc_id>/restore-pdf")
@login_required(roles=("admin",))
def restore_pdf_from_saved_file(doc_id):
    """Restore a real PDF already downloaded on the phone: no rescanning.

    The admin explicitly chooses a PDF from their phone; the active document
    remains untouched until the replacement has been uploaded AND verified.
    """
    doc = get_doc(doc_id)
    check_document_version(doc, request.form.get("expected_version"), required=True)
    file = request.files.get("file")
    if not file or not file.filename.lower().endswith(".pdf"):
        raise UserError("اختر ملف PDF محفوظًا لهذا المعلم من هاتفك.", 422)
    data = file.read(30 * 1024 * 1024 + 1)
    if len(data) > 30 * 1024 * 1024 or len(data) < 50 or not data.startswith(b"%PDF"):
        raise UserError("ملف PDF غير صالح أو يتجاوز 30 ميغابايت.", 422)
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise UserError("ملف PDF محمي بكلمة مرور. افتح نسخة غير محمية ثم ارفعها.", 422)
        pages = len(reader.pages)
        if not 1 <= pages <= 50:
            raise UserError("ملف PDF يجب أن يحتوي على 1 إلى 50 صفحة.", 422)
    except UserError:
        raise
    except Exception as exc:
        raise UserError("تعذر قراءة PDF المختار. تحقق من سلامته.", 422) from exc
    saved = save_doc(doc["teacher_id"], doc["kind"], data, pages, doc)
    audit_document("استرجاع PDF", doc, f"رفع ملف PDF موجود في الهاتف، عدد الصفحات: {pages}")
    return jsonify(document=saved, pages=pages)


@app.get("/api/documents/<doc_id>/pdf")
@login_required(roles=("admin", "viewer", "scanner"))
def download_doc(doc_id):
    doc = get_doc(doc_id)
    if request.current_user["role"] == "scanner":
        require_document_editor(doc)
    teacher = teacher_by_id(doc["teacher_id"])
    data, resolved = safe_doc_pdf(doc)
    name = f"{clean(teacher['full_name'])}-{clean(KINDS[doc['kind']])}.pdf"
    response = send_file(io.BytesIO(data), mimetype="application/pdf", as_attachment=request.args.get("download") == "1", download_name=name)
    if resolved.get("backup_recovery"):
        response.headers["X-Archive-Recovery"] = "backup"
    return response


@app.get("/api/teachers/<teacher_id>/combined.pdf")
@login_required(roles=("admin", "viewer"))
def combined_pdf(teacher_id):
    teacher = teacher_by_id(teacher_id)
    docs = table("documents").select("*").eq("teacher_id", uid(teacher_id)).execute().data or []
    if not docs:
        raise UserError("لا توجد مستندات لهذا المعلم", 404)
    by_kind = {doc["kind"]: doc for doc in docs}
    writer = PdfWriter()
    for kind in KINDS:
        doc = by_kind.get(kind)
        if doc:
            writer.append(io.BytesIO(safe_doc_pdf(doc)[0]))
    out = io.BytesIO()
    writer.write(out)
    return send_file(io.BytesIO(out.getvalue()), mimetype="application/pdf", as_attachment=True,
                     download_name=f"{clean(teacher['full_name'])}-الملف_الكامل.pdf")


def archive_stream(teachers, output_format="folders"):
    """Stream ordered teacher folders or individual combined PDFs in a ZIP."""
    if output_format not in ("folders", "pdf"):
        raise UserError("صيغة التصدير غير صحيحة")
    zs = ZipStream(compress_type=ZIP_STORED)
    doc_rows = all_records("documents", "teacher_id,kind,storage_path,version,pages")
    grouped = {}
    for row in doc_rows:
        grouped.setdefault(row["teacher_id"], {})[row["kind"]] = row
    for teacher in teachers:
        by_kind = grouped.get(teacher["id"], {})
        if not by_kind:
            continue
        label = f"{clean(teacher['full_name'])}_{clean(teacher['national_id'][-4:])}_{teacher['id'][:6]}"
        if output_format == "pdf":
            def build_combined(by_kind=by_kind):
                writer = PdfWriter()
                for kind in KINDS:
                    if kind in by_kind:
                        writer.append(io.BytesIO(safe_doc_pdf(by_kind[kind])[0]))
                output = io.BytesIO()
                writer.write(output)
                contents = output.getvalue()
                for ix in range(0, len(contents), 65536):
                    yield contents[ix:ix+65536]
            zs.add(build_combined(), f"{label}.pdf")
        else:
            for kind in KINDS:
                doc = by_kind.get(kind)
                if not doc:
                    continue
                entry = f"{label}/{clean(KINDS[kind])}.pdf"
                def load_chunks(doc=doc):
                    contents = safe_doc_pdf(doc)[0]
                    for ix in range(0, len(contents), 65536):
                        yield contents[ix:ix+65536]
                zs.add(load_chunks(), entry)
    return zs


@app.get("/api/teachers/<teacher_id>/archive.zip")
@login_required(roles=("admin", "viewer"))
def export_teacher(teacher_id):
    teacher = teacher_by_id(teacher_id)
    output_format = request.args.get("format", "folders")
    if output_format not in ("folders", "pdf"):
        raise UserError("صيغة تصدير غير صحيحة")
    return Response(stream_with_context(archive_stream([teacher], output_format)), mimetype="application/zip",
                    headers={"Content-Disposition": "attachment; filename=teacher_archive.zip", "Cache-Control": "no-store"})


@app.get("/api/export.zip")
@login_required(roles=("admin",))
def export_all():
    try:
        start = max(0, int(request.args.get("start", 0)))
        count = max(1, min(400, int(request.args.get("count", 50))))
    except ValueError:
        raise UserError("عدد المعلمين غير صحيح")
    filter_status = request.args.get("status", "all")
    output_format = request.args.get("format", "folders")
    if filter_status not in ("all", "complete", "incomplete") or output_format not in ("folders", "pdf"):
        raise UserError("فلتر التصدير أو صيغته غير صحيحين")
    teachers = all_records("teachers", "id,full_name,national_id,position,created_at")
    doc_rows = all_records("documents", "teacher_id,kind")
    counts = {}
    for doc in doc_rows:
        counts.setdefault(doc["teacher_id"], set()).add(doc["kind"])
    if filter_status == "complete":
        teachers = [t for t in teachers if len(counts.get(t["id"], ())) == len(KINDS)]
    elif filter_status == "incomplete":
        teachers = [t for t in teachers if len(counts.get(t["id"], ())) < len(KINDS)]
    teachers = sorted(teachers, key=lambda t: t["full_name"])[start:start+count]
    return Response(stream_with_context(archive_stream(teachers, output_format)), mimetype="application/zip",
                    headers={"Content-Disposition": "attachment; filename=school_archive.zip", "Cache-Control": "no-store"})



# V8: durable export history (same dedicated Supabase project, no other projects touched).
# Run migration_v8.sql ONCE inside umm-school-archive-db before using this feature.
def all_export_document_snapshots():
    """Stable paging for the per-document table (up to 400 * 5 records)."""
    rows = []
    for offset in range(0, 10000, 500):
        part = (table("export_document_history")
                .select("teacher_id,output_format,kind,storage_path,version,exported_at")
                .order("teacher_id").order("output_format").order("kind")
                .range(offset, offset + 499).execute().data or [])
        rows.extend(part)
        if len(part) < 500:
            break
    return rows


def export_inventory(status="all", output_format="folders"):
    """Return teacher download state and newly added document kinds.

    Previous teachers remain tied to the explicitly CONFIRMED download,
    while per-kind history identifies documents added to an incomplete file
    after the last confirmed folder export.
    """
    if status not in ("all", "complete", "incomplete") or output_format not in ("folders", "pdf"):
        raise UserError("فلتر أو نوع تصدير غير صحيح")
    teachers = all_records("teachers", "id,full_name,national_id,position")
    documents = all_records("documents", "teacher_id,kind,storage_path,version")
    grouped = {}
    for doc in documents:
        grouped.setdefault(doc["teacher_id"], {})[doc["kind"]] = doc
    try:
        exported = all_records("export_history", "teacher_id,output_format,fingerprint,exported_at", "teacher_id")
        per_doc = all_export_document_snapshots()
    except Exception:
        app.logger.exception("Export history migration missing or inaccessible")
        raise UserError("نفّذ migration_v9.sql في قاعدة أرشيف المدرسة فقط قبل استخدام التصدير.", 503)
    indexed = {(r["teacher_id"], r["output_format"]): r for r in exported}
    file_index = {(r["teacher_id"], r["output_format"], r["kind"]): r for r in per_doc}
    result, empty = [], 0
    for teacher in sorted(teachers, key=lambda t: t["full_name"]):
        td = grouped.get(teacher["id"], {})
        n = len(td)
        if status == "complete" and n != 5:
            continue
        if status == "incomplete" and n == 5:
            continue
        if not n:
            empty += 1
            continue
        parts = [[k, int(td[k].get("version") or 1), td[k]["storage_path"]] for k in KINDS if k in td]
        raw = json.dumps([teacher["full_name"], teacher["national_id"], parts],
                         ensure_ascii=False, separators=(",", ":"))
        fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        prev = indexed.get((teacher["id"], output_format))
        confirmed = {kind: file_index.get((teacher["id"], output_format, kind))
                     for kind in KINDS if kind in td}
        has_confirmed = bool(prev) or any(confirmed.values())
        pending_kinds = [kind for kind in KINDS if kind in td and not (
            confirmed[kind]
            and confirmed[kind]["storage_path"] == td[kind]["storage_path"]
            and int(confirmed[kind]["version"]) == int(td[kind].get("version") or 1)
        )]
        # A batch with some files delivered and others missing is NOT all-new.
        # Missing kinds stay pending; confirmed PDFs are not downloaded twice.
        state = ("new" if not has_confirmed else
                 "previous" if not pending_kinds and (not prev or prev["fingerprint"] == fingerprint)
                 else "updated")
        added_kinds = ([kind for kind in KINDS if kind in td and not confirmed[kind]]
                       if has_confirmed else [])
        result.append({
            "id": teacher["id"], "name": teacher["full_name"], "document_count": n,
            "missing": [label for key, label in KINDS.items() if key not in td],
            "fingerprint": fingerprint, "download_state": state,
            "additions": added_kinds, "additions_count": len(added_kinds),
            "pending_kinds": pending_kinds,
            "exported_at": prev.get("exported_at") if prev else None,
            "files": [{"kind": k, "path": td[k]["storage_path"],
                       "version": int(td[k].get("version") or 1)} for k in KINDS if k in td],
        })
    return result, empty


def export_summary(items, empty=0):
    return {
        "new": sum(x["download_state"] == "new" for x in items),
        "updated": sum(x["download_state"] == "updated" for x in items),
        "previous": sum(x["download_state"] == "previous" for x in items),
        "empty": empty,
        "total": len(items),
        "additions_teachers": sum(x["additions_count"] > 0 for x in items),
        "additions_documents": sum(x["additions_count"] for x in items),
    }


@app.get("/api/export/preview")
@login_required(roles=("admin",))
def preview_export():
    output_format = request.args.get("format", "folders")
    items, empty = export_inventory(request.args.get("status", "all"), output_format)
    # Do not expose fingerprint or full ID unnecessarily in an informational preview.
    return jsonify(summary=export_summary(items, empty),
                   items=[{k: v for k, v in item.items() if k not in ("fingerprint", "files")} for item in items])


@app.post("/api/export/prepare")
@login_required(roles=("admin",))
def prepare_export():
    args = request.get_json(silent=True) or {}
    status, fmt = args.get("status", "all"), args.get("format", "folders")
    selection = args.get("selection", "pending")
    # Same export tables: layout/name are kept in existing JSON payload, no schema change.
    layout = "flat" if fmt == "folders" else "legacy"
    batch_name = str(args.get("batch_name", "الدفعة الأولى")).strip()
    if not batch_name or len(batch_name) > 70:
        raise UserError("اكتب اسم الدفعة (من 1 إلى 70 حرفًا).")
    batch_name = clean(batch_name, 70)
    if selection not in ("pending", "all", "new", "updated", "previous", "additions"):
        raise UserError("اختيار التنزيل غير صحيح")
    if selection == "additions" and fmt != "folders":
        raise UserError("استكمال النواقص يُنزل المستندات المنفصلة داخل مجلد المعلم فقط")
    try:
        start = max(0, int(args.get("start", 0)))
        count = max(1, min(400, int(args.get("count", 20))))
    except (TypeError, ValueError):
        raise UserError("حدود الدفعة غير صحيحة")
    items, _ = export_inventory(status, fmt)
    if selection == "pending":
        items = [i for i in items if i["download_state"] in ("new", "updated")]
    elif selection == "additions":
        items = [i for i in items if i["additions_count"]]
    elif selection != "all":
        items = [i for i in items if i["download_state"] == selection]
    chosen = items[start:start + count]
    if not chosen:
        raise UserError("لا توجد ملفات لهذا الاختيار؛ جرّب الكل أو غيّر حالة الملفات.")
    payload = []
    for item in chosen:
        # The exact PDF paths must be frozen at prepare time; never silently
        # export newer files than the user confirmed.
        # Pending defaults to only missing / changed kinds from the confirmed
        # per-document record, not every PDF in the teacher's file.
        files = ([f for f in item["files"] if f["kind"] in item["additions"]]
                 if selection == "additions" else
                 [f for f in item["files"] if f["kind"] in item["pending_kinds"]]
                 if selection in ("pending", "new", "updated") else item["files"])
        if not files:
            raise UserError("هذه الدفعة لا تحتوي مستندات قابلة للتنزيل")
        payload.append({"id": item["id"], "name": item["name"],
                        "fingerprint": item["fingerprint"], "files": files,
                        "complete_snapshot": len(files) == len(item["files"]),
                        "selection": selection, "layout": layout,
                        "batch_name": batch_name})
    try:
        saved = table("export_batches").insert({
            "actor_id": request.current_user["id"], "output_format": fmt,
            "payload": payload,
        }).execute().data[0]
    except Exception:
        app.logger.exception("Could not prepare export batch")
        raise UserError("تعذّر تجهيز التصدير؛ تأكد من تنفيذ migration_v9.sql.", 503)
    return jsonify(batch_id=saved["id"], count=len(payload),
                   layout=layout, batch_name=batch_name,
                   document_count=sum(len(row["files"]) for row in payload),
                   summary=export_summary(chosen), names=[i["name"] for i in chosen[:10]])


def user_batch(batch_id):
    rows = table("export_batches").select("*").eq("id", uid(batch_id)).limit(1).execute().data or []
    if not rows or rows[0]["actor_id"] != request.current_user["id"]:
        raise UserError("دفعة تنزيل غير موجودة لهذا الحساب", 404)
    batch = rows[0]
    created = datetime.fromisoformat(batch["created_at"].replace("Z", "+00:00"))
    if (datetime.now(timezone.utc) - created).total_seconds() > 48 * 3600:
        raise UserError("انتهت صلاحية هذا التنزيل. جهّز دفعة جديدة.", 410)
    return batch


class StorageFetchError(Exception):
    """Storage transport error; only a status code is shown, never credentials."""
    def __init__(self, code=None, message=""):
        self.code = code
        self.message = str(message)[:180]
        super().__init__(self.message)


def _direct_private_pdf(path):
    """Download using the documented private Storage API, with an explicit timeout.

    Each call opens its own connection. This avoids concurrent use of one SDK
    HTTP client when a large ZIP is being assembled on a small Render instance.
    The service-role key NEVER goes into the browser or a ZIP file.
    """
    base = os.environ.get("SUPABASE_URL", "").rstrip("/")
    token = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if not base or not token:
        raise UserError("إعدادات تخزين Supabase غير موجودة في Render.", 503)
    if not isinstance(path, str) or not path or "\x00" in path or path.startswith("/"):
        raise UserError("مسار المستند غير صالح.", 422)
    endpoint = base + "/storage/v1/object/authenticated/" + quote(BUCKET, safe="") + "/" + quote(path, safe="/")
    req = Request(endpoint, method="GET", headers={
        "Authorization": "Bearer " + token,
        "apikey": token,
        "Accept": "application/pdf",
    })
    try:
        with urlopen(req, timeout=24) as res:
            if res.status != 200:
                raise StorageFetchError(res.status, "غير متاح")
            data = res.read(30 * 1024 * 1024 + 1)
            if len(data) > 30 * 1024 * 1024:
                raise UserError("مستند PDF أكبر من 30 ميغابايت؛ نزّل ملف المعلم منفردًا.", 413)
            if not data.startswith(b"%PDF"):
                raise UserError("محتوى المستند في التخزين ليس ملف PDF سليمًا.", 422)
            return data
    except HTTPError as exc:
        # Don't put the body into logs; Supabase's body can contain internal data.
        raise StorageFetchError(exc.code, "رفضت خدمة التخزين الطلب") from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise StorageFetchError(None, type(exc).__name__) from exc


def _find_backup_pdf(teacher_id, kind, missing_path, expected_pages=0):
    """Look for intact older PDFs under the same teacher/type ONLY.

    A path may be missing because old save_doc versions deleted files on edit.
    We verify PDF structure and page count, and only silently pick an exact
    page-count match. Different-page candidates require human review.
    """
    prefix = f"{uid(teacher_id)}/{kind}"
    candidates = []
    try:
        for offset in (0, 100, 200):
            rows = read_with_retry(lambda: storage().list(prefix, {
                "limit": 100, "offset": offset,
                "sortBy": {"column": "created_at", "order": "desc"},
            })) or []
            for obj in rows:
                name = obj.get("name") or ""
                if name.lower().endswith(".pdf") and "/" not in name:
                    path = prefix + "/" + name
                    if path != missing_path:
                        candidates.append((obj.get("created_at") or "", path))
            if len(rows) < 100:
                break
    except Exception as exc:
        app.logger.warning("Backup scan inaccessible for %s/%s: %s", teacher_id, kind, type(exc).__name__)
        return None, None, []
    candidates.sort(reverse=True)
    alternate_page_counts = []
    for _, path in candidates[:60]:
        try:
            try:
                blob = _direct_private_pdf(path)
            except StorageFetchError:
                blob = storage().download(path)
            reader = PdfReader(io.BytesIO(blob), strict=False)
            count = len(reader.pages)
            if not count:
                continue
            if expected_pages and count != expected_pages:
                alternate_page_counts.append(count)
                continue
            return blob, path, alternate_page_counts
        except Exception:
            continue
    return None, None, alternate_page_counts


def _export_pdf_with_retries(item, teacher_name, teacher_id):
    """Resolve edited PDF paths, retry genuine temporary errors and never drop PDFs.

    Old versions are deleted by save_doc after an edit. A prepared export may
    still refer to that old path, which is PERMANENTLY 404. We must refresh the
    current document row, not keep retrying an obsolete path four times.
    """
    kind = item.get("kind")
    title = KINDS.get(kind, str(kind or "مستند"))
    selected = dict(item)
    if not selected.get("path"):
        raise UserError(f"مسار {title} للمعلم {teacher_name} غير مسجل.", 409)
    last_code = None
    # Bounded total retries. Usually one call is enough; 429/5xx back off.
    for attempt in range(6):
        try:
            return _direct_private_pdf(selected["path"]), selected
        except UserError:
            raise
        except StorageFetchError as exc:
            last_code = exc.code
            app.logger.warning("Archive Storage read failed: teacher=%s kind=%s http=%s attempt=%s/6",
                               teacher_id, kind, exc.code or "network", attempt + 1)
            if exc.code in (401, 403):
                raise UserError(f"تعذّر الوصول إلى تخزين {title} للمعلم {teacher_name} (رمز {exc.code}). تحقق من صلاحيات التخزين في Render.", 503) from exc
            if exc.code in (400, 404, 410):
                # A simultaneous scan may have changed storage_path/version.
                latest = find_doc(teacher_id, kind)
                if latest and latest["storage_path"] != selected["path"]:
                    selected["path"] = latest["storage_path"]
                    selected["version"] = int(latest.get("version") or 1)
                    continue
                # In case an older Storage server doesn't support the documented
                # authenticated route, try the already configured SDK once.
                if exc.code in (400, 404) and attempt == 0:
                    try:
                        blob = storage().download(selected["path"])
                        if isinstance(blob, bytes) and blob.startswith(b"%PDF"):
                            return blob, selected
                    except Exception:
                        app.logger.info("SDK fallback could not read teacher=%s kind=%s", teacher_id, kind)
                expected_pages = int(selected.get("pages") or 0)
                backup, fallback_path, other_counts = _find_backup_pdf(
                    teacher_id, kind, selected["path"], expected_pages)
                if backup is not None:
                    app.logger.warning("Recoverable PDF backup used: teacher=%s kind=%s", teacher_id, kind)
                    selected["path"] = fallback_path
                    selected["backup_recovery"] = True
                    selected["pages"] = len(PdfReader(io.BytesIO(backup)).pages)
                    return backup, selected
                if other_counts:
                    raise UserError(
                        f"المسار الحالي لـ{title} للمعلم {teacher_name} مفقود، "
                        f"وُجدت نسخ مختلفة بعدد صفحات {sorted(set(other_counts))}. "
                        "يجب مراجعتها قبل استبدال مرجع المستند؛ لا تعِد التصوير الآن.", 409) from exc
                raise UserError(
                    f"تعذّر العثور على PDF {title} للمعلم {teacher_name} (404). "
                    "فُحص مجلد المستند ولم تُعثر نسخة سليمة بنفس عدد الصفحات. "
                    "الملفات الأخرى ما زالت محفوظة؛ لا تعد التصوير حتى نفحص تخزين Supabase.", 503) from exc
            if attempt == 5:
                break
            time.sleep((0.4, 0.9, 1.7, 3.3, 5.5)[attempt])
    raise UserError(
        f"فشل اتصال Supabase أثناء تنزيل {title} للمعلم {teacher_name} "
        f"(رمز {last_code or 'شبكة'}). أعد التنزيل بعد تحسن الاتصال؛ لم تُحذف الملفات.", 503)


def _build_complete_export(batch, teacher_lookup):
    """Build entire ZIP in private temporary storage and verify it first.

    Uses the latest DB paths; saves precisely the paths actually included into
    the batch so the later confirmation cannot incorrectly mark stale PDFs.
    """
    payload = batch["payload"]
    handle = tempfile.TemporaryFile(mode="w+b")
    max_size = 350 * 1024 * 1024
    num_files = 0
    resolved_payload = []
    try:
        latest_documents = all_records("documents", "teacher_id,kind,storage_path,version,pages", "created_at")
        latest_index = {(d["teacher_id"], d["kind"]): d for d in latest_documents}
        manifest = io.StringIO()
        csv_writer = csv.writer(manifest)
        csv_writer.writerow(["اسم المعلم", "اسم المستند", "عدد المستندات في الدفعة", "مصدر النسخة"])
        with zipfile.ZipFile(handle, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for row in payload:
                teacher = teacher_lookup.get(row["id"])
                if not teacher:
                    raise UserError("أحد المعلمين حُذف بعد تجهيز الدفعة؛ أعد تجهيز القائمة.", 409)
                original_files = row.get("files") or []
                if not original_files:
                    raise UserError("وجدنا معلمًا بلا مستندات في الدفعة؛ أعد تجهيزها.", 409)
                # IMPORTANT: do not use a frozen old storage path after edits.
                files = []
                for f in original_files:
                    key = (row["id"], f["kind"])
                    current = latest_index.get(key)
                    if not current:
                        raise UserError(
                            f"مستند {KINDS.get(f['kind'],f['kind'])} للمعلم "
                            f"{teacher['full_name']} حُذف بعد تجهيز الدفعة. أعد تجهيزها.", 409)
                    files.append({"kind": f["kind"], "path": current["storage_path"],
                                  "version": int(current.get("version") or 1), "pages": int(current.get("pages") or 0)})
                label = f"{clean(teacher['full_name'])}_{clean(teacher['national_id'][-4:])}_{teacher['id'][:6]}"
                resolved_files = []
                if batch["output_format"] == "pdf":
                    writer = PdfWriter()
                    for item in files:
                        pdf_bytes, resolved = _export_pdf_with_retries(item, teacher["full_name"], row["id"])
                        writer.append(io.BytesIO(pdf_bytes))
                        resolved_files.append(resolved)
                        csv_writer.writerow([teacher["full_name"], KINDS[resolved["kind"]], len(files),
                                             "نسخة احتياطية مسترجعة - راجع المستند" if resolved.get("backup_recovery") else "النسخة الحالية"])
                    merged = io.BytesIO()
                    writer.write(merged)
                    archive.writestr(f"{label}.pdf", merged.getvalue())
                    num_files += 1
                else:
                    for item in files:
                        pdf_bytes, resolved = _export_pdf_with_retries(item, teacher["full_name"], row["id"])
                        entry = f"{label}/{clean(KINDS[resolved['kind']])}.pdf"
                        archive.writestr(entry, pdf_bytes)
                        resolved_files.append(resolved)
                        csv_writer.writerow([teacher["full_name"], KINDS[resolved["kind"]], len(files),
                                             "نسخة احتياطية مسترجعة - راجع المستند" if resolved.get("backup_recovery") else "النسخة الحالية"])
                        num_files += 1
                # Exactly what was sent is recorded; freshly scanned versions
                # remain detected as 'updated' if not included in this ZIP.
                parts = [[k, f["version"], f["path"]] for k in KINDS for f in resolved_files if f["kind"] == k]
                raw = json.dumps([teacher["full_name"], teacher["national_id"], parts],
                                 ensure_ascii=False, separators=(",", ":"))
                resolved_payload.append({**row, "files": resolved_files,
                     "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest()})
                if handle.tell() > max_size:
                    raise UserError("الدفعة أكبر من 350 ميغابايت؛ اختر 20 أو 50 معلمًا في كل دفعة.", 413)
            archive.writestr("قائمة_الملفات.csv", "\ufeff" + manifest.getvalue())
            num_files += 1
        handle.flush()
        size = handle.tell()
        handle.seek(0)
        with zipfile.ZipFile(handle, "r") as check:
            names = check.namelist()
            actual_pdfs = sum(n.lower().endswith(".pdf") for n in names)
            expected = (len(payload) if batch["output_format"] == "pdf"
                        else sum(len(row["files"]) for row in resolved_payload))
            if (actual_pdfs != expected or len(names) != num_files
                    or check.testzip() is not None):
                raise UserError("فشل التحقق من ZIP؛ لن يتم إرساله أو تسجيله.", 503)
        handle.seek(0)
        return handle, size, num_files, resolved_payload
    except Exception:
        handle.close()
        raise


@app.post("/api/archive/repair")
@login_required(roles=("admin",))
def repair_archive_links():
    """Admin-triggered, bounded repair from REAL existing PDFs, no SQL migration.

    Checks the actual storage bytes. If the current PDF is absent but a
    readable older PDF of the SAME teacher/type and page count exists, fix
    the reference using an optimistic version check. Never fabricate pages.
    """
    body = request.get_json(silent=True) or {}
    try:
        start = max(0, int(body.get("start", 0)))
        count = max(1, min(10, int(body.get("count", 10))))
    except (ValueError, TypeError):
        raise UserError("حدود الفحص غير صحيحة", 422)
    docs = all_records("documents", "id,teacher_id,kind,storage_path,version,pages", "created_at")
    by_id = {t["id"]: t["full_name"] for t in all_records("teachers", "id,full_name", "created_at")}
    checked = repaired = ok = 0
    issues = []
    for doc in docs[start:start + count]:
        checked += 1
        label = by_id.get(doc["teacher_id"], "معلم غير معروف")
        kind_label = KINDS.get(doc["kind"], doc["kind"])
        try:
            blob, selected = _export_pdf_with_retries({
                "kind": doc["kind"], "path": doc["storage_path"],
                "version": int(doc.get("version") or 1),
                "pages": int(doc.get("pages") or 0),
            }, label, doc["teacher_id"])
            if not selected.get("backup_recovery"):
                ok += 1
                continue
            # Never silently downgrade documents to a different page count.
            recovered_pages = len(PdfReader(io.BytesIO(blob), strict=False).pages)
            if recovered_pages != doc["pages"]:
                issues.append({"name": label, "kind": kind_label,
                               "reason": "عدد صفحات النسخة البديلة مختلف؛ يحتاج مراجعة"})
                continue
            response = (table("documents").update({
                "storage_path": selected["path"],
                "version": int(doc["version"]) + 1,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", doc["id"]).eq("version", doc["version"])
                .eq("storage_path", doc["storage_path"]).execute())
            if not response.data:
                issues.append({"name": label, "kind": kind_label,
                               "reason": "جرى تعديل المستند بالتزامن؛ أعد فحصه"})
                continue
            audit_document("استرجاع PDF", doc,
                           "تم الربط بنسخة موجودة وسليمة بنفس عدد الصفحات؛ المسار السابق محفوظ بسجل الخادم")
            app.logger.warning("Repaired PDF pointer: doc=%s old=%s new=%s",
                               doc["id"], doc["storage_path"], selected["path"])
            repaired += 1
        except UserError as exc:
            issues.append({"name": label, "kind": kind_label, "reason": exc.message})
        except Exception as exc:
            app.logger.exception("Archive repair check failed: doc=%s", doc["id"])
            issues.append({"name": label, "kind": kind_label,
                           "reason": "تعذّر الاتصال بخدمة التخزين؛ أعد محاولة الفحص"})
    return jsonify(total=len(docs), start=start, checked=checked,
                   healthy=ok, repaired=repaired, issues=issues)


def _build_available_export(batch, teacher_lookup):
    """Read-only emergency export: real reachable PDFs plus explicit missing report.

    IMPORTANT: Does not modify archive_documents, storage or download history.
    It is deliberately not treated as a full/confirmed export.
    """
    handle = tempfile.TemporaryFile(mode="w+b")
    max_size = 350 * 1024 * 1024
    expected_folders = len(batch["payload"])
    pdf_count = 0
    missing = []
    try:
        current_rows = all_records("documents", "teacher_id,kind,storage_path,version,pages", "created_at")
        latest = {(d["teacher_id"], d["kind"]): d for d in current_rows}
        list_csv = io.StringIO()
        writer = csv.writer(list_csv)
        writer.writerow(["اسم المعلم", "المستند", "الحالة", "عدد الصفحات"])
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for row in batch["payload"]:
                teacher = teacher_lookup.get(row["id"])
                if not teacher:
                    raise UserError("تعذر العثور على معلم في دفعة التصدير. لم يجرِ أي حذف.", 409)
                folder = f"{clean(teacher['full_name'])}_{clean(teacher['national_id'][-4:])}_{teacher['id'][:6]}/"
                # Keep one folder per selected teacher even when one or more PDFs are missing.
                archive.writestr(folder, b"")
                teacher_missing = []
                for wanted in row.get("files") or []:
                    kind = wanted.get("kind")
                    title = KINDS.get(kind, "مستند غير معروف")
                    current = latest.get((row["id"], kind))
                    if current is None:
                        err = "لا يوجد مستند مسجل حاليًا"
                    else:
                        try:
                            blob, resolved = _export_pdf_with_retries({
                                "kind": kind, "path": current["storage_path"],
                                "version": int(current.get("version") or 1),
                                "pages": int(current.get("pages") or 0),
                            }, teacher["full_name"], row["id"])
                            actual_pages = len(PdfReader(io.BytesIO(blob), strict=False).pages)
                            if actual_pages < 1 or (current.get("pages") and
                                actual_pages != int(current["pages"])):
                                raise UserError("عدد صفحات PDF لا يطابق السجل؛ يحتاج مراجعة", 409)
                            archive.writestr(folder + clean(title) + ".pdf", blob)
                            pdf_count += 1
                            writer.writerow([teacher["full_name"], title, "سليم - موجود في ZIP", actual_pages])
                            if handle.tell() > max_size:
                                raise UserError("حجم ZIP تجاوز 350 ميغابايت؛ صدّر دفعة أصغر.", 413)
                            continue
                        except UserError as exc:
                            # Do not swallow fatal size limits, permissions, or configuration faults.
                            if exc.code in (401,403,413):
                                raise
                            err = exc.message
                        except Exception as exc:
                            app.logger.exception("Available-only PDF check failed: teacher=%s kind=%s", row["id"], kind)
                            err = "فشل فحص PDF؛ لم يُضف إلى الأرشيف"
                    teacher_missing.append(title)
                    missing.append((teacher["full_name"], title, err))
                    writer.writerow([teacher["full_name"], title, "غير متاح - يحتاج استرجاع", ""])
                if teacher_missing:
                    message = ("تنبيه: هذه نسخة طوارئ للمستندات القابلة للقراءة فقط.\n"
                               "المستندات التالية لم تُضمّن لأنها غير متاحة في التخزين:\n- " +
                               "\n- ".join(teacher_missing) +
                               "\nلم يُحذف أي شيء من المنظومة. هذه ليست نسخة كاملة من الملف.\n")
                    archive.writestr(folder + "تنبيه_مستندات_غير_متاحة.txt", message.encode("utf-8-sig"))
            missing_csv = io.StringIO()
            m = csv.writer(missing_csv)
            m.writerow(["المعلم", "المستند غير المتاح", "السبب"])
            m.writerows(missing)
            archive.writestr("قائمة_الملفات.csv", ("\ufeff" + list_csv.getvalue()).encode("utf-8"))
            archive.writestr("ملفات_غير_متاحة.csv", ("\ufeff" + missing_csv.getvalue()).encode("utf-8"))
            archive.writestr("اقرأني_قبل_الاعتماد.txt", (
                "هذه نسخة للملفات السليمة والمتاحة فقط.\n"
                f"المعلمون في الدفعة: {expected_folders}\n"
                f"ملفات PDF التي تم تضمينها: {pdf_count}\n"
                f"المستندات غير المتاحة: {len(missing)}\n"
                "راجع ملفات_غير_متاحة.csv. لا تُعتبر هذه الدفعة تنزيلاً كاملاً ولن تُسجّل كتأكيد تنزيل.\n"
                "لم يتم حذف أو تعديل أي اسم أو مستند أو ملف في Supabase.\n").encode("utf-8-sig"))
        if not pdf_count:
            raise UserError("لم نجد أي PDF قابل للتنزيل في هذه الدفعة؛ لم نغيّر الأرشيف.", 503)
        handle.flush()
        size = handle.tell()
        handle.seek(0)
        with zipfile.ZipFile(handle, "r") as check:
            entries = check.namelist()
            actual_pdf = sum(n.lower().endswith('.pdf') for n in entries)
            folders = sum(n.endswith('/') for n in entries)
            if (folders != expected_folders or actual_pdf != pdf_count
                    or check.testzip() is not None):
                raise UserError("فشل فحص ZIP للملفات السليمة؛ لم يُرسل ملف ناقص دون بيان.", 503)
            entry_count = len(entries)
        handle.seek(0)
        return handle, size, entry_count, pdf_count, len(missing), expected_folders
    except Exception:
        handle.close()
        raise



# V9.5 — Export-only presentation. Never mutate teachers, documents or Storage.
def _flat_batch_name(batch):
    payload = batch.get("payload") or []
    label = str((payload[0].get("batch_name") if payload else "") or "الدفعة").strip()
    return clean(label, 70)


def _flat_export_filename(teacher, kind, used_names):
    """Keep names human-readable; disambiguate same-name teachers safely."""
    label = KINDS.get(kind, kind)
    stem = clean(f"{teacher['full_name']} - {label}", 150)
    filename = stem + ".pdf"
    if filename.casefold() in used_names:
        suffix = clean(str(teacher.get("national_id", ""))[-4:] + "_" + teacher["id"][:8], 22)
        filename = clean(stem, 125) + "_" + suffix + ".pdf"
    used_names.add(filename.casefold())
    return filename


def _build_flat_export(batch, teacher_lookup, available_only=False):
    """Single named directory with directly named PDFs and audit reports.

    Partial mode never updates the confirmed export history. Complete mode is
    all-or-nothing and returns resolved snapshots for later explicit confirmation.
    """
    payload = batch.get("payload") or []
    if not payload or batch.get("output_format") != "folders":
        raise UserError("تنسيق الدفعة غير صالح، أعد تجهيزها.", 400)
    temp = tempfile.TemporaryFile(mode="w+b")
    max_size = 350 * 1024 * 1024
    used_names, good, bad, resolved_payload = set(), [], [], []
    label = _flat_batch_name(batch)
    prefix = label + "/"
    try:
        all_docs = all_records("documents", "teacher_id,kind,storage_path,version,pages", "created_at")
        current = {(d["teacher_id"], d["kind"]): d for d in all_docs}
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            archive.writestr(prefix, b"")
            for row in payload:
                teacher = teacher_lookup.get(row["id"])
                if not teacher:
                    raise UserError("أحد المعلمين لم يعد موجودًا؛ لم يتم تعديل أي بيانات.", 409)
                chosen = row.get("files") or []
                if not chosen:
                    raise UserError(f"لا توجد مستندات في دفعة المعلم {teacher['full_name']}.", 409)
                success = []
                for item in chosen:
                    kind = item.get("kind")
                    title = KINDS.get(kind, str(kind or "مستند"))
                    fresh = current.get((row["id"], kind))
                    if not fresh:
                        error = "المستند غير مسجل حاليًا"
                        if not available_only:
                            raise UserError(f"{title} للمعلم {teacher['full_name']}: {error}.", 409)
                        bad.append([teacher["full_name"], title, error])
                        continue
                    snapshot = {"kind": kind, "path": fresh["storage_path"],
                                "version": int(fresh.get("version") or 1),
                                "pages": int(fresh.get("pages") or 0)}
                    try:
                        blob, resolved = _export_pdf_with_retries(snapshot, teacher["full_name"], row["id"])
                        pdf = PdfReader(io.BytesIO(blob), strict=False)
                        pages = len(pdf.pages)
                        if pages < 1 or (snapshot["pages"] and pages != snapshot["pages"]):
                            raise UserError("نسخة PDF لا تطابق عدد الصفحات المسجل؛ تحتاج مراجعة.", 409)
                    except UserError as exc:
                        if not available_only or exc.code in (401, 403, 413):
                            raise
                        bad.append([teacher["full_name"], title, exc.message])
                        continue
                    except Exception:
                        app.logger.exception("Flat export could not read pdf: teacher=%s kind=%s", row["id"], kind)
                        if not available_only:
                            raise UserError(f"تعذر التحقق من {title} للمعلم {teacher['full_name']}؛ لم تُرسل الدفعة ناقصة.", 503)
                        bad.append([teacher["full_name"], title, "تعذر فتح PDF أو فحصه"])
                        continue
                    filename = _flat_export_filename(teacher, kind, used_names)
                    archive.writestr(prefix + filename, blob)
                    good.append([teacher["full_name"], title, filename, pages])
                    success.append(resolved)
                    if temp.tell() > max_size:
                        raise UserError("حجم الدفعة تجاوز 350 ميغابايت. نزّل دفعات أصغر حفاظًا على سرعة الهاتف.", 413)
                if available_only and success:
                    resolved_payload.append({**row, "files": success,
                                             "complete_snapshot": False})
                if not available_only:
                    # Keep the full teacher fingerprint when all kinds were included.
                    # For additions only, confirmation stores per-document versions.
                    if len(success) != len(chosen):
                        raise UserError("لم تكتمل مستندات الدفعة. لم نؤكد تنزيل أي ملف.", 503)
                    parts = [[k, f["version"], f["path"]] for k in KINDS for f in success if f["kind"] == k]
                    raw = json.dumps([teacher["full_name"], teacher["national_id"], parts],
                                     ensure_ascii=False, separators=(",", ":"))
                    resolved_payload.append({**row, "files": success,
                        "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest()})
            manifest = io.StringIO()
            csvw = csv.writer(manifest)
            csvw.writerow(["اسم المعلم", "المستند", "اسم PDF في المجلد", "عدد الصفحات"])
            csvw.writerows(good)
            archive.writestr(prefix + "كشف_الملفات.csv", ("\ufeff" + manifest.getvalue()).encode("utf-8"))
            missing = io.StringIO()
            mc = csv.writer(missing)
            mc.writerow(["اسم المعلم", "المستند غير المتاح", "السبب"])
            mc.writerows(bad)
            archive.writestr(prefix + "ملفات_تحتاج_استرجاع.csv", ("\ufeff" + missing.getvalue()).encode("utf-8"))
            note = (f"اسم الدفعة: {label}\n"
                    f"عدد ملفات PDF الموجودة فعليًا: {len(good)}\n"
                    f"عدد المستندات المتعذرة: {len(bad)}\n"
                    "لا يتم حذف أو تعديل أي ملفات في Supabase أثناء التصدير.\n"
                    "إذا كان هناك مستند غير متاح، لا تعتبر هذا تنزيلًا كاملًا.\n")
            archive.writestr(prefix + "معلومات_الدفعة.txt", note.encode("utf-8-sig"))
        if not good:
            raise UserError("لا توجد مستندات PDF سليمة متاحة لهذه الدفعة حاليًا.", 503)
        temp.flush()
        size = temp.tell()
        temp.seek(0)
        with zipfile.ZipFile(temp, "r") as verify:
            names = verify.namelist()
            pdf_names = [x for x in names if x.casefold().endswith(".pdf")]
            expected = sum(len(row.get("files") or []) for row in payload)
            if (len(pdf_names) != len(good) or len(pdf_names) != len(set(pdf_names))
                    or (not available_only and (bad or len(good) != expected))
                    or any(not x.startswith(prefix) for x in names)
                    or sum(x.endswith("/") for x in names) != 1 or verify.testzip() is not None):
                raise UserError("فشل تدقيق ZIP قبل الإرسال؛ لم تُسجَّل الدفعة على أنها كاملة.", 503)
            entry_count = len(names)
        temp.seek(0)
        if available_only:
            return temp, size, entry_count, len(good), len(bad), len(payload), resolved_payload
        return temp, size, entry_count, resolved_payload
    except Exception:
        temp.close()
        raise


@app.get("/api/export/batch/<batch_id>/available.zip")
@login_required(roles=("admin",))
def get_available_export_batch(batch_id):
    """Download reachable PDFs now; deliberately never updates confirmed history."""
    batch = user_batch(batch_id)
    teachers_lookup = {t["id"]: t for t in all_records("teachers", "id,full_name,national_id,position")}
    flat = batch.get("output_format") == "folders" and any(
        row.get("layout") == "flat" for row in batch.get("payload") or [])
    if flat:
        handle, size, entries, pdfs, missing, folders, delivered = _build_flat_export(
            batch, teachers_lookup, available_only=True)
        # Never auto-confirm. Store only a snapshot of files proven present in ZIP.
        by_id = {r["id"]: r["files"] for r in delivered}
        now_stamp = datetime.now(timezone.utc).isoformat()
        updated_payload = [{**row, "available_files": by_id.get(row["id"], []),
                            "available_built_at": now_stamp} for row in batch["payload"]]
        try:
            table("export_batches").update({"payload": updated_payload}).eq(
                "id", batch["id"]).eq("actor_id", request.current_user["id"]).execute()
        except Exception:
            handle.close()
            raise UserError("تعذر تسجيل قائمة المستندات الجاهزة للتنزيل؛ أعد المحاولة دون حذف أي ملف.", 503)
    else:
        handle, size, entries, pdfs, missing, folders = _build_available_export(
            batch, teachers_lookup)
    label = clean((batch.get("payload") or [{}])[0].get("batch_name") or "دفعة", 40)
    filename = (f"{label}_available_{pdfs}_pdf_"
                f"{missing}_missing_{batch['id'][:8]}.zip")
    response = send_file(handle, mimetype="application/zip", as_attachment=True,
                         download_name=filename, conditional=False)
    response.content_length = size
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Archive-Teachers"] = str(folders)
    response.headers["X-Archive-Pdfs"] = str(pdfs)
    response.headers["X-Archive-Missing"] = str(missing)
    response.headers["X-Archive-Entries"] = str(entries)
    response.call_on_close(handle.close)
    return response


@app.post("/api/export/confirm-available")
@login_required(roles=("admin",))
def confirm_available_export():
    """Confirm a partially available ZIP only after manual phone verification.

    Never mark absent PDFs as downloaded, and never delete any storage object.
    Uses the already present archive_export_document_history table (V9).
    """
    data = request.get_json(silent=True) or {}
    batch = user_batch(data.get("batch_id"))
    if batch.get("confirmed_at"):
        return jsonify(ok=True, already_confirmed=True, count=0)
    if batch["output_format"] != "folders":
        raise UserError("التأكيد الجزئي متاح لمجلد PDF المنفصل فقط.", 400)
    if not batch.get("payload") or any(not row.get("available_built_at") for row in batch["payload"]):
        raise UserError("لم يُجهز ملف المستندات المتاحة بعد. نزّله أولًا وتأكد من وصوله.", 409)
    # Reconcile every file against LIVE document version, to avoid claiming a
    # different document was saved while another scanner was editing it.
    live = all_records("documents", "teacher_id,kind,storage_path,version", "created_at")
    index = {(r["teacher_id"], r["kind"]): r for r in live}
    stamp = datetime.now(timezone.utc).isoformat()
    rows, skipped = [], 0
    seen = set()
    for teacher in batch["payload"]:
        for item in teacher.get("available_files") or []:
            key = (teacher["id"], item["kind"])
            doc = index.get(key)
            if not doc or doc["storage_path"] != item["path"] or int(doc["version"]) != int(item["version"]):
                skipped += 1
                continue
            if key in seen:
                continue
            seen.add(key)
            rows.append({"teacher_id": teacher["id"], "output_format": "folders",
                         "kind": item["kind"], "storage_path": item["path"],
                         "version": item["version"], "exported_at": stamp})
    if not rows:
        raise UserError("لا يوجد مستند مطابق للنسخة الحالية للتأكيد؛ أعد تجهيز الدفعة.", 409)
    for offset in range(0, len(rows), 200):
        table("export_document_history").upsert(rows[offset:offset+200],
            on_conflict="teacher_id,output_format,kind").execute()
    # A teacher is fully downloaded only when ALL current kinds match confirmed PDFs.
    history = all_export_document_snapshots()
    histories = {(r["teacher_id"], r["output_format"], r["kind"]): r for r in history}
    teacher_data = {t["id"]: t for t in all_records("teachers", "id,full_name,national_id")}
    grouped = {}
    for doc in live:
        grouped.setdefault(doc["teacher_id"], {})[doc["kind"]] = doc
    reconciled = []
    for ident in {r["teacher_id"] for r in rows}:
        info, current = teacher_data.get(ident), grouped.get(ident, {})
        if not info or not current:
            continue
        if all((histories.get((ident, "folders", kind)) or {}).get("storage_path") == doc["storage_path"]
               and int((histories.get((ident, "folders", kind)) or {}).get("version") or 0) == int(doc["version"])
               for kind, doc in current.items()):
            parts = [[kind, int(current[kind]["version"]), current[kind]["storage_path"]]
                     for kind in KINDS if kind in current]
            raw = json.dumps([info["full_name"], info["national_id"], parts],
                             ensure_ascii=False, separators=(",", ":"))
            reconciled.append({"teacher_id": ident, "output_format": "folders",
                               "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                               "exported_at": stamp, "exported_by": request.current_user["id"]})
    if reconciled:
        table("export_history").upsert(reconciled, on_conflict="teacher_id,output_format").execute()
    table("export_batches").update({"confirmed_at": stamp}).eq("id", batch["id"]).is_(
        "confirmed_at", "null").execute()
    audit("تأكيد ملفات ZIP المتاحة فقط", f"{len(rows)} ملف PDF • لم يُؤكد {skipped} ملف تغيّر")
    return jsonify(ok=True, count=len(rows), changed=skipped)


@app.get("/api/export/batch/<batch_id>.zip")
@login_required(roles=("admin",))
def get_export_batch(batch_id):
    batch = user_batch(batch_id)
    lookup = {t["id"]: t for t in all_records("teachers", "id,full_name,national_id,position")}
    try:
        flat = batch.get("output_format") == "folders" and any(
            row.get("layout") == "flat" for row in batch.get("payload") or [])
        if flat:
            handle, size, num_files, resolved_payload = _build_flat_export(
                batch, lookup, available_only=False)
        else:
            handle, size, num_files, resolved_payload = _build_complete_export(batch, lookup)
    except UserError:
        raise
    except Exception:
        app.logger.exception("Archive ZIP assembly error")
        raise UserError("تعذّر تجهيز ZIP بسبب خطأ في خدمة التخزين. لم تُحذف ملفات أو تُسجل دفعة تنزيل.", 503)
    try:
        table("export_batches").update({
            "built_at": datetime.now(timezone.utc).isoformat(),
            "built_bytes": size, "built_entries": num_files,
            "payload": resolved_payload,
        }).eq("id", batch["id"]).execute()
        batch_label = clean((resolved_payload or [{}])[0].get("batch_name") or "دفعة", 45)
        name = (f"{batch_label}_{sum(len(r.get('files') or []) for r in resolved_payload)}_pdf_"
                f"{datetime.now(timezone.utc).strftime('%Y%m%d')}_{batch['id'][:8]}.zip")
        response = send_file(handle, mimetype="application/zip", as_attachment=True,
                             download_name=name, conditional=False)
        response.content_length = size
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Archive-Teachers"] = str(len(resolved_payload))
        response.headers["X-Archive-Pdfs"] = str(
            len(resolved_payload) if batch["output_format"] == "pdf" else
            sum(len(r.get("files") or []) for r in resolved_payload))
        response.headers["X-Archive-Entries"] = str(num_files)
        response.call_on_close(handle.close)
        return response
    except Exception:
        handle.close()
        raise


@app.post("/api/export/confirm")
@login_required(roles=("admin",))
def confirm_export():
    args = request.get_json(silent=True) or {}
    batch = user_batch(args.get("batch_id"))
    if batch.get("confirmed_at"):
        return jsonify(ok=True, count=0, already_confirmed=True)
    if not batch.get("built_at") or not batch.get("built_bytes"):
        raise UserError("لم يكتمل تجهيز ZIP؛ لا يمكن تسجيل تنزيله.", 409)
    stamp = datetime.now(timezone.utc).isoformat()
    ids = [r["id"] for r in batch["payload"]]
    existing = table("export_history").select("teacher_id,exported_at").eq(
        "output_format", batch["output_format"]).in_("teacher_id", ids).execute().data or []
    newer = {r["teacher_id"] for r in existing if r.get("exported_at") and
             datetime.fromisoformat(r["exported_at"].replace("Z", "+00:00")) >
             datetime.fromisoformat(batch["created_at"].replace("Z", "+00:00"))}
    safe = [r for r in batch["payload"] if r["id"] not in newer]
    # Keep histories of individual PDFs so 'added missing documents' can
    # download ONLY kinds not included in a previous confirmed export.
    detail_rows = [{"teacher_id": r["id"], "output_format": batch["output_format"],
                    "kind": f["kind"], "storage_path": f["path"],
                    "version": f["version"], "exported_at": stamp}
                   for r in safe for f in r.get("files", [])]
    if detail_rows:
        for start in range(0, len(detail_rows), 200):
            table("export_document_history").upsert(
                detail_rows[start:start+200],
                on_conflict="teacher_id,output_format,kind").execute()
    full_rows = [{"teacher_id": r["id"], "output_format": batch["output_format"],
                  "fingerprint": r["fingerprint"], "exported_at": stamp,
                  "exported_by": request.current_user["id"]}
                 for r in safe if r.get("complete_snapshot", True)]
    if full_rows:
        table("export_history").upsert(full_rows,
                                       on_conflict="teacher_id,output_format").execute()
    # For additions-only, update the overall status ONLY when all present
    # documents (including old ones) are actually covered by confirmed versions.
    partial = [r for r in safe if not r.get("complete_snapshot", True)]
    if partial:
        documents = all_records("documents", "teacher_id,kind,storage_path,version")
        grouped = {}
        for d in documents:
            grouped.setdefault(d["teacher_id"], {})[d["kind"]] = d
        recent_history = all_export_document_snapshots()
        known = {(r["teacher_id"], r["output_format"], r["kind"]): r for r in recent_history}
        reconciled = []
        for item in partial:
            current = grouped.get(item["id"], {})
            if current and all((item["id"], batch["output_format"], k) in known and
                known[(item["id"], batch["output_format"], k)]["storage_path"] == doc["storage_path"]
                and int(known[(item["id"], batch["output_format"], k)]["version"]) == int(doc["version"])
                for k, doc in current.items()):
                # Recompute fingerprint from the CURRENT teacher info, not the
                # old prepared batch, so another user edit stays 'updated'.
                teacher = teacher_by_id(item["id"])
                parts = [[k, int(current[k]["version"]), current[k]["storage_path"]] for k in KINDS if k in current]
                raw = json.dumps([teacher["full_name"], teacher["national_id"], parts],
                                 ensure_ascii=False, separators=(",", ":"))
                reconciled.append({"teacher_id": item["id"],
                    "output_format": batch["output_format"],
                    "fingerprint": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    "exported_at": stamp, "exported_by": request.current_user["id"]})
        if reconciled:
            table("export_history").upsert(reconciled,
                                           on_conflict="teacher_id,output_format").execute()
    table("export_batches").update({"confirmed_at": stamp}).eq("id", batch["id"]).is_("confirmed_at", "null").execute()
    audit("تأكيد تنزيل الأرشيف", f"{len(batch['payload'])} معلم • الصيغة: {batch['output_format']}")
    return jsonify(ok=True, count=len(batch["payload"]))


@app.post("/api/export/mark-existing")
@login_required(roles=("admin",))
def mark_exports_before_upgrade():
    """Admin may tag folders that were saved to the phone BEFORE V8 tracking."""
    data = request.get_json(silent=True) or {}
    fmt = data.get("format", "folders")
    ids = data.get("teacher_ids", [])
    if not isinstance(ids, list) or not 1 <= len(ids) <= 400 or len(set(ids)) != len(ids):
        raise UserError("اختر معلمًا واحدًا على الأقل، بحد أقصى 400")
    inventory, _ = export_inventory("all", fmt)
    indexed = {item["id"]: item for item in inventory}
    if any(teacher_id not in indexed for teacher_id in ids):
        raise UserError("أحد المعلمين غير موجود أو ليس لديه مستندات")
    stamp = datetime.now(timezone.utc).isoformat()
    rows = [{
        "teacher_id": teacher_id, "output_format": fmt,
        "fingerprint": indexed[teacher_id]["fingerprint"],
        "exported_at": stamp, "exported_by": request.current_user["id"],
    } for teacher_id in ids]
    table("export_history").upsert(rows, on_conflict="teacher_id,output_format").execute()
    snapshots = [{"teacher_id": teacher_id, "output_format": fmt,
                  "kind": doc["kind"], "storage_path": doc["path"],
                  "version": doc["version"], "exported_at": stamp}
                 for teacher_id in ids for doc in indexed[teacher_id]["files"]]
    if snapshots:
        for start in range(0, len(snapshots), 200):
            table("export_document_history").upsert(
                snapshots[start:start+200], on_conflict="teacher_id,output_format,kind").execute()
    audit("تسجيل ملفات نُزّلت سابقًا", f"{len(ids)} معلم • الصيغة: {fmt}")
    return jsonify(ok=True, count=len(ids))



@app.post("/api/export/reset")
@login_required(roles=("admin",))
def reset_export_for_missing_phone_files():
    """Undo mistakenly marked teacher downloads; NEVER delete archived PDFs."""
    data = request.get_json(silent=True) or {}
    fmt, teacher_ids = data.get("format", "folders"), data.get("teacher_ids", [])
    if fmt not in ("folders", "pdf") or not isinstance(teacher_ids, list) or not 1 <= len(teacher_ids) <= 400:
        raise UserError("صيغة التنزيل أو قائمة المعلمين غير صحيحة")
    normalized = [uid(identifier) for identifier in teacher_ids]
    if len(set(normalized)) != len(normalized):
        raise UserError("قائمة المعلمين فيها تكرار")
    table("export_history").delete().eq("output_format", fmt).in_("teacher_id", normalized).execute()
    table("export_document_history").delete().eq("output_format", fmt).in_("teacher_id", normalized).execute()
    audit("إعادة تصنيف تنزيلات لم تصل للهاتف", f"{len(normalized)} معلم • النوع: {fmt}")
    return jsonify(ok=True, count=len(normalized))


# V8 notification center: audit data + account-level read pointer, no public document URLs.
DOCUMENT_EVENT_ACTIONS = (
    "تصوير مستند", "تعديل مستند", "استبدال صفحة", "حذف صفحة",
    "حذف مستند", "تحسين وضوح PDF", "استرجاع PDF",
)


def document_notifications():
    # Supabase order by server timestamp; never expose events to scanner roles.
    history = (table("logs")
               .select("id,actor_name,action,details,created_at")
               .in_("action", list(DOCUMENT_EVENT_ACTIONS))
               .order("created_at", desc=True).limit(120).execute().data or [])
    teacher_id_re = re.compile(r"(?:^|\s|\|)ID:([0-9a-fA-F-]{36})(?:$|\s|\|)")
    notifications = []
    for row in history:
        details = row.get("details") or ""
        ident = teacher_id_re.search(details)
        # The teacher record may be deleted later; display historical name anyway.
        name = re.search(r"معلم:\s*([^|]+)", details)
        kind = re.search(r"مستند:\s*([^|]+)", details)
        notifications.append({
            "id": row["id"], "action": row["action"],
            "actor": row.get("actor_name") or "النظام",
            "teacher_name": name.group(1).strip() if name else "اسم المعلم غير متوفر في السجل القديم",
            "teacher_id": ident.group(1) if ident else None,
            "kind": kind.group(1).strip() if kind else "",
            "created_at": row["created_at"],
        })
    return notifications


@app.get("/api/notifications")
@login_required(roles=("admin",))
def notifications():
    entries = document_notifications()
    actor_id = request.current_user["id"]
    history = (table("notification_reads").select("last_seen_at")
               .eq("user_id", actor_id).limit(1).execute().data or [])
    if not history:
        # Historical activity remains visible, but it does not cause a fake
        # avalanche of old notifications when the feature is first installed.
        # Keep activities from the last 24 hours visible as new.
        initial = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        table("notification_reads").upsert({
            "user_id": actor_id, "last_seen_at": initial,
        }, on_conflict="user_id").execute()
        read_at = initial
    else:
        read_at = history[0]["last_seen_at"]
    last_read_dt = datetime.fromisoformat(read_at.replace("Z", "+00:00"))
    unread = sum(datetime.fromisoformat(event["created_at"].replace("Z", "+00:00")) > last_read_dt
                 for event in entries)
    return jsonify(items=entries, unread=unread, last_seen_at=read_at)


@app.post("/api/notifications/read")
@login_required(roles=("admin",))
def mark_notifications_read():
    # Mark the events that are actually visible, not future events.
    data = request.get_json(silent=True) or {}
    through = data.get("through")
    if not isinstance(through, str):
        raise UserError("حدد الإشعار الذي شاهدته")
    try:
        stamp = datetime.fromisoformat(through.replace("Z", "+00:00"))
    except ValueError:
        raise UserError("تاريخ الإشعار غير صحيح")
    if stamp.tzinfo is None or stamp > datetime.now(timezone.utc):
        raise UserError("تاريخ الإشعار غير صحيح")
    actor_id = request.current_user["id"]
    old = (table("notification_reads").select("last_seen_at")
           .eq("user_id", actor_id).limit(1).execute().data or [])
    if old and datetime.fromisoformat(old[0]["last_seen_at"].replace("Z", "+00:00")) >= stamp:
        return jsonify(ok=True)
    table("notification_reads").upsert({
        "user_id": actor_id, "last_seen_at": stamp.isoformat(),
    }, on_conflict="user_id").execute()
    return jsonify(ok=True)


@app.post("/api/users")
@login_required(roles=("admin",))
def create_user():
    vals = request.get_json(silent=True) or {}
    username = str(vals.get("username", "")).strip()
    full_name = str(vals.get("full_name", "")).strip()
    password = str(vals.get("password", ""))
    role = vals.get("role", "scanner")
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username) or len(full_name) < 3 or len(password) < 10 or role not in ("admin", "scanner", "viewer"):
        raise UserError("اسم الدخول 3 خانات إنجليزية على الأقل، الاسم 3 خانات، وكلمة المرور 10 خانات على الأقل")
    table("users").insert({"username": username, "full_name": full_name, "password_hash": generate_password_hash(password), "role": role, "active": True}).execute()
    audit("إنشاء حساب", username)
    return jsonify(ok=True), 201


@app.patch("/api/users/<user_id>")
@login_required(roles=("admin",))
def edit_user(user_id):
    uid(user_id)
    data = request.get_json(silent=True) or {}
    update = {}
    if "active" in data:
        if not isinstance(data["active"], bool):
            raise UserError("حالة الحساب غير صحيحة")
        update["active"] = data["active"]
    if "role" in data:
        if data["role"] not in ("admin", "scanner", "viewer"):
            raise UserError("صلاحية غير صحيحة")
        update["role"] = data["role"]
    if "password" in data:
        if len(str(data["password"])) < 10:
            raise UserError("كلمة المرور الجديدة يجب أن تكون 10 خانات على الأقل")
        update["password_hash"] = generate_password_hash(str(data["password"]))
    if "full_name" in data:
        if len(str(data["full_name"]).strip()) < 3:
            raise UserError("أدخل الاسم كاملًا")
        update["full_name"] = str(data["full_name"]).strip()
    if user_id == session.get("uid") and (update.get("active") is False or update.get("role") in ("scanner", "viewer")):
        raise UserError("لا يمكنك تعطيل أو تخفيض صلاحية حسابك الإداري الحالي")
    if not update:
        raise UserError("لا يوجد تعديل")
    table("users").update(update).eq("id", user_id).execute()
    audit("تعديل حساب", user_id)
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
