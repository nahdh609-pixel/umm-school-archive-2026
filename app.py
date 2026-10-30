"""أرشيف مدرسة أم المؤمنين — server-only Supabase access, private storage."""
import csv
import io
import logging
import os
import re
import secrets
import time
from datetime import datetime, timezone
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


def all_records(name, fields="*", order="created_at"):
    result = []
    for offset in range(0, 10000, 500):
        part = table(name).select(fields).order(order).range(offset, offset + 499).execute().data or []
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
            users = table("users").select("id,username,full_name,role,active").eq("id", user_id).limit(1).execute().data
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
    return send_from_directory(ROOT, "index.html")


@app.get("/health")
def health():
    return jsonify(ok=True)


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
        logs = table("logs").select("actor_name,action,details,created_at").order("created_at", desc=True).limit(30).execute().data or []
        users = table("users").select("id,username,full_name,role,active,created_at").order("created_at").execute().data or []
    return jsonify(teachers=teachers, documents=docs, logs=logs, users=users)


def teacher_by_id(id_):
    rows = table("teachers").select("*").eq("id", uid(id_)).limit(1).execute().data or []
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
    found = table("documents").select("*").eq("teacher_id", uid(teacher_id)).eq("kind", kind).limit(1).execute().data or []
    return found[0] if found else None


def get_doc(id_):
    found = table("documents").select("*").eq("id", uid(id_)).limit(1).execute().data or []
    if not found:
        raise UserError("المستند غير موجود", 404)
    return found[0]


def require_document_editor(doc):
    """Scanner may correct/delete only docs last saved by their own account.

    This also allows different phones logged in to the same account to correct
    that account's scans. Other users' documents remain admin-only.
    """
    actor = request.current_user
    if actor["role"] == "admin":
        return
    if actor["role"] == "scanner" and doc.get("uploaded_by") == actor["id"]:
        return
    raise UserError("لا يمكنك تعديل مستند صوّره مستخدم آخر؛ تواصل مع المدير.", 403)


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


def image_pdf(data, mode="clear"):
    """Convert phone photo to print-quality A4 without early JPEG downsizing.

    clear: neutralize gray shadows, retain handwriting and thin ink details.
    color: preserve stamp/ink colors and improve lighting conservatively.
    bw: stronger monochrome for high-contrast printed originals.
    Unreadable source cannot be restored by software.
    """
    if mode not in ("clear", "color", "bw"):
        raise UserError("نمط التحسين غير صحيح")
    if len(data) > MAX_IMAGE:
        raise UserError("حجم الصورة يتجاوز 12 ميغابايت")
    try:
        im = Image.open(io.BytesIO(data))
        im.load()
        im = ImageOps.exif_transpose(im).convert("RGB")
    except Exception:
        raise UserError("تعذر فتح الصورة؛ استخدم JPG أو PNG")
    if min(im.size) < 650:
        raise UserError("دقة الصورة ضعيفة. قرّب الهاتف وأعد التصوير.")
    # Bound memory use on a small Render server, while retaining ~300dpi detail.
    if max(im.size) > 3200:
        im.thumbnail((3200, 3200), Image.Resampling.LANCZOS)
    im, cropped = detect_page(im)
    rgb = np.asarray(im.convert("RGB"))
    if mode == "color":
        lab = cv2.cvtColor(rgb, cv2.COLOR_RGB2LAB)
        light, a, b = cv2.split(lab)
        light = cv2.createCLAHE(clipLimit=1.35, tileGridSize=(8, 8)).apply(light)
        rgb = cv2.cvtColor(cv2.merge((light, a, b)), cv2.COLOR_LAB2RGB)
        processed = Image.fromarray(rgb).filter(
            ImageFilter.UnsharpMask(radius=.8, percent=90, threshold=3))
    else:
        gray = cv2.cvtColor(rgb, cv2.COLOR_RGB2GRAY)
        # Normalize uneven lighting using a slowly varying estimate of paper
        # background, without applying hard thresholds to handwriting.
        h, w = gray.shape
        smw, smh = max(48, round(w * min(1., 500/max(w,h)))), max(48, round(h * min(1., 500/max(w,h))))
        background_small = cv2.resize(gray, (smw, smh), interpolation=cv2.INTER_AREA)
        background_small = cv2.GaussianBlur(background_small, (0,0), sigmaX=15)
        background = cv2.resize(background_small, (w,h), interpolation=cv2.INTER_LINEAR)
        background = np.maximum(background, 80)
        normalized = cv2.divide(gray, background, scale=246)
        # Gentle dark-text enhancement with well-defined white background.
        normalized = cv2.convertScaleAbs(normalized, alpha=1.10, beta=-12)
        if mode == "bw":
            # Deliberately stronger, optional printing mode; not the default.
            normalized = cv2.adaptiveThreshold(
                normalized, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
                cv2.THRESH_BINARY, 41, 14)
        processed = Image.fromarray(normalized).filter(
            ImageFilter.UnsharpMask(radius=.8, percent=115, threshold=2))
    # A4 portrait at 300 dpi; preserve aspect ratio and 9mm margins.
    page_w, page_h = 2480, 3508
    margin = 105
    if processed.width > processed.height:
        processed = processed.rotate(90, expand=True)
    target_w, target_h = page_w - 2 * margin, page_h - 2 * margin
    factor = min(target_w / processed.width, target_h / processed.height)
    new_size = (max(1, round(processed.width*factor)), max(1, round(processed.height*factor)))
    processed = processed.resize(new_size, Image.Resampling.LANCZOS if factor < 1 else Image.Resampling.BICUBIC)
    page = Image.new("RGB" if mode == "color" else "L", (page_w, page_h), "white")
    page.paste(processed, ((page_w-new_size[0])//2, (page_h-new_size[1])//2))
    output = io.BytesIO()
    page.save(output, format="PDF", resolution=300, quality=95)
    return output.getvalue(), cropped

def images_as_pdf(files, mode="clear"):
    if not files or len(files) > 20:
        raise UserError("اختَر من 1 إلى 20 صورة في كل مرة")
    writer, auto_crop_count = PdfWriter(), 0
    for f in files:
        if not (f.mimetype or "").startswith("image/"):
            raise UserError("يُسمح برفع الصور فقط")
        pdf, auto = image_pdf(f.read(MAX_IMAGE + 1), mode=mode)
        auto_crop_count += int(auto)
        writer.append(io.BytesIO(pdf))
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue(), auto_crop_count


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
        try:
            storage().remove([path])
        except Exception:
            app.logger.exception("Failed to remove unsaved PDF")
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
    if old:
        try:
            storage().remove([old["storage_path"]])
        except Exception:
            app.logger.exception("Old PDF cleanup failed")
    return resp.data[0]


@app.post("/api/teachers/<teacher_id>/documents/<kind>")
@login_required(roles=("admin", "scanner"))
def upload_doc(teacher_id, kind):
    teacher = teacher_by_id(teacher_id)
    if kind not in KINDS:
        raise UserError("نوع المستند غير معروف")
    new_pdf, cropped = images_as_pdf(request.files.getlist("images"), request.form.get("quality", "clear"))
    mode = request.form.get("mode", "append")
    old = find_doc(teacher_id, kind)
    # Scanners may add/correct their OWN documents; edits to others remain admin-only.
    if old:
        require_document_editor(old)
    if old:
        check_document_version(old, request.form.get("expected_version"), required=True)
    else:
        raw_expected = request.form.get("expected_version", "0")
        if raw_expected not in ("", "0"):
            raise UserError("تم تصوير هذا المستند من جهاز آخر؛ حدّث القائمة.", 409)
    final = new_pdf
    if old and mode == "append":
        final = merge_pdfs(storage().download(old["storage_path"]), new_pdf, "append")
    elif mode not in ("append", "replace"):
        raise UserError("اختر إضافة صفحات أو استبدال المستند")
    saved = save_doc(teacher_id, kind, final, len(PdfReader(io.BytesIO(final)).pages), old)
    audit("تعديل مستند" if old else "تصوير مستند", f"{teacher['full_name']} - {KINDS[kind]}")
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
    pdf, cropped = images_as_pdf(imgs, request.form.get("quality", "clear"))
    updated = merge_pdfs(storage().download(doc["storage_path"]), pdf, "replace_page", page)
    saved = save_doc(doc["teacher_id"], doc["kind"], updated, doc["pages"], doc)
    audit("استبدال صفحة", f"{doc['kind']} - صفحة {page+1}")
    return jsonify(document=saved, auto_crop_count=cropped)


@app.delete("/api/documents/<doc_id>/pages/<int:page>")
@login_required(roles=("admin", "scanner"))
def remove_page(doc_id, page):
    doc = get_doc(doc_id)
    require_document_editor(doc)
    check_document_version(doc, request.args.get("expected_version"), required=True)
    old = PdfReader(io.BytesIO(storage().download(doc["storage_path"])))
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
    audit("حذف صفحة", f"{doc['kind']} - صفحة {page+1}")
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
    audit("حذف مستند", doc["kind"])
    return jsonify(ok=True)


@app.get("/api/documents/<doc_id>/pdf")
@login_required(roles=("admin", "viewer", "scanner"))
def download_doc(doc_id):
    doc = get_doc(doc_id)
    if request.current_user["role"] == "scanner":
        require_document_editor(doc)
    teacher = teacher_by_id(doc["teacher_id"])
    data = storage().download(doc["storage_path"])
    name = f"{clean(teacher['full_name'])}-{clean(KINDS[doc['kind']])}.pdf"
    return send_file(io.BytesIO(data), mimetype="application/pdf", as_attachment=request.args.get("download") == "1", download_name=name)


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
            writer.append(io.BytesIO(storage().download(doc["storage_path"])))
    out = io.BytesIO()
    writer.write(out)
    return send_file(io.BytesIO(out.getvalue()), mimetype="application/pdf", as_attachment=True,
                     download_name=f"{clean(teacher['full_name'])}-الملف_الكامل.pdf")


def archive_stream(teachers, output_format="folders"):
    """Stream ordered teacher folders or individual combined PDFs in a ZIP."""
    if output_format not in ("folders", "pdf"):
        raise UserError("صيغة التصدير غير صحيحة")
    zs = ZipStream(compress_type=ZIP_STORED)
    doc_rows = all_records("documents", "teacher_id,kind,storage_path")
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
                        writer.append(io.BytesIO(storage().download(by_kind[kind]["storage_path"])))
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
                path = doc["storage_path"]
                def load_chunks(path=path):
                    contents = storage().download(path)
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
