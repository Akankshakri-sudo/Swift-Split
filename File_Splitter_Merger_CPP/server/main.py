"""
SecureVault API server
======================

FastAPI wrapper around the SecureVault engine.

New in this version:
  * /api/split      - fragment a file with k-of-n threshold reconstruction
                      (Shamir key sharing + Reed-Solomon erasure coding)
  * /api/merge      - rebuild a file from ANY >= k fragments
  * /api/inspect    - parse fragment headers (used for live preview cards)
  * /api/vault      - list fragment sets + reconstructed files
  * /api/download/... - download fragments / merged files
  * /api/audit      - operation history
  * /api/health     - engine + server status for the UI status chip
  * legacy /split, /merge kept working (C++ binary when present, otherwise
    the Python engine); legacy ".enc" fragments can still be merged.

Run:
    cd server
    python -m uvicorn main:app --reload --port 8000
The frontend is served at http://127.0.0.1:8000/
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import cloud
from cloud import CloudError
import engine
from engine import EngineError

app = FastAPI(title="SecureVault API", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ================= DIRECTORIES =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
VAULT_DIR = os.path.join(BASE_DIR, "vault")
MERGE_DIR = os.path.join(BASE_DIR, "merged_files")

for d in (UPLOAD_DIR, VAULT_DIR, MERGE_DIR):
    os.makedirs(d, exist_ok=True)

AUDIT_LOG = os.path.join(BASE_DIR, "audit.log")

# Optional legacy C++ engine (used only by the legacy endpoints)
FSM_PATH = os.path.abspath(os.path.join(BASE_DIR, "..", "backend", "fsm"))
if os.name == "nt":
    FSM_PATH = FSM_PATH + ".exe" if not FSM_PATH.endswith(".exe") else FSM_PATH
CPP_ENGINE_AVAILABLE = os.path.isfile(FSM_PATH) and os.access(FSM_PATH, os.X_OK)


# ================= HELPERS =================

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ ()\[\]-]")


def safe_name(name: str) -> str:
    base = os.path.basename(name or "").strip()
    base = _SAFE_NAME.sub("_", base)
    return base[:150] or "unnamed"


def audit(action: str, detail: dict | str = "") -> None:
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "detail": detail if isinstance(detail, str) else json.dumps(detail)[:400],
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass


async def save_upload(upload: UploadFile, directory: str) -> str:
    """Stage an upload with a collision-proof name."""
    name = safe_name(upload.filename)
    path = os.path.join(directory, f"{uuid.uuid4().hex[:8]}_{name}")
    with open(path, "wb") as buf:
        shutil.copyfileobj(upload.file, buf)
    return path


async def save_upload_clean(upload: UploadFile) -> str:
    """Stage an upload under its own clean name in a fresh temp dir,
    so the engine sees the real original filename."""
    stage = tempfile.mkdtemp(prefix="svupload_")
    path = os.path.join(stage, safe_name(upload.filename))
    with open(path, "wb") as buf:
        shutil.copyfileobj(upload.file, buf)
    return path


def read_manifest(uid: str) -> dict:
    path = os.path.join(VAULT_DIR, uid, "manifest.json")
    if not os.path.isfile(path):
        raise HTTPException(404, "Fragment set not found")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def fragment_set_summary(uid: str) -> dict:
    m = read_manifest(uid)
    location = m.get("location", os.path.join(VAULT_DIR, uid))
    return {
        "id": uid,
        "original": m["original"],
        "size": m["size"],
        "parts": m["parts"],
        "threshold": m["threshold"],
        "mode": m["mode"],
        "total_sha256": m.get("total_sha256", ""),
        "location": "vault" if location.startswith(VAULT_DIR) else location,
        "cloud": m.get("cloud"),
        "created": datetime.fromtimestamp(
            os.path.getctime(os.path.join(VAULT_DIR, uid, "manifest.json"))
        ).isoformat(timespec="seconds"),
        "fragments": [
            {
                **f,
                "url": f"/api/download/fragment/{uid}/{f['name']}",
                "present": os.path.isfile(os.path.join(location, f["name"])),
            }
            for f in m["fragments"]
        ],
    }


# ================= HEALTH / STATS / AUDIT =================


@app.get("/api/health")
def health():
    frag_sets = len(os.listdir(VAULT_DIR)) if os.path.isdir(VAULT_DIR) else 0
    merged = len(os.listdir(MERGE_DIR)) if os.path.isdir(MERGE_DIR) else 0
    return {
        "status": "ok",
        "engine": "python-enhanced",
        "legacy_cpp_engine": CPP_ENGINE_AVAILABLE,
        "version": "2.0",
        "vault_sets": frag_sets,
        "merged_files": merged,
        "cloud_connections": len(cloud.list_connections()),
        "time": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/stats")
def stats():
    total_frag_bytes = 0
    if os.path.isdir(VAULT_DIR):
        for uid in os.listdir(VAULT_DIR):
            set_dir = os.path.join(VAULT_DIR, uid)
            for f in os.listdir(set_dir):
                if f != "manifest.json":
                    total_frag_bytes += os.path.getsize(os.path.join(set_dir, f))
    merged_bytes = sum(
        os.path.getsize(os.path.join(MERGE_DIR, f)) for f in os.listdir(MERGE_DIR)
    )
    return {
        "fragment_bytes": total_frag_bytes,
        "merged_bytes": merged_bytes,
        "sets": len(os.listdir(VAULT_DIR)),
        "merged_files": len(os.listdir(MERGE_DIR)),
    }


@app.get("/api/audit")
def get_audit(limit: int = 100):
    if not os.path.isfile(AUDIT_LOG):
        return {"entries": []}
    with open(AUDIT_LOG, encoding="utf-8") as fh:
        lines = fh.readlines()[-limit:]
    entries = []
    for line in reversed(lines):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"entries": entries}


# ================= SPLIT =================


@app.post("/api/split")
async def api_split(
    file: UploadFile = File(...),
    parts: int = Form(4),
    threshold: int = Form(0),          # 0 => all parts required
    mode: str = Form("auto"),          # auto | none | password | shamir
    password: str = Form(""),
    destination: str = Form(""),       # "" => vault; else a server folder path
):
    try:
        threshold = threshold if threshold and threshold > 0 else parts
        if parts < 2 or parts > 16:
            raise EngineError("Parts must be between 2 and 16")
        if threshold > parts:
            raise EngineError("Threshold cannot exceed the number of parts")

        # Resolve "auto": password wins, then shamir when k < n, else none.
        if mode == "auto":
            mode = engine.MODE_PASSWORD if password else (
                engine.MODE_SHAMIR if threshold < parts else engine.MODE_NONE)

        tmp_path = await save_upload_clean(file)
        stage_dir = os.path.dirname(tmp_path)
        uid = uuid.uuid4().hex[:12]

        # Storage destination: vault by default, or a user-chosen folder.
        if destination.strip():
            out_dir = os.path.abspath(destination.strip())
            if not os.path.isabs(out_dir):
                raise EngineError("Destination must be an absolute folder path")
            # refuse to write into the server's own root (cross-drive paths
            # have no common path, which is fine - the check just doesn't apply)
            try:
                if os.path.commonpath([out_dir, BASE_DIR]) == BASE_DIR:
                    raise EngineError("Refusing to write into the server root")
            except ValueError:
                pass  # different drive than the server - allow it
            os.makedirs(out_dir, exist_ok=True)
        else:
            out_dir = os.path.join(VAULT_DIR, uid)

        manifest = engine.split_file(
            tmp_path, out_dir, parts=parts, threshold=threshold,
            mode=mode, password=password,
        )
        shutil.rmtree(stage_dir, ignore_errors=True)

        # Register the set in the vault index (points at the real location).
        manifest["location"] = out_dir
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2)
        if out_dir != os.path.join(VAULT_DIR, uid):
            os.makedirs(os.path.join(VAULT_DIR, uid), exist_ok=True)
            with open(os.path.join(VAULT_DIR, uid, "manifest.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=2)

        audit("split", {"file": manifest["original"], "parts": parts,
                        "threshold": threshold, "mode": mode, "set": uid})
        return {
            "message": (f"'{manifest['original']}' shattered into {parts} shards "
                        f"(any {threshold} reconstruct it)"),
            "set": fragment_set_summary(uid),
        }
    except EngineError as exc:
        audit("split-error", str(exc))
        raise HTTPException(400, str(exc))
    except Exception as exc:  # pragma: no cover
        audit("split-error", str(exc))
        raise HTTPException(500, str(exc))


# ================= INSPECT =================


@app.post("/api/inspect")
async def api_inspect(files: list[UploadFile] = File(...)):
    results = []
    for upload in files:
        path = await save_upload(upload, UPLOAD_DIR)
        try:
            results.append(engine.inspect_fragment(path))
        except EngineError as exc:
            results.append({"filename": safe_name(upload.filename),
                            "error": str(exc), "integrity": "invalid"})
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
    return {"fragments": results}


# ================= MERGE =================


@app.post("/api/merge")
async def api_merge(
    files: list[UploadFile] = File(...),
    password: str = Form(""),
):
    staged: list[str] = []
    try:
        for upload in files:
            staged.append(await save_upload(upload, UPLOAD_DIR))

        is_legacy = False
        try:
            probe = engine.inspect_fragment(staged[0])
            original = safe_name(probe.get("original", "reconstructed.bin"))
        except EngineError:
            if staged[0].endswith(".enc") or any((f.filename or "").endswith(".enc") for f in files):
                is_legacy = True
                first_name = safe_name(files[0].filename)
                if first_name.endswith(".enc"):
                    first_name = first_name[:-4]
                if "_part" in first_name:
                    first_name = first_name.rsplit("_part", 1)[0]
                original = first_name or "reconstructed.bin"
            else:
                raise

        out_path = os.path.join(MERGE_DIR, f"{uuid.uuid4().hex[:8]}_{original}")

        if is_legacy:
            result = engine.merge_legacy_enc(staged, out_path, password=password, original=original)
        else:
            result = engine.merge_fragments(staged, out_path, password=password)

        result["download"] = f"/api/download/merged/{os.path.basename(out_path)}"
        audit("merge", {"file": result["original"],
                        "fragments_used": result["fragments_used"],
                        "integrity": result.get("integrity", "legacy")})
        return {"message": f"Reconstructed '{result['original']}' from "
                           f"{result['fragments_used']} fragments",
                "result": result}
    except EngineError as exc:
        audit("merge-error", str(exc))
        raise HTTPException(400, str(exc))
    except Exception as exc:  # pragma: no cover
        audit("merge-error", str(exc))
        raise HTTPException(500, str(exc))
    finally:
        for p in staged:
            try:
                os.remove(p)
            except OSError:
                pass


# ================= VAULT / DOWNLOADS =================


@app.get("/api/vault")
def api_vault():
    sets = []
    if os.path.isdir(VAULT_DIR):
        for uid in sorted(os.listdir(VAULT_DIR)):
            try:
                sets.append(fragment_set_summary(uid))
            except (HTTPException, OSError, KeyError, json.JSONDecodeError):
                continue
    merged = []
    for name in sorted(os.listdir(MERGE_DIR)):
        p = os.path.join(MERGE_DIR, name)
        if os.path.isfile(p):
            merged.append({
                "name": name,
                "size": os.path.getsize(p),
                "created": datetime.fromtimestamp(os.path.getctime(p))
                             .isoformat(timespec="seconds"),
                "url": f"/api/download/merged/{name}",
            })
    return {"sets": sets, "merged": merged}


@app.delete("/api/vault/{uid}")
def api_delete_set(uid: str):
    if not re.fullmatch(r"[0-9a-f]{12}", uid):
        raise HTTPException(400, "Invalid set id")
    set_dir = os.path.join(VAULT_DIR, uid)
    if not os.path.isdir(set_dir):
        raise HTTPException(404, "Fragment set not found")
    shutil.rmtree(set_dir)
    audit("delete-set", uid)
    return {"message": f"Fragment set {uid} destroyed"}


@app.delete("/api/vault/merged/{name}")
def api_delete_merged(name: str):
    path = os.path.join(MERGE_DIR, safe_name(name))
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    os.remove(path)
    audit("delete-merged", name)
    return {"message": f"Deleted {name}"}


@app.get("/api/download/fragment/{uid}/{name}")
def api_download_fragment(uid: str, name: str):
    if not re.fullmatch(r"[0-9a-f]{12}", uid):
        raise HTTPException(400, "Invalid set id")
    m = read_manifest(uid)
    location = m.get("location", os.path.join(VAULT_DIR, uid))
    path = os.path.join(location, safe_name(name))
    if not os.path.isfile(path):
        raise HTTPException(404, "Fragment not found")
    return FileResponse(path, filename=safe_name(name))


@app.get("/api/download/merged/{name}")
def api_download_merged(name: str):
    path = os.path.join(MERGE_DIR, safe_name(name))
    if not os.path.isfile(path):
        raise HTTPException(404, "File not found")
    return FileResponse(path, filename=safe_name(name))


# ================= CLOUD STORAGE =================


@app.get("/api/cloud")
def cloud_list():
    return {"connections": cloud.list_connections()}


@app.post("/api/cloud")
def cloud_save(cfg: dict = Body(...), test: bool = False):
    try:
        masked = cloud.save_connection(cfg)
        if test:
            conn = cloud.get_connection(masked["name"])
            result = cloud.test_connection(conn)
            return {"saved": masked, "test": result}
        return {"saved": masked, "test": None}
    except CloudError as exc:
        raise HTTPException(400, str(exc))


@app.delete("/api/cloud/{name}")
def cloud_delete(name: str):
    try:
        cloud.delete_connection(name)
        audit("cloud-delete", name)
        return {"message": f"Connection '{name}' removed"}
    except CloudError as exc:
        raise HTTPException(404, str(exc))


@app.post("/api/cloud/test")
def cloud_test(cfg: dict = Body(...)):
    try:
        conn = cloud.normalize_conn(cfg)
        return cloud.test_connection(conn)
    except CloudError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/cloud/{name}/upload/{uid}")
def cloud_upload(name: str, uid: str):
    if not re.fullmatch(r"[0-9a-f]{12}", uid):
        raise HTTPException(400, "Invalid set id")
    m = read_manifest(uid)
    location = m.get("location", os.path.join(VAULT_DIR, uid))
    names = [f["name"] for f in m["fragments"]]
    missing = [n for n in names if not os.path.isfile(os.path.join(location, n))]
    if missing:
        raise HTTPException(400, f"{len(missing)} fragments are missing locally "
                                 f"(custom location moved?); re-split or upload "
                                 f"from the vault")
    try:
        conn = cloud.get_connection(name)
        res = cloud.upload_set(conn, uid, location, names)
        m["cloud"] = {"connection": name, "prefix": res["prefix"],
                      "uploaded": res["uploaded"]}
        with open(os.path.join(VAULT_DIR, uid, "manifest.json"),
                  "w", encoding="utf-8") as fh:
            json.dump(m, fh, indent=2)
        audit("cloud-upload", {"set": uid, "connection": name,
                               "fragments": len(res["uploaded"])})
        return {"message": f"Pushed {len(res['uploaded'])} shards to "
                           f"'{name}' under {res['prefix']}/",
                "prefix": res["prefix"], "uploaded": res["uploaded"]}
    except CloudError as exc:
        audit("cloud-upload-error", str(exc))
        raise HTTPException(400, str(exc))


@app.get("/api/cloud/{name}/list")
def cloud_remote_list(name: str, set_id: str = ""):
    try:
        conn = cloud.get_connection(name)
        return {"fragments": cloud.list_remote(conn, set_id or None)}
    except CloudError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/cloud/{name}/merge")
def cloud_merge(name: str, body: dict = Body(...)):
    """Fetch chosen remote fragments and reconstruct from them."""
    keys = body.get("keys", [])
    password = body.get("password", "")
    if not keys:
        raise HTTPException(400, "No fragments selected")
    try:
        conn = cloud.get_connection(name)
        stage = tempfile.mkdtemp(prefix="svcloud_")
        paths = cloud.fetch_remote(conn, keys, stage)
        probe = engine.inspect_fragment(paths[0])
        out_path = os.path.join(MERGE_DIR,
                                f"{uuid.uuid4().hex[:8]}_{safe_name(probe['original'])}")
        result = engine.merge_fragments(paths, out_path, password=password)
        result["download"] = f"/api/download/merged/{os.path.basename(out_path)}"
        audit("cloud-merge", {"file": result["original"],
                              "fragments_used": result["fragments_used"],
                              "connection": name})
        return {"message": f"Reconstructed '{result['original']}' from "
                           f"{result['fragments_used']} cloud shards",
                "result": result}
    except CloudError as exc:
        audit("cloud-merge-error", str(exc))
        raise HTTPException(400, str(exc))
    except EngineError as exc:
        audit("cloud-merge-error", str(exc))
        raise HTTPException(400, str(exc))
    finally:
        shutil.rmtree(stage, ignore_errors=True)


# ================= LEGACY ENDPOINTS (original frontend / C++ engine) ========


@app.post("/split")
async def legacy_split(
    file: UploadFile = File(...),
    parts: int = Form(...),
    encrypt: bool = Form(False),
    password: str = Form(""),
):
    """Original API. Uses the C++ binary when available, else the Python
    engine in compatible mode (threshold = parts)."""
    file_path = await save_upload_clean(file)

    if CPP_ENGINE_AVAILABLE:
        command = [FSM_PATH, "split", file_path, UPLOAD_DIR, str(parts)]
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        if encrypt:
            process.stdin.write("y\n")
            process.stdin.write(password + "\n")
        else:
            process.stdin.write("n\n")
        process.stdin.flush()
        _, error = process.communicate()
        if process.returncode != 0:
            msg = ("Split operation failed. Wrong password."
                   if "bad decrypt" in (error or "").lower()
                   else "Split operation not successful.")
            return JSONResponse({"error": msg}, status_code=400)
        out = f"File split successfully. Parts saved in: {UPLOAD_DIR}"
    else:
        try:
            engine.split_file(
                file_path, os.path.join(UPLOAD_DIR, f"set_{uuid.uuid4().hex[:8]}"),
                parts=parts, threshold=parts,
                mode=engine.MODE_PASSWORD if encrypt else engine.MODE_NONE,
                password=password)
            out = "File split successfully (Python engine)."
        except EngineError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
    os.remove(file_path)
    shutil.rmtree(os.path.dirname(file_path), ignore_errors=True)
    audit("legacy-split", {"file": file.filename, "parts": parts})
    return {"message": out}


@app.post("/merge")
async def legacy_merge(
    files: list[UploadFile] = File(...),
    output_name: str = Form(...),
    encrypted: bool = Form(False),
    password: str = Form(""),
):
    """Original API; auto-detects new .svf fragments vs legacy .enc parts."""
    staged = [await save_upload(f, UPLOAD_DIR) for f in files]
    out_path = os.path.join(MERGE_DIR, safe_name(output_name))
    try:
        with open(staged[0], "rb") as fh:
            head = fh.read(7)
        if head == engine.MAGIC:
            result = engine.merge_fragments(staged, out_path, password=password)
        elif encrypted:
            result = engine.merge_legacy_enc(staged, out_path, password)
        else:
            with open(out_path, "wb") as fout:
                for p in staged:
                    with open(p, "rb") as fin:
                        shutil.copyfileobj(fin, fout)
            result = {"output": os.path.basename(out_path)}
        audit("legacy-merge", {"output": result.get("output")})
        return {"message": f"Files merged successfully. File saved in: {out_path}"}
    except EngineError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    finally:
        for p in staged:
            try:
                os.remove(p)
            except OSError:
                pass


# ================= STATIC FRONTEND (mounted last) =================

app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
