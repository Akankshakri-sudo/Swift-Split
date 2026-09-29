"""
SecureVault cloud distribution
==============================

Upload / list / fetch fragment sets on user-connected cloud storage.

Two provider families, both implemented with the standard library only:

  * s3     — any S3-compatible object storage (AWS S3, Cloudflare R2,
             Backblaze B2, MinIO, Wasabi, ...). Requests are signed with
             AWS Signature V4 (hashlib + hmac + urllib).
  * webdav — any WebDAV server (Nextcloud, ownCloud, Synology, Box, ...).
             Plain PUT / GET / PROPFIND / DELETE with basic auth.

Connections are stored server-side in cloud_connections.json (credentials
never reach the browser after saving; the API only returns masked values).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

CONN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "cloud_connections.json")


class CloudError(Exception):
    """User-facing cloud failure."""


# --------------------------------------------------------------------------
# connection storage
# --------------------------------------------------------------------------

def _load_all() -> dict:
    if not os.path.isfile(CONN_FILE):
        return {}
    try:
        with open(CONN_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_all(conns: dict) -> None:
    with open(CONN_FILE, "w", encoding="utf-8") as fh:
        json.dump(conns, fh, indent=2)


def normalize_conn(cfg: dict) -> dict:
    """Validate + normalize a connection config from the client."""
    name = (cfg.get("name") or "").strip()
    provider = (cfg.get("provider") or "").strip().lower()
    if not re.fullmatch(r"[A-Za-z0-9 _-]{1,32}", name):
        raise CloudError("Connection name: 1-32 letters/digits/spaces/-_")
    if provider not in ("s3", "webdav"):
        raise CloudError("Provider must be 's3' or 'webdav'")

    out = {"name": name, "provider": provider}

    if provider == "s3":
        endpoint = (cfg.get("endpoint") or "").strip()
        bucket = (cfg.get("bucket") or "").strip()
        region = (cfg.get("region") or "us-east-1").strip() or "us-east-1"
        access_key = (cfg.get("access_key") or "").strip()
        secret_key = (cfg.get("secret_key") or "").strip()
        if not endpoint:
            raise CloudError("S3 needs an endpoint URL, e.g. "
                             "https://s3.amazonaws.com or https://<account>.r2.cloudflarestorage.com")
        if not bucket:
            raise CloudError("S3 needs a bucket name")
        if not access_key or not secret_key:
            raise CloudError("S3 needs an access key + secret key")
        out.update(endpoint=endpoint.rstrip("/"), bucket=bucket,
                   region=region, access_key=access_key, secret_key=secret_key)
    else:
        url = (cfg.get("url") or "").strip()
        username = (cfg.get("username") or "").strip()
        password = cfg.get("password") or ""
        if not url.startswith(("http://", "https://")):
            raise CloudError("WebDAV needs a server URL starting with http(s)://")
        if not username:
            raise CloudError("WebDAV needs a username")
        out.update(url=url.rstrip("/"), username=username, password=password)
    return out


def save_connection(cfg: dict) -> dict:
    conns = _load_all()
    conn = normalize_conn(cfg)
    # when editing an existing connection without re-entering the secret,
    # keep the stored one
    old = conns.get(conn["name"], {})
    if conn["provider"] == "s3" and conn["secret_key"] == "•••••":
        conn["secret_key"] = old.get("secret_key", "")
    if conn["provider"] == "webdav" and conn["password"] == "•••••":
        conn["password"] = old.get("password", "")
    conns[conn["name"]] = conn
    _save_all(conns)
    return mask(conn)


def delete_connection(name: str) -> None:
    conns = _load_all()
    if name not in conns:
        raise CloudError(f"No connection named '{name}'")
    del conns[name]
    _save_all(conns)


def get_connection(name: str) -> dict:
    conn = _load_all().get(name)
    if not conn:
        raise CloudError(f"No connection named '{name}' — add it in Cloud settings")
    return conn


def list_connections() -> list[dict]:
    return [mask(c) for c in _load_all().values()]


def mask(conn: dict) -> dict:
    out = {"name": conn["name"], "provider": conn["provider"]}
    if conn["provider"] == "s3":
        out.update(bucket=conn["bucket"], region=conn["region"],
                   endpoint=conn["endpoint"],
                   access_key=conn["access_key"],
                   secret_key="•••••" if conn.get("secret_key") else "")
    else:
        out.update(url=conn["url"], username=conn["username"],
                   password="•••••" if conn.get("password") else "")
    return out


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------

def _request(method: str, url: str, *, data: bytes = b"", headers: dict | None = None,
             timeout: int = 30) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data if data else None, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise CloudError(f"Cannot reach {url.split('/')[2]}: {e}") from e


# --------------------------------------------------------------------------
# S3 — AWS Signature V4
# --------------------------------------------------------------------------

def _uri_encode(s: str, encode_slash: bool = True) -> str:
    safe = "" if encode_slash else "/"
    return urllib.parse.quote(s, safe=safe)


def _encode_path(key: str) -> str:
    """Percent-encode each path segment but keep the slashes structural."""
    return "/".join(urllib.parse.quote(seg, safe="") for seg in key.split("/"))


def _s3_sign(conn: dict, method: str, key: str, payload: bytes,
             extra_headers: dict | None = None,
             now: datetime | None = None) -> tuple[str, dict]:
    """Return (url, headers) for a signed S3 request."""
    endpoint = conn["endpoint"]
    host = endpoint.split("://", 1)[1]
    region, bucket = conn["region"], conn["bucket"]
    access, secret = conn["access_key"], conn["secret_key"]

    if now is None:
        now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(payload).hexdigest()

    canonical_uri = f"/{bucket}/{_uri_encode(key)}"
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join([
        method, canonical_uri, "", canonical_headers, signed_headers, payload_hash])

    scope = f"{datestamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest()])

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = _hmac(("AWS4" + secret).encode(), datestamp)
    k = _hmac(k, region)
    k = _hmac(k, "s3")
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth = (f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}")
    headers = {
        "Authorization": auth,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        **(extra_headers or {}),
    }
    return f"{endpoint}{canonical_uri}", headers


def s3_put(conn: dict, key: str, data: bytes) -> None:
    url, headers = _s3_sign(conn, "PUT", key, data)
    status, body = _request("PUT", url, data=data, headers=headers)
    if status not in (200, 201, 204):
        raise CloudError(f"S3 upload failed ({status}): {body[:200]!r}")


def s3_get(conn: dict, key: str) -> bytes:
    url, headers = _s3_sign(conn, "GET", key, b"")
    status, body = _request("GET", url, headers=headers)
    if status != 200:
        raise CloudError(f"S3 download failed ({status}) for '{key}'")
    return body


def s3_delete(conn: dict, key: str) -> None:
    url, headers = _s3_sign(conn, "DELETE", key, b"")
    status, body = _request("DELETE", url, headers=headers)
    if status not in (200, 202, 204):
        raise CloudError(f"S3 delete failed ({status})")


def s3_list(conn: dict, prefix: str) -> list[dict]:
    """List objects under prefix. Returns [{key, size}]."""
    from urllib.parse import urlencode
    query = urlencode({"list-type": "2", "prefix": prefix})
    # sign with empty key but query string in URL
    endpoint = conn["endpoint"]
    host = endpoint.split("://", 1)[1]
    bucket = conn["bucket"]
    path = f"/{bucket}/?{query}"          # canonical query must be sorted-encoded

    # rebuild canonical query in sorted order per SigV4
    from urllib.parse import quote
    canon_query = "&".join(
        f"{quote(k, safe='')}={quote(v, safe='')}"
        for k, v in sorted([("list-type", "2"), ("prefix", prefix)]))

    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join([
        "GET", f"/{bucket}/", canon_query,
        f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n",
        "host;x-amz-content-sha256;x-amz-date", payload_hash])
    scope = f"{datestamp}/{conn['region']}/s3/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest()])

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = _hmac(("AWS4" + conn["secret_key"]).encode(), datestamp)
    k = _hmac(k, conn["region"])
    k = _hmac(k, "s3")
    k = _hmac(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={conn['access_key']}/{scope}, "
            f"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={signature}")
    url = f"{endpoint}/{bucket}/?{canon_query}"
    status, body = _request("GET", url, headers={
        "Authorization": auth, "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash})
    if status != 200:
        raise CloudError(f"S3 list failed ({status}): {body[:200]!r}")

    items = []
    for m in re.finditer(r"<Key>([^<]+)</Key>\s*<LastModified>[^<]*</LastModified>"
                         r'\s*<ETag>[^<]*</ETag>\s*<Size>(\d+)</Size>', body.decode("utf-8", "replace")):
        items.append({"key": m.group(1), "size": int(m.group(2))})
    return items


def s3_head(conn: dict) -> bool:
    """Cheap connectivity/bucket probe: list with an impossible prefix."""
    s3_list(conn, "securevault-probe-\x00")
    return True


# --------------------------------------------------------------------------
# WebDAV
# --------------------------------------------------------------------------

def _wd_auth(conn: dict) -> dict:
    import base64
    tok = base64.b64encode(
        f"{conn['username']}:{conn['password']}".encode()).decode()
    return {"Authorization": f"Basic {tok}"}


def wd_put(conn: dict, key: str, data: bytes) -> None:
    url = f"{conn['url']}/{_encode_path(key)}"
    status, body = _request("PUT", url, data=data, headers={
        **_wd_auth(conn), "Content-Type": "application/octet-stream"})
    if status not in (200, 201, 204):
        raise CloudError(f"WebDAV upload failed ({status}): {body[:200]!r}")


def wd_get(conn: dict, key: str) -> bytes:
    url = f"{conn['url']}/{_encode_path(key)}"
    status, body = _request("GET", url, headers=_wd_auth(conn))
    if status != 200:
        raise CloudError(f"WebDAV download failed ({status}) for '{key}'")
    return body


def wd_delete(conn: dict, key: str) -> None:
    url = f"{conn['url']}/{_encode_path(key)}"
    status, _ = _request("DELETE", url, headers=_wd_auth(conn))
    if status not in (200, 202, 204, 404):
        raise CloudError(f"WebDAV delete failed ({status})")


def wd_list(conn: dict, prefix: str) -> list[dict]:
    """PROPFIND depth-1 on the prefix folder."""
    url = f"{conn['url']}/{_encode_path(prefix.rstrip('/'))}/"
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:">'
            '<d:prop><d:displayname/><d:getcontentlength/></d:prop></d:propfind>').encode()
    status, resp = _request("PROPFIND", url, data=body, headers={
        **_wd_auth(conn), "Depth": "1",
        "Content-Type": "application/xml"})
    if status not in (207, 200):
        raise CloudError(f"WebDAV list failed ({status}): {resp[:200]!r}")
    items = []
    text = resp.decode("utf-8", "replace")
    for resp_m in re.finditer(r"<d:response>(.*?)</d:response>", text, re.S):
        block = resp_m.group(1)
        href_m = re.search(r"<d:href>([^<]+)</d:href>", block)
        size_m = re.search(r"<d:getcontentlength>(\d+)</d:getcontentlength>", block)
        if not href_m:
            continue
        href = href_m.group(1)
        name = urllib.parse.unquote(href.rstrip("/").rsplit("/", 1)[-1])
        if not name or name == prefix.rstrip("/").rsplit("/", 1)[-1]:
            continue
        items.append({"key": name, "size": int(size_m.group(1)) if size_m else 0})
    return items


def wd_head(conn: dict) -> bool:
    url = f"{conn['url']}/"
    body = ('<?xml version="1.0"?><d:propfind xmlns:d="DAV:">'
            '<d:prop><d:displayname/></d:prop></d:propfind>').encode()
    status, _ = _request("PROPFIND", url, data=body, headers={
        **_wd_auth(conn), "Depth": "0", "Content-Type": "application/xml"})
    if status in (401, 403):
        raise CloudError("WebDAV rejected the credentials (401/403)")
    if status not in (207, 200):
        raise CloudError(f"WebDAV probe failed ({status})")
    return True


# --------------------------------------------------------------------------
# provider-neutral facade
# --------------------------------------------------------------------------

def test_connection(conn: dict) -> dict:
    if conn["provider"] == "s3":
        s3_head(conn)
        return {"ok": True, "message": f"S3 bucket '{conn['bucket']}' reachable"}
    wd_head(conn)
    return {"ok": True, "message": f"WebDAV server reachable at {conn['url']}"}


def remote_prefix(set_id: str) -> str:
    return f"securevault/{set_id}"


def upload_set(conn: dict, set_id: str, fragment_dir: str,
               fragments: list[str]) -> dict:
    """Upload the given fragment filenames to the cloud under
    securevault/<set_id>/."""
    put = s3_put if conn["provider"] == "s3" else wd_put
    uploaded = []
    for name in fragments:
        path = os.path.join(fragment_dir, name)
        with open(path, "rb") as fh:
            blob = fh.read()
        put(conn, f"{remote_prefix(set_id)}/{name}", blob)
        uploaded.append(name)
    return {"prefix": remote_prefix(set_id), "uploaded": uploaded}


def list_remote(conn: dict, set_id: str | None = None) -> list[dict]:
    ls = s3_list if conn["provider"] == "s3" else wd_list
    prefix = remote_prefix(set_id) if set_id else "securevault"
    items = ls(conn, prefix)
    out = []
    for it in items:
        name = it["key"].rsplit("/", 1)[-1]
        if not name:
            continue
        # wd_list yields bare filenames; re-attach the folder path
        key = it["key"] if "/" in it["key"] else f"{prefix}/{it['key']}"
        sid = key.split("/")[1] if key.startswith("securevault/") else ""
        out.append({"set": sid, "name": name, "size": it["size"], "key": key})
    return out


def fetch_remote(conn: dict, keys: list[str], dest_dir: str) -> list[str]:
    """Download remote fragments into dest_dir; returns local paths."""
    os.makedirs(dest_dir, exist_ok=True)
    get = s3_get if conn["provider"] == "s3" else wd_get
    paths = []
    for key in keys:
        blob = get(conn, key)
        local = os.path.join(dest_dir, os.path.basename(key))
        with open(local, "wb") as fh:
            fh.write(blob)
        paths.append(local)
    return paths


def delete_remote(conn: dict, keys: list[str]) -> int:
    rm = s3_delete if conn["provider"] == "s3" else wd_delete
    count = 0
    for key in keys:
        try:
            rm(conn, key)
            count += 1
        except CloudError:
            continue
    return count
