#!/usr/bin/env python3
"""KaoHorm — Version Manager & GitHub Save System

ใช้:  python save.py [--dry-run]

วิเคราะห์การเปลี่ยนแปลงจาก Git (ใช้หลักฐานจากโค้ดจริงเท่านั้น), ให้ผู้พัฒนายืนยันเวอร์ชัน,
บันทึก version.json / version_history.json / CHANGELOG.md แล้ว commit + push + ตรวจผลจริง
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PROJECT = "KaoHorm"
EXPECTED_REPO = "ProjectWakumi/KaoHormDiscordBot"
REPO_URL = f"https://github.com/{EXPECTED_REPO}"
VERSION_FILE = ROOT / "version.json"
HISTORY_FILE = ROOT / "version_history.json"
CHANGELOG_FILE = ROOT / "CHANGELOG.md"
MANAGED = {"version.json", "version_history.json", "CHANGELOG.md"}

SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
SENSITIVE_GLOBS = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.sqlite", "*.sqlite3", "*.db",
    "id_rsa*", "*secret*", "*token*", "*password*", "*credentials*",
]
SENSITIVE_ALLOW = {".env.example"}
SECRET_PATTERNS = {
    "Discord Bot Token": re.compile(r"[A-Za-z\d_-]{23,32}\.[\w-]{6}\.[\w-]{25,}"),
    "GitHub Token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# จุดต่อสำหรับระบบส่ง Log เข้า Discord ในอนาคต (เรียกหลัง push ตรวจผลแล้วเท่านั้น)
POST_SAVE_HOOKS: list = []


# ---------------------------------------------------------------- utilities
class Abort(Exception):
    pass


def say(msg: str = "") -> None:
    print(msg, flush=True)


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        raise Abort("ยกเลิกโดยผู้ใช้")


def confirm(prompt: str, default: bool = False) -> bool:
    ans = ask(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").lower()
    return default if not ans else ans in ("y", "yes", "ใช่")


def git(*args: str, check: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args],
        cwd=ROOT, capture_output=True, text=text, encoding="utf-8" if text else None, errors="replace",
    )
    if check and proc.returncode != 0:
        raise Abort(f"git {' '.join(args)} ล้มเหลว: {(proc.stderr or '').strip()}")
    return proc


def write_atomic(path: Path, content: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(tmp, path)


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise Abort(f"{path.name} เสียหาย (JSON ไม่ถูกต้อง: {e}) — แก้ไขหรือกู้คืนจาก Git ก่อน")


# ------------------------------------------------------------ change analysis
@dataclass
class Change:
    status: str  # added | modified | deleted | renamed
    path: str
    old_path: str | None = None


def parse_status() -> tuple[list[Change], list[str]]:
    out = git("status", "--porcelain=v1", "-z", "-uall").stdout
    parts = out.split("\0")
    changes: list[Change] = []
    conflicts: list[str] = []
    i = 0
    while i < len(parts):
        entry = parts[i]
        i += 1
        if len(entry) < 4:
            continue
        xy, path = entry[:2], entry[3:]
        old = None
        if "R" in xy or "C" in xy:
            old = parts[i] if i < len(parts) else None
            i += 1
        if "U" in xy or xy in ("AA", "DD"):
            conflicts.append(path)
        elif xy == "??" or "A" in xy or "C" in xy:
            changes.append(Change("added", path))
        elif "R" in xy:
            changes.append(Change("renamed", path, old))
        elif "D" in xy:
            changes.append(Change("deleted", path))
        elif "M" in xy or "T" in xy:
            changes.append(Change("modified", path))
    return changes, conflicts


def pair_renames(changes: list[Change], has_head: bool) -> list[Change]:
    """จับคู่ deleted+added ที่เนื้อหาเหมือนกันเป็น renamed (เทียบ blob hash)"""
    if not has_head:
        return changes
    deleted = [c for c in changes if c.status == "deleted"]
    added = [c for c in changes if c.status == "added"]
    if not deleted or not added:
        return changes
    old_hash = {}
    for c in deleted:
        p = git("rev-parse", f"HEAD:{c.path}", check=False)
        if p.returncode == 0:
            old_hash[p.stdout.strip()] = c
    result = [c for c in changes if c not in deleted and c not in added]
    used = set()
    for a in added:
        fp = ROOT / a.path
        h = git("hash-object", "--", a.path, check=False).stdout.strip() if fp.is_file() else ""
        d = old_hash.get(h)
        if d and id(d) not in used:
            used.add(id(d))
            result.append(Change("renamed", a.path, d.path))
        else:
            result.append(a)
    result += [d for d in deleted if id(d) not in used]
    return result


def extract_symbols(source: str) -> dict[str, set[str]] | None:
    """อ่านโครงสร้างจาก AST: คำสั่ง, Listener, Cog — ไม่ใช้การเดา"""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    syms: dict[str, set[str]] = {"commands": set(), "listeners": set(), "cogs": set()}

    def call_name(call: ast.Call, default: str) -> str:
        for kw in call.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                return str(kw.value.value)
        return default

    # ตัวแปรที่เป็น Group เช่น security = app_commands.Group(name="security")
    groups: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            fn = node.value.func
            if (fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")) == "Group":
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        groups[t.id] = call_name(node.value, t.id)

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for b in node.bases:
                nm = b.attr if isinstance(b, ast.Attribute) else getattr(b, "id", "")
                if nm == "Cog":
                    syms["cogs"].add(node.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                attr = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
                if attr in ("command", "group", "hybrid_command", "hybrid_group", "context_menu"):
                    name = call_name(dec, node.name) if isinstance(dec, ast.Call) else node.name
                    owner = target.value if isinstance(target, ast.Attribute) else None
                    if isinstance(owner, ast.Name) and owner.id in groups:
                        name = f"{groups[owner.id]} {name}"
                    syms["commands"].add(name)
                elif attr == "listener":
                    syms["listeners"].add(node.name)
    return syms


def old_source(path: str) -> str | None:
    p = git("show", f"HEAD:{path}", check=False)
    return p.stdout if p.returncode == 0 else None


def new_source(path: str) -> str | None:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def system_name(path: str) -> str:
    p = Path(path)
    if p.parts and p.parts[0] == "cogs":
        return f"ระบบ {p.stem}"
    return f"ไฟล์ {path}"


def analyze(changes: list[Change], has_head: bool) -> dict:
    res = {
        "added_systems": [], "modified_systems": [], "removed_systems": [],
        "commands_added": [], "commands_removed": [], "unclassified": [],
        "files": {"added": [], "modified": [], "deleted": [], "renamed": []},
    }
    for c in changes:
        res["files"][c.status].append(c.path if c.status != "renamed" else f"{c.old_path} -> {c.path}")
        if not c.path.endswith(".py") and not (c.old_path or "").endswith(".py"):
            res["unclassified"].append(c.path)
            continue
        is_cog = c.path.startswith("cogs/") and Path(c.path).name != "__init__.py"
        old = old_source(c.old_path or c.path) if has_head and c.status != "added" else None
        new = new_source(c.path) if c.status != "deleted" else None
        osym = extract_symbols(old) if old else None
        nsym = extract_symbols(new) if new else None
        if (c.status in ("added", "modified", "renamed") and nsym is None) or (c.status == "deleted" and old and osym is None):
            res["unclassified"].append(c.path)  # วิเคราะห์ไม่ได้ (เช่น Syntax Error) → ไม่เดา
            continue
        label = system_name(c.path)
        if c.status == "added":
            if is_cog:
                res["added_systems"].append(label)
        elif c.status == "deleted":
            if is_cog:
                res["removed_systems"].append(label)
        elif c.status in ("modified", "renamed"):
            res["modified_systems"].append(label)
        before = (osym or {}).get("commands", set())
        after = (nsym or {}).get("commands", set())
        res["commands_added"] += sorted(f"/{x}" for x in after - before)
        res["commands_removed"] += sorted(f"/{x}" for x in before - after)
        if c.status == "modified" and osym and nsym and osym == nsym and not is_cog:
            pass
    for k in ("added_systems", "modified_systems", "removed_systems", "commands_added", "commands_removed", "unclassified"):
        res[k] = sorted(set(res[k]))
    return res


def suggest_version(current: str, a: dict) -> tuple[str, str]:
    m = SEMVER.match(current)
    major, minor, patch = (int(x) for x in m.groups()) if m else (1, 0, 0)
    if a["added_systems"] or a["commands_added"]:
        return f"{major}.{minor + 1}.0", "มีระบบ/คำสั่งใหม่ → MINOR"
    if a["removed_systems"] or a["commands_removed"]:
        return f"{major}.{minor + 1}.0", "มีการลบระบบ/คำสั่ง → MINOR (หากกระทบการใช้งานเดิม ให้พิจารณา MAJOR)"
    return f"{major}.{minor}.{patch + 1}", "แก้ไขของเดิม → PATCH"


# ------------------------------------------------------------------- security
def security_scan(paths: list[str]) -> dict[str, list[str]]:
    flagged: dict[str, list[str]] = {}
    for p in paths:
        name = Path(p).name.lower()
        if name in SENSITIVE_ALLOW:
            continue
        for g in SENSITIVE_GLOBS:
            if fnmatch.fnmatch(name, g):
                flagged.setdefault(p, []).append(f"ชื่อไฟล์เข้าข่ายข้อมูลลับ ({g})")
                break
        fp = ROOT / p
        if fp.is_file() and fp.stat().st_size < 1_000_000:
            try:
                text = fp.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for label, rx in SECRET_PATTERNS.items():
                if rx.search(text):
                    flagged.setdefault(p, []).append(f"พบรูปแบบ {label} ในเนื้อไฟล์")
    return flagged


# ------------------------------------------------------------ version records
def build_changelog(history: dict) -> str:
    lines = [f"# {PROJECT} — Changelog", "", "รูปแบบเวอร์ชันตาม Semantic Versioning", ""]
    for r in history.get("versions", []):
        lines += [f"## [{r['version']}] - {r['date'][:10]}", "", r["description"], ""]
        for title, key in (("เพิ่มระบบ", "added_systems"), ("แก้ไขระบบ", "modified_systems"),
                           ("ลบระบบ", "removed_systems"), ("คำสั่งที่เพิ่ม", "commands_added"),
                           ("คำสั่งที่ลบ", "commands_removed"), ("เปลี่ยนแปลงที่ยังจำแนกไม่ได้", "unclassified")):
            if r.get(key):
                lines += [f"### {title}"] + [f"- {x}" for x in r[key]] + [""]
        f = r.get("files", {})
        for title, key in (("ไฟล์ที่เพิ่ม", "added"), ("ไฟล์ที่แก้ไข", "modified"),
                           ("ไฟล์ที่ลบ", "deleted"), ("ไฟล์ที่เปลี่ยนชื่อ/ย้าย", "renamed")):
            if f.get(key):
                lines += [f"### {title}"] + [f"- `{x}`" for x in f[key]] + [""]
        if r.get("commit"):
            lines += [f"Commit: `{r['commit'][:10]}`", ""]
    return "\n".join(lines).rstrip() + "\n"


def write_records(record: dict, branch: str) -> None:
    history = read_json(HISTORY_FILE, {"project": PROJECT, "versions": []})
    versions = [r for r in history.get("versions", []) if r.get("version") != record["version"]]
    history["versions"] = [record] + versions
    write_atomic(HISTORY_FILE, json.dumps(history, ensure_ascii=False, indent=2) + "\n")
    write_atomic(CHANGELOG_FILE, build_changelog(history))
    write_atomic(VERSION_FILE, json.dumps({
        "project": PROJECT, "repository": REPO_URL, "version": record["version"],
        "updated_at": record["date"], "branch": branch, "last_commit": record.get("commit"),
    }, ensure_ascii=False, indent=2) + "\n")


# ----------------------------------------------------------------------- main
def run(dry_run: bool) -> None:
    say(f"🌸 {PROJECT} Version Manager")
    say("=" * 50)

    if git("rev-parse", "--is-inside-work-tree", check=False).stdout.strip() != "true":
        raise Abort("โฟลเดอร์นี้ยังไม่ใช่ Git Repository (รัน `git init` และตั้ง remote origin ก่อน)")
    top = Path(git("rev-parse", "--show-toplevel").stdout.strip()).resolve()
    if top != ROOT:
        say(f"⚠️  Git root คือ {top} (ไม่ใช่โฟลเดอร์ของ save.py)")

    branch = git("rev-parse", "--abbrev-ref", "HEAD", check=False).stdout.strip()
    has_head = git("rev-parse", "--verify", "HEAD", check=False).returncode == 0
    if not has_head:
        branch = git("symbolic-ref", "--short", "HEAD", check=False).stdout.strip() or "main"
    if branch == "HEAD":
        raise Abort("อยู่ใน detached HEAD — สลับไป branch ก่อนบันทึก")

    remote = git("remote", "get-url", "origin", check=False)
    if remote.returncode != 0:
        raise Abort(f"ยังไม่ได้ตั้ง remote origin (เช่น git remote add origin {REPO_URL}.git)")
    url = remote.stdout.strip()
    if EXPECTED_REPO.lower() not in url.lower():
        say(f"⚠️  origin = {url}\n   ไม่ตรงกับ {EXPECTED_REPO}")
        if not confirm("ต้องการดำเนินการต่อกับ remote นี้?"):
            raise Abort("ยกเลิก")

    version_data = read_json(VERSION_FILE, {"version": "0.0.0"})
    current = str(version_data.get("version", "0.0.0"))
    say(f"โปรเจกต์ : {PROJECT}\nเวอร์ชันปัจจุบัน : {current}\nBranch : {branch}\nRemote : {url}\n")

    changes, conflicts = parse_status()
    if conflicts:
        raise Abort("มีไฟล์ขัดแย้ง (merge conflict): " + ", ".join(conflicts))
    changes = [c for c in pair_renames(changes, has_head) if c.path not in MANAGED]
    if not changes:
        say("ไม่พบการเปลี่ยนแปลงที่ต้องบันทึก ✅")
        return

    # .gitignore
    if (ROOT / ".env").exists() and git("check-ignore", "-q", ".env", check=False).returncode != 0:
        say("⚠️  พบไฟล์ .env แต่ยังไม่อยู่ใน .gitignore")

    analysis = analyze(changes, has_head)
    say("📋 สรุปการเปลี่ยนแปลง (จากโค้ดจริง)")
    for title, key in (("➕ ระบบที่เพิ่ม", "added_systems"), ("✏️  ระบบ/ไฟล์ที่แก้ไข", "modified_systems"),
                       ("🗑️  ระบบที่ลบ", "removed_systems"), ("🆕 คำสั่งที่เพิ่ม", "commands_added"),
                       ("❌ คำสั่งที่ลบ", "commands_removed"), ("❓ เปลี่ยนแปลงที่ยังจำแนกไม่ได้", "unclassified")):
        if analysis[key]:
            say(f"{title}: " + ", ".join(analysis[key]))
    say("\n📁 ไฟล์")
    for title, key in (("Added", "added"), ("Modified", "modified"), ("Deleted", "deleted"), ("Renamed", "renamed")):
        for f in analysis["files"][key]:
            say(f"  {title:9} {f}")

    # ตรวจความปลอดภัย
    to_check = [c.path for c in changes if c.status != "deleted"]
    flagged = security_scan(to_check)
    if flagged:
        say("\n🚨 พบไฟล์ต้องสงสัย:")
        for p, why in flagged.items():
            say(f"  {p}: " + "; ".join(why))
        say("ไฟล์เหล่านี้จะ *ไม่ถูก* ส่งขึ้น GitHub ในรอบนี้")
        if not confirm("ดำเนินการต่อโดยข้ามไฟล์เหล่านี้?"):
            raise Abort("หยุดการบันทึกเพื่อความปลอดภัย")
    staged_now = set(git("diff", "--cached", "--name-only").stdout.splitlines()) if has_head else set(git("ls-files").stdout.splitlines())
    bad_staged = [p for p in staged_now if p in flagged]
    if bad_staged:
        raise Abort("ไฟล์ต้องสงสัยถูก stage/track อยู่แล้ว: " + ", ".join(bad_staged) + " — ถอดออกจาก Git ด้วยตัวเองก่อน (git rm --cached)")

    # เวอร์ชัน
    suggested, reason = suggest_version(current, analysis)
    if not has_head:
        suggested, reason = current, "บันทึกครั้งแรกของ Repository → ใช้เวอร์ชันปัจจุบัน"
    say(f"\n💡 แนะนำเวอร์ชัน {suggested} ({reason})")
    history = read_json(HISTORY_FILE, {"project": PROJECT, "versions": []})
    existing = {r.get("version") for r in history.get("versions", [])}
    while True:
        version = ask(f"เวอร์ชันใหม่ [{suggested}]: ") or suggested
        version = version.lstrip("vV")
        if not SEMVER.match(version):
            say("❌ รูปแบบต้องเป็น MAJOR.MINOR.PATCH เช่น 1.2.0")
            continue
        if version in existing:
            say(f"⚠️  เวอร์ชัน {version} มีบันทึกอยู่แล้วในประวัติ")
            if not confirm("เขียนทับรายการประวัติของเวอร์ชันนี้? (ไม่ลบ Git commits เดิม)"):
                continue
        break
    tag = f"v{version}"
    create_tag = True
    if git("tag", "-l", tag).stdout.strip():
        say(f"⚠️  Git tag {tag} มีอยู่แล้ว — จะ *ไม่* สร้าง/ย้าย tag ให้ (จัดการเองเพื่อป้องกันความสับสนในการย้อนกลับ)")
        create_tag = False

    description = ""
    while not description:
        description = ask("รายละเอียดการอัปเดต: ")

    say(f"\nสรุป: {current} → {version} | branch {branch} | {len(changes)} ไฟล์ | tag {'สร้างใหม่' if create_tag else 'ข้าม'}")
    if dry_run:
        say("🧪 --dry-run: ยังไม่เขียนไฟล์/commit/push")
        return
    if not confirm("ยืนยัน บันทึกและ Push ขึ้น GitHub?"):
        raise Abort("ยกเลิก")

    # ตรวจสิทธิ์ push ก่อนแตะไฟล์ใด ๆ
    say("\n🔐 ตรวจสอบสิทธิ์ Push ...")
    if has_head:
        dry = git("push", "--dry-run", "origin", branch, check=False)
        if dry.returncode != 0:
            raise Abort("Push ไม่ได้ (ยังไม่มีการแก้ไขไฟล์): " + (dry.stderr or "").strip())
    else:
        if git("ls-remote", "--exit-code", "origin", check=False).returncode == 2:
            pass  # remote ว่าง — push ครั้งแรกได้
        elif git("ls-remote", "origin", check=False).returncode != 0:
            raise Abort("เข้าถึง remote origin ไม่ได้ ตรวจสอบสิทธิ์/ล็อกอิน GitHub")

    # เขียนไฟล์เวอร์ชัน (มี backup กู้คืนหากพลาด)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    record = {"version": version, "date": now, "description": description, **{k: analysis[k] for k in (
        "added_systems", "modified_systems", "removed_systems", "commands_added", "commands_removed", "unclassified", "files")},
        "commit": None}
    backups = {p: (p.read_bytes() if p.exists() else None) for p in (VERSION_FILE, HISTORY_FILE, CHANGELOG_FILE)}
    try:
        write_records(record, branch)
    except Exception as e:
        for p, data in backups.items():
            if data is None:
                p.unlink(missing_ok=True)
            else:
                p.write_bytes(data)
        raise Abort(f"บันทึกไฟล์เวอร์ชันไม่สำเร็จ (กู้คืนไฟล์เดิมแล้ว): {e}")

    # stage เฉพาะไฟล์ที่ตรวจแล้ว
    paths = set(MANAGED)
    for c in changes:
        if c.path in flagged:
            continue
        paths.add(c.path)
        if c.old_path:
            paths.add(c.old_path)
    git("add", "-A", "--", *sorted(paths))
    body = "\n".join(f"- {x}" for k in ("added_systems", "modified_systems", "removed_systems") for x in analysis[k])
    msg = ["commit", "-m", f"release: v{version} — {description}"]
    if body:
        msg += ["-m", body]
    if git(*msg, check=False).returncode != 0:
        raise Abort("commit ไม่สำเร็จ (ไฟล์เวอร์ชันถูกเขียนแล้ว ตรวจ `git status`)")
    commit = git("rev-parse", "HEAD").stdout.strip()
    say(f"✅ commit {commit[:10]}")
    if create_tag:
        git("tag", "-a", tag, "-m", f"{PROJECT} {tag}: {description}")

    # บันทึก commit hash (hash ใส่ใน commit เดียวกันไม่ได้ จึงใช้ commit ติดตามเล็ก ๆ)
    record["commit"] = commit
    write_records(record, branch)
    git("add", "--", *sorted(MANAGED))
    git("commit", "-m", f"chore(version): บันทึก commit hash ของ v{version}", check=False)

    # push + ตรวจผลจริง
    say("🚀 Push ขึ้น GitHub ...")
    push = git("push", "origin", branch, check=False)
    tag_ok = True
    if push.returncode == 0 and create_tag:
        tag_ok = git("push", "origin", tag, check=False).returncode == 0
    remote_head = ""
    if push.returncode == 0:
        remote_head = git("ls-remote", "origin", f"refs/heads/{branch}", check=False).stdout.split("\t")[0].strip()
    local_head = git("rev-parse", "HEAD").stdout.strip()

    if push.returncode == 0 and remote_head == local_head:
        say(f"\n🌸 สำเร็จ! v{version} อยู่บน GitHub แล้ว (ตรวจแล้ว {local_head[:10]})")
        if not tag_ok:
            say(f"⚠️  push tag {tag} ไม่สำเร็จ — ลอง: git push origin {tag}")
        for hook in POST_SAVE_HOOKS:
            try:
                hook(record)
            except Exception as e:  # noqa: BLE001
                say(f"⚠️  hook ผิดพลาด: {e}")
    else:
        say("\n❌ Push ไม่สำเร็จ — ข้อมูลถูกเก็บในเครื่องไว้แล้ว")
        say((push.stderr or "ไม่ทราบสาเหตุ หรือ GitHub ยังไม่ได้รับการอัปเดต").strip())
        say(f"แก้ปัญหาแล้วรัน: git push origin {branch}" + (f" && git push origin {tag}" if create_tag else ""))
        sys.exit(1)


def main() -> None:
    for s in (sys.stdout, sys.stderr, sys.stdin):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
    ap = argparse.ArgumentParser(description="KaoHorm Save / Version Manager")
    ap.add_argument("--dry-run", action="store_true", help="วิเคราะห์อย่างเดียว ไม่แก้ไข/ไม่ push")
    args = ap.parse_args()
    try:
        run(args.dry_run)
    except Abort as e:
        say(f"\n⛔ {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
