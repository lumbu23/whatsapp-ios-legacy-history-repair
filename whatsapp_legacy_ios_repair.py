#!/usr/bin/env python3
"""Repair one known legacy WhatsApp Android-to-iPhone import state.

The tool operates on encrypted Finder/iTunes backups and changes only
ZWAMESSAGE rows matching LEGACY_WHERE. Selection is independent of message
date, type, chat, sender, and direction. The original backup encryption keys
are reused, and the rewritten backup is decrypted and integrity-checked before
success is reported.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    from Crypto.Cipher import AES
except Exception as exc:  # pragma: no cover - dependency check
    print("ERROR: pycryptodome is required. Install it with: pip install pycryptodome", file=sys.stderr)
    raise SystemExit(2) from exc

APPLE_EPOCH_UNIX = 978307200
WHATSAPP_RELATIVE_PATH = "ChatStorage.sqlite"
WHATSAPP_DOMAIN_PREFIX = "AppDomainGroup-group.net.whatsapp"
WRAP_PASSCODE = 2
RFC3394_IV = 0xA6A6A6A6A6A6A6A6
ZERO_IV = b"\x00" * 16

LEGACY_WHERE = """
    ZMESSAGEERRORSTATUS IS NULL
    AND ZCHILDMESSAGESDELIVEREDCOUNT IS NULL
    AND ZCHILDMESSAGESREADCOUNT IS NULL
    AND ZCHILDMESSAGESPLAYEDCOUNT IS NULL
    AND ZENCRETRYCOUNT IS NULL
    AND ZSPOTLIGHTSTATUS IS NULL
    AND ZFILTEREDRECIPIENTCOUNT = 1
"""

PATCH_COLUMNS = {
    "ZMESSAGEERRORSTATUS": 0,
    "ZCHILDMESSAGESDELIVEREDCOUNT": 0,
    "ZCHILDMESSAGESREADCOUNT": 0,
    "ZCHILDMESSAGESPLAYEDCOUNT": 0,
    "ZENCRETRYCOUNT": 0,
    "ZFILTEREDRECIPIENTCOUNT": 0,
    "ZSPOTLIGHTSTATUS": -32768,
}

REQUIRED_MESSAGE_COLUMNS = {
    "Z_PK",
    "ZMESSAGEDATE",
    "ZMESSAGETYPE",
    *PATCH_COLUMNS.keys(),
}


class RepairError(RuntimeError):
    pass


def eprint(*args: Any, **kwargs: Any) -> None:
    print(*args, file=sys.stderr, **kwargs)


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0 or unit == "TiB":
            return f"{value:.2f} {unit}"
        value /= 1024.0
    return f"{n} B"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def aes_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 16:
        raise RepairError(f"Encrypted data length {len(data)} is not AES-block aligned")
    return AES.new(key, AES.MODE_CBC, iv=ZERO_IV).decrypt(data)


def aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv=ZERO_IV).encrypt(pkcs7_pad(data, 16))


def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES key unwrap."""
    if len(wrapped) < 24 or len(wrapped) % 8:
        raise RepairError(f"Invalid wrapped-key length: {len(wrapped)}")
    c = [int.from_bytes(wrapped[i : i + 8], "big") for i in range(0, len(wrapped), 8)]
    n = len(c) - 1
    a = c[0]
    r = [0] + c[1:]
    cipher = AES.new(kek, AES.MODE_ECB)
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = n * j + i
            block = (a ^ t).to_bytes(8, "big") + r[i].to_bytes(8, "big")
            b = cipher.decrypt(block)
            a = int.from_bytes(b[:8], "big")
            r[i] = int.from_bytes(b[8:], "big")
    if a != RFC3394_IV:
        raise RepairError("AES key unwrap integrity check failed (wrong backup password/key?)")
    return b"".join(x.to_bytes(8, "big") for x in r[1:])


def iter_tlv(blob: bytes) -> Iterable[tuple[bytes, bytes]]:
    pos = 0
    while pos + 8 <= len(blob):
        tag = blob[pos : pos + 4]
        length = struct.unpack(">I", blob[pos + 4 : pos + 8])[0]
        end = pos + 8 + length
        if end > len(blob):
            raise RepairError("Malformed BackupKeyBag TLV")
        yield tag, blob[pos + 8 : end]
        pos = end
    if pos != len(blob):
        raise RepairError("Trailing bytes in BackupKeyBag TLV")


def tlv_value(value: bytes) -> Any:
    if len(value) == 4:
        return struct.unpack(">I", value)[0]
    return value


@dataclass
class Keybag:
    attrs: dict[bytes, Any]
    class_keys: dict[int, dict[bytes, Any]]

    @classmethod
    def parse(cls, blob: bytes) -> "Keybag":
        attrs: dict[bytes, Any] = {}
        class_keys: dict[int, dict[bytes, Any]] = {}
        current: dict[bytes, Any] | None = None
        global_uuid_seen = False

        def close_current() -> None:
            nonlocal current
            if current is None:
                return
            if b"CLAS" not in current:
                raise RepairError("Keybag class record missing CLAS")
            raw = int(current[b"CLAS"])
            class_keys[raw] = current
            # Some historical implementations mask class flags to the low nibble.
            class_keys.setdefault(raw & 0xF, current)
            current = None

        for tag, raw_value in iter_tlv(blob):
            value = tlv_value(raw_value)
            if tag == b"UUID" and not global_uuid_seen:
                attrs[tag] = raw_value
                global_uuid_seen = True
            elif tag == b"UUID":
                close_current()
                current = {b"UUID": raw_value}
            elif current is not None and tag in {b"CLAS", b"WRAP", b"WPKY", b"KTYP", b"PBKY"}:
                current[tag] = value
            else:
                attrs[tag] = value
        close_current()
        return cls(attrs=attrs, class_keys=class_keys)

    def unlock(self, password: str) -> None:
        passcode = password.encode("utf-8")
        if b"DPSL" in self.attrs and b"DPIC" in self.attrs:
            intermediate = hashlib.pbkdf2_hmac(
                "sha256",
                passcode,
                bytes(self.attrs[b"DPSL"]),
                int(self.attrs[b"DPIC"]),
                dklen=32,
            )
        else:
            intermediate = passcode
        if b"SALT" not in self.attrs or b"ITER" not in self.attrs:
            raise RepairError("Backup keybag is missing SALT/ITER")
        kek = hashlib.pbkdf2_hmac(
            "sha1",
            intermediate,
            bytes(self.attrs[b"SALT"]),
            int(self.attrs[b"ITER"]),
            dklen=32,
        )
        unlocked = 0
        # Avoid processing aliases twice.
        seen_ids: set[int] = set()
        for record in self.class_keys.values():
            rid = id(record)
            if rid in seen_ids:
                continue
            seen_ids.add(rid)
            if b"WPKY" not in record:
                continue
            wrap = int(record.get(b"WRAP", 0))
            if not (wrap & WRAP_PASSCODE):
                continue
            wrapped = bytes(record[b"WPKY"])
            record[b"KEY"] = aes_unwrap(kek, wrapped)
            unlocked += 1
        if unlocked == 0:
            raise RepairError("No passcode-wrapped class keys could be unlocked")

    def unwrap_for_class(self, protection_class: int, wrapped: bytes) -> bytes:
        record = self.class_keys.get(protection_class) or self.class_keys.get(protection_class & 0xF)
        if not record or b"KEY" not in record:
            raise RepairError(f"No unlocked key for protection class {protection_class}")
        return aes_unwrap(bytes(record[b"KEY"]), wrapped)


@dataclass
class MBFileRecord:
    archive: Any
    root: dict[str, Any]
    objects: list[Any] | None

    def _uid_index(self, value: Any) -> int | None:
        if isinstance(value, plistlib.UID):
            return value.data
        return None

    def resolve(self, value: Any) -> Any:
        idx = self._uid_index(value)
        if idx is not None:
            if self.objects is None or not 0 <= idx < len(self.objects):
                raise RepairError(f"Invalid NSKeyedArchiver UID {idx}")
            return self.objects[idx]
        return value

    def get_data(self, value: Any) -> bytes:
        obj = self.resolve(value)
        if isinstance(obj, (bytes, bytearray)):
            return bytes(obj)
        if isinstance(obj, dict):
            for key in ("NS.data", "NS.bytes", "data"):
                if key in obj:
                    return self.get_data(obj[key])
        raise RepairError(f"Could not resolve NSData value of type {type(obj).__name__}")

    def set_data(self, key: str, data: bytes) -> None:
        if key not in self.root:
            return
        value = self.root[key]
        idx = self._uid_index(value)
        if idx is None:
            if isinstance(value, (bytes, bytearray)):
                self.root[key] = data
                return
            if isinstance(value, dict):
                for nested in ("NS.data", "NS.bytes", "data"):
                    if nested in value:
                        value[nested] = data
                        return
            raise RepairError(f"Unsupported {key} representation")
        if self.objects is None:
            raise RepairError(f"Cannot resolve {key} UID")
        target = self.objects[idx]
        if isinstance(target, (bytes, bytearray)):
            self.objects[idx] = data
            return
        if isinstance(target, dict):
            for nested in ("NS.data", "NS.bytes", "data"):
                if nested in target:
                    target[nested] = data
                    return
        raise RepairError(f"Unsupported referenced {key} representation")

    @property
    def size(self) -> int:
        return int(self.root["Size"])

    @size.setter
    def size(self, value: int) -> None:
        self.root["Size"] = int(value)

    @property
    def protection_class(self) -> int:
        return int(self.root["ProtectionClass"])

    @property
    def wrapped_file_key(self) -> bytes:
        raw = self.get_data(self.root["EncryptionKey"])
        if len(raw) < 44:
            raise RepairError(f"Unexpected EncryptionKey length: {len(raw)}")
        encoded_class = struct.unpack("<I", raw[:4])[0]
        if encoded_class != self.protection_class:
            raise RepairError(
                f"ProtectionClass mismatch: record={self.protection_class}, key={encoded_class}"
            )
        wrapped = raw[4:]
        if len(wrapped) != 40:
            raise RepairError(f"Expected 40-byte wrapped file key, got {len(wrapped)}")
        return wrapped

    def update_digest_if_present(self, digest: bytes) -> None:
        if "Digest" in self.root:
            self.set_data("Digest", digest)

    def dumps(self) -> bytes:
        return plistlib.dumps(self.archive, fmt=plistlib.FMT_BINARY, sort_keys=False)


def load_mbfile_record(blob: bytes) -> MBFileRecord:
    archive = plistlib.loads(blob)
    if isinstance(archive, dict) and "$objects" in archive and "$top" in archive:
        objects = archive["$objects"]
        top = archive["$top"]
        if not isinstance(objects, list) or not isinstance(top, dict):
            raise RepairError("Malformed NSKeyedArchiver file record")
        root_ref = top.get("root")
        if isinstance(root_ref, plistlib.UID):
            root = objects[root_ref.data]
        else:
            root = root_ref
        if not isinstance(root, dict) or "Size" not in root:
            # Locate MBFile metadata in alternate keyed-archive layouts.
            root = next(
                (
                    x
                    for x in objects
                    if isinstance(x, dict)
                    and "Size" in x
                    and "ProtectionClass" in x
                    and "EncryptionKey" in x
                ),
                None,
            )
        if not isinstance(root, dict):
            raise RepairError("Could not locate MBFile root object")
        return MBFileRecord(archive=archive, root=root, objects=objects)
    if isinstance(archive, dict):
        if not {"Size", "ProtectionClass", "EncryptionKey"}.issubset(archive):
            raise RepairError("Manifest file record is missing encryption metadata")
        return MBFileRecord(archive=archive, root=archive, objects=None)
    raise RepairError("Unsupported Manifest file record format")


def sqlite_actual_size(data: bytes) -> int:
    if not data.startswith(b"SQLite format 3\x00") or len(data) < 100:
        raise RepairError("Decrypted data does not look like SQLite")
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1:
        page_size = 65536
    page_count = int.from_bytes(data[28:32], "big")
    if page_size < 512 or page_size > 65536 or page_count <= 0:
        raise RepairError("Invalid SQLite header after decryption")
    size = page_size * page_count
    if size > len(data):
        raise RepairError(
            f"SQLite header implies {size} bytes but decrypted payload has only {len(data)}"
        )
    return size


def decrypt_sqlite_blob(encrypted: bytes, key: bytes, expected_size: int | None = None) -> bytes:
    # Manifest Size can be stale; SQLite page_size * page_count is authoritative.
    plain = aes_cbc_decrypt(encrypted, key)
    actual_size = sqlite_actual_size(plain)

    if expected_size is not None and expected_size != actual_size:
        eprint(
            "WARNING: Manifest records SQLite size "
            f"{expected_size:,} bytes, but the decrypted SQLite header "
            f"defines {actual_size:,} bytes; using the SQLite size."
        )

    return plain[:actual_size]

def default_backup_roots() -> list[Path]:
    roots: list[Path] = []
    home = Path.home()
    if sys.platform == "darwin":
        roots.append(home / "Library/Application Support/MobileSync/Backup")
    elif os.name == "nt":
        for env_name, suffix in (
            ("APPDATA", Path("Apple Computer/MobileSync/Backup")),
            ("USERPROFILE", Path("Apple/MobileSync/Backup")),
        ):
            base = os.environ.get(env_name)
            if base:
                roots.append(Path(base) / suffix)
    return roots


def read_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        obj = plistlib.load(f)
    if not isinstance(obj, dict):
        raise RepairError(f"Expected dictionary plist: {path}")
    return obj


def list_backups(root: Path | None) -> int:
    roots = [root] if root else default_backup_roots()
    found = 0
    for backup_root in roots:
        if backup_root is None or not backup_root.exists():
            continue
        print(f"Backup root: {backup_root}")
        for d in sorted((p for p in backup_root.iterdir() if p.is_dir()), key=lambda p: p.name):
            info_path = d / "Info.plist"
            manifest_path = d / "Manifest.plist"
            if not info_path.exists() or not manifest_path.exists():
                continue
            try:
                info = read_plist(info_path)
                manifest = read_plist(manifest_path)
            except Exception as exc:
                print(f"  {d.name}: unreadable metadata ({exc})")
                continue
            found += 1
            print(f"  Path:       {d}")
            print(f"  Device:     {info.get('Device Name', info.get('Display Name', '?'))}")
            print(f"  iOS:        {info.get('Product Version', '?')}")
            print(f"  LastBackup: {info.get('Last Backup Date', '?')}")
            print(f"  Encrypted:  {bool(manifest.get('IsEncrypted'))}")
            print()
    if not found:
        eprint("No Finder/iTunes backups found.")
        return 1
    return 0


@dataclass
class BackupContext:
    backup_dir: Path
    keybag: Keybag
    manifest_key: bytes
    workdir: Path
    manifest_plain_path: Path


def ensure_backup_quiescent(backup_dir: Path) -> None:
    if not backup_dir.is_dir():
        raise RepairError(f"Backup directory does not exist: {backup_dir}")
    for required in ("Manifest.plist", "Manifest.db", "Info.plist"):
        if not (backup_dir / required).exists():
            raise RepairError(f"Missing {required}; not a complete Finder/iTunes backup")
    for sidecar in ("Manifest.db-wal", "Manifest.db-shm"):
        if (backup_dir / sidecar).exists():
            raise RepairError(
                f"{sidecar} exists. Refusing to modify a possibly active/uncheckpointed backup. "
                "Quit backup/restore software and make a fresh completed backup first."
            )


def unlock_backup(backup_dir: Path, password: str, workdir: Path) -> BackupContext:
    ensure_backup_quiescent(backup_dir)
    manifest = read_plist(backup_dir / "Manifest.plist")
    if not manifest.get("IsEncrypted"):
        raise RepairError(
            "This script currently requires an encrypted Finder/iTunes backup. "
            "Create a new encrypted local backup with a known password."
        )
    if "BackupKeyBag" not in manifest or "ManifestKey" not in manifest:
        raise RepairError("Encrypted backup is missing BackupKeyBag/ManifestKey")

    keybag = Keybag.parse(bytes(manifest["BackupKeyBag"]))
    keybag.unlock(password)
    manifest_key_blob = bytes(manifest["ManifestKey"])
    if len(manifest_key_blob) < 44:
        raise RepairError("Unexpected ManifestKey length")
    manifest_class = struct.unpack("<I", manifest_key_blob[:4])[0]
    manifest_key = keybag.unwrap_for_class(manifest_class, manifest_key_blob[4:])

    encrypted_manifest = (backup_dir / "Manifest.db").read_bytes()
    manifest_plain = decrypt_sqlite_blob(encrypted_manifest, manifest_key)
    manifest_plain_path = workdir / "Manifest.decrypted.db"
    manifest_plain_path.write_bytes(manifest_plain)

    with sqlite3.connect(manifest_plain_path) as db:
        result = db.execute("PRAGMA quick_check").fetchone()
        if not result or result[0] != "ok":
            raise RepairError(f"Decrypted Manifest.db quick_check failed: {result}")

    return BackupContext(
        backup_dir=backup_dir,
        keybag=keybag,
        manifest_key=manifest_key,
        workdir=workdir,
        manifest_plain_path=manifest_plain_path,
    )


@dataclass
class WhatsAppFile:
    file_id: str
    domain: str
    relative_path: str
    metadata: MBFileRecord
    file_key: bytes
    encrypted_path: Path
    plain_path: Path


def locate_whatsapp(ctx: BackupContext) -> WhatsAppFile:
    with sqlite3.connect(ctx.manifest_plain_path) as db:
        rows = db.execute(
            """
            SELECT fileID, domain, relativePath, file
            FROM Files
            WHERE relativePath = ?
              AND domain LIKE ?
              AND flags = 1
            ORDER BY domain
            """,
            (WHATSAPP_RELATIVE_PATH, WHATSAPP_DOMAIN_PREFIX + "%"),
        ).fetchall()
    if not rows:
        # Report alternate ChatStorage entries without selecting one automatically.
        with sqlite3.connect(ctx.manifest_plain_path) as db:
            nearby = db.execute(
                "SELECT fileID, domain, relativePath FROM Files WHERE relativePath LIKE '%ChatStorage.sqlite%'"
            ).fetchall()
        detail = "\n".join(f"  {r}" for r in nearby) if nearby else "  none"
        raise RepairError(f"WhatsApp ChatStorage.sqlite not found. Similar entries:\n{detail}")
    if len(rows) != 1:
        detail = "\n".join(f"  {r[0]}  {r[1]}  {r[2]}" for r in rows)
        raise RepairError(f"Multiple WhatsApp ChatStorage candidates; refusing to guess:\n{detail}")

    file_id, domain, relative_path, metadata_blob = rows[0]
    metadata = load_mbfile_record(bytes(metadata_blob))
    file_key = ctx.keybag.unwrap_for_class(metadata.protection_class, metadata.wrapped_file_key)
    encrypted_path = ctx.backup_dir / file_id[:2] / file_id
    if not encrypted_path.exists():
        raise RepairError(f"Manifest points to missing backup blob: {encrypted_path}")

    encrypted = encrypted_path.read_bytes()
    plain = decrypt_sqlite_blob(encrypted, file_key, metadata.size)
    plain_path = ctx.workdir / "ChatStorage.sqlite"
    plain_path.write_bytes(plain)

    return WhatsAppFile(
        file_id=file_id,
        domain=domain,
        relative_path=relative_path,
        metadata=metadata,
        file_key=file_key,
        encrypted_path=encrypted_path,
        plain_path=plain_path,
    )


def check_chat_schema(db: sqlite3.Connection) -> None:
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if "ZWAMESSAGE" not in tables:
        raise RepairError("ChatStorage.sqlite does not contain ZWAMESSAGE")
    columns = {r[1] for r in db.execute("PRAGMA table_info(ZWAMESSAGE)")}
    missing = sorted(REQUIRED_MESSAGE_COLUMNS - columns)
    if missing:
        raise RepairError(
            "WhatsApp schema differs from the tested repair schema; refusing to patch. "
            f"Missing columns: {', '.join(missing)}"
        )


def apple_ts_to_iso(value: float | None) -> str:
    if value is None:
        return "NULL"
    return datetime.fromtimestamp(float(value) + APPLE_EPOCH_UNIX, tz=timezone.utc).isoformat()


def get_chat_stats(chat_path: Path) -> dict[str, Any]:
    with sqlite3.connect(chat_path) as db:
        check_chat_schema(db)
        qc = db.execute("PRAGMA integrity_check").fetchone()
        if not qc or qc[0] != "ok":
            raise RepairError(f"ChatStorage.sqlite integrity_check failed: {qc}")

        total = db.execute("SELECT COUNT(*) FROM ZWAMESSAGE").fetchone()[0]
        legacy_total = db.execute(f"SELECT COUNT(*) FROM ZWAMESSAGE WHERE {LEGACY_WHERE}").fetchone()[0]
        date_range = db.execute(
            f"SELECT MIN(ZMESSAGEDATE), MAX(ZMESSAGEDATE) FROM ZWAMESSAGE WHERE {LEGACY_WHERE}"
        ).fetchone()
        by_type = db.execute(
            f"""
            SELECT ZMESSAGETYPE, COUNT(*)
            FROM ZWAMESSAGE
            WHERE {LEGACY_WHERE}
            GROUP BY ZMESSAGETYPE
            ORDER BY ZMESSAGETYPE
            """
        ).fetchall()
        null_dates = db.execute(
            f"SELECT COUNT(*) FROM ZWAMESSAGE WHERE ({LEGACY_WHERE}) AND ZMESSAGEDATE IS NULL"
        ).fetchone()[0]

        return {
            "total": total,
            "legacy_total": legacy_total,
            "legacy_min": date_range[0],
            "legacy_max": date_range[1],
            "by_type": by_type,
            "legacy_null_dates": null_dates,
        }


def print_stats(stats: dict[str, Any]) -> None:
    print(f"ZWAMESSAGE rows:                  {stats['total']:,}")
    print(f"Exact legacy-signature rows:      {stats['legacy_total']:,}")
    print(f"Matching rows with NULL date:     {stats['legacy_null_dates']:,}")
    print(
        "Legacy-signature date range (UTC): "
        f"{apple_ts_to_iso(stats['legacy_min'])} .. {apple_ts_to_iso(stats['legacy_max'])}"
    )
    print("Matching rows by message type:")
    for msg_type, count in stats["by_type"]:
        print(f"  type {msg_type:>3}: {count:,}")


def patch_chat_storage(chat_path: Path) -> tuple[int, int]:
    # Keep committed changes in the main SQLite file, not an untracked WAL.
    with sqlite3.connect(chat_path) as db:
        check_chat_schema(db)
        mode_row = db.execute("PRAGMA journal_mode").fetchone()
        journal_mode = str(mode_row[0]).lower() if mode_row else "unknown"
        db.execute("PRAGMA synchronous=FULL")
        before = db.execute(
            f"SELECT COUNT(*) FROM ZWAMESSAGE WHERE {LEGACY_WHERE}"
        ).fetchone()[0]
        if before <= 0:
            raise RepairError("No rows match the exact legacy signature; nothing to patch")
        db.execute("BEGIN IMMEDIATE")
        db.execute(
            f"""
            UPDATE ZWAMESSAGE
            SET ZMESSAGEERRORSTATUS = 0,
                ZCHILDMESSAGESDELIVEREDCOUNT = 0,
                ZCHILDMESSAGESREADCOUNT = 0,
                ZCHILDMESSAGESPLAYEDCOUNT = 0,
                ZENCRETRYCOUNT = 0,
                ZFILTEREDRECIPIENTCOUNT = 0,
                ZSPOTLIGHTSTATUS = -32768
            WHERE {LEGACY_WHERE}
            """
        )
        changed = db.execute("SELECT changes()").fetchone()[0]
        db.commit()
        if journal_mode == "wal":
            checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            # SQLite returns (busy, log_frames, checkpointed_frames).
            if checkpoint and int(checkpoint[0]) != 0:
                raise RepairError(f"WAL checkpoint remained busy: {checkpoint}")
        if changed != before:
            raise RepairError(f"SQLite changed {changed} rows, expected {before}")
        remaining = db.execute(
            f"SELECT COUNT(*) FROM ZWAMESSAGE WHERE {LEGACY_WHERE}"
        ).fetchone()[0]
        qc = db.execute("PRAGMA integrity_check").fetchone()
        if not qc or qc[0] != "ok":
            raise RepairError(f"Patched ChatStorage integrity_check failed: {qc}")
        if remaining != 0:
            raise RepairError(f"{remaining} exact-signature rows remain after patch")
    # WAL/journal data must be empty before encrypting the main database file.
    # The SHM file is only a transient WAL index and can be discarded here.
    for suffix in ("-wal", "-journal"):
        sidecar = Path(str(chat_path) + suffix)
        if sidecar.exists() and sidecar.stat().st_size:
            raise RepairError(f"Unexpected SQLite sidecar remains after patch: {sidecar}")
        sidecar.unlink(missing_ok=True)

    shm = Path(str(chat_path) + "-shm")
    shm.unlink(missing_ok=True)

    return before, changed


def update_manifest_file_record(
    manifest_plain_path: Path,
    file_id: str,
    metadata: MBFileRecord,
    plain_size: int,
    encrypted_digest: bytes,
) -> None:
    metadata.size = plain_size
    metadata.update_digest_if_present(encrypted_digest)
    new_blob = metadata.dumps()
    with sqlite3.connect(manifest_plain_path) as db:
        mode_row = db.execute("PRAGMA journal_mode").fetchone()
        journal_mode = str(mode_row[0]).lower() if mode_row else "unknown"
        db.execute("UPDATE Files SET file = ? WHERE fileID = ?", (new_blob, file_id))
        changed = db.execute("SELECT changes()").fetchone()[0]
        if changed != 1:
            raise RepairError(f"Manifest Files update affected {changed} rows, expected 1")
        db.commit()
        if journal_mode == "wal":
            checkpoint = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint and int(checkpoint[0]) != 0:
                raise RepairError(f"Manifest WAL checkpoint remained busy: {checkpoint}")
        qc = db.execute("PRAGMA integrity_check").fetchone()
        if not qc or qc[0] != "ok":
            raise RepairError(f"Modified Manifest.db integrity_check failed: {qc}")


def make_snapshot(ctx: BackupContext, wa: WhatsAppFile, snapshot_root: Path | None) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = snapshot_root or (ctx.backup_dir.parent / "whatsapp-legacy-repair-snapshots")
    snap = base / f"{ctx.backup_dir.name}-{timestamp}"
    snap.mkdir(parents=True, exist_ok=False)
    shutil.copy2(ctx.backup_dir / "Manifest.db", snap / "Manifest.db")
    shutil.copy2(ctx.backup_dir / "Manifest.plist", snap / "Manifest.plist")
    shutil.copy2(wa.encrypted_path, snap / wa.file_id)
    (snap / "README.txt").write_text(
        "Critical-file rollback snapshot created before WhatsApp legacy-history repair.\n"
        f"Backup: {ctx.backup_dir}\n"
        f"WhatsApp fileID: {wa.file_id}\n"
        f"WhatsApp blob SHA256: {sha256_file(snap / wa.file_id)}\n",
        encoding="utf-8",
    )
    return snap


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".repair-tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def reencrypt_and_commit(
    ctx: BackupContext,
    wa: WhatsAppFile,
    snapshot_root: Path | None,
) -> tuple[Path, str]:
    patched_plain = wa.plain_path.read_bytes()
    encrypted_wa = aes_cbc_encrypt(patched_plain, wa.file_key)
    digest = hashlib.sha1(encrypted_wa).digest()
    update_manifest_file_record(
        ctx.manifest_plain_path,
        wa.file_id,
        wa.metadata,
        len(patched_plain),
        digest,
    )
    manifest_plain = ctx.manifest_plain_path.read_bytes()
    # Exclude decrypted padding/trailing bytes before re-encryption.
    manifest_plain = manifest_plain[: sqlite_actual_size(manifest_plain)]
    encrypted_manifest = aes_cbc_encrypt(manifest_plain, ctx.manifest_key)

    snapshot = make_snapshot(ctx, wa, snapshot_root)
    # Install the data file before the manifest that describes it.
    atomic_write(wa.encrypted_path, encrypted_wa)
    atomic_write(ctx.backup_dir / "Manifest.db", encrypted_manifest)
    return snapshot, hashlib.sha256(encrypted_wa).hexdigest()


def verify_on_disk(
    backup_dir: Path,
    password: str,
    work_parent: Path | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="wa-legacy-verify-", dir=work_parent) as tmp:
        ctx = unlock_backup(backup_dir, password, Path(tmp))
        wa = locate_whatsapp(ctx)
        with sqlite3.connect(wa.plain_path) as db:
            qc = db.execute("PRAGMA integrity_check").fetchone()
            remaining = db.execute(
                f"SELECT COUNT(*) FROM ZWAMESSAGE WHERE {LEGACY_WHERE}"
            ).fetchone()[0]
        return {
            "integrity": qc[0] if qc else None,
            "remaining": remaining,
            "sha256": sha256_file(wa.encrypted_path),
            "file_id": wa.file_id,
        }


def resolve_password(args: argparse.Namespace) -> str:
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            raise RepairError(f"Environment variable {args.password_env!r} is not set")
        return value
    return getpass.getpass("Encrypted backup password: ")


def make_work_parent(args: argparse.Namespace) -> Path | None:
    if args.work_dir:
        path = Path(args.work_dir).expanduser().resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path
    return None


def run_diagnose(args: argparse.Namespace) -> int:
    backup_dir = Path(args.backup).expanduser().resolve()
    password = resolve_password(args)
    work_parent = make_work_parent(args)

    with tempfile.TemporaryDirectory(prefix="wa-legacy-diagnose-", dir=work_parent) as tmp:
        ctx = unlock_backup(backup_dir, password, Path(tmp))
        wa = locate_whatsapp(ctx)
        info = read_plist(backup_dir / "Info.plist")
        print(f"Backup:      {backup_dir}")
        print(f"Device:      {info.get('Device Name', info.get('Display Name', '?'))}")
        print(f"Last backup: {info.get('Last Backup Date', '?')}")
        print(f"WhatsApp:    {wa.domain}/{wa.relative_path}")
        print(f"fileID:      {wa.file_id}")
        print(f"Blob SHA256: {sha256_file(wa.encrypted_path)}")
        print(f"Plain size:  {human_bytes(wa.plain_path.stat().st_size)}")
        print()
        stats = get_chat_stats(wa.plain_path)
        print_stats(stats)
        print()
        candidates = stats["legacy_total"]
        if candidates == 0:
            print("No exact legacy-signature rows exist. This repair has nothing to change.")
        else:
            print(f"If applied, exactly {candidates:,} rows would be changed.")
            print("Selection is based only on the exact seven-field signature, regardless of date/type.")
    return 0


def run_apply(args: argparse.Namespace) -> int:
    backup_dir = Path(args.backup).expanduser().resolve()
    password = resolve_password(args)
    work_parent = make_work_parent(args)

    with tempfile.TemporaryDirectory(prefix="wa-legacy-apply-", dir=work_parent) as tmp:
        ctx = unlock_backup(backup_dir, password, Path(tmp))
        wa = locate_whatsapp(ctx)
        before_stats = get_chat_stats(wa.plain_path)
        print_stats(before_stats)
        candidates = before_stats["legacy_total"]
        if candidates <= 0:
            raise RepairError("No rows match the exact legacy signature")

        print()
        print("EXACT-SIGNATURE PATCH PLAN")
        print(f"  Backup:     {backup_dir}")
        print(f"  ChatStorage fileID: {wa.file_id}")
        print(f"  Rows:       {candidates:,}")
        print("  Selector:   exact seven-field legacy signature only")
        print("  Date filter: none")
        print("  Type filter: none")
        print("  Media DB:   not modified")
        print("  Search DB:  not modified")
        print()

        if not args.yes:
            answer = input("Type PATCH to continue: ").strip()
            if answer != "PATCH":
                print("Aborted; backup not modified.")
                return 1

        expected, changed = patch_chat_storage(wa.plain_path)
        if expected != candidates or changed != candidates:
            raise RepairError("Candidate count changed unexpectedly during patch")

        snapshot_root = Path(args.snapshot_dir).expanduser().resolve() if args.snapshot_dir else None
        snapshot, new_hash = reencrypt_and_commit(ctx, wa, snapshot_root)
        print()
        print(f"Snapshot: {snapshot}")
        print(f"Patched encrypted ChatStorage SHA256: {new_hash}")

    # Verify the completed encrypted backup through a fresh decrypt.
    verify = verify_on_disk(backup_dir, password, work_parent)
    if verify["integrity"] != "ok" or verify["remaining"] != 0:
        raise RepairError(f"Fresh decrypt verification failed: {verify}")
    print("Fresh decrypt verification: integrity_check = ok")
    print("Exact legacy-signature rows remaining: 0")
    print(f"Verified encrypted blob SHA256: {verify['sha256']}")
    print()
    print("SUCCESS. The Finder/iTunes backup is patched and can now be restored to the iPhone.")
    print("Do not delete the rollback snapshot. After restore, verify old text, old media, reply navigation, and search.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Diagnose and repair one exact legacy WhatsApp imported-message state."
    )
    sub = p.add_subparsers(dest="command", required=True)

    lp = sub.add_parser("list-backups", help="List local Finder/iTunes backups without decrypting them")
    lp.add_argument("--root", help="Backup root; otherwise use the platform default")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--backup", required=True, help="Path to one device-specific Finder/iTunes backup directory")
        sp.add_argument(
            "--password-env",
            help="Read encrypted-backup password from this environment variable; otherwise prompt securely",
        )
        sp.add_argument("--work-dir", help="Optional parent directory for temporary decrypted files")

    dp = sub.add_parser("diagnose", help="Decrypt read-only temp copies and report the legacy signature")
    add_common(dp)

    ap = sub.add_parser("apply", help="Patch all exact-signature rows in the encrypted backup")
    add_common(ap)
    ap.add_argument("--snapshot-dir", help="Directory in which to keep critical encrypted rollback snapshots")
    ap.add_argument("--yes", action="store_true", help="Skip typing PATCH at the destructive confirmation")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.command == "list-backups":
            root = Path(args.root).expanduser().resolve() if args.root else None
            return list_backups(root)
        if args.command == "diagnose":
            return run_diagnose(args)
        if args.command == "apply":
            return run_apply(args)
        parser.error("unknown command")
    except RepairError as exc:
        eprint(f"ERROR: {exc}")
        return 2
    except KeyboardInterrupt:
        eprint("Interrupted.")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
