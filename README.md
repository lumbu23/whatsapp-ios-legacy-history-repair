# WhatsApp iOS Legacy History Repair

Repair one specific legacy WhatsApp Android-to-iPhone import state where messages still exist in `ChatStorage.sqlite` but no longer display or resolve correctly in current WhatsApp versions.

The tool edits an **encrypted Finder/iTunes iPhone backup**, not the live phone. It only changes rows matching the exact seven-field state documented below.

> Keep an untouched backup before using this. This is not a general WhatsApp database repair utility.

## Known affected row state

The original affected backup contained `ZWAMESSAGE` rows matching all seven conditions:

```sql
ZMESSAGEERRORSTATUS IS NULL
AND ZCHILDMESSAGESDELIVEREDCOUNT IS NULL
AND ZCHILDMESSAGESREADCOUNT IS NULL
AND ZCHILDMESSAGESPLAYEDCOUNT IS NULL
AND ZENCRETRYCOUNT IS NULL
AND ZFILTEREDRECIPIENTCOUNT = 1
AND ZSPOTLIGHTSTATUS IS NULL
```

The repair changes only those fields:

| Column | Before | After |
|---|---:|---:|
| `ZMESSAGEERRORSTATUS` | `NULL` | `0` |
| `ZCHILDMESSAGESDELIVEREDCOUNT` | `NULL` | `0` |
| `ZCHILDMESSAGESREADCOUNT` | `NULL` | `0` |
| `ZCHILDMESSAGESPLAYEDCOUNT` | `NULL` | `0` |
| `ZENCRETRYCOUNT` | `NULL` | `0` |
| `ZFILTEREDRECIPIENTCOUNT` | `1` | `0` |
| `ZSPOTLIGHTSTATUS` | `NULL` | `-32768` |

Selection is based only on that row state. There is no date, chat, sender, direction, or message-type filter.

This signature was observed in one affected migration and should not be assumed to be universal.

## What it does not change

The script does not modify message text, timestamps, message status, sort order, chat/session relationships, stanza IDs, `Z_OPT`, media records, media paths, message-info blobs, or WhatsApp's search database.

Media message rows matching the signature are repaired. Missing photo, video, audio, or document payload files are not recreated.

## Requirements

- Python 3.9+
- `pycryptodome`
- an **encrypted** local Finder/iTunes backup
- the password for that backup

The repair path has been tested on macOS. Backup discovery includes common Windows locations, but that platform is less tested.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 1. Make a fresh encrypted backup

Create a complete encrypted Finder/iTunes backup and wait for it to finish before running the tool.

Typical macOS location:

```text
~/Library/Application Support/MobileSync/Backup/<DEVICE-ID>
```

If `MobileSync/Backup` is a symlink or your backups live elsewhere, pass the real device-specific directory to `--backup`.

Do not run the repair while Finder, iTunes, or Apple Devices is creating or restoring the same backup.

## 2. List backups

```bash
python whatsapp_legacy_ios_repair.py list-backups
```

Custom backup root:

```bash
python whatsapp_legacy_ios_repair.py list-backups \
  --root "/path/to/MobileSync/Backup"
```

## 3. Diagnose

Diagnosis decrypts temporary copies and does not modify the backup:

```bash
python whatsapp_legacy_ios_repair.py diagnose \
  --backup "/path/to/MobileSync/Backup/<device-id>"
```

The report includes:

- WhatsApp `ChatStorage.sqlite` file ID and encrypted SHA-256
- actual decrypted SQLite size
- full SQLite integrity status
- total `ZWAMESSAGE` row count
- exact-signature row count
- matching date range
- matching rows by message type

If the exact-signature count is zero, the tool has nothing to repair.

## 4. Apply

After reviewing the diagnosis:

```bash
python whatsapp_legacy_ios_repair.py apply \
  --backup "/path/to/device-backup" \
  --snapshot-dir "/path/to/rollback-snapshots"
```

Without `--yes`, the script requires typing:

```text
PATCH
```

before any write-back.

The apply path:

1. decrypts `Manifest.db` into a temporary workspace;
2. locates exactly one WhatsApp `ChatStorage.sqlite` from the manifest;
3. unwraps its original per-file encryption key;
4. decrypts ChatStorage and requires `PRAGMA integrity_check = ok`;
5. patches every row matching the exact seven-field state;
6. verifies the expected row count changed and zero matches remain;
7. checkpoints SQLite and refuses to continue if committed data remains in a WAL or rollback journal;
8. snapshots the original encrypted ChatStorage blob, `Manifest.db`, and `Manifest.plist`;
9. re-encrypts ChatStorage with its original file key;
10. updates the corresponding Manifest file metadata, including size and digest when present;
11. re-encrypts `Manifest.db` with its original Manifest key;
12. atomically replaces the encrypted files;
13. reopens the finished backup, decrypts it again, and verifies SQLite integrity and zero remaining matches.

## Stale Manifest sizes

Finder/iTunes backups can contain a stale `Size` value for a SQLite file after an app compacts or replaces the database.

The script derives the logical SQLite size from the database header (`page_size × page_count`) and verifies that the complete page range exists in the decrypted payload. If the Manifest size disagrees, it warns and uses the SQLite size. A successful write-back updates the Manifest to the actual repaired database size.

## 5. Verify again

Run diagnosis against the modified backup:

```bash
python whatsapp_legacy_ios_repair.py diagnose \
  --backup "/path/to/device-backup"
```

The important result is:

```text
Exact legacy-signature rows:      0
```

## 6. Restore

In Finder, select the iPhone and choose **Restore Backup…** using the patched backup.

Do not confuse **Restore Backup…** with **Restore iPhone…**. The latter erases/reinstalls the device rather than selecting a device backup to restore.

After the restore, allow WhatsApp time to rebuild its indexes before judging search behavior.

Useful checks include:

- old imported text appears in the timeline;
- imported media-message bubbles appear;
- replies navigate into imported history;
- old messages become searchable after indexing;
- recent/native history still behaves normally.

## Scope and validation

The row signature and field normalization were derived from one affected Android-to-iPhone migration. The initial case involved Backuptrans, but the signature has not been established as universal across Backuptrans releases or other migration tools.

The encrypted backup rewrite path performs a fresh decrypt and SQLite integrity check after write-back. The tool refuses unfamiliar WhatsApp schemas or ambiguous `ChatStorage.sqlite` matches instead of guessing.

## Privacy

Never publish a real `ChatStorage.sqlite`, Finder/iTunes backup, `Manifest.db`, WhatsApp media, phone numbers/JIDs, or backup password.

## Background and attribution

The encrypted-backup rewrite approach was informed in part by [`robposch/whatsapp-ios-send-fix`](https://github.com/robposch/whatsapp-ios-send-fix), which is MIT licensed. Its copyright notice is preserved in this repository's license.

This project is not affiliated with or endorsed by WhatsApp, Meta, Apple, Backuptrans, or the upstream project.

## License and disclaimer

MIT licensed. Use only on a backup you own or are explicitly authorized to modify.

The software is provided as-is, without warranty.
