# SAST Report & Form System

Local SAST records application for the RP server. The application is designed to be completed locally first, then transferred to hosted/cloud infrastructure.

## Local location

- Application: D:\SAST_Report_System
- Persistent records: D:\SAST_Report_System\records
- Primary JSON archive: D:\SAST_Report_System\records\sast_records.json
- Per-record JSON files: D:\SAST_Report_System\records\0001_1ST-F-101.json
- Attachments: D:\SAST_Report_System\records\attachments
- Automatic backups: D:\SAST_Report_System\records\backups
- Local URL: http://localhost:3050

## Start

1. Open a terminal in D:\SAST_Report_System.
2. Run `npm.cmd install` if dependencies are not installed.
3. Run `npm.cmd start`.
4. Open http://localhost:3050.

The current local environment uses JSON storage so the system does not depend on a separate database service.

## Access model

- Administrator: full administration, officer/rank/template management, supervisor functions.
- Supervisor: edit and sign records/forms, approve/review records, view edit history.
- Standard Officer: file, view, search, and cross-reference records.
- The local development session is Administrator access.
- Discord OAuth support is present and can be configured with the Discord values in .env.

## Filing and document numbering

Filing numbers are sequential: 0001, 0002, 0003...
Document numbers are separate:
- Forms: 1ST-F-101 onward
- Reports: 1ST-R-101 onward

## Templates currently included

- 1ST-F-101 — SAST Daily Patrol Log
- 1ST-F-102 — Society Fund Reimbursement Form
- 1ST-F-103 — Armory Sign-In / Sign-Out
- 1ST-F-104 — Vehicle Sign-Out Sheet
- 1ST-R-101 — Incident Report
- 1ST-R-102 — Taser Deployment Report
- 1ST-R-103 — Use of Force Report
- 1ST-R-104 — Firearm Discharge Report
- 1ST-R-105 — K-9 Subdivision Report
- 1ST-R-106 — SWAT Subdivision Report
- 1ST-R-107 — NARCOTICS Subdivision Report
- 1ST-R-108 — TRAFFIC Division Report
- 1ST-R-109 — MBU Subdivision Report
- 1ST-R-110 — Equipment Loss Report

## Completed system features

- Persistent local archive and per-record JSON files.
- Automatic archive backups.
- Officer database with rank, unit, division, role, active status, and Discord ID.
- Officer @mention autocomplete and officer auto-fill.
- Rank hierarchy and stylized RP rank-insignia previews.
- Administrator / Supervisor / Standard Officer access controls.
- Supervisor edit/sign workflow with live signature preview and selectable signature fonts.
- Saved supervisor signature display on archived reports and forms.
- Edit history attached to records.
- Report/form cross-references with document and filing-number autocomplete.
- Up to 10 photo attachments with size/type limits and authenticated retrieval.
- Fictional in-character SAST Penal Code with search and report picker.
- Browser print / Save as PDF.
- Grey/black SAST bear branding and charcoal/silver UI.
- Discord webhook configuration support.
- Discord OAuth configuration support.

## Transfer point

Before moving the application to hosted/cloud infrastructure:

1. Preserve the entire `records` directory, including `sast_records.json`, per-record files, attachments, and backups.
2. Copy the application source from `public\`, `server.js`, `package.json`, `package-lock.json`, and configuration templates.
3. Do not transfer the local `.env` file or expose its secrets. Recreate production environment variables on the destination.
4. Run `npm.cmd install` on the destination.
5. Set production `STORAGE_PATH` to the intended persistent storage location.
6. Configure Discord OAuth and webhook values for the production URL.
7. Test authentication, filing, editing/signing, archive search, cross-references, attachments, and officer administration before opening it to users.

This local build is the handoff point for the next phase: hosted/cloud deployment and production Discord configuration.
