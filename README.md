# ConnectID — Professional College Demo

ConnectID is a prototype for **user-controlled identity data sharing**. A person uploads identity documents, receives a permanent Person ID, and controls which verified organization can access selected data.

## Architecture
- **Frontend:** single responsive HTML/CSS/JavaScript application.
- **Backend:** Node.js + Express REST API.
- **Persistence:** JSON datastore on a Render persistent disk (chosen for a simple, native-build-free college demo).
- **Authentication:** bcrypt password hashing + signed JWT sessions.
- **Authorization:** separate `person`, `organization`, and `admin` roles.
- **Documents:** private files stored outside the public web root.
- **OCR:** Tesseract OCR for images and text extraction for PDFs; the registered name must match the detected document name. Document authenticity is **not** verified by this prototype.

## Core workflow
1. Person registers with Gmail and receives a verification OTP by Resend when configured (otherwise the demo fallback displays the OTP).
2. Backend creates a permanent Person ID (`PID-100245`, `PID-100246`, ...).
3. Person uploads a document; OCR extracts the name, compares it with the registered profile name, and rejects the file if they do not match.
4. Organization searches by Person ID and requests specific fields/documents, purpose, and duration.
5. Person approves or denies the request.
6. Approval generates a time-limited OTP.
7. Organization completes OTP authorization.
8. Only the approved fields/documents are exposed while the request is `Granted`.
9. Person can revoke granted access.
10. Audit and notification records are retained for the demo.

## Demo credentials
- Organization: `HOSP001` / `hospital123`
- Admin: `ADMIN001` / `admin12345`
- Registration verification OTP is emailed through Resend when configured; otherwise it is displayed in demo mode.

## Admin Portal
The Admin Portal is intentionally **demo-only**. It can inspect all registered users, profile data, documents, OCR metadata, requests, notifications, and audit history, and can open stored uploaded files. This is included for judging/demo visibility and is not a production privacy model.

## Security measures in this demo
- Passwords are hashed with bcrypt.
- JWT sessions have a fixed lifetime.
- Resend API keys are read only from server environment variables and are never sent to the browser.
- Role-based authorization is enforced server-side.
- OTPs are stored as SHA-256 hashes and expire.
- OTP attempts are limited.
- Authentication and sensitive organization endpoints are rate-limited.
- Uploads are limited to 10 MB and restricted to PDF/PNG/JPG/WEBP.
- Uploaded filenames are sanitized and stored with random server-side names.
- Documents are never served as public static files.
- Basic security response headers are enabled.
- Request ownership is checked on every person/organization data endpoint.

## Important prototype limitations
This is a college/demo system, not a government identity verification service. It does not connect to Aadhaar, government databases, banks, hospitals, or real identity registries. OCR name matching is implemented, but authenticity is not checked against a government source; demo OTPs are shown in the UI instead of being delivered through a real verification provider.

## Render deployment
Use the included `render.yaml` or configure the service with:
- Build: `npm install`
- Start: `npm start`
- Node: `20.19.0`
- Data directory: `/var/data`
- Persistent disk: required for demo data/files to survive restarts.

Set `JWT_SECRET` to a long random value and keep `.env` out of Git.


## OCR name verification
Uploaded JPG, PNG, and WEBP files are processed with Tesseract OCR. Text-based PDFs are parsed with pdf-parse. The backend extracts the document name and compares it with the registered profile name. If the names do not match, the upload is rejected as an **Invalid file** and the stored file is deleted. This is a prototype verification layer, not government-source authenticity verification.


## Resend OTP setup on Render

Add these environment variables to the Render service:
- `RESEND_API_KEY` = your Resend API key (keep it secret).
- `RESEND_FROM` = `ConnectID <onboarding@resend.dev>` for the Resend-provided test sender, or a sender address from a verified domain.
- `EMAIL_MODE` = `auto`.

In `auto` mode, the backend uses Resend when `RESEND_API_KEY` is present. If the key is absent, it falls back to demo OTP mode. The browser never receives the real OTP when Resend mode is active.

After changing Render environment variables, redeploy the service. `/api/health` reports non-secret email configuration status.
