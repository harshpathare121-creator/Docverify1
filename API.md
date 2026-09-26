# ConnectID API

All protected endpoints use `Authorization: Bearer <JWT>`.

## Person
- `POST /api/auth/register`
- `POST /api/auth/verify-email`
- `POST /api/auth/login`
- `GET /api/me`
- `GET /api/documents`
- `POST /api/documents` (multipart field: `document`)
- `GET /api/access-requests`
- `POST /api/access-requests/:id/decision`
- `POST /api/access-requests/:id/revoke`
- `GET /api/notifications`
- `POST /api/notifications/:id/read`
- `GET /api/audit`

## Organization
- `POST /api/org/login`
- `GET /api/org/me`
- `POST /api/access-requests`
- `GET /api/org/access-requests`
- `POST /api/access-requests/:id/authorize`
- `GET /api/granted-data/:requestId`
- `GET /api/granted-data/:requestId/documents/:documentId/download`

## Admin — demo only
- `POST /api/admin/login`
- `GET /api/admin/me`
- `GET /api/admin/overview`
- `GET /api/admin/users`
- `GET /api/admin/documents/:id/download`
- `GET /api/admin/organizations`
- `GET /api/admin/audit`

## System
- `GET /api/health`


### Document OCR verification
`POST /api/documents` now performs OCR/text extraction before storing a document. The registered profile name must match the name detected in the document. A mismatch returns HTTP `422` with an `Invalid file` message and the file is not stored. Image OCR uses Tesseract.js; text-based PDFs use pdf-parse.
