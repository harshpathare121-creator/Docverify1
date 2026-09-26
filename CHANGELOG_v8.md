# ConnectID v8 — Resend OTP fix

- Added actual server-side Resend email delivery using `https://api.resend.com/emails`.
- Registration OTPs are emailed when `RESEND_API_KEY` is configured.
- Access-approval OTPs are emailed when Resend is configured.
- Real OTPs are never returned to the browser in Resend mode.
- Demo fallback remains available when `EMAIL_MODE=auto` and no Resend key is configured.
- `/api/health` reports non-secret email configuration status.
- Render Blueprint default changed from `EMAIL_MODE=demo` to `EMAIL_MODE=auto`.
