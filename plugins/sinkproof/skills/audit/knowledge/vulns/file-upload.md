# Unrestricted File Upload
CWE-434 · OWASP A04:2021 · ASVS V12.2.1

## What it is
An upload feature accepts files without adequately restricting their type, content, size or storage location, letting an attacker upload a script, executable, or other dangerous file that is later executed by the server, served to other users, or used to exhaust resources.

## Where to look
- Node/Express: `multer` configs without `fileFilter`/`limits`, files saved under a web-served static directory.
- Python: Flask/Django `request.files`, `FileField`/`ImageField` without `validators`, files saved by client-supplied filename.
- PHP/Laravel: `move_uploaded_file`, `$request->file(...)->move(...)`, files stored inside `public/`.
- Ruby/Rails: `ActiveStorage`/`CarrierWave`/`Paperclip` without a content-type or extension allow-list.
- Java/Spring: `MultipartFile.transferTo(...)` writing to a servlet-served path.
- Any path built from the original filename (`req.file.originalname`, `params[:filename]`) without sanitization — also a path traversal risk.

## How to confirm
Show that the upload endpoint accepts an attacker-chosen file extension/content-type and MIME sniffing is not independently verified (server trusts the client-supplied `Content-Type` or extension only), and that the destination is reachable and executable by the web server (same domain/subdomain as application code, or a path interpreted by the runtime, e.g. `.php`, `.jsp`, `.asp`, `.svg` with embedded script, or a filename containing traversal sequences).

## False-positive traps
- Files stored in an object store (S3, GCS, Azure Blob) served from a separate domain with `Content-Disposition: attachment` and no execute permissions are not remote-code-execution risk, even without strict type checks — but may still warrant a lower-severity note for stored XSS via SVG/HTML uploads if served inline.
- Extension checks alone (`.jpg`) are bypassable via double extensions or null bytes; only content-based validation (magic-byte/library re-encode) plus a non-executable storage path counts as a real fix.
- Antivirus/malware scanning integrated into the upload pipeline is a genuine mitigation, not a false positive to ignore — note it in the finding.
- A hard file-size limit alone does not fix type/content validation gaps; both are independent controls.

## Safe patterns
```js
const upload = multer({
  storage: multer.diskStorage({
    destination: "/var/uploads",
    filename: (req, file, cb) => cb(null, crypto.randomUUID()),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  // mimetype is client-supplied; verify magic bytes (e.g. the file-type package) after upload
  fileFilter: (req, file, cb) => cb(null, ["image/png", "image/jpeg"].includes(file.mimetype)),
});
```

## Fix guidance
Validate file type by content (magic bytes or re-encoding through an image/document library), not by extension or client-supplied `Content-Type` alone; generate a random server-side filename; store uploads outside the web root or in object storage on a separate domain with execute permissions disabled; enforce a size limit; scan for malware where feasible; set `Content-Disposition: attachment` and a strict `Content-Type` when serving user uploads back.

## Severity guide
- Impact `high`: an executable or server-side script can be uploaded and reached, leading to remote code execution.
- Impact `medium`: uploaded content is served inline and can carry stored XSS (e.g. unsanitized SVG/HTML), or unrestricted size enables denial of service.
- Impact `low`: type/content validation is weak but storage is non-executable and isolated, limiting impact to storage abuse.
- Exploitability: `high` when any authenticated user can upload; `medium` when upload requires a specific role or passes through partial filtering that must be bypassed.
