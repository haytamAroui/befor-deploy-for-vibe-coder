# FastAPI file-upload control boundary

**Status:** Bounded deterministic control, version `0.1.0`.

`SEC-API-UPLOAD-001` inspects Python AST only. It reports a direct `UploadFile.filename` value passed as an argument to the built-in `open()` inside a literal mutating FastAPI route whose parameter is directly annotated `UploadFile`. This exact shape is treated as an unsafe filename-to-filesystem boundary and requires explicit filename sanitization or an approved storage abstraction.

| Property | Contract |
|---|---|
| Policy | `fastapi-file-upload-policy.yaml` only; default and strict profiles are unchanged. |
| Finding evidence | Constant `{artifact: python, issue: upload_filename_filesystem_sink}` plus relative path and sink line. |
| Vulnerable shape | Direct `UploadFile.filename` expression passed to the built-in `open` in a literal mutating route. |
| Safe/excluded shapes | Sanitized or locally transformed values, local aliases, helper calls, storage APIs, dynamic routes, decorator aliases, non-mutating routes, and non-direct dataflow. |
| Error behavior | Invalid Python is normalized by the orchestrator as a fail-closed control error. |

The control does not prove upload binding, filename content, path resolution, storage behavior, sanitization effectiveness, archive safety, malware scanning, MIME validation, size limits, authorization, or runtime reachability. It does not execute Python, FastAPI, application code, tests, builds, package managers, scanners, Docker, or network requests.

Reports never retain filenames, route paths, parameter names, source excerpts, or target-controlled values. The policy engine remains the sole release authority; this control cannot select tools, create waivers, or alter any decision unless its own finding is explicitly selected by the dedicated policy.
