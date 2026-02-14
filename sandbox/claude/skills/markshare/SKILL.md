---
name: markshare
description: Share markdown files as a webpage on markshare.to. Use when the user wants to share, publish, or upload markdown files to markshare, or mentions markshare.to.
---

# Markshare

Share markdown files as a beautiful webpage on markshare.to.

## OUTPUT RULES (CRITICAL)

- Work **SILENTLY** - do NOT narrate, explain, or show intermediate steps
- Keep output limited to the exact emoji stage messages shown below
- Do NOT pause between phases when no user input is required; emit multiple stage messages in order in a single response
- If user input is required (missing API key, missing files, or too many files), stop after the relevant message
- **NEVER** show API keys, tokens, file contents, JSON payloads, or curl commands
- **NEVER** execute `echo $MARKSHARE_API_KEY` or any command that outputs secret values
- Execute tools silently between stage messages

---

## PHASE 1: Get API Key

Silently check using this EXACT command (no echo of values!):

```bash
python3 - <<'PY'
import json, os, sys
key = os.environ.get("MARKSHARE_API_KEY", "")
if isinstance(key, str) and key.strip():
    print("env")
    sys.exit(0)
path = os.path.expanduser("~/.markshare/config.json")
try:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    key = data.get("apiKey", "")
    if isinstance(key, str) and key.strip():
        print("config")
except Exception:
    pass
PY
```

If "env" printed: API key is in environment variable
If "config" printed: API key is in config file (will be used inline in curl header)
If nothing printed: No API key found

**If found**, output ONLY and continue immediately to Phase 2:
```
🔑 Authenticated with markshare.to
```

**If NOT found**, output ONLY and STOP:
```
🔒 No API key found!

Grab yours at: https://markshare.to/dashboard/settings

Then either:
• Set env: export MARKSHARE_API_KEY=mk_xxxxx
• Or create: ~/.markshare/config.json with {"apiKey": "mk_xxxxx"}
```

---

## PHASE 2: Find Files

Determine which markdown files to share based on the user's request:

1. **Explicit paths**: If the user specified file paths or @file references, use those
2. **Context clues**: If the user mentioned specific files by name, find and use them
3. **Ask user**: If unclear, ask the user which markdown files they want to share

Read each file to get its content.

After reading file contents, choose a single markshare title that best represents the combined content.
Title rules:
- Must be 10 words or fewer (trim if needed).
- Prefer concrete, descriptive nouns; avoid generic labels like "Notes", "Document", or "Untitled".
- If multiple files, synthesize a unifying theme rather than mirroring a single filename.
- Ignore file paths and folder names; base the title only on the markdown content.
- Use Title Case unless the content clearly calls for lowercase (e.g., CLI flags).
Store this as MARKSHARE_TITLE for Phase 3.

Before packaging, decide the most cohesive order for the markdown files so the final page reads naturally.
Do not edit file contents or add summaries; preserve content fidelity 1:1 and only change the order.

**On success**, output ONLY and continue immediately to Phase 3:
```
📄 Found {count} file(s) to share: {filenames}
```

**If >10 files**, output ONLY and STOP:
```
📚 Too many files! Found {count} (max 10). Pick your favorites.
```

**If no files found**, ask the user which files to share.

---

## PHASE 3: Upload

Output ONLY:
```
📦 Packaging your markdown magic...
```

Then silently execute the upload in a single chained command. We use **Python 3** for JSON generation because it handles escaping and large files more reliably than `jq` without adding extra dependencies.

```bash
# Example for multiple files (the AI should dynamically build this command)
# NOTE: Using www.markshare.to to avoid redirects and -L for safety
MARKSHARE_TITLE="Your 10-word title" python3 - <<'PY' file1.md file2.md
import json, os, re, sys

title = os.environ.get("MARKSHARE_TITLE", "").strip()
if title:
    words = title.split()
    if len(words) > 10:
        title = " ".join(words[:10])

files = []
for path in sys.argv[1:]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        files.append({"name": os.path.basename(path), "content": f.read()})

if title and files:
    content = files[0]["content"]
    match = re.search(r"^#\s+.*$", content, flags=re.M)
    if match and content[:match.start()].strip() == "":
        content = content[:match.start()] + f"# {title}" + content[match.end():]
    else:
        content = f"# {title}\n\n" + content
    files[0]["content"] = content

print(json.dumps({"content": {"files": files}}))
PY
curl -s -L -X POST https://www.markshare.to/api/v1/markshare \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(python3 - <<'PY'
import json, os
key = os.environ.get("MARKSHARE_API_KEY", "")
if isinstance(key, str):
    key = key.strip()
if not key:
    try:
        with open(os.path.expanduser("~/.markshare/config.json"), "r", encoding="utf-8") as f:
            data = json.load(f)
        k = data.get("apiKey", "")
        key = k.strip() if isinstance(k, str) else ""
    except Exception:
        key = ""
print(key)
PY
)" \
  -d @-
```

**Key points:**
- **Streaming Pipeline**: Content flows directly from Python to Curl via stdin (`-d @-`), avoiding temp files and shell argument limits.
- **Robust Escaping**: Python's `json.dumps` perfectly handles quotes, backslashes, and newlines in markdown.
- **Title Control**: `MARKSHARE_TITLE` injects or replaces the top H1 in the first file so the API uses the chosen <=10-word title.
- **Zero-Dependency Auth**: Uses Python's JSON parser to extract and trim the API key from config (or env), avoiding brittle `grep/sed` parsing and extra deps like `jq`.
- **Follow Redirects**: Uses `www.markshare.to` and `-L` to ensure the request reaches the API.
- **Atomic**: One-liner that either works or fails cleanly.

Output ONLY:
```
🚀 Launching to the cloud...
```

---

## PHASE 4: Report Result

Silently parse the JSON response. Output ONLY the final link and status.

**On success**, output ONLY:
```
✨ Markshare it to the world!
📝 {title}
🔗 https://markshare.to{url}
```

**On error**, output ONLY:
- 401: `🔐 Invalid API key. Check markshare.to/dashboard/settings`
- 413: `📏 Files too large.`
- 429: `🐢 Rate limited. Try again later.`
- Other: `❌ Something went wrong.`
