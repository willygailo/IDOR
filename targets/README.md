# Targets

Research materials organized per target application.

## Subfolders

| Folder | Contents |
|--------|----------|
| `recon/` | Endpoint discovery and API mapping notes |
| `scope/` | Program scope definitions (in-scope / out-of-scope assets) |
| `notes/` | General research observations per target |

## Naming Convention

```
recon/recon-[target-name].md
scope/scope-[program-name].md
notes/notes-[target-name].md

Examples:
  recon/recon-example-app.md
  scope/scope-hackerone-example.md
  notes/notes-example-app.md
```

## Before Testing Any Target

1. Fill out `scope/scope-[program].md` — define what is in and out of scope
2. Create `recon/recon-[target].md` — map all endpoints before testing
3. Use `notes/notes-[target].md` — record observations as you test
