# DSH Plugin Auditor

`dsh-plugin-auditor` is a DeepSeek Harness plugin that reviews installed plugins before a user enables or updates them.

It combines:

- Read-only static scanning for common remote execution, download-and-execute, encoded evaluation, persistence, and environment exfiltration patterns.
- Semantic review through the model selected by the current DSH session. It does not hard-code DeepSeek or silently choose another model.
- Comment and README contradiction reporting through `commentConflicts`.
- User confirmation gates for enabling, updating, and disabling/quarantining a plugin.

The auditor never requires, imports, launches, installs, downloads, or executes the plugin being inspected. Plugin code, comments, README files, strings, and model output are treated as untrusted data.

## DSH installation

Copy this package into the DSH profile's `node_modules` directory and add it to the profile patch:

```yaml
- insert:
    - id: plugin-auditor
      name: dsh-plugin-auditor
```

The DSH Desktop companion synchronizer performs those two steps automatically for the bundled plugin.

## Use

Open DSH settings, choose **AI 审查**, enter the installed package name and its path under the current profile's `node_modules`, then start the review. The result shows the active provider/model, static findings, semantic findings, and comment/document conflicts.

Static high-risk findings disable the enable/update actions. A user can still explicitly choose isolation/disable after reviewing the report.

## Development tests

Run from a DSH Desktop checkout with the bundled Node runtime:

```powershell
vendor/node/node.exe --test scripts/test/unit-plugin-auditor-protocol.test.js scripts/test/unit-plugin-auditor.test.js
```

## Limitations

Static scanning is intentionally conservative and can produce findings for security-related example strings or regular expressions. It is a review signal, not proof of malware. Semantic review also requires an active DSH model and credentials; if the current model cannot be determined, the plugin fails closed.

## License

MIT. See [LICENSE](LICENSE).
