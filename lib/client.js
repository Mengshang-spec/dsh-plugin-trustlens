window.__ModuleLoader__.load({
  id: "dsh-plugin-auditor",
  factory: (require) => {
    const react = require("react");
    const { jsx, jsxs } = require("react/jsx-runtime");
    const AUDIT_ROUTE = "/api/dsh-plugin-auditor/audit";

    function AuditorTab({ sessions }) {
      const [path, setPath] = react.useState("");
      const [name, setName] = react.useState("");
      const [request, setRequest] = react.useState("审查这个插件是否安全，是否符合我的要求；重点检查木马、凭据读取、外传、持久化，以及注释和实际代码是否冲突。只读分析，不执行插件。\n");
      const [busy, setBusy] = react.useState(false);
      const [result, setResult] = react.useState(null);
      const [error, setError] = react.useState("");
      const [actionMessage, setActionMessage] = react.useState("");
      const currentSession = sessions?.list?.getSnapshot?.()?.current || "";
      const report = result?.report;
      const canReview = report && report.verdict !== "block";
      const canEnable = report && report.verdict !== "block" && !result.staticFindings?.length;
      const canUpdate = report && report.verdict !== "block" && !result.staticFindings?.length;
      const bridge = () => typeof window !== "undefined" ? window.dshDesktop?.pluginManager : null;

      const run = async () => {
        setBusy(true); setError(""); setActionMessage(""); setResult(null);
        try {
          const response = await fetch(AUDIT_ROUTE, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
            pluginId: name.trim(), packageName: name.trim(), packagePath: path.trim(), userRequest: request, sessionId: currentSession,
          }) });
          const value = await response.json();
          if (!value.ok) throw new Error(value.error || "审查失败");
          setResult(value);
        } catch (e) { setError(String(e?.message || e)); }
        finally { setBusy(false); }
      };

      const confirmUser = (message) => typeof window === "undefined" || typeof window.confirm !== "function" || window.confirm(message);
      const disable = async () => {
        const b = bridge();
        if (!b?.setEnabled) return setError("插件管理桥不可用，请在插件管理页手动禁用");
        if (!confirmUser("审查结果将禁用该插件，并在重启后生效。继续吗？")) return;
        const answer = await b.setEnabled(name.trim(), false);
        if (!answer?.ok) setError(answer?.error || "禁用失败"); else setActionMessage("已写入禁用决定，重启 DSH 后生效。");
      };
      const enable = async () => {
        const b = bridge();
        if (!b?.setEnabled || !canEnable) return setError("当前审查结论不允许启用");
        if (!confirmUser("模型结论不是自动授权。你已查看报告，确认启用该插件吗？")) return;
        const answer = await b.setEnabled(name.trim(), true);
        if (!answer?.ok) setError(answer?.error || "启用失败"); else setActionMessage("已写入启用决定，重启 DSH 后生效。");
      };
      const update = async () => {
        const b = bridge();
        if (!b?.update || !canUpdate) return setError("当前审查结论不允许更新");
        if (!confirmUser("更新会下载并替换插件文件；更新器还会执行静态扫描。确认继续吗？")) return;
        const answer = await b.update(name.trim());
        if (!answer?.ok) setError(answer?.error || "更新失败"); else setActionMessage("更新已写入，重启 DSH 后生效。");
      };
      const quarantine = async () => {
        const b = bridge();
        if (!confirmUser("将插件隔离/禁用以阻止下次加载。确认吗？")) return;
        if (typeof b?.quarantine === "function") {
          const answer = await b.quarantine(name.trim(), { source: "ai-auditor", reason: report?.verdict || "review" });
          if (!answer?.ok) setError(answer?.error || "隔离失败"); else setActionMessage("已写入隔离决定，重启 DSH 后生效。");
          return;
        }
        await disable();
      };

      return jsxs("div", { style: { display: "flex", flexDirection: "column", gap: 10, maxWidth: 760 }, children: [
        jsx("div", { style: { fontWeight: 600 }, children: "AI 插件安全审查" }),
        jsx("div", { style: { fontSize: 12, opacity: .7 }, children: "审查使用当前会话实际模型。插件代码、注释、README 和字符串都只作为不可信数据读取，不会被执行。" }),
        jsx("input", { value: name, onChange: (e) => setName(e.target.value), placeholder: "插件 id 或包名" }),
        jsx("input", { value: path, onChange: (e) => setPath(e.target.value), placeholder: "插件包路径（当前 profile 的 node_modules 内）" }),
        jsx("textarea", { value: request, onChange: (e) => setRequest(e.target.value), rows: 5 }),
        jsx("button", { type: "button", disabled: busy || !path.trim() || !name.trim(), onClick: run, children: busy ? "审查中…" : "开始审查" }),
        error ? jsx("div", { style: { color: "#c33", whiteSpace: "pre-wrap" }, children: error }) : null,
        actionMessage ? jsx("div", { style: { color: "#176b3a" }, children: actionMessage }) : null,
        result ? jsxs("div", { style: { border: "1px solid var(--dsw-alias-border-l2, #ccc)", padding: 10, borderRadius: 8 }, children: [
          jsx("div", { children: `当前模型：${result.active?.provider || "未知"} / ${result.active?.model || "未知"}（来源：${result.active?.source || "unknown"}）` }),
          jsx("div", { children: `结论：${report?.verdict || "review"}${report?.staticOverride ? "（静态高危发现已强制进入人工复核）" : ""}` }),
          result.staticFindings?.length ? jsx("pre", { style: { whiteSpace: "pre-wrap", color: "#a33" }, children: "静态发现：\n" + JSON.stringify(result.staticFindings, null, 2) }) : null,
          report?.findings?.length ? jsx("pre", { style: { whiteSpace: "pre-wrap" }, children: "模型发现：\n" + JSON.stringify(report.findings, null, 2) }) : null,
          report?.commentConflicts?.length ? jsx("pre", { style: { whiteSpace: "pre-wrap", color: "#a65" }, children: "注释/文档冲突：\n" + report.commentConflicts.join("\n") }) : null,
          jsx("div", { style: { fontSize: 12, marginTop: 8 }, children: "模型结论不是自动授权。以下每个变更动作都需要你的再次确认；审查对象代码始终不会被本插件执行。" }),
          jsxs("div", { style: { display: "flex", gap: 8, flexWrap: "wrap", marginTop: 8 }, children: [
            jsx("button", { type: "button", disabled: !canEnable, onClick: enable, children: "确认并启用" }),
            jsx("button", { type: "button", disabled: !canUpdate, onClick: update, children: "审查后更新" }),
            jsx("button", { type: "button", onClick: quarantine, children: "隔离/禁用" }),
          ] })
        ] }) : null
      ] });
    }

    function apply(ctx) {
      const sessions = ctx.get("sessions", false) || null;
      ctx.slots.inject("settings.plugins.tab", () => ctx.slots.register({
        name: "settings.plugins.tab", id: "ai-auditor", order: 35, label: "AI 审查", inject: () => ({ sessions })
      }, AuditorTab));
    }
    return { apply, inject: ["slots", "sessions"] };
  }
});
