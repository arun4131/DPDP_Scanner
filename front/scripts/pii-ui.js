/** PII report table rendering for the scanner page. */

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function normalizePiiTableName(table) {
  const t = String(table || "")
    .trim()
    .toLowerCase();
  if (!t) return "";
  const stripped = t.replace(/"/g, "");
  const parts = stripped.split(".").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : stripped;
}

export function qualifyTable(schema, table) {
  const t = String(table || "").trim();
  if (!t) return "";
  if (t.includes('"') || (t.includes(".") && t.split(".").length >= 2))
    return t;
  const s = (schema || "public").trim();
  return '"' + s + '"."' + t + '"';
}

function parsePiiMatched(raw) {
  const s = String(raw || "").trim();
  const m = s.match(/^(\d+)\s*\/\s*(\d+)$/);
  if (!m) return { hit: 0, total: 0, pct: 0, text: s || "—" };
  const hit = parseInt(m[1], 10);
  const total = parseInt(m[2], 10);
  const pct = total ? Math.round((hit / total) * 100) : 0;
  return { hit, total, pct, text: hit + "/" + total };
}

function labelChipClass(label) {
  const l = String(label || "").toLowerCase();
  if (l.includes("email")) return "pii-label-chip--email";
  if (l.includes("phone") || l.includes("mobile"))
    return "pii-label-chip--phone";
  if (l.includes("password")) return "pii-label-chip--password";
  if (l.includes("user") || l.includes("name")) return "pii-label-chip--user";
  if (l.includes("address") || l.includes("ip") || l.includes("mac"))
    return "pii-label-chip--address";
  if (
    l.includes("pan") ||
    l.includes("tan") ||
    l.includes("cin") ||
    l.includes("gstin")
  )
    return "pii-label-chip--pan";
  if (l.includes("aadhaar") || l.includes("adhar") || l.includes("aadhar"))
    return "pii-label-chip--aadhaar";
  if (
    l.includes("passport") ||
    l.includes("voter") ||
    l.includes("driving") ||
    l.includes("vehicle")
  )
    return "pii-label-chip--id";
  if (
    l.includes("credit") ||
    l.includes("debit") ||
    l.includes("card") ||
    l.includes("cvv") ||
    l.includes("micr")
  )
    return "pii-label-chip--card";
  if (
    l.includes("bank") ||
    l.includes("account") ||
    l.includes("ifsc") ||
    l.includes("upi") ||
    l.includes("loan") ||
    l.includes("demat") ||
    l.includes("cheque") ||
    l.includes("cif") ||
    l.includes("fastag")
  )
    return "pii-label-chip--bank";
  if (l.includes("insurance")) return "pii-label-chip--insurance";
  return "pii-label-chip--default";
}

function formatFqTable(fq) {
  const s = String(fq || "").trim();
  if (!s) return { short: "—", full: "" };
  const stripped = s.replace(/"/g, "");
  const parts = stripped.split(".");
  const short =
    parts.length >= 2
      ? parts[parts.length - 2] + "." + parts[parts.length - 1]
      : stripped;
  return { short, full: stripped };
}

function renderTableCell(fqTable) {
  const { short, full } = formatFqTable(fqTable);
  if (!full) return '<span class="pii-table-empty">—</span>';
  const title = full !== short ? ' title="' + escapeHtml(full) + '"' : "";
  return (
    '<code class="pii-fq-name"' + title + ">" + escapeHtml(short) + "</code>"
  );
}

function renderColumnCell(column) {
  if (!column) return '<span class="pii-table-empty">—</span>';
  return '<code class="pii-col-name">' + escapeHtml(column) + "</code>";
}

function renderLabelChip(label) {
  if (!label) return '<span class="pii-table-empty">—</span>';
  return (
    '<span class="pii-label-chip ' +
    labelChipClass(label) +
    '">' +
    escapeHtml(label) +
    "</span>"
  );
}

function renderConfBadge(level) {
  const s = String(level || "High").toLowerCase();
  const cls = s.includes("low")
    ? "pii-conf-badge--low"
    : s.includes("medium") || s.includes("warn")
      ? "pii-conf-badge--medium"
      : "pii-conf-badge--high";
  const text = s.includes("high")
    ? "High"
    : s.includes("low")
      ? "Low"
      : "Medium";
  return (
    '<span class="pii-conf-badge ' + cls + '">● ' + escapeHtml(text) + "</span>"
  );
}

function renderDetectorTag(detector) {
  const d = String(detector || "regex").trim() || "regex";
  return '<span class="pii-detector-tag">' + escapeHtml(d) + "</span>";
}

function renderMatchedCell(matched) {
  const m = parsePiiMatched(matched);
  const barCls =
    m.pct >= 80
      ? "pii-match-bar-fill--high"
      : m.pct >= 40
        ? "pii-match-bar-fill--medium"
        : "pii-match-bar-fill--low";
  return (
    '<div class="pii-match-cell">' +
    '<span class="pii-match-ratio">' +
    escapeHtml(m.text) +
    "</span>" +
    (m.total
      ? '<span class="pii-match-bar"><span class="pii-match-bar-fill ' +
        barCls +
        '" style="width:' +
        m.pct +
        '%"></span></span>'
      : "") +
    "</div>"
  );
}

function buildGroupedDisplayRows(rows, schema) {
  const out = [];
  let lastTableKey = null;
  rows.forEach((r) => {
    if (!r.table) {
      out.push({
        table: "",
        column: r.column,
        label: r.label,
        matched: r.matched,
        detector: r.detector,
        rowspan: 0,
      });
      return;
    }
    const tableKey = normalizePiiTableName(r.table) || r.table;
    const fq = qualifyTable(schema, r.table);
    const newGroup = tableKey !== lastTableKey;
    if (newGroup) lastTableKey = tableKey;
        out.push({
      table: fq,
      column: r.column,
      label: r.label,
      matched: r.matched,
      detector: r.detector,
      confidence: r.confidence,
      rowspan: 0,
      groupStart: newGroup,
    });
  });
  return out;
}

export function buildPiiDisplayRows(rows, schema) {
  return buildGroupedDisplayRows(rows || [], schema);
}

function rowClass(r) {
  return r.groupStart ? "pii-row pii-row--group-start" : "pii-row";
}

export function renderPiiDataTableRows(rows) {
  if (!rows?.length) return "";
  return rows
    .map((r) => {
      return (
        '<tr class="' +
        rowClass(r) +
        '">' +
        '<td class="pii-col-table">' +
        renderTableCell(r.table) +
        "</td>" +
        '<td class="pii-col-column">' +
        renderColumnCell(r.column) +
        "</td>" +
        '<td class="pii-col-label">' +
        renderLabelChip(r.label) +
        "</td>" +
        '<td class="pii-col-conf">' +
        renderConfBadge("High") +
        "</td>" +
        '<td class="pii-col-detector">' +
        renderDetectorTag(r.detector) +
        "</td>" +
        '<td class="pii-col-matched">' +
        renderMatchedCell(r.matched) +
        "</td></tr>"
      );
    })
    .join("");
}

export function renderPiiMetaTableRows(rows, schema) {
  const display = buildGroupedDisplayRows(rows || [], schema);
  if (!display.length) return "";
  return display
    .map((r) => {
      return (
        '<tr class="' +
        rowClass(r) +
        '">' +
        '<td class="pii-col-table">' +
        renderTableCell(r.table) +
        "</td>" +
        '<td class="pii-col-column">' +
        renderColumnCell(r.column) +
        "</td>" +
        '<td class="pii-col-label">' +
        renderLabelChip(r.label) +
        "</td>" +
        '<td class="pii-col-conf">' +
        renderConfBadge(r.confidence || "Medium") +
        "</td></tr>"
      );
    })
    .join("");
}

export function renderPiiSummaryBar(stats) {
  const items = [
    { label: "Tables", value: stats.tables ?? 0, accent: "" },
    {
      label: "Data Findings",
      value: stats.dataFindings ?? 0,
      accent: "pii-stat--data",
    },
    {
      label: "Meta Findings",
      value: stats.metaFindings ?? 0,
      accent: "pii-stat--meta",
    },
    {
      label: "Low Confidence",
      value: stats.lowConf ?? 0,
      accent: "pii-stat--low",
    },
  ];
  return items
    .map(
      (item) =>
        '<div class="stat-card pii-stat-card ' +
        item.accent +
        '">' +
        '<div class="stat-label">' +
        escapeHtml(item.label) +
        "</div>" +
        '<div class="stat-value">' +
        escapeHtml(item.value) +
        "</div></div>",
    )
    .join("");
}

export function countPiiTables(dataRows, metaRows) {
  const set = new Set();
  [...(dataRows || []), ...(metaRows || [])].forEach((r) => {
    const key = normalizePiiTableName(r.table);
    if (key) set.add(key);
  });
  return set.size;
}

export function renderPiiEmptyState(message, hint) {
  return (
    '<div class="pii-empty-state">' +
    '<div class="pii-empty-icon">◇</div>' +
    '<p class="pii-empty-title">' +
    escapeHtml(message) +
    "</p>" +
    (hint ? '<p class="pii-empty-hint">' + hint + "</p>" : "") +
    "</div>"
  );
}

/** Render low-confidence table chips only (for paginated grids). */
export function renderPiiLowConfChips(tables, schema) {
  const list = (tables || [])
    .map((t) => String(t || "").trim())
    .filter(Boolean);
  if (!list.length) return "";
  return list
    .map((raw) => {
      const fq = qualifyTable(schema, normalizePiiTableName(raw) || raw);
      const { short, full } = formatFqTable(fq);
      const title =
        full && full !== short ? ' title="' + escapeHtml(full) + '"' : "";
      const searchKey = (short + " " + full).toLowerCase();
      return (
        '<span class="pii-low-conf-chip" data-search="' +
        escapeHtml(searchKey) +
        '"' +
        title +
        ">" +
        '<span class="pii-low-conf-chip__schema">' +
        escapeHtml((schema || "public").trim()) +
        "</span>" +
        '<span class="pii-low-conf-chip__name">' +
        escapeHtml(short.split(".").pop() || short) +
        "</span>" +
        "</span>"
      );
    })
    .join("");
}

/** Low-confidence table list — chip grid with optional filter. */
export function renderPiiLowConfPanel(tables, schema) {
  const list = (tables || [])
    .map((t) => String(t || "").trim())
    .filter(Boolean);
  if (!list.length) return "";

  const chips = renderPiiLowConfChips(list, schema);

  return (
    '<div class="pii-low-conf-panel">' +
    '<p class="pii-low-conf-intro">' +
    "These tables had <strong>medium or low</strong> confidence PII signals during the value scan. " +
    "They are not shown in the Data Scan table above because matches did not meet the high-confidence threshold." +
    "</p>" +
    '<div class="pii-low-conf-toolbar">' +
    '<label class="pii-low-conf-search-wrap">' +
    '<span class="pii-low-conf-search-icon" aria-hidden="true">⌕</span>' +
    '<input type="search" id="pii-low-conf-search" class="pii-low-conf-search" ' +
    'placeholder="Filter tables…" autocomplete="off" aria-label="Filter low-confidence tables" />' +
    "</label>" +
    '<span class="pii-low-conf-showing" id="pii-low-conf-showing">' +
    list.length +
    " tables</span>" +
    "</div>" +
    '<div class="pii-low-conf-grid" id="pii-low-conf-grid">' +
    chips +
    "</div>" +
    "</div>"
  );
}

export function bindPiiLowConfFilter() {
  const input = document.getElementById("pii-low-conf-search");
  const grid = document.getElementById("pii-low-conf-grid");
  const showing = document.getElementById("pii-low-conf-showing");
  if (!input || !grid) return;

  const chips = [...grid.querySelectorAll(".pii-low-conf-chip")];
  const total = chips.length;

  const apply = () => {
    const q = input.value.trim().toLowerCase();
    let visible = 0;
    chips.forEach((chip) => {
      const match = !q || (chip.dataset.search || "").includes(q);
      chip.style.display = match ? "" : "none";
      if (match) visible++;
    });
    if (showing) {
      showing.textContent = q
        ? visible + " of " + total + " tables"
        : total + " tables";
    }
  };

  input.addEventListener("input", apply);
  apply();
}
