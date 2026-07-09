import {
  buildPiiDisplayRows,
  countPiiTables,
  renderPiiDataTableRows,
  renderPiiEmptyState,
  renderPiiLowConfChips,
  renderPiiMetaTableRows,
  renderPiiSummaryBar,
} from './pii-ui.js';
import { paginateSlice, mountTablePagination } from './pagination.js';

const piiDataPager     = { page: 1, pageSize: 15 };
const piiMetaPager     = { page: 1, pageSize: 15 };
const piiLowConfPager  = { page: 1, pageSize: 24 };
const piiLowConfFilter = { search: '' };
let piiLowConfToolbarBound = false;

let piiCatalog = {
  rows: [], meta: [], lowConf: [], schema: 'public',
  runOption: '', status: '', available: false, message: '',
};

// ── Mock data (kept for frontend testing) ─────────────────────────────────────
// const MOCK_HOSTS = [
//   {
//     instance: 'localhost:5432',
//     databases: [
//       {
//         name: 'mydb',
//         results: {
//           available: true, schema: 'public', runOption: 'datascan',
//           rows: [
//             { table: 'users',     column: 'email',      label: 'Email',           matched: '9821/10000', detector: 'regex' },
//             { table: 'users',     column: 'phone',      label: 'Phone',           matched: '7430/10000', detector: 'regex' },
//             { table: 'customers', column: 'pan_number', label: 'PANNumber',       matched: '5000/5000',  detector: 'regex' },
//             { table: 'customers', column: 'aadhaar',    label: 'AdharcardNumber', matched: '4980/5000',  detector: 'regex' },
//             { table: 'payments',  column: 'card_no',    label: 'CreditCard',      matched: '3200/4000',  detector: 'regex' },
//           ],
//           meta: [
//             { table: 'employees', column: 'dob', label: 'BirthDate', matched: '', detector: 'regex' },
//           ],
//           lowConf: ['audit_logs', 'temp_records', 'session_data'],
//         },
//       },
//       {
//         name: 'testdb',
//         results: {
//           available: true, schema: 'public', runOption: 'metascan',
//           rows: [],
//           meta: [
//             { table: 'orders', column: 'billing_address', label: 'Address', matched: '', detector: 'regex' },
//             { table: 'orders', column: 'contact_email',   label: 'Email',   matched: '', detector: 'regex' },
//           ],
//           lowConf: ['logs'],
//         },
//       },
//     ],
//   },
//   {
//     instance: 'prod-db:5432',
//     databases: [
//       {
//         name: 'proddb',
//         results: {
//           available: true, schema: 'public', runOption: 'deepscan',
//           rows: [
//             { table: 'accounts', column: 'email',       label: 'Email',     matched: '12000/12000', detector: 'regex' },
//             { table: 'accounts', column: 'gstin',       label: 'GSTIN',     matched: '8000/12000',  detector: 'regex' },
//             { table: 'kyc',      column: 'voter_id',    label: 'VoterID',   matched: '3100/5000',   detector: 'regex' },
//             { table: 'kyc',      column: 'passport_no', label: 'PassportNumber', matched: '2900/5000', detector: 'regex' },
//           ],
//           meta: [],
//           lowConf: [],
//         },
//       },
//     ],
//   },
// ];

// ── API config ─────────────────────────────────────────────────────────────────
const API_BASE = 'http://localhost:8080';

// ── Helpers ────────────────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function hidePager(id) {
  const el = document.getElementById(id);
  if (el) { el.hidden = true; el.innerHTML = ''; }
}

function setDataTableVisible(visible) {
  const w = document.querySelector('#pii-data-scan-block .pii-table-wrap');
  if (w) w.style.display = visible ? '' : 'none';
}

function filterLowConfTables(tables) {
  const q = (piiLowConfFilter.search || '').trim().toLowerCase();
  if (!q) return tables || [];
  return (tables || []).filter(t => String(t || '').toLowerCase().includes(q));
}

function bindPiiLowConfToolbarOnce() {
  if (piiLowConfToolbarBound) return;
  const block = document.getElementById('pii-low-conf-block');
  if (!block) return;
  piiLowConfToolbarBound = true;
  block.addEventListener('input', (e) => {
    if (e.target?.id !== 'pii-low-conf-search') return;
    piiLowConfFilter.search = e.target.value;
    piiLowConfPager.page = 1;
    renderLowConfSection(piiCatalog.schema || 'public');
  });
}

function renderLowConfSection(schema) {
  const lowBlock   = document.getElementById('pii-low-conf-block');
  const lowContent = document.getElementById('pii-low-conf-content');
  const lowBadge   = document.getElementById('pii-low-conf-badge');
  const pagerEl    = document.getElementById('pii-low-conf-pagination');
  if (!lowBlock || !lowContent) return;

  const all      = piiCatalog.lowConf || [];
  const filtered = filterLowConfTables(all);
  const pg       = paginateSlice(filtered, piiLowConfPager.page, piiLowConfPager.pageSize);
  piiLowConfPager.page = pg.page;

  if (!all.length) {
    lowBlock.style.display = 'none'; lowContent.innerHTML = '';
    hidePager('pii-low-conf-pagination'); return;
  }

  lowBlock.style.display = 'block';
  if (lowBadge) lowBadge.textContent = all.length + ' table' + (all.length === 1 ? '' : 's');

  const showingText = filtered.length !== all.length
    ? pg.total + ' of ' + all.length + ' tables'
    : all.length + ' tables';

  lowContent.innerHTML =
    '<div class="pii-low-conf-panel">' +
    '<p class="pii-low-conf-intro">These tables had <strong>medium or low</strong> confidence PII signals. They are not shown in the Data Scan table above because matches did not meet the high-confidence threshold.</p>' +
    '<div class="pii-low-conf-toolbar">' +
    '<label class="pii-low-conf-search-wrap"><span class="pii-low-conf-search-icon" aria-hidden="true">⌕</span>' +
    '<input type="search" id="pii-low-conf-search" class="pii-low-conf-search" placeholder="Filter tables…" autocomplete="off" value="' + escapeHtml(piiLowConfFilter.search) + '" /></label>' +
    '<span class="pii-low-conf-showing">' + escapeHtml(showingText) + '</span></div>' +
    '<div class="pii-low-conf-grid">' +
    (pg.items.length ? renderPiiLowConfChips(pg.items, schema) : '<p class="pii-empty-hint" style="margin:0;">No tables match this filter.</p>') +
    '</div></div>';

  bindPiiLowConfToolbarOnce();
  mountTablePagination(pagerEl, {
    page: pg.page, totalPages: pg.totalPages, total: pg.total,
    start: pg.start, end: pg.end, pageSize: pg.pageSize,
    pageSizes: [24, 48, 96],
    onPage:     (p) => { piiLowConfPager.page = p; renderLowConfSection(schema); },
    onPageSize: (s) => { piiLowConfPager.pageSize = s; piiLowConfPager.page = 1; renderLowConfSection(schema); },
  });
}

function renderPiiResults() {
  const schema      = piiCatalog.schema || 'public';
  const dataDisplay = buildPiiDisplayRows(piiCatalog.rows, schema);
  const dataBody    = document.getElementById('pii-data-tbody');
  const dataPagerEl = document.getElementById('pii-data-pagination');
  const noData      = document.getElementById('pii-no-data');
  const metaBlock   = document.getElementById('pii-meta-scan-block');
  const metaBody    = document.getElementById('pii-meta-tbody');
  const metaPagerEl = document.getElementById('pii-meta-pagination');
  const lowBlock    = document.getElementById('pii-low-conf-block');
  const summaryEl   = document.getElementById('pii-results-summary');

  if (!piiCatalog.available) {
    if (summaryEl) summaryEl.innerHTML = '';
    setDataTableVisible(false);
    if (dataBody) dataBody.innerHTML = '';
    hidePager('pii-data-pagination'); hidePager('pii-meta-pagination'); hidePager('pii-low-conf-pagination');
    if (noData) { noData.style.display = 'block'; noData.innerHTML = renderPiiEmptyState(piiCatalog.message || 'No PII scan results yet.', 'Run the PII scanner and refresh this page.'); }
    if (metaBlock) metaBlock.style.display = 'none';
    if (lowBlock)  lowBlock.style.display  = 'none';
    return;
  }

  if (summaryEl) summaryEl.innerHTML = renderPiiSummaryBar({
    tables:       countPiiTables(piiCatalog.rows, piiCatalog.meta),
    dataFindings: piiCatalog.rows.length,
    metaFindings: piiCatalog.meta.length,
    lowConf:      piiCatalog.lowConf.length,
  });

  if (dataDisplay.length) {
    const pg = paginateSlice(dataDisplay, piiDataPager.page, piiDataPager.pageSize);
    piiDataPager.page = pg.page;
    setDataTableVisible(true);
    if (dataBody) dataBody.innerHTML = renderPiiDataTableRows(pg.items);
    if (noData)   noData.style.display = 'none';
    mountTablePagination(dataPagerEl, {
      page: pg.page, totalPages: pg.totalPages, total: pg.total,
      start: pg.start, end: pg.end, pageSize: pg.pageSize,
      pageSizes: [15, 25, 50],
      onPage:     (p) => { piiDataPager.page = p; renderPiiResults(); },
      onPageSize: (s) => { piiDataPager.pageSize = s; piiDataPager.page = 1; renderPiiResults(); },
    });
  } else {
    setDataTableVisible(false);
    if (dataBody) dataBody.innerHTML = '';
    hidePager('pii-data-pagination');
    if (noData) { noData.style.display = 'block'; noData.innerHTML = renderPiiEmptyState('No high-confidence PII found in data scan.', 'Try <code>deepscan</code> run option.'); }
  }

  if (metaBlock && metaBody) {
    if (piiCatalog.meta.length) {
      const pg = paginateSlice(piiCatalog.meta, piiMetaPager.page, piiMetaPager.pageSize);
      piiMetaPager.page = pg.page;
      metaBlock.style.display = 'block';
      metaBody.innerHTML = renderPiiMetaTableRows(pg.items, schema);
      mountTablePagination(metaPagerEl, {
        page: pg.page, totalPages: pg.totalPages, total: pg.total,
        start: pg.start, end: pg.end, pageSize: pg.pageSize,
        pageSizes: [15, 25, 50],
        onPage:     (p) => { piiMetaPager.page = p; renderPiiResults(); },
        onPageSize: (s) => { piiMetaPager.pageSize = s; piiMetaPager.page = 1; renderPiiResults(); },
      });
    } else {
      metaBlock.style.display = 'none';
      hidePager('pii-meta-pagination');
    }
  }

  if (lowBlock) {
    piiCatalog.lowConf.length ? renderLowConfSection(schema) : (lowBlock.style.display = 'none');
  }
}

// ── Dropdown logic ─────────────────────────────────────────────────────────────

function populateInstanceSelect() {
  // No-op: instance is typed in as a text input
}

function populateDatabaseSelect(instance) {
  const select = document.getElementById('pii-database-select');
  if (!select) return;
  if (!instance) {
    select.disabled = true;
    return;
  }
  select.disabled = false;
}

async function loadForSelection() {
  const instanceVal = document.getElementById('pii-instance-select')?.value;
  const database    = document.getElementById('pii-database-select')?.value;
  const statusEl    = document.getElementById('pii-scan-target');

  if (!instanceVal || !database) {
    if (statusEl) statusEl.innerHTML = 'Select instance and database to view PII results.';
    piiCatalog = { rows: [], meta: [], lowConf: [], schema: 'public', runOption: '', status: '', available: false, message: '' };
    renderPiiResults();
    return;
  }

  const parts = instanceVal.split(':');
  const host  = parts[0];
  const port  = parts[1] || '5432';

  if (statusEl) statusEl.innerHTML = 'Scanning…';

  try {
    const res = await fetch(API_BASE + '/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        host,
        port,
        user:       document.getElementById('pii-pg-user')?.value     || 'postgres',
        password:   document.getElementById('pii-pg-password')?.value || '',
        database,
        schema:     'public',
        run_option: 'datascan',
      }),
    });

    const data = await res.json();
    piiDataPager.page = 1; piiMetaPager.page = 1; piiLowConfPager.page = 1;
    piiLowConfFilter.search = '';
    piiCatalog = {
      available:  data.available,
      schema:     data.schema     || 'public',
      runOption:  data.run_option || 'datascan',
      rows:       data.rows       || [],
      meta:       data.meta       || [],
      lowConf:    data.low_conf   || [],
      message:    data.message    || '',
    };
  } catch (err) {
    piiCatalog = { rows: [], meta: [], lowConf: [], schema: 'public', runOption: '', available: false, message: 'API error: ' + err.message };
  }

  if (statusEl) {
    const run = piiCatalog.runOption ? ' · <code>' + escapeHtml(piiCatalog.runOption) + '</code>' : '';
    statusEl.innerHTML = piiCatalog.available
      ? '<strong>' + escapeHtml(instanceVal) + '</strong> · database <code class="pii-db-badge">' + escapeHtml(database) + '</code>' + run + ' — Results from DPA scanner'
      : escapeHtml(piiCatalog.message || 'No results');
  }

  renderPiiResults();
}

// ── Init ───────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('pii-instance-select')?.addEventListener('blur', (e) => {
    populateDatabaseSelect(e.target.value);
    loadForSelection();
  });

  document.getElementById('pii-database-select')?.addEventListener('blur', () => {
    loadForSelection();
  });

  document.getElementById('pii-refresh-btn')?.addEventListener('click', loadForSelection);
});