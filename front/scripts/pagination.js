/**
 * Client-side table pagination (fleet category and other large tables).
 */

export function paginateSlice(items, page, pageSize) {
  const total = items?.length || 0;
  const size = Math.max(1, pageSize || 15);
  const pages = Math.max(1, Math.ceil(total / size));
  const current = Math.min(Math.max(1, page || 1), pages);
  const startIdx = (current - 1) * size;
  const endIdx = Math.min(startIdx + size, total);
  return {
    items: total ? items.slice(startIdx, endIdx) : [],
    page: current,
    pageSize: size,
    total,
    totalPages: pages,
    start: total ? startIdx + 1 : 0,
    end: endIdx,
  };
}

function pageWindow(current, totalPages, maxButtons = 7) {
  if (totalPages <= maxButtons) {
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }
  const half = Math.floor(maxButtons / 2);
  let start = Math.max(1, current - half);
  let end = start + maxButtons - 1;
  if (end > totalPages) {
    end = totalPages;
    start = end - maxButtons + 1;
  }
  const pages = [];
  for (let p = start; p <= end; p++) pages.push(p);
  return pages;
}

/**
 * @param {HTMLElement} container
 * @param {{
 *   page: number,
 *   totalPages: number,
 *   total: number,
 *   start: number,
 *   end: number,
 *   pageSize: number,
 *   pageSizes?: number[],
 *   onPage: (page: number) => void,
 *   onPageSize?: (size: number) => void,
 * }} opts
 */
export function mountTablePagination(container, opts) {
  if (!container) return;
  const {
    page,
    totalPages,
    total,
    start,
    end,
    pageSize,
    pageSizes = [15, 25, 50],
    onPage,
    onPageSize,
  } = opts;

  if (total <= 0) {
    container.hidden = true;
    container.innerHTML = '';
    return;
  }

  container.hidden = false;
  const info =
    total === 0
      ? 'No rows'
      : `Showing <strong>${start}–${end}</strong> of <strong>${total}</strong>`;

  const pages = pageWindow(page, totalPages);
  const pageBtns = pages
    .map(
      (p) =>
        `<button type="button" class="table-pagination__btn${p === page ? ' active' : ''}" data-page="${p}" aria-label="Page ${p}"${p === page ? ' aria-current="page"' : ''}>${p}</button>`,
    )
    .join('');

  const sizeBtns = pageSizes
    .map(
      (s) =>
        `<button type="button" class="table-pagination__size${s === pageSize ? ' active' : ''}" data-size="${s}">${s} / page</button>`,
    )
    .join('');

  container.innerHTML =
    `<div class="table-pagination__info">${info}</div>` +
    '<div class="table-pagination__controls">' +
    (onPageSize ? `<div class="table-pagination__sizes">${sizeBtns}</div>` : '') +
    '<nav class="table-pagination__nav" aria-label="Table pages">' +
    `<button type="button" class="table-pagination__btn" data-page="prev" ${page <= 1 ? 'disabled' : ''}>Prev</button>` +
    (pages[0] > 1 ? '<button type="button" class="table-pagination__btn" data-page="1">1</button><span class="table-pagination__ellipsis">…</span>' : '') +
    pageBtns +
    (pages[pages.length - 1] < totalPages
      ? '<span class="table-pagination__ellipsis">…</span><button type="button" class="table-pagination__btn" data-page="' +
        totalPages +
        '">' +
        totalPages +
        '</button>'
      : '') +
    `<button type="button" class="table-pagination__btn" data-page="next" ${page >= totalPages ? 'disabled' : ''}>Next</button>` +
    '</nav></div>';

  container.onclick = (e) => {
    const btn = e.target.closest('[data-page],[data-size]');
    if (!btn || btn.disabled) return;
    if (btn.dataset.size && onPageSize) {
      onPageSize(Number(btn.dataset.size));
      return;
    }
    const raw = btn.dataset.page;
    if (raw === 'prev') onPage(page - 1);
    else if (raw === 'next') onPage(page + 1);
    else onPage(Number(raw));
  };
}
