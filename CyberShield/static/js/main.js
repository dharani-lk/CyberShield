// static/js/main.js

// =============== GLOBAL STATE ===============
const toastContainerId = 'toastContainer';
const loadingOverlayId = 'loadingOverlay';
let toastQueue = [];
let toastActive = false;

// =============== UTILITIES ===============
function $(selector, scope = document) {
  return scope.querySelector(selector);
}
function $all(selector, scope = document) {
  return Array.from(scope.querySelectorAll(selector));
}
function safeText(s) {
  return String(s == null ? '' : s);
}

// =============== SIDEBAR & NAV ===============
(function initSidebar() {
  const sidebar = $('#sidebar');
  const sidebarToggle = $('#sidebarToggle');
  const mobileMenuBtn = $('#mobileMenuBtn');

  if (!sidebar) return;

  const collapsedClass = 'collapsed';
  const mobileOpenClass = 'mobile-open';

  function toggleSidebar() {
    sidebar.classList.toggle(collapsedClass);
    // Persist preference (desktop only)
    if (window.innerWidth >= 992) {
      const collapsed = sidebar.classList.contains(collapsedClass);
      try {
        localStorage.setItem('cs_sidebar_collapsed', collapsed ? '1' : '0');
      } catch {}
    }
  }

  function toggleMobileSidebar() {
    sidebar.classList.toggle(mobileOpenClass);
  }

  // Restore preference
  try {
    const pref = localStorage.getItem('cs_sidebar_collapsed');
    if (pref === '1' && window.innerWidth >= 992) {
      sidebar.classList.add(collapsedClass);
    }
  } catch {}

  sidebarToggle && sidebarToggle.addEventListener('click', toggleSidebar);
  mobileMenuBtn && mobileMenuBtn.addEventListener('click', toggleMobileSidebar);

  // Close on outside click (mobile)
  document.addEventListener('click', (e) => {
    if (window.innerWidth < 992) {
      if (!sidebar.contains(e.target) && e.target !== mobileMenuBtn) {
        sidebar.classList.remove(mobileOpenClass);
      }
    }
  });

  // Close on ESC (mobile)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      sidebar.classList.remove(mobileOpenClass);
    }
  });
})();

// =============== LOADING OVERLAY ===============
function showLoading(message = 'Analyzing...') {
  const overlay = $('#' + loadingOverlayId);
  if (!overlay) return;
  const textEl = overlay.querySelector('.loading-text');
  if (textEl) textEl.textContent = message;
  overlay.style.display = 'flex';
  overlay.setAttribute('aria-busy', 'true');
}
function hideLoading() {
  const overlay = $('#' + loadingOverlayId);
  if (!overlay) return;
  overlay.style.display = 'none';
  overlay.removeAttribute('aria-busy');
}

// =============== TOAST NOTIFICATIONS ===============
function ensureToastContainer() {
  let el = $('#' + toastContainerId);
  if (!el) {
    el = document.createElement('div');
    el.id = toastContainerId;
    el.className = 'toast-container';
    document.body.appendChild(el);
  }
  return el;
}

function showToast(message, type = 'info', opts = {}) {
  const duration = opts.duration ?? 3500;
  toastQueue.push({ message, type, duration });
  if (!toastActive) {
    renderNextToast();
  }
}

function renderNextToast() {
  if (toastQueue.length === 0) {
    toastActive = false;
    return;
  }
  toastActive = true;

  const { message, type, duration } = toastQueue.shift();
  const container = ensureToastContainer();
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');

  toast.innerHTML = `
    <div class="toast-icon">${toastIcon(type)}</div>
    <div class="toast-message">${safeText(message)}</div>
    <button class="toast-close" aria-label="Close">&times;</button>
  `;

  container.appendChild(toast);

  const close = () => {
    toast.classList.add('toast-hide');
    setTimeout(() => {
      toast.remove();
      renderNextToast();
    }, 200);
  };

  toast.querySelector('.toast-close').addEventListener('click', close);

  setTimeout(close, duration);
}

function toastIcon(type) {
  switch (type) {
    case 'success': return '<i class="fas fa-check-circle"></i>';
    case 'error': return '<i class="fas fa-times-circle"></i>';
    case 'warning': return '<i class="fas fa-exclamation-triangle"></i>';
    default: return '<i class="fas fa-info-circle"></i>';
  }
}

// =============== DRAG & DROP HELPERS ===============
function wireDropZone(zoneEl, options) {
  // options: { onFile, multiple=false }
  if (!zoneEl) return;
  const fileInput = zoneEl.querySelector('input[type="file"]');

  const pick = () => fileInput && fileInput.click();

  zoneEl.addEventListener('click', pick);

  zoneEl.addEventListener('dragover', (e) => {
    e.preventDefault();
    zoneEl.classList.add('dragover');
  });

  zoneEl.addEventListener('dragleave', () => {
    zoneEl.classList.remove('dragover');
  });

  zoneEl.addEventListener('drop', (e) => {
    e.preventDefault();
    zoneEl.classList.remove('dragover');
    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;
    if (options?.onFile) {
      if (options.multiple) {
        options.onFile(files);
      } else {
        options.onFile(files[0]);
      }
    }
  });

  if (fileInput) {
    fileInput.addEventListener('change', (e) => {
      const files = e.target.files;
      if (!files || files.length === 0) return;
      if (options?.onFile) {
        if (options.multiple) {
          options.onFile(files);
        } else {
          options.onFile(files[0]);
        }
      }
    });
  }
}

// =============== COMMON HELPERS USED BY PAGES ===============
function animateValue(element, start, end, duration) {
  if (!element) return;
  const startTime = performance.now();
  const clamp = (n, min, max) => Math.min(Math.max(n, min), max);

  function update(now) {
    const elapsed = now - startTime;
    const t = clamp(elapsed / duration, 0, 1);
    // easeOutCubic
    const eased = 1 - Math.pow(1 - t, 3);
    const value = Math.floor(start + eased * (end - start));
    element.textContent = value;
    if (t < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}

function getSeverityIcon(severity) {
  const map = {
    low: 'info-circle',
    medium: 'exclamation-circle',
    high: 'exclamation-triangle',
    critical: 'skull-crossbones',
  };
  return map[severity] || 'info-circle';
}

function formatType(type) {
  // turns "brandimpersonation" or "excessive_subdomains" into "Brand Impersonation" etc.
  return String(type || '')
    .replace(/[_-]+/g, ' ')
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/\b\w/g, (m) => m.toUpperCase())
    .trim();
}

// =============== ACCESSIBILITY & SMALL UX ===============
(function initFocusOutline() {
  // Show focus outlines only when using keyboard
  function handleMouseDown() {
    document.body.classList.add('using-mouse');
  }
  function handleKeyDown(e) {
    if (e.key === 'Tab') {
      document.body.classList.remove('using-mouse');
    }
  }
  document.addEventListener('mousedown', handleMouseDown);
  document.addEventListener('keydown', handleKeyDown);
})();

(function initCopyButtons() {
  // Delegate copy-to-clipboard for any element with data-copy-target
  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-copy-target]');
    if (!btn) return;
    const selector = btn.getAttribute('data-copy-target');
    const target = selector ? document.querySelector(selector) : null;
    const text =
      target?.value ??
      target?.textContent ??
      btn.getAttribute('data-copy-text');

    if (!text) return;

    try {
      await navigator.clipboard.writeText(text.trim());
      showToast('Copied to clipboard!', 'success');
    } catch {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text.trim();
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        showToast('Copied to clipboard!', 'success');
      } catch {
        showToast('Copy failed', 'error');
      } finally {
        document.body.removeChild(ta);
      }
    }
  });
})();

// =============== PARTICLES (DECORATION) ===============
(function initParticles() {
  const container = document.getElementById('particles');
  if (!container) return;
  // If template didn't include six spans, add them
  if (container.children.length === 0) {
    for (let i = 0; i < 12; i++) {
      const s = document.createElement('span');
      s.style.left = `${Math.floor(Math.random() * 95) + 2}%`;
      s.style.animationDelay = `${Math.random() * 12}s`;
      container.appendChild(s);
    }
  }
})();

// =============== EXPORTS TO WINDOW (if needed by inline scripts) ===============
window.showToast = showToast;
window.showLoading = showLoading;
window.hideLoading = hideLoading;
window.animateValue = animateValue;
window.getSeverityIcon = getSeverityIcon;
window.formatType = formatType;
window.wireDropZone = wireDropZone;
