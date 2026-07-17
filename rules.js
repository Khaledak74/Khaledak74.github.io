/* ============================================
   RULES PAGE — RENDER + FILTER LOGIC
   ============================================ */

document.addEventListener('DOMContentLoaded', function () {
    const sidebarEl   = document.getElementById('rules-sidebar');
    const listEl       = document.getElementById('rules-list');
    const countEl      = document.getElementById('rules-count');
    const activeLabelEl = document.getElementById('active-filter-label');

    let activeFilter = 'ALL';

    /* ---------- Build sidebar ---------- */
    function buildSidebar() {
        // group techniques by tactic, preserving TACTIC_ORDER
        const groups = {};
        TECHNIQUES.forEach(t => {
            if (t.id === 'ALL') return;
            if (!groups[t.tactic]) groups[t.tactic] = [];
            groups[t.tactic].push(t);
        });

        let html = `
            <button class="mitre-tab mitre-tab-all active" data-id="ALL">
                <span class="mitre-tab-id">ALL</span>
                <span class="mitre-tab-name">All Techniques</span>
            </button>`;

        TACTIC_ORDER.forEach(tacticName => {
            if (tacticName === 'Correlation') return; // umbrella handled separately, always pinned
            const items = groups[tacticName];
            if (!items || !items.length) return;
            const meta = TACTIC_META[tacticName] || { color: 'cyan', label: tacticName };

            html += `<div class="mitre-group">
                <div class="mitre-group-title tactic-${meta.color}">${meta.label}</div>`;

            items.forEach(t => {
                const ruleCount = RULES.filter(r => !r.isUmbrella && r.techniqueId === t.id).length;
                html += `
                    <button class="mitre-tab tactic-border-${meta.color}" data-id="${t.id}">
                        <span class="mitre-tab-id">${t.id}</span>
                        <span class="mitre-tab-name">${t.name}</span>
                        <span class="mitre-tab-count">${ruleCount}</span>
                    </button>`;
            });

            html += `</div>`;
        });

        sidebarEl.innerHTML = html;

        sidebarEl.querySelectorAll('.mitre-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                sidebarEl.querySelectorAll('.mitre-tab').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeFilter = btn.getAttribute('data-id');
                renderRules();
            });
        });
    }

    /* ---------- Build a single rule card ---------- */
    function ruleCard(rule) {
        const sevClass = 'sev-' + severityBucket(rule.severity);
        const meta = TACTIC_META[rule.tactic] || { color: 'cyan', label: rule.tactic };

        const umbrellaClass = rule.isUmbrella ? 'rule-card umbrella-card' : 'rule-card';
        const numberLabel = rule.isUmbrella ? 'CORRELATION' : ('Rule ' + rule.num);

        const sysmonNote = rule.sysmonNote
            ? `<div class="sysmon-note">⚠ ${escapeHtml(rule.sysmonNote)}</div>`
            : '';

        return `
        <article class="${umbrellaClass}" data-technique="${rule.techniqueId}">
            <div class="rule-card-header">
                <div class="rule-card-titles">
                    <span class="rule-number mono">${numberLabel}</span>
                    <h3 class="mono">${escapeHtml(rule.title)}</h3>
                </div>
                <div class="rule-card-badges">
                    <span class="badge-mitre tactic-badge-${meta.color}">${escapeHtml(rule.techniqueId)}</span>
                    <span class="badge-sev ${sevClass}">${escapeHtml(rule.severity)}</span>
                </div>
            </div>

            <div class="rule-card-meta mono">
                <span>${escapeHtml(rule.techniqueName)}</span>
                <span class="dot">•</span>
                <span class="tactic-text tactic-${meta.color}">${escapeHtml(rule.tactic)}</span>
            </div>

            ${sysmonNote}

            <p class="rule-catches">${escapeHtml(rule.catches)}</p>

            ${rule.note ? `<p class="rule-extra-note">${escapeHtml(rule.note)}</p>` : ''}

            <div class="spl-block">
                <div class="spl-toolbar">
                    <span class="spl-label mono">splunk query</span>
                    <div class="spl-actions">
                        <button class="spl-btn spl-toggle" type="button">Show SPL ▾</button>
                        <button class="spl-btn spl-copy" type="button">Copy</button>
                    </div>
                </div>
                <pre class="spl-code" hidden><code></code></pre>
            </div>
        </article>`;
    }

    function severityBucket(sevText) {
        const s = sevText.toLowerCase();
        if (s.includes('critical')) return 'critical';
        if (s.includes('high')) return 'high';
        if (s.includes('medium') || s.includes('dynamic')) return 'medium';
        return 'low';
    }

    function escapeHtml(str) {
        return String(str)
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;');
    }

    /* ---------- Render list ---------- */
    function renderRules() {
        const umbrella = RULES.find(r => r.isUmbrella);
        let visible;

        if (activeFilter === 'ALL') {
            visible = RULES.filter(r => !r.isUmbrella);
            activeLabelEl.textContent = 'All Techniques';
        } else {
            visible = RULES.filter(r => !r.isUmbrella && r.techniqueId === activeFilter);
            const t = TECHNIQUES.find(t => t.id === activeFilter);
            activeLabelEl.textContent = t ? `${t.id} — ${t.name}` : activeFilter;
        }

        countEl.textContent = visible.length + (visible.length === 1 ? ' rule' : ' rules');

        // Umbrella is always pinned at the top regardless of filter
        let html = ruleCard(umbrella);
        html += visible.map(ruleCard).join('');

        listEl.innerHTML = html;

        // insert SPL text safely via textContent (avoids HTML-escaping headaches)
        listEl.querySelectorAll('.rule-card').forEach((cardEl, idx) => {
            const rule = idx === 0 ? umbrella : visible[idx - 1];
            const codeEl = cardEl.querySelector('.spl-code code');
            codeEl.textContent = rule.spl;
        });

        attachCardHandlers();

        // scroll reveal (reuse main.js style behavior)
        listEl.querySelectorAll('.rule-card').forEach(el => {
            el.style.opacity = '1';
            el.style.transform = 'none';
        });
    }

    function attachCardHandlers() {
        listEl.querySelectorAll('.rule-card').forEach(card => {
            const toggleBtn = card.querySelector('.spl-toggle');
            const copyBtn   = card.querySelector('.spl-copy');
            const pre       = card.querySelector('.spl-code');

            toggleBtn.addEventListener('click', () => {
                const isHidden = pre.hasAttribute('hidden');
                if (isHidden) {
                    pre.removeAttribute('hidden');
                    toggleBtn.textContent = 'Hide SPL ▴';
                } else {
                    pre.setAttribute('hidden', '');
                    toggleBtn.textContent = 'Show SPL ▾';
                }
            });

            copyBtn.addEventListener('click', () => {
                const text = pre.querySelector('code').textContent;
                navigator.clipboard.writeText(text).then(() => {
                    const original = copyBtn.textContent;
                    copyBtn.textContent = 'Copied ✓';
                    copyBtn.classList.add('copied');
                    setTimeout(() => {
                        copyBtn.textContent = original;
                        copyBtn.classList.remove('copied');
                    }, 1500);
                });
            });
        });
    }

    buildSidebar();
    renderRules();

    // Umbrella card SPL expanded by default (it's the highlight rule)
    const firstPre = listEl.querySelector('.umbrella-card .spl-code');
    const firstToggle = listEl.querySelector('.umbrella-card .spl-toggle');
    if (firstPre && firstToggle) {
        firstPre.removeAttribute('hidden');
        firstToggle.textContent = 'Hide SPL ▴';
    }
});
