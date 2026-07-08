/* EXCITE plus Vital DB Research Platform
   Front-end prototype logic: localStorage 기반으로 서버 연결 전 기능을 검증합니다.
   실제 배포 시 saveState/loadState 부분을 API 호출로 교체하면 됩니다. */
(function () {
  const STORE_KEY = 'excite_plus_vitaldb_state_v2';
  const USER = '로그인 사용자';
  const BOOTSTRAP_ADMIN = {
    id: 'USER_BOOTSTRAP_ADMIN',
    name: '초기 관리자',
    username: 'Admin_cs',
    email: '',
    passwordHash: '09eeb0a88f80b448f7f65547ea67712f0e0e402219435e58c8256ad325f28a67',
    role: 'Admin',
    affiliation: 'EXCITE',
    status: '활성',
    createdAt: 'bootstrap',
    lastLogin: '-'
  };

  const DEFAULT_STATE = {
    tags: [],
    axes: [],
    vitalFiles: [],
    variables: [],
    variableDefinitions: [],
    assignments: [],
    analyses: [],
    users: [],
    signupRequests: [],
    audit: [],
    csvConversions: [],
    vitalConversions: [],
    patients: [],
    studyPatients: [],
    projects: [],
    tagTrees: [],
    tagTreeView: { showPatients: true, showCsv: true },
    monitorAssignments: [],
    monitorRooms: ['SICU', 'CCU', '이동형']
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  function ensureBootstrapAdmin(state) {
    if (!Array.isArray(state.users)) state.users = [];
    const existing = state.users.find(u => u.id === BOOTSTRAP_ADMIN.id || (u.username || '').toLowerCase() === BOOTSTRAP_ADMIN.username.toLowerCase());
    if (existing) {
      delete existing.password;
      Object.assign(existing, BOOTSTRAP_ADMIN);
    } else {
      state.users.unshift(Object.assign({}, BOOTSTRAP_ADMIN));
    }
    return state;
  }

  function readState() {
    try {
      const parsed = JSON.parse(localStorage.getItem(STORE_KEY));
      return ensureBootstrapAdmin(Object.assign({}, DEFAULT_STATE, parsed || {}));
    } catch (error) {
      console.warn('state read failed', error);
      return ensureBootstrapAdmin(structuredClone(DEFAULT_STATE));
    }
  }

  function writeState(state) {
    localStorage.setItem(STORE_KEY, JSON.stringify(state));
  }

  function patchState(mutator) {
    const state = readState();
    mutator(state);
    writeState(state);
    return state;
  }

  function uid(prefix) {
    return `${prefix}_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 7)}`.toUpperCase();
  }

  function nowText() {
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }

  function sha256Fallback(value) {
    const bytes = new TextEncoder().encode(String(value || ''));
    const bitLength = BigInt(bytes.length) * 8n;
    const paddingLength = (64 - ((bytes.length + 1 + 8) % 64)) % 64;
    const data = new Uint8Array(bytes.length + 1 + paddingLength + 8);
    data.set(bytes);
    data[bytes.length] = 0x80;
    let remaining = bitLength;
    for (let index = 0; index < 8; index += 1) {
      data[data.length - 1 - index] = Number(remaining & 0xffn);
      remaining >>= 8n;
    }
    const constants = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    const hash = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    const rotateRight = (value32, count) => (value32 >>> count) | (value32 << (32 - count));
    const words = new Uint32Array(64);
    for (let offset = 0; offset < data.length; offset += 64) {
      for (let index = 0; index < 16; index += 1) {
        const pos = offset + index * 4;
        words[index] = ((data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]) >>> 0;
      }
      for (let index = 16; index < 64; index += 1) {
        const s0 = rotateRight(words[index - 15], 7) ^ rotateRight(words[index - 15], 18) ^ (words[index - 15] >>> 3);
        const s1 = rotateRight(words[index - 2], 17) ^ rotateRight(words[index - 2], 19) ^ (words[index - 2] >>> 10);
        words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
      }
      let [a,b,c,d,e,f,g,h] = hash;
      for (let index = 0; index < 64; index += 1) {
        const sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
        const choice = (e & f) ^ (~e & g);
        const temp1 = (h + sigma1 + choice + constants[index] + words[index]) >>> 0;
        const sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (sigma0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      hash[0] = (hash[0] + a) >>> 0; hash[1] = (hash[1] + b) >>> 0;
      hash[2] = (hash[2] + c) >>> 0; hash[3] = (hash[3] + d) >>> 0;
      hash[4] = (hash[4] + e) >>> 0; hash[5] = (hash[5] + f) >>> 0;
      hash[6] = (hash[6] + g) >>> 0; hash[7] = (hash[7] + h) >>> 0;
    }
    return hash.map(word => word.toString(16).padStart(8, '0')).join('');
  }

  async function sha256Text(value) {
    if (globalThis.crypto?.subtle) {
      try {
        const bytes = new TextEncoder().encode(String(value || ''));
        const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
        return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
      } catch (error) {
        console.warn('Web Crypto SHA-256 unavailable; using local fallback.', error);
      }
    }
    return sha256Fallback(value);
  }

  function escapeHtml(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#039;');
  }

  function formatBytes(bytes) {
    const n = Number(bytes || 0);
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
  }

  function badge(text, tone = 'gray') {
    return `<span class="badge ${tone}">${escapeHtml(text)}</span>`;
  }

  function normalizeTagColor(color) {
    const named = { Navy: '#0b1f3a', Teal: '#0b8f8a', Blue: '#1d5d9b', Gray: '#66768c', Warning: '#9a5b00' };
    const value = String(color || '').trim();
    if (/^#[0-9a-fA-F]{6}$/.test(value)) return value;
    return named[value] || '#0b8f8a';
  }

  function tagBadge(tagOrName) {
    const tag = typeof tagOrName === 'object' ? tagOrName : null;
    const name = tag ? tag.name : tagOrName;
    const color = normalizeTagColor(tag?.color);
    return `<span class="badge tag-badge-custom" style="background:${color};border-color:${color};color:#fff">${escapeHtml(name)}</span>`;
  }

  function colorSwatch(color) {
    const value = normalizeTagColor(color);
    return `<span class="tag-color-cell"><i style="background:${value}"></i><code>${escapeHtml(value)}</code></span>`;
  }

  function addAudit(action, target, description) {
    patchState(state => {
      state.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: USER, action, target, description, status: 'success' });
      state.audit = state.audit.slice(0, 200);
    });
  }

  function toast(message, tone = 'teal') {
    let wrap = $('#toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.id = 'toast-wrap';
      wrap.className = 'toast-wrap';
      document.body.appendChild(wrap);
    }
    const el = document.createElement('div');
    el.className = `toast ${tone}`;
    el.textContent = message;
    wrap.appendChild(el);
    setTimeout(() => el.classList.add('show'), 10);
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 220);
    }, 2600);
  }

  function downloadText(filename, content, mime = 'text/plain;charset=utf-8') {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  function currentPage() {
    return location.pathname.split('/').pop() || 'dashboard.html';
  }

  function cardByHeading(text) {
    return $$('.card').find(card => {
      const h = $('h3', card);
      return h && h.textContent.trim().includes(text);
    });
  }

  function setMetricByLabel(labelText, valueText, deltaText) {
    const cards = $$('.card.metric');
    const card = cards.find(c => $('.label', c)?.textContent.includes(labelText));
    if (!card) return;
    const value = $('.value', card);
    const delta = $('.delta', card);
    if (value) value.textContent = valueText;
    if (delta && deltaText) delta.textContent = deltaText;
  }

  function setTableEmpty(tbody, colspan, title, msg) {
    if (!tbody) return;
    tbody.innerHTML = `<tr class="empty-row"><td colspan="${colspan}"><strong>${escapeHtml(title)}</strong><br><span>${escapeHtml(msg)}</span></td></tr>`;
  }

  function option(value, text, selected = false) {
    return `<option value="${escapeHtml(value)}"${selected ? ' selected' : ''}>${escapeHtml(text)}</option>`;
  }

  function fillTagSelect(select, placeholder = '등록된 연구 태그가 없습니다.') {
    if (!select) return;
    const state = readState();
    if (!state.tags.length) {
      select.innerHTML = option('', placeholder);
      return;
    }
    const previous = select.value;
    select.innerHTML = option('', '연구 태그 선택') + state.tags.map(t => option(t.id, t.name, previous === t.id)).join('');
  }

  function axesForTag(tagId) {
    const state = readState();
    return state.axes.filter(a => a.tagId === tagId);
  }

  function valuesForAxis(tagId, axisName) {
    const axis = axesForTag(tagId).find(a => a.name.toLowerCase() === axisName.toLowerCase() || a.name.includes(axisName));
    return axis ? axis.values || [] : [];
  }

  function axisValueOptions(tagId, keywords, fallback = '등록된 표준값 없음') {
    const axes = axesForTag(tagId);
    const matched = axes.find(axis => keywords.some(k => axis.name.toLowerCase().includes(k.toLowerCase())));
    if (!matched || !matched.values?.length) return option('', fallback) + option('__direct__', '직접 작성 후 등록');
    return option('', '선택 안 함') + matched.values.map(v => option(v.label, v.label)).join('') + option('__direct__', '직접 작성 후 등록');
  }

  function selectedText(select) {
    if (!select) return '';
    const opt = select.options[select.selectedIndex];
    return opt && select.value ? opt.textContent.trim() : '';
  }

  function removeDisabledAction(el) {
    if (el) el.removeAttribute('data-disabled-action');
  }

  const WORKSPACE_NAV_ITEMS = [
    { href: 'workplace.html', title: '작업공간 홈', description: '전체 업무 흐름과 바로가기' },
    { href: 'patient-upload.html', title: '환자/검사 정보 입력', description: '환자 master, ECMO episode, 검사' },
    { href: 'vital-upload.html', title: 'Raw CSV 업로드', description: '업로드 즉시 변환 및 QC' },
    { href: 'patient-matching.html', title: '환자–CSV 통합 관리', description: '환자·episode·CSV 연결 및 순서 설정' },
    { href: 'tag-assignment.html', title: '태그 부여', description: '환자에게 연구 태그와 분류값 적용' },
    { href: 'system-info.html', title: '시스템 정보', description: '분석환경과 파이프라인 버전' }
  ];

  function normalizeWorkspaceNavigation() {
    const dropdown = $('.dropdown-content');
    if (dropdown) {
      dropdown.innerHTML = WORKSPACE_NAV_ITEMS.map(item => `<a href="${item.href}" data-href="${item.href}">${escapeHtml(item.title)}</a>`).join('');
    }
    const sidebar = $('.sidebar');
    if (sidebar) sidebar.remove();
    document.body.classList.add('workspace-topnav-only');
  }

  function commonInit() {
    normalizeWorkspaceNavigation();
    const page = currentPage();
    $$('[data-href]').forEach(a => {
      a.classList.toggle('active', a.dataset.href === page);
    });

    $$('.dropdown .dropbtn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const parent = btn.closest('.dropdown');
        $$('.dropdown.open').forEach(d => { if (d !== parent) d.classList.remove('open'); });
        parent?.classList.toggle('open');
      });
    });

  
  document.addEventListener('click', (e) => {
      if (!e.target.closest('.dropdown')) $$('.dropdown.open').forEach(d => d.classList.remove('open'));
    });
  }

  function bindFallbackDisabledButtons() {
    $$('[data-disabled-action]').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        toast(btn.dataset.disabledAction || '데이터를 먼저 등록해 주세요.', 'gray');
      });
    });
  }

  function initLogin() {
    const submit = $('#loginSubmit');
    if (!submit) return;
    submit.addEventListener('click', async () => {
      const loginId = ($('#loginEmail')?.value || '').trim();
      const loginKey = loginId.toLowerCase();
      const password = $('#loginPassword')?.value || '';
      const state = readState();
      const matchesLoginId = u => (u.username || '').toLowerCase() === loginKey || (u.email || '').toLowerCase() === loginKey;
      const user = (state.users || []).find(matchesLoginId);
      const pending = (state.signupRequests || []).find(u => (u.email || '').toLowerCase() === loginKey && u.status === '승인 대기');

      if (!loginId || !password) {
        toast('아이디와 비밀번호를 입력해 주세요.', 'yellow');
        return;
      }
      if (pending) {
        toast('아직 관리자 승인 대기 중인 계정입니다.', 'yellow');
        return;
      }
      const passwordMatches = user ? (user.passwordHash ? (await sha256Text(password)) === user.passwordHash : user.password === password) : false;
      if (user && passwordMatches && user.status === '활성') {
        patchState(s => {
          const found = (s.users || []).find(matchesLoginId);
          if (found) found.lastLogin = nowText();
        });
        localStorage.setItem('excite_plus_current_user', JSON.stringify({ name: user.name, username: user.username || '', email: user.email || '', role: user.role }));
        addAudit('login', 'user', `${user.username || user.email || user.name} 로그인`);
        location.href = 'dashboard.html';
        return;
      }
      toast('로그인 정보를 확인해 주세요.', 'gray');
    });
  }

  function initSignup() {
    const submit = $('#signupSubmit');
    if (!submit) return;
    submit.addEventListener('click', () => {
      const name = ($('#signupName')?.value || '').trim();
      const email = ($('#signupEmail')?.value || '').trim().toLowerCase();
      const password = $('#signupPassword')?.value || '';
      const confirm = $('#signupPasswordConfirm')?.value || '';
      const role = $('#signupRole')?.value || '';
      const affiliation = ($('#signupAffiliation')?.value || '').trim();
      const reason = ($('#signupReason')?.value || '').trim();

      if (!name || !email || !password || !confirm || !role) {
        toast('이름, 이메일, 비밀번호, 요청 역할은 필수입니다.', 'yellow');
        return;
      }
      if (!email.includes('@')) {
        toast('이메일 형식을 확인해 주세요.', 'yellow');
        return;
      }
      if (password !== confirm) {
        toast('비밀번호 확인이 일치하지 않습니다.', 'yellow');
        return;
      }
      const state = readState();
      const exists = [...(state.users || []), ...(state.signupRequests || [])]
        .some(u => (u.email || '').toLowerCase() === email);
      if (exists) {
        toast('이미 등록되었거나 승인 대기 중인 이메일입니다.', 'yellow');
        return;
      }

      patchState(s => {
        if (!Array.isArray(s.signupRequests)) s.signupRequests = [];
        s.signupRequests.unshift({
          id: uid('REQ'), name, email, password, role, affiliation, reason,
          status: '승인 대기', requestedAt: nowText()
        });
        s.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: name, action: 'signup request', target: 'user', description: `${email} 회원가입 신청`, status: 'pending' });
      });
      toast('회원가입 신청이 저장되었습니다. 관리자 승인 후 사용할 수 있습니다.');
      setTimeout(() => { location.href = 'login.html'; }, 900);
    });
  }

  function initMembers() {
    const state = readState();
    const memberCard = cardByHeading('구성원 목록');
    const memberBody = memberCard ? $('tbody', memberCard) : null;
    if (memberBody) {
      const rows = (state.users || []).map(u => `<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.username || u.email || '')}</td><td>${badge(u.role || 'Viewer', 'blue')}</td><td>${escapeHtml(u.affiliation || '')}</td><td>${badge(u.status || '활성', 'green')}</td><td>${escapeHtml(u.lastLogin || '-')}</td><td><button class="btn ghost" data-deactivate-user="${escapeHtml(u.id)}">비활성</button></td></tr>`).join('');
      memberBody.innerHTML = rows || `<tr class="empty-row"><td colspan="7"><strong>아직 등록된 구성원이 없습니다.</strong><br><span>회원가입 신청을 승인하면 구성원 목록에 표시됩니다.</span></td></tr>`;
    }

    const requestBody = $('#signupRequestBody');
    if (requestBody) {
      const rows = (state.signupRequests || []).map(r => `<tr><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.email)}</td><td>${badge(r.role || 'Viewer', 'gray')}</td><td>${escapeHtml(r.affiliation || '')}</td><td>${escapeHtml(r.requestedAt || '')}</td><td>${badge(r.status || '승인 대기', r.status === '승인 완료' ? 'green' : 'yellow')}</td><td><button class="btn teal" data-approve-request="${escapeHtml(r.id)}">승인</button> <button class="btn ghost" data-reject-request="${escapeHtml(r.id)}">거절</button></td></tr>`).join('');
      requestBody.innerHTML = rows || `<tr class="empty-row"><td colspan="7"><strong>아직 회원가입 신청이 없습니다.</strong><br><span>회원가입 화면에서 신청하면 이 목록에 표시됩니다.</span></td></tr>`;
    }

    $$('[data-approve-request]').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.approveRequest;
      patchState(s => {
        const idx = (s.signupRequests || []).findIndex(r => r.id === id);
        if (idx < 0) return;
        const r = s.signupRequests[idx];
        if (!Array.isArray(s.users)) s.users = [];
        s.users.unshift({
          id: uid('USER'), name: r.name, email: r.email, password: r.password,
          role: r.role || 'Viewer', affiliation: r.affiliation || '', status: '활성',
          createdAt: nowText(), lastLogin: '-'
        });
        s.signupRequests.splice(idx, 1);
        s.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: USER, action: 'member approval', target: 'user', description: `${r.email} 승인`, status: 'success' });
      });
      toast('회원가입 신청을 승인했습니다.');
      initMembers();
    }));

    $$('[data-reject-request]').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.rejectRequest;
      patchState(s => {
        const r = (s.signupRequests || []).find(x => x.id === id);
        s.signupRequests = (s.signupRequests || []).filter(x => x.id !== id);
        s.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: USER, action: 'member reject', target: 'user', description: `${r?.email || id} 거절`, status: 'success' });
      });
      toast('회원가입 신청을 거절했습니다.', 'gray');
      initMembers();
    }));

    $$('[data-deactivate-user]').forEach(btn => btn.addEventListener('click', () => {
      const id = btn.dataset.deactivateUser;
      patchState(s => {
        const user = (s.users || []).find(u => u.id === id);
        if (user) user.status = user.status === '활성' ? '비활성' : '활성';
      });
      initMembers();
    }));
  }

  function refreshDashboard() {
    const state = readState();
    const totalVital = state.vitalFiles.length;
    const error = state.vitalFiles.filter(f => f.uploadStatus === '오류').length;
    const tagged = state.vitalFiles.filter(f => (f.tagIds || []).length > 0).length;
    const untagged = state.vitalFiles.filter(f => f.uploadStatus !== '오류' && !(f.tagIds || []).length).length;
    const waitingMatch = state.vitalFiles.filter(f => f.uploadStatus !== '오류' && !f.patientId).length;
    const subjects = new Set(state.assignments.map(a => a.patientId).filter(Boolean));

    setMetricByLabel('등록된 연구대상자', `${subjects.size}명`, subjects.size ? '등록됨' : '대기');
    setMetricByLabel('업로드된 Vital 파일', `${totalVital}개`, totalVital ? '등록됨' : '대기');
    setMetricByLabel('활성 연구 태그', `${state.tags.length}개`, state.tags.length ? '등록됨' : '대기');
    setMetricByLabel('미태그 Vital 파일', `${untagged}개`, untagged ? '확인 필요' : '대기');

    const recentCard = cardByHeading('최근 업로드');
    const recentBody = recentCard ? $('tbody', recentCard) : null;
    if (recentBody) {
      const rows = state.vitalFiles.slice(0, 6).map(f => `<tr><td>${escapeHtml(f.name)}</td><td>.vital</td><td>${escapeHtml(f.uploadedBy || USER)}</td><td>${badge(f.uploadStatus || '업로드 완료', f.uploadStatus === '오류' ? 'red' : 'green')}</td></tr>`).join('');
      recentBody.innerHTML = rows || `<tr class="empty-row"><td colspan="4"><strong>아직 업로드된 파일이 없습니다.</strong><br><span>Vital 파일을 업로드하면 최근 목록에 표시됩니다.</span></td></tr>`;
    }

    const donut = $('.donut');
    if (donut) {
      const safeTotal = Math.max(totalVital, 1);
      const degTagged = tagged / safeTotal * 360;
      const degUntagged = untagged / safeTotal * 360;
      const degWaiting = waitingMatch / safeTotal * 360;
      const a = degTagged;
      const b = a + degUntagged;
      const c = b + degWaiting;
      donut.style.background = totalVital
        ? `conic-gradient(var(--teal) 0deg ${a}deg, #98a2b3 ${a}deg ${b}deg, #f79009 ${b}deg ${c}deg, #f04438 ${c}deg 360deg)`
        : 'conic-gradient(#e5ebf3 0deg 360deg)';
      const center = $('.donut-center strong', donut);
      if (center) center.textContent = String(totalVital);
    }
    const legend = $$('.legend-item strong');
    if (legend[0]) legend[0].textContent = `${tagged}개`;
    if (legend[1]) legend[1].textContent = `${untagged}개`;
    if (legend[2]) legend[2].textContent = `${waitingMatch}개`;
    if (legend[3]) legend[3].textContent = `${error}개`;

    const analysisCard = cardByHeading('분석 작업 현황');
    const analysisBody = analysisCard ? $('tbody', analysisCard) : null;
    if (analysisBody) {
      const rows = state.analyses.slice(0, 6).map(a => `<tr><td>${escapeHtml(a.name)}</td><td>${escapeHtml(a.tagName || '미선택')}</td><td>${badge(a.status || '계산 대기', 'blue')}</td><td><a class="btn ghost" href="analysis-results.html">보기</a></td></tr>`).join('');
      analysisBody.innerHTML = rows || `<tr class="empty-row"><td colspan="4"><strong>아직 실행된 분석이 없습니다.</strong><br><span>통계 분석 화면에서 분석 설정을 저장하면 표시됩니다.</span></td></tr>`;
    }
  }

  function buildPreviewDataFromFeatures(features = []) {
    if (!Array.isArray(features) || !features.length) return null;
    const candidates = ['HR','MAP','SBP','DBP','SpO2','RR','PI'];
    const output = {};
    candidates.forEach(signal => {
      const keys = Object.keys(features[0] || {});
      const key = keys.find(name => name.toLowerCase() === `${signal.toLowerCase()}_mean`) || keys.find(name => name.toLowerCase().includes(signal.toLowerCase()) && name.toLowerCase().endsWith('_mean'));
      if (!key) return;
      const points = features.map((row, index) => ({ minute: Number(row.minute_index ?? row.minute ?? index), value: Number(row[key]) })).filter(point => Number.isFinite(point.minute) && Number.isFinite(point.value));
      if (!points.length) return;
      const step = Math.max(1, Math.ceil(points.length / 360));
      output[signal] = points.filter((_, index) => index % step === 0).slice(0, 360);
    });
    return Object.keys(output).length ? output : null;
  }

  function normalizeMonitorPart(value) {
    return String(value || '').trim().toUpperCase().replace(/\s+/g, '');
  }

  function normalizeTimeText(value, fallback = '') {
    const raw = String(value || '').trim();
    if (!raw) return fallback;
    const match = raw.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
    if (!match) return fallback;
    const hour = Number(match[1]);
    const minute = Number(match[2]);
    const second = Number(match[3] || 0);
    if (hour > 23 || minute > 59 || second > 59) return fallback;
    return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}${match[3] ? `:${String(second).padStart(2, '0')}` : ''}`;
  }

  function monitorAssignmentRange(item) {
    const date = String(item?.recordingDate || '').trim();
    if (!date) return null;
    const startTime = normalizeTimeText(item?.startTime, '00:00');
    const endTime = normalizeTimeText(item?.endTime, '23:59');
    const start = safeDate(`${date}T${startTime}`);
    let end = safeDate(`${date}T${endTime}`);
    if (!start || !end) return null;
    if (end <= start) end = new Date(end.getTime() + 24 * 60 * 60 * 1000);
    return { start, end };
  }

  function parseCsvMonitorMeta(fileName) {
    const base = String(fileName || '').split(/[\\/]/).pop().replace(/\.csv$/i, '');
    const match = base.match(/^([A-Za-z가-힣]+)([0-9][A-Za-z0-9-]*)_([0-9]{6}|[0-9]{8})(?:_([0-9]{4}|[0-9]{6}))?(?:_|$)/);
    if (!match) return null;
    const room = normalizeMonitorPart(match[1]);
    const monitorNumber = normalizeMonitorPart(match[2]);
    const raw = match[3];
    const rawTime = match[4] || '';
    const year = raw.length === 6 ? Number(`20${raw.slice(0, 2)}`) : Number(raw.slice(0, 4));
    const month = raw.length === 6 ? Number(raw.slice(2, 4)) : Number(raw.slice(4, 6));
    const day = raw.length === 6 ? Number(raw.slice(4, 6)) : Number(raw.slice(6, 8));
    const date = new Date(year, month - 1, day);
    if (date.getFullYear() !== year || date.getMonth() !== month - 1 || date.getDate() !== day) return null;
    const pad = value => String(value).padStart(2, '0');
    const recordingDate = `${year}-${pad(month)}-${pad(day)}`;
    let recordingTime = '';
    if (rawTime) {
      const hour = Number(rawTime.slice(0, 2));
      const minute = Number(rawTime.slice(2, 4));
      const second = rawTime.length === 6 ? Number(rawTime.slice(4, 6)) : 0;
      if (hour <= 23 && minute <= 59 && second <= 59) recordingTime = `${pad(hour)}:${pad(minute)}:${pad(second)}`;
    }
    return {
      room,
      monitorNumber,
      monitorKey: `${room}${monitorNumber}`,
      recordingDate,
      recordingTime,
      recordingDateTime: recordingTime ? `${recordingDate}T${recordingTime}` : ''
    };
  }

  function monitorAssignmentForMeta(state, meta) {
    if (!meta) return null;
    const monitorKey = normalizeMonitorPart(meta.monitorKey || `${meta.room || ''}${meta.monitorNumber || ''}`);
    const assignments = (state.monitorAssignments || [])
      .filter(item => normalizeMonitorPart(item.monitorKey || `${item.room || ''}${item.monitorNumber || ''}`) === monitorKey)
      .slice()
      .sort((a, b) => Number(a.displayOrder || 0) - Number(b.displayOrder || 0));
    const timestamp = safeDate(meta.recordingDateTime || meta.recordingStart || '');
    if (timestamp) {
      return assignments.find(item => {
        const range = monitorAssignmentRange(item);
        return range && timestamp >= range.start && timestamp <= range.end;
      }) || null;
    }
    const sameDate = assignments.filter(item => item.recordingDate === meta.recordingDate);
    return sameDate.length === 1 ? sameDate[0] : null;
  }

  function applyMonitorAssignmentsToFiles(state) {
    if (!Array.isArray(state.monitorAssignments)) state.monitorAssignments = [];
    if (!Array.isArray(state.vitalFiles)) state.vitalFiles = [];
    if (!Array.isArray(state.monitorRooms)) state.monitorRooms = [];
    ['SICU', 'CCU', '이동형'].forEach(room => {
      if (!state.monitorRooms.some(item => normalizeMonitorPart(item) === normalizeMonitorPart(room))) state.monitorRooms.push(room);
    });
    state.monitorAssignments.forEach((item, index) => {
      if (!Number.isFinite(Number(item.displayOrder))) item.displayOrder = index;
      item.room = normalizeMonitorPart(item.room);
      item.monitorNumber = normalizeMonitorPart(item.monitorNumber);
      item.monitorKey = normalizeMonitorPart(item.monitorKey || `${item.room}${item.monitorNumber}`);
      item.startTime = normalizeTimeText(item.startTime, '00:00');
      item.endTime = normalizeTimeText(item.endTime, '23:59');
    });
    state.vitalFiles.forEach((file, index) => {
      if (!Number.isFinite(Number(file.uploadOrder))) file.uploadOrder = index;
      const parsed = parseCsvMonitorMeta(file.name);
      const baseMeta = parsed || (file.monitorKey && file.recordingDate ? {
        room: normalizeMonitorPart(file.monitorRoom),
        monitorNumber: normalizeMonitorPart(file.monitorNumber),
        monitorKey: normalizeMonitorPart(file.monitorKey),
        recordingDate: file.recordingDate,
        recordingTime: file.recordingTime || '',
        recordingDateTime: file.recordingStart || file.recordingDateTime || ''
      } : null);
      const meta = baseMeta ? Object.assign({}, baseMeta, {
        recordingDateTime: file.recordingStart || baseMeta.recordingDateTime || '',
        recordingStart: file.recordingStart || baseMeta.recordingDateTime || ''
      }) : null;
      if (!meta) {
        file.autoMatchStatus = file.patientId ? (file.autoMatchStatus || '수동 매칭') : '파일명 인식 실패';
        return;
      }
      Object.assign(file, {
        monitorRoom: meta.room,
        monitorNumber: meta.monitorNumber,
        monitorKey: meta.monitorKey,
        recordingDate: meta.recordingDate,
        recordingTime: meta.recordingTime || file.recordingTime || '',
        recordingDateTime: meta.recordingDateTime || file.recordingDateTime || ''
      });
      const assignment = monitorAssignmentForMeta(state, meta);
      const manualMatch = file.patientId && file.matchSource !== 'monitor-assignment';
      if (assignment) {
        if (!manualMatch || file.patientId === assignment.patientId) {
          file.patientId = assignment.patientId;
          file.monitorAssignmentId = assignment.id;
          file.matchSource = 'monitor-assignment';
          file.autoMatchStatus = '자동 매칭 완료';
          file.matchedAt = file.matchedAt || nowText();
        } else {
          file.monitorAssignmentId = '';
          file.autoMatchStatus = '수동 매칭 유지';
        }
      } else if (file.matchSource === 'monitor-assignment') {
        file.patientId = '';
        file.monitorAssignmentId = '';
        file.matchSource = '';
        file.autoMatchStatus = meta.recordingDateTime ? '해당 시간대 배정 없음' : '시간 확인 필요';
      } else if (!file.patientId) {
        file.monitorAssignmentId = '';
        file.autoMatchStatus = meta.recordingDateTime ? '해당 시간대 배정 없음' : '시간 확인 필요';
      }
    });
    return state;
  }

  function storedPreviewRows(file) {
    const preview = file?.previewData;
    if (!preview || typeof preview !== 'object') return [];
    const rows = new Map();
    Object.entries(preview).forEach(([signal, points]) => {
      if (!Array.isArray(points)) return;
      points.forEach((point, index) => {
        const minute = Number(point?.minute ?? point?.x ?? index);
        const value = Number(point?.value ?? point?.y ?? point);
        if (!Number.isFinite(minute) || !Number.isFinite(value)) return;
        if (!rows.has(minute)) rows.set(minute, { Minute: minute });
        rows.get(minute)[`${signal}_mean`] = value;
      });
    });
    return Array.from(rows.values()).sort((a, b) => a.Minute - b.Minute);
  }

  function initVitalUpload() {
    const flow = $('#rawCsvUploadFlow');
    if (!flow) return;

    const fileInput = $('#rawCsvAutoInput');
    const selectBtn = $('#rawCsvAutoSelectBtn');
    const dropzone = $('#rawCsvAutoDropzone');
    const progress = $('#rawCsvAutoProgress');
    const status = $('#rawCsvAutoStatus');
    const body = $('#autoCsvUploadBody');
    const qcSummary = $('#autoCsvQcSummary');
    const qcPanel = $('#autoCsvTrajectorySummary');
    const downloadFeatures = $('#autoCsvDownloadFeaturesBtn');
    const downloadDict = $('#autoCsvDownloadDictBtn');
    const assignmentBody = $('#monitorAssignmentBody');
    const assignmentDate = $('#monitorAssignmentDate');
    const assignmentStartTime = $('#monitorAssignmentStartTime');
    const assignmentEndTime = $('#monitorAssignmentEndTime');
    const assignmentRoom = $('#monitorAssignmentRoom');
    const assignmentRoomOptions = $('#monitorRoomOptions');
    const assignmentRoomChips = $('#monitorRoomOptionChips');
    const addMonitorRoomOptionBtn = $('#addMonitorRoomOptionBtn');
    const assignmentNumber = $('#monitorAssignmentNumber');
    const assignmentPatient = $('#monitorAssignmentPatientSearch');
    const assignmentPatientOptions = $('#monitorAssignmentPatientOptions');
    const saveAssignmentBtn = $('#saveMonitorAssignmentBtn');
    const resetAssignmentBtn = $('#resetMonitorAssignmentBtn');
    const assignmentEditStatus = $('#monitorAssignmentEditStatus');

    [selectBtn, downloadFeatures, downloadDict, saveAssignmentBtn, resetAssignmentBtn, addMonitorRoomOptionBtn].forEach(removeDisabledAction);
    let latestResult = null;
    let selectedResultKey = '';
    let editingMonitorAssignmentId = '';
    let draggedAssignmentId = '';
    let draggedCsvRowKey = '';
    const conversionResults = new Map();

    const initialState = patchState(state => applyMonitorAssignmentsToFiles(state));
    let autoCsvTableRows = (initialState.vitalFiles || [])
      .filter(file => file.sourceType === 'raw CSV' || String(file.name || '').toLowerCase().endsWith('.csv'))
      .slice()
      .sort((a, b) => Number(a.uploadOrder || 0) - Number(b.uploadOrder || 0))
      .map(file => ({
        rowKey: `file:${file.id}`,
        fileId: file.id,
        name: file.name,
        size: file.size,
        caseId: file.caseId || '-',
        status: file.processStatus || file.uploadStatus || '등록됨',
        featureRows: file.featureRowCount ?? '-',
        segmentCount: file.segmentCount ?? '-',
        qc: file.previewStatus || 'QC 대기',
        error: file.errorMessage || '-'
      }));

    const setProgressLocal = pct => { if (progress) progress.style.width = `${Math.max(0, Math.min(100, pct))}%`; };
    const setStatusLocal = msg => { if (status) status.textContent = msg; };
    const setMetricText = (id, value, delta) => {
      const el = $(id);
      if (el) el.textContent = value;
      const metric = el?.closest('.metric');
      const d = metric ? $('.delta', metric) : null;
      if (d) d.textContent = delta || '대기';
    };

    function patientFromAssignmentInput(rawValue, state = readState()) {
      const raw = String(rawValue || '').trim();
      if (!raw) return null;
      const lower = raw.toLowerCase();
      const exact = (state.patients || []).find(patient => patientDisplayLabel(patient).toLowerCase() === lower);
      if (exact) return exact;
      const matches = (state.patients || []).filter(patient => {
        const values = [patient.pseudoId, patient.registrationNo, String(patient.registrationNo || '').slice(-4), patientMaskedRegistration(patient.registrationNo)];
        return values.some(value => String(value || '').toLowerCase() === lower);
      });
      return matches.length === 1 ? matches[0] : null;
    }

    function fillMonitorPatientOptions(state = readState()) {
      if (!assignmentPatientOptions) return;
      assignmentPatientOptions.innerHTML = (state.patients || []).map(patient => `<option value="${escapeHtml(patientDisplayLabel(patient))}"></option>`).join('');
    }

    function monitorRoomValues(state = readState()) {
      const values = ['SICU', 'CCU', '이동형', ...(state.monitorRooms || [])];
      const seen = new Set();
      return values.map(value => String(value || '').trim()).filter(value => {
        const key = normalizeMonitorPart(value);
        if (!key || seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    }

    function fillMonitorRoomOptions(state = readState()) {
      const rooms = monitorRoomValues(state);
      if (assignmentRoomOptions) assignmentRoomOptions.innerHTML = rooms.map(room => `<option value="${escapeHtml(room)}"></option>`).join('');
      if (assignmentRoomChips) assignmentRoomChips.innerHTML = rooms.map(room => `<button type="button" class="monitor-room-chip" data-monitor-room-choice="${escapeHtml(room)}">${escapeHtml(room)}</button>`).join('');
      $$('[data-monitor-room-choice]', assignmentRoomChips || document).forEach(button => button.addEventListener('click', () => {
        if (assignmentRoom) assignmentRoom.value = button.dataset.monitorRoomChoice || '';
      }));
    }

    function addMonitorRoomOption() {
      const room = String(assignmentRoom?.value || '').trim();
      if (!room) return toast('추가할 병동/방 이름을 먼저 입력하세요.', 'yellow');
      const next = patchState(stateDraft => {
        if (!Array.isArray(stateDraft.monitorRooms)) stateDraft.monitorRooms = [];
        if (!stateDraft.monitorRooms.some(item => normalizeMonitorPart(item) === normalizeMonitorPart(room))) stateDraft.monitorRooms.push(room);
      });
      fillMonitorRoomOptions(next);
      if (assignmentRoom) assignmentRoom.value = room;
      toast(`${room} 병동/방을 선택 목록에 추가했습니다.`);
    }

    function resetMonitorAssignmentForm() {
      editingMonitorAssignmentId = '';
      if (assignmentDate) assignmentDate.value = '';
      if (assignmentStartTime) assignmentStartTime.value = '00:00';
      if (assignmentEndTime) assignmentEndTime.value = '23:59';
      if (assignmentRoom) assignmentRoom.value = '';
      if (assignmentNumber) assignmentNumber.value = '';
      if (assignmentPatient) assignmentPatient.value = '';
      if (assignmentEditStatus) assignmentEditStatus.textContent = '새 배정 등록';
      if (saveAssignmentBtn) saveAssignmentBtn.textContent = '배정 저장';
    }

    function assignmentPatientLabel(state, patientId) {
      const patient = patientById(state, patientId);
      return patient ? patientDisplayLabel(patient) : '환자 정보 없음';
    }

    function monitorAssignmentTimeLabel(item) {
      return `${item.recordingDate || '-'} ${normalizeTimeText(item.startTime, '00:00')}–${normalizeTimeText(item.endTime, '23:59')}`;
    }

    function renderMonitorAssignments(state = readState()) {
      if (!assignmentBody) return;
      const assignments = (state.monitorAssignments || []).slice().sort((a, b) => Number(a.displayOrder || 0) - Number(b.displayOrder || 0));
      if (!assignments.length) {
        setTableEmpty(assignmentBody, 6, '등록된 모니터 배정이 없습니다.', '날짜·시간·모니터·환자를 저장하면 해당 시간대 CSV가 자동 연결됩니다.');
        return;
      }
      assignmentBody.innerHTML = assignments.map((item, index) => {
        const fileCount = (state.vitalFiles || []).filter(file => file.monitorAssignmentId === item.id && file.matchSource === 'monitor-assignment').length;
        return `<tr draggable="true" data-monitor-assignment-row="${escapeHtml(item.id)}">
          <td><button type="button" class="row-drag-handle" title="드래그하여 순서 변경">⋮⋮</button><span class="order-number">${index + 1}</span></td>
          <td><strong>${escapeHtml(item.recordingDate)}</strong><div class="muted">${escapeHtml(`${normalizeTimeText(item.startTime, '00:00')}–${normalizeTimeText(item.endTime, '23:59')}`)}</div></td>
          <td>${badge(`${item.room} ${item.monitorNumber}`, 'blue')}</td>
          <td>${escapeHtml(assignmentPatientLabel(state, item.patientId))}</td>
          <td>${badge(`${fileCount}개`, fileCount ? 'teal' : 'gray')}</td>
          <td><div class="table-action-row"><button class="btn ghost compact-btn" data-edit-monitor-assignment="${escapeHtml(item.id)}">수정</button><button class="btn ghost compact-btn" data-delete-monitor-assignment="${escapeHtml(item.id)}">삭제</button></div></td>
        </tr>`;
      }).join('');

      $$('[data-edit-monitor-assignment]', assignmentBody).forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const item = (readState().monitorAssignments || []).find(row => row.id === button.dataset.editMonitorAssignment);
        if (!item) return;
        editingMonitorAssignmentId = item.id;
        if (assignmentDate) assignmentDate.value = item.recordingDate || '';
        if (assignmentStartTime) assignmentStartTime.value = normalizeTimeText(item.startTime, '00:00').slice(0, 5);
        if (assignmentEndTime) assignmentEndTime.value = normalizeTimeText(item.endTime, '23:59').slice(0, 5);
        if (assignmentRoom) assignmentRoom.value = item.room || '';
        if (assignmentNumber) assignmentNumber.value = item.monitorNumber || '';
        if (assignmentPatient) assignmentPatient.value = assignmentPatientLabel(readState(), item.patientId);
        if (assignmentEditStatus) assignmentEditStatus.textContent = `${monitorAssignmentTimeLabel(item)} · ${item.room}${item.monitorNumber} 배정 수정 중`;
        if (saveAssignmentBtn) saveAssignmentBtn.textContent = '배정 변경사항 저장';
        assignmentDate?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }));

      $$('[data-delete-monitor-assignment]', assignmentBody).forEach(button => button.addEventListener('click', event => {
        event.stopPropagation();
        const id = button.dataset.deleteMonitorAssignment;
        const item = (readState().monitorAssignments || []).find(row => row.id === id);
        if (!item || !confirm(`${monitorAssignmentTimeLabel(item)} ${item.room}${item.monitorNumber} 배정을 삭제할까요?\n이 배정으로 자동 연결된 CSV는 미매칭 상태로 돌아갑니다.`)) return;
        const next = patchState(stateDraft => {
          stateDraft.monitorAssignments = (stateDraft.monitorAssignments || []).filter(row => row.id !== id);
          stateDraft.monitorAssignments.forEach((row, index) => { row.displayOrder = index; });
          applyMonitorAssignmentsToFiles(stateDraft);
        });
        if (editingMonitorAssignmentId === id) resetMonitorAssignmentForm();
        renderMonitorAssignments(next);
        renderAutoCsvUploadRows(autoCsvTableRows);
        addAudit('monitor assignment delete', 'monitor_assignment', `${monitorAssignmentTimeLabel(item)} ${item.room}${item.monitorNumber}`);
      }));

      $$('[data-monitor-assignment-row]', assignmentBody).forEach(row => {
        row.addEventListener('dragstart', event => {
          draggedAssignmentId = row.dataset.monitorAssignmentRow;
          row.classList.add('dragging');
          event.dataTransfer.effectAllowed = 'move';
        });
        row.addEventListener('dragend', () => { draggedAssignmentId = ''; row.classList.remove('dragging'); });
        row.addEventListener('dragover', event => { event.preventDefault(); row.classList.add('drag-over'); });
        row.addEventListener('dragleave', () => row.classList.remove('drag-over'));
        row.addEventListener('drop', event => {
          event.preventDefault();
          row.classList.remove('drag-over');
          const targetId = row.dataset.monitorAssignmentRow;
          if (!draggedAssignmentId || draggedAssignmentId === targetId) return;
          const next = patchState(stateDraft => {
            const list = (stateDraft.monitorAssignments || []).slice().sort((a, b) => Number(a.displayOrder || 0) - Number(b.displayOrder || 0));
            const from = list.findIndex(item => item.id === draggedAssignmentId);
            const to = list.findIndex(item => item.id === targetId);
            if (from < 0 || to < 0) return;
            const [moved] = list.splice(from, 1);
            list.splice(to, 0, moved);
            list.forEach((item, index) => { item.displayOrder = index; });
            stateDraft.monitorAssignments = list;
          });
          renderMonitorAssignments(next);
        });
      });
    }

    function saveMonitorAssignment() {
      const recordingDate = assignmentDate?.value || '';
      const startTime = normalizeTimeText(assignmentStartTime?.value, '00:00');
      const endTime = normalizeTimeText(assignmentEndTime?.value, '23:59');
      const roomRaw = String(assignmentRoom?.value || '').trim();
      const room = normalizeMonitorPart(roomRaw);
      const monitorNumber = normalizeMonitorPart(assignmentNumber?.value);
      const patient = patientFromAssignmentInput(assignmentPatient?.value);
      if (!recordingDate || !startTime || !endTime || !room || !monitorNumber || !patient) {
        return toast('배정 날짜, 시작·종료 시간, 병동/방, 모니터 번호와 등록된 환자를 모두 입력하세요.', 'yellow');
      }
      const monitorKey = `${room}${monitorNumber}`;
      const candidate = { recordingDate, startTime, endTime };
      const candidateRange = monitorAssignmentRange(candidate);
      if (!candidateRange) return toast('배정 날짜와 시간을 확인하세요.', 'yellow');
      const currentState = readState();
      const duplicate = (currentState.monitorAssignments || []).find(item => {
        if (item.id === editingMonitorAssignmentId) return false;
        const sameMonitor = normalizeMonitorPart(item.monitorKey || `${item.room}${item.monitorNumber}`) === monitorKey;
        const existingRange = monitorAssignmentRange(item);
        return sameMonitor && existingRange && candidateRange.start <= existingRange.end && candidateRange.end >= existingRange.start;
      });
      if (duplicate) return toast(`같은 모니터의 ${monitorAssignmentTimeLabel(duplicate)} 배정과 시간이 겹칩니다. 기존 배정을 수정하거나 시간을 조정하세요.`, 'yellow');

      const next = patchState(stateDraft => {
        if (!Array.isArray(stateDraft.monitorAssignments)) stateDraft.monitorAssignments = [];
        if (!Array.isArray(stateDraft.monitorRooms)) stateDraft.monitorRooms = [];
        if (!stateDraft.monitorRooms.some(item => normalizeMonitorPart(item) === room)) stateDraft.monitorRooms.push(roomRaw || room);
        const existing = stateDraft.monitorAssignments.find(item => item.id === editingMonitorAssignmentId);
        const payload = {
          recordingDate,
          startTime,
          endTime,
          room,
          roomLabel: roomRaw || room,
          monitorNumber,
          monitorKey,
          patientId: patient.id,
          patientLabel: patientDisplayLabel(patient),
          updatedAt: nowText(),
          updatedBy: USER
        };
        if (existing) Object.assign(existing, payload);
        else stateDraft.monitorAssignments.push(Object.assign({ id: uid('MONASSIGN'), displayOrder: stateDraft.monitorAssignments.length, createdAt: nowText() }, payload));
        applyMonitorAssignmentsToFiles(stateDraft);
      });
      addAudit(editingMonitorAssignmentId ? 'monitor assignment update' : 'monitor assignment add', 'monitor_assignment', `${recordingDate} ${startTime}–${endTime} ${monitorKey} → ${patientDisplayLabel(patient)}`);
      resetMonitorAssignmentForm();
      fillMonitorRoomOptions(next);
      renderMonitorAssignments(next);
      renderAutoCsvUploadRows(autoCsvTableRows);
      toast('시간대별 모니터 배정을 저장하고 일치하는 기존 CSV에도 자동 적용했습니다.');
    }

    function updateMetrics() {
      const total = autoCsvTableRows.length;
      const converted = autoCsvTableRows.filter(row => String(row.status || '').includes('완료')).length;
      const qcDone = autoCsvTableRows.filter(row => String(row.qc || '').includes('완료')).length;
      const errors = autoCsvTableRows.filter(row => /오류|차단/.test(String(row.status || ''))).length;
      setMetricText('#autoCsvTotal', `${total}개`, total ? '누적' : '대기');
      setMetricText('#autoCsvConverted', `${converted}개`, converted ? '완료' : '대기');
      setMetricText('#autoCsvQcDone', `${qcDone}개`, qcDone ? '완료' : '대기');
      setMetricText('#autoCsvError', `${errors}개`, errors ? '확인' : '대기');
    }

    function persistCsvRowOrder() {
      patchState(stateDraft => {
        autoCsvTableRows.forEach((row, index) => {
          if (!row.fileId) return;
          const file = (stateDraft.vitalFiles || []).find(item => item.id === row.fileId);
          if (file) file.uploadOrder = index;
        });
      });
    }

    function renderStoredAutoCsvQc(file, options = {}) {
      if (!file) return;
      const state = readState();
      const meta = parseCsvMonitorMeta(file.name) || (file.monitorKey ? { room: file.monitorRoom, monitorNumber: file.monitorNumber, recordingDate: file.recordingDate, recordingDateTime: file.recordingStart || file.recordingDateTime || '' } : null);
      const patient = patientById(state, file.patientId);
      if (qcSummary) {
        qcSummary.innerHTML = `<dl class="kv"><dt>선택 파일</dt><dd>${escapeHtml(file.name)}</dd><dt>case_id</dt><dd>${escapeHtml(file.caseId || '-')}</dd><dt>모니터</dt><dd>${escapeHtml(meta ? `${meta.room} ${meta.monitorNumber}` : '파일명 인식 실패')}</dd><dt>기록일시</dt><dd>${escapeHtml(file?.recordingStart || meta?.recordingDateTime || meta?.recordingDate || '-')}</dd><dt>환자 매칭</dt><dd>${escapeHtml(patient ? patientDisplayLabel(patient) : '미매칭')} · ${escapeHtml(file.autoMatchStatus || '확인 필요')}</dd><dt>feature row</dt><dd>${escapeHtml(file.featureRowCount ?? '-')}</dd><dt>상태</dt><dd>${escapeHtml(file.previewStatus || file.processStatus || '-')}</dd></dl>`;
      }
      const rows = storedPreviewRows(file);
      const signals = Object.keys(file.previewData || {}).slice(0, 6);
      renderSignalTrajectoryPanel(qcPanel, rows, file.name, {
        title: '신호 궤적 미리보기',
        subtitle: rows.length ? `${file.name} · 저장된 QC 축약 데이터` : '이전에 저장된 그래프 데이터가 없으면 CSV를 다시 업로드해야 실제 궤적이 표시됩니다.',
        emptyText: '저장된 신호 궤적이 없습니다.',
        badge: file.previewStatus || 'QC preview',
        signals
      });
      if (options.scroll) $('#autoCsvQcCard')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function renderAutoCsvUploadRows(rows) {
      if (!body) return;
      if (!rows.length) {
        setTableEmpty(body, 7, '아직 업로드된 CSV가 없습니다.', 'CSV 파일을 업로드하면 자동으로 변환·QC·환자 매칭이 실행됩니다.');
        updateMetrics();
        return;
      }
      const state = readState();
      body.innerHTML = rows.map((row, index) => {
        const file = row.fileId ? (state.vitalFiles || []).find(item => item.id === row.fileId) : null;
        const meta = file ? (parseCsvMonitorMeta(file.name) || (file.monitorKey ? { room: file.monitorRoom, monitorNumber: file.monitorNumber, recordingDate: file.recordingDate, recordingDateTime: file.recordingStart || file.recordingDateTime || '' } : null)) : parseCsvMonitorMeta(row.name);
        const patient = file ? patientById(state, file.patientId) : null;
        const resultSelectable = row.resultKey && conversionResults.has(row.resultKey);
        const storedSelectable = Boolean(file);
        const selectionKey = resultSelectable ? row.resultKey : storedSelectable ? `file:${file.id}` : '';
        const selected = selectionKey && selectionKey === selectedResultKey;
        const rowKey = row.rowKey || row.fileId || row.resultKey || `local:${index}`;
        row.rowKey = rowKey;
        const matchTone = file?.patientId ? (file.matchSource === 'monitor-assignment' ? 'teal' : 'blue') : 'gray';
        return `<tr class="${selected ? 'selected' : ''} ${(resultSelectable || storedSelectable) ? 'qc-selectable-row' : ''}" draggable="true" data-auto-csv-row-key="${escapeHtml(rowKey)}"${selectionKey ? ` data-auto-csv-selection="${escapeHtml(selectionKey)}"` : ''}>
          <td><button type="button" class="row-drag-handle" title="드래그하여 순서 변경">⋮⋮</button><span class="order-number">${index + 1}</span></td>
          <td><strong>${escapeHtml(row.name)}</strong><div class="muted">${escapeHtml(row.caseId || '-')} · ${formatBytes(row.size)}</div></td>
          <td>${meta ? `${badge(`${meta.room} ${meta.monitorNumber}`, 'blue')}<div class="muted">${escapeHtml(file?.recordingStart || meta.recordingDateTime || meta.recordingDate)}</div>` : `${badge('인식 실패', 'yellow')}<div class="muted">파일명 확인</div>`}</td>
          <td>${badge(patient ? patientDisplayLabel(patient) : '미매칭', matchTone)}<div class="muted">${escapeHtml(file?.autoMatchStatus || (meta ? '배정 없음' : '파일명 인식 실패'))}</div></td>
          <td>${badge(row.status || '-', String(row.status || '').includes('완료') ? 'green' : /오류|차단/.test(String(row.status || '')) ? 'red' : 'yellow')}</td>
          <td><strong>${escapeHtml(row.featureRows)}</strong> rows<div class="muted">segment ${escapeHtml(row.segmentCount)} · ${escapeHtml(row.qc || '-')}</div></td>
          <td>${escapeHtml(row.error || '-')}</td>
        </tr>`;
      }).join('');

      $$('[data-auto-csv-selection]', body).forEach(rowElement => rowElement.addEventListener('click', event => {
        if (event.target.closest('.row-drag-handle')) return;
        const key = rowElement.dataset.autoCsvSelection;
        selectedResultKey = key;
        if (conversionResults.has(key)) {
          const result = conversionResults.get(key);
          latestResult = result;
          window.__exciteCsvConversion = result;
          window.__exciteVitalConversion = result;
          renderAutoCsvQc(result, result.sourceFile || result.caseId);
        } else if (key.startsWith('file:')) {
          latestResult = null;
          const file = (readState().vitalFiles || []).find(item => item.id === key.slice(5));
          renderStoredAutoCsvQc(file);
        }
        renderAutoCsvUploadRows(rows);
      }));

      $$('[data-auto-csv-row-key]', body).forEach(rowElement => {
        rowElement.addEventListener('dragstart', event => {
          draggedCsvRowKey = rowElement.dataset.autoCsvRowKey;
          rowElement.classList.add('dragging');
          event.dataTransfer.effectAllowed = 'move';
        });
        rowElement.addEventListener('dragend', () => { draggedCsvRowKey = ''; rowElement.classList.remove('dragging'); });
        rowElement.addEventListener('dragover', event => { event.preventDefault(); rowElement.classList.add('drag-over'); });
        rowElement.addEventListener('dragleave', () => rowElement.classList.remove('drag-over'));
        rowElement.addEventListener('drop', event => {
          event.preventDefault();
          rowElement.classList.remove('drag-over');
          const targetKey = rowElement.dataset.autoCsvRowKey;
          if (!draggedCsvRowKey || draggedCsvRowKey === targetKey) return;
          const from = autoCsvTableRows.findIndex(item => item.rowKey === draggedCsvRowKey);
          const to = autoCsvTableRows.findIndex(item => item.rowKey === targetKey);
          if (from < 0 || to < 0) return;
          const [moved] = autoCsvTableRows.splice(from, 1);
          autoCsvTableRows.splice(to, 0, moved);
          persistCsvRowOrder();
          renderAutoCsvUploadRows(autoCsvTableRows);
        });
      });
      updateMetrics();
    }

    function renderAutoCsvQc(result, fileName, options = {}) {
      const state = readState();
      const file = (state.vitalFiles || []).find(item => item.name === fileName);
      const meta = parseCsvMonitorMeta(fileName);
      const patient = file ? patientById(state, file.patientId) : null;
      const core = ['HR','MAP','SBP','DBP','SpO2','PI','RR'].filter(variable => result.detectedSignalNames?.includes(variable));
      const aux = (result.auxiliarySignals || []).map(item => item.signal);
      const qcSignals = core.length ? ['HR','MAP','SpO2','RR'].filter(variable => core.includes(variable)) : aux.slice(0, 4);
      const detectedText = [...core, ...aux].join(', ') || '없음';
      if (qcSummary) {
        qcSummary.innerHTML = `<dl class="kv"><dt>선택 파일</dt><dd>${escapeHtml(fileName)}</dd><dt>case_id</dt><dd>${escapeHtml(result.caseId)}</dd><dt>모니터</dt><dd>${escapeHtml(meta ? `${meta.room} ${meta.monitorNumber}` : '파일명 인식 실패')}</dd><dt>기록일시</dt><dd>${escapeHtml(file?.recordingStart || meta?.recordingDateTime || meta?.recordingDate || '-')}</dd><dt>환자 매칭</dt><dd>${escapeHtml(patient ? patientDisplayLabel(patient) : '미매칭')} · ${escapeHtml(file?.autoMatchStatus || '확인 필요')}</dd><dt>feature row</dt><dd>${result.features.length.toLocaleString()}행</dd><dt>segment</dt><dd>${result.segmentCount.toLocaleString()}개</dd><dt>감지 신호</dt><dd>${escapeHtml(detectedText)}</dd><dt>encoding</dt><dd>${escapeHtml(result.encoding)}</dd></dl>`;
      }
      const subtitle = core.length ? 'core vital trend를 기준으로 QC 궤적을 표시합니다.' : 'HR/MAP/SpO2/RR trend가 없어 감지된 수치형 auxiliary channel을 표시합니다.';
      renderSignalTrajectoryPanel(qcPanel, result.features, result.caseId, { title: '신호 궤적 미리보기', subtitle, badge: '자동 QC 완료', signals: qcSignals });
      if (options.scroll) $('#autoCsvQcCard')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    selectBtn?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', () => {
      processAutoCsvFiles(fileInput.files);
      fileInput.value = '';
    });
    dropzone?.addEventListener('dragover', event => { event.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone?.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone?.addEventListener('drop', event => {
      event.preventDefault();
      dropzone.classList.remove('dragover');
      processAutoCsvFiles(event.dataTransfer.files);
    });
    saveAssignmentBtn?.addEventListener('click', saveMonitorAssignment);
    resetAssignmentBtn?.addEventListener('click', resetMonitorAssignmentForm);
    addMonitorRoomOptionBtn?.addEventListener('click', addMonitorRoomOption);

    downloadFeatures?.addEventListener('click', () => {
      if (!latestResult?.features?.length) return toast('현재 선택한 파일의 변환 결과는 이 브라우저 세션에 없습니다. CSV를 다시 업로드하세요.', 'gray');
      downloadText(latestResult.outputName || `${latestResult.caseId}_ml_features.csv`, '\uFEFF' + toCsv(latestResult.features), 'text/csv;charset=utf-8');
      addExportRow(latestResult.outputName || `${latestResult.caseId}_ml_features.csv`, 'CSV');
    });
    downloadDict?.addEventListener('click', () => {
      if (!latestResult?.dictionary?.length) return toast('현재 선택한 파일의 컬럼 사전은 이 브라우저 세션에 없습니다. CSV를 다시 업로드하세요.', 'gray');
      downloadText(latestResult.dictionaryName || `${latestResult.caseId}_column_dictionary.csv`, '\uFEFF' + toCsv(latestResult.dictionary), 'text/csv;charset=utf-8');
      addExportRow(latestResult.dictionaryName || `${latestResult.caseId}_column_dictionary.csv`, 'CSV');
    });

    async function processAutoCsvFiles(fileList) {
      const files = Array.from(fileList || []);
      if (!files.length) return;
      const csvFiles = files.filter(file => file.name.toLowerCase().endsWith('.csv'));
      const rejected = files.filter(file => !file.name.toLowerCase().endsWith('.csv'));
      if (rejected.length) toast('.vital 포함 비CSV 파일은 이 화면에서 업로드할 수 없습니다.', 'yellow');
      if (!csvFiles.length) return setStatusLocal('CSV 파일만 업로드할 수 있습니다.');

      setProgressLocal(12);
      setStatusLocal(`${csvFiles.length}개 CSV 자동 변환을 시작합니다.`);
      rejected.forEach(file => autoCsvTableRows.push({ rowKey: uid('LOCALROW'), name: file.name, size: file.size, caseId: '-', status: '차단', featureRows: '-', segmentCount: '-', qc: '불가', error: '.csv만 업로드 가능' }));
      renderAutoCsvUploadRows(autoCsvTableRows);

      let converted = 0;
      let errors = rejected.length;
      for (let index = 0; index < csvFiles.length; index += 1) {
        const file = csvFiles[index];
        setProgressLocal(15 + Math.round((index / csvFiles.length) * 65));
        setStatusLocal(`${file.name} 변환 중...`);
        try {
          const result = await convertRawVitalCsvFile(file);
          result.sourceFile = file.name;
          result.sourceType = 'raw CSV';
          result.outputName = `${result.caseId}_ml_features.csv`;
          result.dictionaryName = `${result.caseId}_column_dictionary.csv`;
          const resultKey = `csv_${Date.now()}_${index}_${Math.random().toString(16).slice(2)}`;
          result.resultKey = resultKey;
          conversionResults.set(resultKey, result);
          latestResult = result;
          selectedResultKey = resultKey;
          window.__exciteCsvConversion = result;
          window.__exciteVitalConversion = result;
          converted += 1;

          const parsedMeta = parseCsvMonitorMeta(file.name);
          const firstFeature = result.features?.[0] || {};
          const lastFeature = result.features?.[result.features.length - 1] || {};
          const recordingStart = firstFeature.Minute_start_datetime_iso || parsedMeta?.recordingDateTime || '';
          const recordingEnd = lastFeature.Minute_end_datetime_iso || recordingStart || '';
          const parsedMetaWithTime = parsedMeta ? Object.assign({}, parsedMeta, {
            recordingDateTime: recordingStart || parsedMeta.recordingDateTime || '',
            recordingStart: recordingStart || parsedMeta.recordingDateTime || ''
          }) : null;
          let savedFile = null;
          const nextState = patchState(stateDraft => {
            if (!Array.isArray(stateDraft.monitorAssignments)) stateDraft.monitorAssignments = [];
            const duplicateIndex = (stateDraft.vitalFiles || []).findIndex(item => item.name === file.name && item.size === file.size);
            const existing = duplicateIndex >= 0 ? stateDraft.vitalFiles[duplicateIndex] : null;
            const assignment = monitorAssignmentForMeta(stateDraft, parsedMetaWithTime);
            const hasManualPatient = Boolean(existing?.patientId && existing.matchSource !== 'monitor-assignment');
            const patientId = hasManualPatient ? existing.patientId : (assignment?.patientId || existing?.patientId || '');
            const matchSource = hasManualPatient ? (existing.matchSource || 'manual') : (assignment ? 'monitor-assignment' : (existing?.matchSource || ''));
            const autoMatchStatus = !parsedMeta ? '파일명 인식 실패' : assignment ? (hasManualPatient ? '수동 매칭 유지' : '자동 매칭 완료') : (patientId ? '수동 매칭' : '배정 없음');
            const item = Object.assign({}, existing || {}, {
              id: existing?.id || uid('CSVF'),
              caseId: result.caseId,
              name: file.name,
              size: file.size,
              sourceType: 'raw CSV',
              uploadedBy: USER,
              uploadedAt: nowText(),
              uploadStatus: '업로드 완료',
              processStatus: '자동 변환 완료',
              errorMessage: '',
              downloadStatus: 'feature CSV 준비 완료',
              previewStatus: 'QC 완료',
              previewMessage: `${result.features.length}개 1분 feature row 생성`,
              previewVariables: Object.keys(buildPreviewDataFromFeatures(result.features) || {}),
              previewData: buildPreviewDataFromFeatures(result.features),
              featureRowCount: result.features.length,
              segmentCount: result.segmentCount,
              patientId,
              matchSource,
              autoMatchStatus,
              monitorAssignmentId: hasManualPatient ? '' : (assignment?.id || ''),
              monitorRoom: parsedMeta?.room || '',
              monitorNumber: parsedMeta?.monitorNumber || '',
              monitorKey: parsedMeta?.monitorKey || '',
              recordingDate: parsedMeta?.recordingDate || (recordingStart ? String(recordingStart).slice(0, 10) : ''),
              recordingTime: parsedMeta?.recordingTime || (recordingStart ? String(recordingStart).slice(11, 19) : ''),
              recordingDateTime: recordingStart || parsedMeta?.recordingDateTime || '',
              recordingStart,
              recordingEnd,
              matchedAt: assignment && !hasManualPatient ? nowText() : (existing?.matchedAt || ''),
              uploadOrder: existing?.uploadOrder ?? autoCsvTableRows.length,
              tagIds: existing?.tagIds || [],
              episodeId: existing?.episodeId || '',
              eventId: existing?.eventId || ''
            });
            if (duplicateIndex >= 0) stateDraft.vitalFiles[duplicateIndex] = item;
            else stateDraft.vitalFiles.push(item);
            savedFile = item;
            if (!Array.isArray(stateDraft.csvConversions)) stateDraft.csvConversions = [];
            stateDraft.csvConversions.unshift({
              id: uid('CSVCONV'), sourceFile: file.name, caseId: result.caseId, status: '자동 변환 완료', rowsRead: result.rowsRead,
              featureRows: result.features.length, columns: result.columns.length, segmentCount: result.segmentCount, createdAt: nowText(), output: result.outputName,
              monitorKey: parsedMeta?.monitorKey || '', recordingDate: parsedMeta?.recordingDate || '', recordingStart, recordingEnd, patientId
            });
            stateDraft.csvConversions = stateDraft.csvConversions.slice(0, 50);
          });

          const row = {
            rowKey: `file:${savedFile.id}`,
            fileId: savedFile.id,
            resultKey,
            name: file.name,
            size: file.size,
            caseId: result.caseId,
            status: '변환 완료',
            featureRows: result.features.length,
            segmentCount: result.segmentCount,
            qc: 'QC 완료',
            error: '-'
          };
          const existingRowIndex = autoCsvTableRows.findIndex(item => item.fileId === savedFile.id);
          if (existingRowIndex >= 0) autoCsvTableRows.splice(existingRowIndex, 1, row);
          else autoCsvTableRows.push(row);
          renderMonitorAssignments(nextState);
          renderAutoCsvQc(result, file.name);
          addAudit('raw csv auto conversion', 'raw_csv', `${file.name} -> ${result.outputName}${savedFile.patientId ? ' · 환자 자동/기존 매칭' : ''}`);
        } catch (error) {
          console.error(error);
          errors += 1;
          autoCsvTableRows.push({ rowKey: uid('LOCALROW'), name: file.name, size: file.size, caseId: makeCaseIdFromName(file.name, true), status: '변환 오류', featureRows: '-', segmentCount: '-', qc: '불가', error: error.message || 'CSV 변환 중 오류' });
        }
        renderAutoCsvUploadRows(autoCsvTableRows);
      }
      setProgressLocal(100);
      setStatusLocal(`자동 변환 완료: ${converted}개 성공, ${errors}개 오류/차단`);
      setTimeout(() => setProgressLocal(0), 900);
      toast(`CSV 자동 변환 및 QC가 완료되었습니다. 성공 ${converted}개, 오류/차단 ${errors}개`);
    }

    fillMonitorPatientOptions(initialState);
    fillMonitorRoomOptions(initialState);
    renderMonitorAssignments(initialState);
    renderAutoCsvUploadRows(autoCsvTableRows);
    if (autoCsvTableRows[0]?.fileId) {
      selectedResultKey = `file:${autoCsvTableRows[0].fileId}`;
      renderStoredAutoCsvQc((initialState.vitalFiles || []).find(file => file.id === autoCsvTableRows[0].fileId));
      renderAutoCsvUploadRows(autoCsvTableRows);
    } else {
      renderSignalTrajectoryPanel(qcPanel, [], '', { title: '신호 궤적 미리보기', subtitle: 'CSV 업로드 후 자동 변환되면 core vital 또는 감지된 수치형 channel 궤적이 표시됩니다.', emptyText: '아직 업로드된 CSV가 없습니다.', badge: '대기' });
    }
  }
  function handleVitalFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length) return;
    const progress = $('.upload-zone .progress > i');
    if (progress) progress.style.width = '18%';
    const state = patchState(s => {
      files.forEach(file => {
        const isVital = file.name.toLowerCase().endsWith('.vital');
        const isCsv = file.name.toLowerCase().endsWith('.csv');
        const accepted = isVital || isCsv;
        const duplicate = s.vitalFiles.some(v => v.name === file.name && v.size === file.size);
        s.vitalFiles.unshift({
          id: uid(isCsv ? 'CSVF' : 'VF'),
          caseId: accepted ? makeCaseIdFromName(file.name, true) : uid('CASE').replace('CASE_', 'CASE-'),
          name: file.name,
          size: file.size,
          sourceType: isCsv ? 'raw CSV' : isVital ? 'raw .vital' : 'unsupported',
          uploadedBy: USER,
          uploadedAt: nowText(),
          uploadStatus: accepted && !duplicate ? '업로드 완료' : '오류',
          processStatus: accepted && !duplicate ? (isCsv ? '변환 가능' : '서버 파서 대기') : '처리 제외',
          errorMessage: !accepted ? '지원 형식 아님: .csv만 업로드 가능' : duplicate ? '동일 파일이 이미 등록됨' : '',
          downloadStatus: accepted && !duplicate ? (isCsv ? '자동 변환 완료' : '준비 전') : '불가',
          previewStatus: accepted && !duplicate ? (isCsv ? '자동 변환 완료' : '자동 QC 대기') : '프리뷰 불가',
          previewMessage: accepted && !duplicate ? (isCsv ? '내보내기/CSV 변환 화면에서 바로 1분 feature와 QC 궤적을 생성할 수 있습니다.' : '파일 메타정보는 즉시 확인되었습니다. 서버 .vital 파서가 preview signal을 반환하면 그래프가 자동으로 표시됩니다.') : '지원하지 않는 파일은 프리뷰할 수 없습니다.',
          previewVariables: accepted && !duplicate ? ['MAP','HR','SBP','DBP','SpO2','RR'] : [],
          previewData: null,
          tagIds: [],
          patientId: '',
          eventId: ''
        });
      });
    });
    addAudit('file upload', 'raw_file', `${files.length}개 파일 선택`);
    renderVitalUpload(state);
    let pct = 18;
    const timer = setInterval(() => {
      pct += 27;
      if (progress) progress.style.width = `${Math.min(pct, 100)}%`;
      if (pct >= 100) {
        clearInterval(timer);
        setTimeout(() => { if (progress) progress.style.width = '0%'; }, 700);
        const nextState = patchState(s => {
          s.vitalFiles.forEach(f => {
            if (f.processStatus === '처리 대기') {
              f.processStatus = '처리 완료';
              f.downloadStatus = '준비 가능';
              if (!f.previewData && f.previewStatus !== '프리뷰 불가') f.previewStatus = '메타 확인';
            }
          });
        });
        renderVitalUpload(nextState);
        toast('Raw CSV 업로드 상태가 저장되었습니다.');
      }
    }, 180);
  }

  function renderVitalUpload(state = readState()) {
    const body = cardByHeading('업로드 상태 목록')?.querySelector('tbody');
    if (body) {
      if (!state.vitalFiles.length) {
        setTableEmpty(body, 9, '아직 선택된 raw CSV이 없습니다.', 'CSV 파일 선택 또는 드래그 앤 드롭으로 업로드 목록을 만들 수 있습니다.');
      } else {
        body.innerHTML = state.vitalFiles.map(f => `<tr>
          <td><input type="checkbox" data-vital-id="${escapeHtml(f.id)}"></td>
          <td>${escapeHtml(f.name)}</td>
          <td>${formatBytes(f.size)}</td>
          <td>${badge(f.uploadStatus, f.uploadStatus === '오류' ? 'red' : 'green')}</td>
          <td>${badge(f.processStatus, f.processStatus === '처리 완료' ? 'teal' : f.processStatus === '처리 제외' ? 'gray' : 'yellow')}</td>
          <td>${badge(f.previewStatus || '자동 QC 대기', previewTone(f.previewStatus))}</td>
          <td>${escapeHtml(f.errorMessage || '-')}</td>
          <td>${escapeHtml(f.downloadStatus || '준비 전')}</td>
          <td><button class="btn ghost" data-qc-file="${escapeHtml(f.id)}">QC 보기</button></td>
        </tr>`).join('');
        $$('[data-qc-file]', body).forEach(btn => btn.addEventListener('click', () => {
          const select = $('#qcFileSelect');
          if (select) select.value = btn.dataset.qcFile;
          renderVitalQcPreview();
          document.querySelector('.qc-card')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }));
      }
    }
    const completed = state.vitalFiles.filter(f => f.uploadStatus === '업로드 완료').length;
    const errors = state.vitalFiles.filter(f => f.uploadStatus === '오류').length;
    const pending = state.vitalFiles.filter(f => f.processStatus === '처리 대기').length;
    const ready = state.vitalFiles.filter(f => f.downloadStatus === '준비 가능' || f.downloadStatus === '다운로드 목록 생성').length;
    setMetricByLabel('업로드 완료', `${completed}개`, completed ? '완료' : '대기');
    setMetricByLabel('업로드 오류', `${errors}개`, errors ? '확인' : '대기');
    setMetricByLabel('처리 대기', `${pending}개`, pending ? '진행' : '대기');
    setMetricByLabel('다운로드 준비', `${ready}개`, ready ? '가능' : '대기');
    const dd = $$('.preview-card .kv dd');
    if (dd[0]) dd[0].textContent = `${state.vitalFiles.length}개`;
    if (dd[1]) dd[1].textContent = formatBytes(state.vitalFiles.reduce((sum, f) => sum + Number(f.size || 0), 0));
    if (dd[2]) dd[2].textContent = `${errors}개`;
    if (dd[3]) dd[3].textContent = `0개`;
    renderVitalQcOptions(state);
    renderVitalQcPreview(state);
  }

  function previewTone(status) {
    if (status === '프리뷰 가능' || status === '메타 확인') return 'teal';
    if (status === '자동 QC 대기' || status === '프리뷰 요청됨') return 'yellow';
    if (status === '프리뷰 불가') return 'red';
    return 'gray';
  }

  function renderVitalQcOptions(state = readState()) {
    const select = $('#qcFileSelect');
    if (!select) return;
    const current = select.value;
    const files = state.vitalFiles || [];
    select.innerHTML = files.length
      ? option('', '파일 선택') + files.map(f => option(f.id, `${f.name} · ${f.previewStatus || '자동 QC 대기'}`)).join('')
      : option('', '업로드된 파일 없음');
    if (current && files.some(f => f.id === current)) select.value = current;
    else if (!select.value && files.length) select.value = files[0].id;
  }

  function renderVitalQcPreview(state = readState()) {
    const card = $('.qc-card');
    if (!card) return;
    const fileId = $('#qcFileSelect')?.value || '';
    const variable = $('#qcVariableSelect')?.value || 'MAP';
    const windowMin = $('#qcWindowSelect')?.value || '30';
    const file = (state.vitalFiles || []).find(f => f.id === fileId);
    const summary = $('#qcSummary');
    const chart = $('#qcChart');
    if (!summary || !chart) return;
    if (!file) {
      summary.innerHTML = '<span>선택된 파일이 없습니다.</span>';
      chart.innerHTML = '<div class="empty-state"><div><strong>QC 미리보기 없음</strong><span>raw CSV를 변환하면 QC 궤적이 표시됩니다. .vital은 서버 파서 연결 후 표시됩니다.</span></div></div>';
      return;
    }
    const vars = Array.isArray(file.previewVariables) && file.previewVariables.length ? file.previewVariables.join(', ') : '파서 반환 전';
    summary.innerHTML = `
      ${badge(file.name, 'blue')}
      ${badge(file.previewStatus || '프리뷰 미생성', previewTone(file.previewStatus))}
      <span>크기 ${formatBytes(file.size)}</span>
      <span>case_id ${escapeHtml(file.caseId || '-')}</span>
      <span>사용 가능 변수: ${escapeHtml(vars)}</span>
    `;
    const data = extractPreviewSeries(file, variable, windowMin);
    if (!data.length) {
      const msg = file.previewMessage || '파일 메타정보는 표시되었습니다. 서버 .vital 파서가 preview signal을 반환하면 그래프가 자동으로 표시됩니다.';
      chart.innerHTML = `<div class="empty-state"><div><strong>${escapeHtml(variable)} 신호 그래프 대기</strong><span>${escapeHtml(msg)}</span><br><span>파일명, 크기, case_id는 위에서 즉시 확인할 수 있습니다. 실제 파형/수치 preview는 백엔드 파서 연결 후 자동 표시됩니다.</span></div></div>`;
      return;
    }
    chart.innerHTML = drawQcSvg(data, variable, file.name);
  }

  function extractPreviewSeries(file, variable, windowMin) {
    const raw = file && file.previewData;
    if (!raw) return [];
    let arr = raw[variable] || raw[String(variable).toUpperCase()] || raw[String(variable).toLowerCase()];
    if (!Array.isArray(arr)) return [];
    let data = arr.map((d, i) => {
      if (typeof d === 'number') return { minute: i, value: d };
      return { minute: Number(d.minute ?? d.x ?? i), value: Number(d.value ?? d.y) };
    }).filter(d => Number.isFinite(d.minute) && Number.isFinite(d.value));
    if (windowMin !== 'all') {
      const maxMin = Number(windowMin);
      if (Number.isFinite(maxMin)) data = data.filter(d => d.minute <= maxMin);
    }
    return data;
  }

  function drawQcSvg(data, variable, fileName) {
    const w = 820, h = 280, left = 54, right = 20, top = 36, bottom = 42;
    const xs = data.map(d => d.minute), ys = data.map(d => d.value);
    const xMin = Math.min(...xs), xMax = Math.max(...xs);
    let yMin = Math.min(...ys), yMax = Math.max(...ys);
    if (yMin === yMax) { yMin -= 1; yMax += 1; }
    const pad = (yMax - yMin) * 0.12;
    yMin -= pad; yMax += pad;
    const xScale = x => left + ((x - xMin) / Math.max(1, xMax - xMin)) * (w - left - right);
    const yScale = y => top + (1 - ((y - yMin) / Math.max(1e-9, yMax - yMin))) * (h - top - bottom);
    const path = data.map((d, i) => `${i ? 'L' : 'M'}${xScale(d.minute).toFixed(1)},${yScale(d.value).toFixed(1)}`).join(' ');
    const yTicks = Array.from({ length: 5 }, (_, i) => yMin + (yMax - yMin) * i / 4);
    const xTicks = Array.from({ length: 5 }, (_, i) => xMin + (xMax - xMin) * i / 4);
    const dots = data.filter((_, i) => i % Math.ceil(data.length / 24) === 0).map(d => `<circle class="qc-dot" cx="${xScale(d.minute).toFixed(1)}" cy="${yScale(d.value).toFixed(1)}" r="3.2"/>`).join('');
    return `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="${escapeHtml(variable)} QC preview">
      <text class="qc-title" x="${left}" y="22">${escapeHtml(variable)} · 업로드 QC</text>
      <text class="qc-axis-text" x="${w - right}" y="22" text-anchor="end">${escapeHtml(fileName)}</text>
      ${yTicks.map(t => `<line class="qc-grid-line" x1="${left}" x2="${w - right}" y1="${yScale(t).toFixed(1)}" y2="${yScale(t).toFixed(1)}"/><text class="qc-axis-text" x="${left - 10}" y="${(yScale(t)+4).toFixed(1)}" text-anchor="end">${t.toFixed(1)}</text>`).join('')}
      ${xTicks.map(t => `<text class="qc-axis-text" x="${xScale(t).toFixed(1)}" y="${h - 14}" text-anchor="middle">${Math.round(t)}분</text>`).join('')}
      <line class="qc-grid-line" x1="${left}" x2="${left}" y1="${top}" y2="${h - bottom}"/>
      <line class="qc-grid-line" x1="${left}" x2="${w - right}" y1="${h - bottom}" y2="${h - bottom}"/>
      <path class="qc-line" d="${path}"/>
      ${dots}
    </svg>`;
  }

  function initVitalRegistry() {
    populateRegistryFilters();
    renderVitalRegistry();
    const filterBtn = cardByHeading('파일 검색/필터')?.querySelector('button');
    filterBtn?.addEventListener('click', renderVitalRegistry);
    $$('.filters input, .filters select').forEach(el => el.addEventListener('input', renderVitalRegistry));
  }

  function populateRegistryFilters() {
    const selects = $$('.filters select');
    const state = readState();
    if (selects[1]) {
      selects[1].innerHTML = option('', '전체 태그') + state.tags.map(t => option(t.id, t.name)).join('');
    }
  }

  function renderVitalRegistry() {
    const state = readState();
    const table = $('.table-wrap.registry table');
    if (!table) return;
    const body = $('tbody', table);
    const filters = $$('.filters input, .filters select');
    const query = filters[0]?.value?.trim().toLowerCase() || '';
    const tagId = filters[2]?.value || '';
    const status = filters[3]?.value || '';
    let files = state.vitalFiles.slice();
    if (query) files = files.filter(f => [f.name, f.caseId, f.id].some(v => String(v || '').toLowerCase().includes(query)));
    if (tagId) files = files.filter(f => (f.tagIds || []).includes(tagId));
    if (status && !status.includes('전체')) {
      files = files.filter(f => {
        if (status === '처리 완료') return f.processStatus === '처리 완료';
        if (status === '미처리') return f.processStatus !== '처리 완료';
        if (status === '미매칭') return !f.patientId;
        if (status === '미태그') return !(f.tagIds || []).length;
        return true;
      });
    }
    if (!files.length) return setTableEmpty(body, 13, '표시할 Vital 파일이 없습니다.', '업로드하거나 필터 조건을 변경하세요.');
    body.innerHTML = files.map(f => {
      const tags = (f.tagIds || []).map(id => state.tags.find(t => t.id === id)?.name).filter(Boolean);
      return `<tr>
        <td>${escapeHtml(f.id)}</td><td>${escapeHtml(f.caseId)}</td><td>${escapeHtml(f.name)}</td><td>${formatBytes(f.size)}</td>
        <td>${escapeHtml(f.uploadedBy || USER)}</td><td>${escapeHtml(f.uploadedAt)}</td><td>${escapeHtml(f.patientId || '미매칭')}</td><td>${escapeHtml(f.observationId || f.timepoint || f.eventId || '-')}</td>
        <td>${badge(f.patientId ? '매칭됨' : '미매칭', f.patientId ? 'green' : 'yellow')}</td><td>${badge(f.processStatus || '미처리', f.processStatus === '처리 완료' ? 'teal' : 'gray')}</td>
        <td>${tags.length ? tags.map(t => badge(t, 'blue')).join(' ') : badge('미태그', 'gray')}</td><td>${escapeHtml(f.downloadStatus || '준비 전')}</td>
        <td><button class="btn ghost" data-send-tag="${escapeHtml(f.id)}">태그 부여</button> <button class="btn ghost" data-delete-vital="${escapeHtml(f.id)}">삭제</button></td>
      </tr>`;
    }).join('');
    $$('[data-delete-vital]', body).forEach(btn => btn.addEventListener('click', () => {
      if (!confirm('이 Vital 파일 메타데이터를 등록대장에서 삭제할까요?')) return;
      patchState(s => { s.vitalFiles = s.vitalFiles.filter(f => f.id !== btn.dataset.deleteVital); });
      renderVitalRegistry();
      toast('Vital 파일 메타데이터를 삭제했습니다.');
    }));
    $$('[data-send-tag]', body).forEach(btn => btn.addEventListener('click', () => {
      sessionStorage.setItem('excite_selected_target_id', btn.dataset.sendTag);
      location.href = 'tag-assignment.html';
    }));
  }


  function ensure2026EcmoTemplate() {
    const exists = readState().tags.some(t => t.name === '2026_ECMO_Registry');
    if (exists) return toast('이미 2026_ECMO_Registry 태그 구조가 있습니다.', 'yellow');
    const tagId = uid('TAG');
    const axes = [
      { name: 'ECMO episode', level: '연구 이벤트 단위', values: ['ECMO_01','ECMO_02'] },
      { name: 'Timepoint', level: 'Day/visit 단위', values: ['Pre ECMO','Intra ECMO','4h','24h','Post ABGA 24h','Outcome','Follow-up'] },
      { name: 'Group', level: '환자 단위', values: ['Control','Treatment','VA-ECMO','VV-ECMO','Survivor','Non-survivor','CRRT yes','CRRT no','CPR yes','CPR no'] },
      { name: 'Clinical section', level: '관측값 단위', values: ['Patient master','Pre ECMO lab','Intra ECMO','Ventilator','Outcome','Diagnosis','Past history','Microbiology','Perfusionist file'] },
      { name: 'ECMO mode', level: '연구 이벤트 단위', values: ['VA','VV','VAV','Other'] },
      { name: 'Specimen / culture', level: '관측값 단위', values: ['Blood','Urine','Respiratory','Wound','Other'] }
    ];
    const presetVariables = [
      ['gender','환자 기본정보','범주형',''], ['birth_date_or_year','환자 기본정보','날짜/시간',''], ['height','환자 기본정보','숫자','cm'], ['weight','환자 기본정보','숫자','kg'],
      ['ecmo_start_datetime','ECMO episode','날짜/시간',''], ['ecmo_end_datetime','ECMO episode','날짜/시간',''], ['ecmo_duration_hours','ECMO episode','숫자','h'], ['ecmo_indication','ECMO episode','범주형',''], ['ecmo_type','ECMO episode','범주형',''], ['ecmo_mode','ECMO episode','범주형',''], ['ecmo_location','ECMO episode','범주형',''],
      ['PH','lab','숫자',''], ['PCO2','lab','숫자','mmHg'], ['PO2','lab','숫자','mmHg'], ['HCO3','lab','숫자','mmol/L'], ['SaO2','lab','숫자','%'], ['Lactate','lab','숫자','mmol/L'], ['Creatinine','lab','숫자','mg/dL'], ['Hgb','lab','숫자','g/dL'], ['Plt','lab','숫자','10^3/uL'], ['INR','lab','숫자',''], ['APTT','lab','숫자','sec'], ['AST','lab','숫자','U/L'], ['ALT','lab','숫자','U/L'], ['Bilirubin','lab','숫자','mg/dL'], ['Albumin','lab','숫자','g/dL'], ['CRP','lab','숫자','mg/dL'], ['ESR','lab','숫자','mm/h'], ['proBNP','lab','숫자','pg/mL'], ['Myoglobin','lab','숫자',''], ['CK-MB','lab','숫자',''], ['Troponin I','lab','숫자',''], ['Troponin T','lab','숫자',''],
      ['GCS','intra_ecmo','숫자',''], ['pump_flow','intra_ecmo','숫자','L/min'], ['RPM','intra_ecmo','숫자','rpm'], ['ECMO_FiO2','intra_ecmo','숫자',''], ['sweep_gas','intra_ecmo','숫자',''],
      ['SBP','ventilator','숫자','mmHg'], ['DBP','ventilator','숫자','mmHg'], ['mean_bp','ventilator','숫자','mmHg'], ['PR','ventilator','숫자','/min'], ['vent_mode','ventilator','범주형',''], ['FiO2','ventilator','숫자',''], ['RR','ventilator','숫자','/min'], ['PEEP','ventilator','숫자','cmH2O'], ['flow_rate','ventilator','숫자','L/min'], ['O2','ventilator','숫자',''],
      ['discharge_alive','outcome','예/아니오',''], ['icu_admission_datetime','outcome','날짜/시간',''], ['icu_discharge_datetime','outcome','날짜/시간',''], ['hospital_discharge_datetime','outcome','날짜/시간',''], ['death_datetime','outcome','날짜/시간',''], ['creatinine_28d','outcome','숫자','mg/dL'], ['last_follow_up_date','outcome','날짜/시간',''],
      ['diagnosis_name','diagnosis','자유 텍스트',''], ['past_history_hypertension','past_history','예/아니오',''], ['past_history_diabetes','past_history','예/아니오',''], ['past_history_cancer','past_history','예/아니오',''], ['chief_complaint_admission_reason','diagnosis','자유 텍스트',''],
      ['microbiology_sample_datetime','microbiology','날짜/시간',''], ['organism_name','microbiology','자유 텍스트',''], ['microbiology_result','microbiology','범주형',''], ['susceptibility','microbiology','자유 텍스트',''],
      ['operator','perfusionist_file','자유 텍스트',''], ['assistant','perfusionist_file','자유 텍스트',''], ['perfusionist','perfusionist_file','자유 텍스트',''], ['circuit_change_note','perfusionist_file','자유 텍스트',''], ['weaning','perfusionist_file','예/아니오','']
    ];
    patchState(s => {
      s.tags.unshift({ id: tagId, name: '2026_ECMO_Registry', status: '준비 중', color: '#0b8f8a', description: '2026 총정리본 기반 ECMO 환자 연구용 태그. 환자 마스터는 고정하고, ECMO episode·timepoint·group·clinical section별 반복 자료를 연결합니다.', irb: '', matchUnit: '복합 단위', createdBy: USER, createdAt: nowText(), updatedAt: nowText() });
      axes.forEach(ax => {
        s.axes.push({ id: uid('AXIS'), tagId, name: ax.name, inputMode: '드롭다운 + 관리자 새 값 추가', level: ax.level, values: ax.values.map(v => ({ id: uid('VAL'), label: v, synonyms: [] })), createdAt: nowText() });
      });
      presetVariables.forEach(([name, kind, type, unit]) => {
        s.variables.push({ id: uid('VAR'), tagId, tagName: '2026_ECMO_Registry', categories: [kind], name, kind, type, unit, valueRule: '직접 입력 허용', level: kind === '환자 기본정보' ? '환자 단위' : '연구 이벤트/관측값 단위', matching: '가명 연구대상자 ID + ECMO episode + timepoint', internal: {}, rule: '2026 총정리본 sheet 구조 기반 preset', status: '저장 대기', createdAt: nowText() });
      });
      s.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: USER, action: 'preset tag template', target: 'research_tag', description: '2026 총정리본 기반 연구 태그/분류축/변수 preset 생성', status: 'success' });
    });
    renderTagManager();
    toast('2026 총정리본 기반 연구 태그 구조를 생성했습니다.');
  }


  function ensureTrajectoryComparisonTemplate() {
    const templateTagName = 'ECMO_NonECMO_Trajectory';
    const templateAxes = [
      { name: '비교군', level: '환자 단위', values: ['ECMO', 'Non-ECMO', 'Matched Non-ECMO'] },
      { name: '기준시점', level: '자료묶음 단위', values: ['ECMO start', 'ICU admission', 'Procedure start', 'Pseudo-index time'] },
      { name: '관찰구간', level: '관찰구간/Timepoint 단위', values: ['Pre-index', 'During ECMO', 'Post-index', 'Follow-up', 'Single observation'] },
      { name: 'Timepoint', level: '관찰구간/Timepoint 단위', values: ['Pre', '4h', '24h', 'Day 1', 'Day 2', 'Day 3', 'Day 7'] },
      { name: '측정밀도', level: '관측값 단위', values: ['Repeated trajectory', 'Sparse observation', 'Single observation'] },
      { name: '자료영역', level: '관측값 단위', values: ['Vital', 'Lab', 'Microbiology', 'Ventilator', 'Medication', 'Outcome'] },
      { name: '분석비교', level: '자료묶음 단위', values: ['Within ECMO pre-post trajectory', 'ECMO vs Non-ECMO trajectory', 'Group × time interaction', 'Cross-sectional comparison'] }
    ];
    let created = false;
    patchState(s => {
      let tag = s.tags.find(t => t.name === templateTagName);
      if (!tag) {
        tag = { id: uid('TAG'), name: templateTagName, status: '준비 중', color: '#1d5d9b', description: 'ECMO군과 Non-ECMO군의 시간 궤적을 비교하기 위한 예시 연구 태그입니다. 일반 태그이므로 수정하거나 삭제할 수 있습니다.', irb: '', matchUnit: '복합 단위', createdBy: USER, createdAt: nowText(), updatedAt: nowText() };
        s.tags.unshift(tag);
        created = true;
      }
      templateAxes.forEach(ax => {
        let axis = s.axes.find(a => a.tagId === tag.id && a.name.toLowerCase() === ax.name.toLowerCase());
        if (!axis) {
          axis = { id: uid('AXIS'), tagId: tag.id, name: ax.name, inputMode: '드롭다운 + 관리자 새 값 추가', level: ax.level, values: [], createdAt: nowText() };
          s.axes.push(axis);
        }
        axis.level = ax.level;
        axis.inputMode = '드롭다운 + 관리자 새 값 추가';
        ax.values.forEach(label => {
          if (!axis.values.some(v => v.label.toLowerCase() === label.toLowerCase())) axis.values.push({ id: uid('VAL'), label, synonyms: [] });
        });
      });
      s.audit.unshift({ id: uid('AUDIT'), time: nowText(), user: USER, action: 'trajectory example tag', target: 'research_tag', description: 'ECMO / Non-ECMO 궤적 비교 예시 태그 생성/갱신', status: 'success' });
    });
    renderTagManager();
    toast(created ? '예시 연구 태그를 생성했습니다. 목록에서 수정/삭제할 수 있습니다.' : '이미 있는 예시 태그의 분류축을 갱신했습니다.');
  }

  function setTagColorInputs(tagCard, color) {
    const value = normalizeTagColor(color || '#0b1f3a');
    const colorPicker = $('[data-role="tag-color"]', tagCard);
    const colorText = $('[data-role="tag-color-text"]', tagCard);
    if (colorPicker) colorPicker.value = value;
    if (colorText) colorText.value = value;
    $$('.palette-swatch', tagCard).forEach(btn => btn.classList.toggle('active', normalizeTagColor(btn.dataset.color) === value));
  }

  function bindTagColorPalette(tagCard) {
    const colorPicker = $('[data-role="tag-color"]', tagCard);
    const colorText = $('[data-role="tag-color-text"]', tagCard);
    $$('.palette-swatch', tagCard).forEach(btn => {
      btn.addEventListener('click', () => setTagColorInputs(tagCard, btn.dataset.color));
    });
    colorPicker?.addEventListener('input', () => setTagColorInputs(tagCard, colorPicker.value));
    colorText?.addEventListener('input', () => {
      const value = colorText.value.trim();
      if (/^#[0-9a-fA-F]{6}$/.test(value)) setTagColorInputs(tagCard, value);
    });
    setTagColorInputs(tagCard, colorText?.value || colorPicker?.value || '#0b1f3a');
  }

  function axisValueLabels(axis) {
    return (axis?.values || []).map(v => v.label).filter(Boolean);
  }

  function axisMatches(axis, keywords) {
    const name = String(axis?.name || '').toLowerCase();
    return keywords.some(k => name.includes(k.toLowerCase()));
  }

  function renderTagStructurePreview(state = readState()) {
    const select = $('#tagStructureSelect');
    const box = $('#tagStructurePreview');
    if (!select || !box) return;
    fillTagSelect(select, '등록된 연구 태그가 없습니다.');
    const tagId = select.value || state.tags[0]?.id || '';
    if (tagId && select.value !== tagId && [...select.options].some(o => o.value === tagId)) select.value = tagId;
    const tag = state.tags.find(t => t.id === tagId);
    const axes = state.axes.filter(a => a.tagId === tagId);
    if (!tag) {
      box.innerHTML = '<div class="empty-state"><strong>연구 태그를 선택하세요.</strong><span>태그를 만들면 군/시점 구조가 여기에 표시됩니다.</span></div>';
      return;
    }
    if (!axes.length) {
      box.innerHTML = `<div class="empty-state"><strong>${escapeHtml(tag.name)}</strong><span>아직 이 태그에 연결된 군, 시점, 표준값이 없습니다.</span></div>`;
      return;
    }
    const groupAxes = axes.filter(a => axisMatches(a, ['group', '군', '그룹', '비교군', 'cohort']));
    const timeAxes = axes.filter(a => axisMatches(a, ['timepoint', 'day', 'visit', '시점', '시간', '관찰구간', '기준시점']));
    const otherAxes = axes.filter(a => !groupAxes.includes(a) && !timeAxes.includes(a));
    const chipList = (items, emptyText = '등록된 값 없음') => {
      const labels = items.flatMap(axisValueLabels);
      return labels.length ? labels.map(v => `<span class="structure-chip">${escapeHtml(v)}</span>`).join('') : `<span class="structure-empty">${escapeHtml(emptyText)}</span>`;
    };
    const otherHtml = otherAxes.map(a => `<div class="structure-axis"><strong>${escapeHtml(a.name)}</strong><div class="structure-chip-row">${chipList([a])}</div></div>`).join('') || '<div class="structure-empty">기타 분류축 없음</div>';
    const groupLabels = groupAxes.flatMap(axisValueLabels);
    const timeLabels = timeAxes.flatMap(axisValueLabels);
    const matrix = groupLabels.length || timeLabels.length ? `
      <div class="tag-structure-matrix">
        ${(groupLabels.length ? groupLabels : ['군 미지정']).map(g => `<div class="matrix-row"><div class="matrix-group">${escapeHtml(g)}</div><div class="matrix-timepoints">${(timeLabels.length ? timeLabels : ['시점 미지정']).map(t => `<span>${escapeHtml(t)}</span>`).join('')}</div></div>`).join('')}
      </div>` : '<div class="structure-empty">군/시점 matrix를 만들 표준값이 아직 없습니다.</div>';
    box.innerHTML = `
      <div class="structure-title"><strong>${tagBadge(tag)}</strong><span>${escapeHtml(tag.description || '설명 없음')}</span></div>
      <div class="structure-section"><h4>군, Group</h4><div class="structure-chip-row">${chipList(groupAxes, '군 표준값 없음')}</div></div>
      <div class="structure-section"><h4>시점, Timepoint</h4><div class="structure-chip-row">${chipList(timeAxes, '시점 표준값 없음')}</div></div>
      <div class="structure-section"><h4>군 × 시점 한눈에 보기</h4>${matrix}</div>
      <div class="structure-section"><h4>기타 분류축</h4>${otherHtml}</div>`;
  }

  function initTagManager() {
    const tagCard = cardByHeading('새 연구 태그 만들기');
    const axisCard = cardByHeading('연구 내 분류축 설계') || cardByHeading('태그 내부 분류축 설계');
    if (!tagCard || !axisCard) return;

    ensureAxisTagSelect(axisCard);
    const duplicateBtn = $$('button', tagCard).find(b => b.textContent.includes('중복'));
    const saveTagBtn = $$('button', tagCard).find(b => b.textContent.includes('연구 태그 저장'));
    const addAxisBtn = $$('button', axisCard).find(b => b.textContent.includes('분류축 추가'));
    const saveValueBtn = $$('button', axisCard).find(b => b.textContent.includes('표준값 저장'));
    const presetBtn = $('#seed2026TemplateBtn');
    const trajectoryPresetBtn = $('#seedTrajectoryTemplateBtn');
    [duplicateBtn, saveTagBtn, addAxisBtn, saveValueBtn, presetBtn, trajectoryPresetBtn].forEach(removeDisabledAction);

    bindTagColorPalette(tagCard);

    duplicateBtn?.addEventListener('click', () => {
      const name = $('input', tagCard)?.value.trim();
      if (!name) return toast('검사할 태그명을 입력하세요.', 'gray');
      const exists = readState().tags.some(t => t.name.toLowerCase() === name.toLowerCase());
      toast(exists ? '이미 같은 태그명이 있습니다.' : '사용 가능한 태그명입니다.', exists ? 'yellow' : 'teal');
    });

    saveTagBtn?.addEventListener('click', () => saveTag(tagCard));
    addAxisBtn?.addEventListener('click', () => saveAxis(axisCard, false));
    saveValueBtn?.addEventListener('click', () => saveAxis(axisCard, true));
    presetBtn?.addEventListener('click', ensure2026EcmoTemplate);
    trajectoryPresetBtn?.addEventListener('click', ensureTrajectoryComparisonTemplate);
    $('#tagStructureSelect')?.addEventListener('change', () => renderTagStructurePreview());

    renderTagManager();
  }

  function ensureAxisTagSelect(axisCard) {
    if ($('[data-role="axis-tag-select"]', axisCard)) return;
    const firstGrid = $('.grid.three', axisCard);
    const wrap = document.createElement('div');
    wrap.className = 'field';
    wrap.innerHTML = '<label>적용할 연구 태그</label><select data-role="axis-tag-select"><option>등록된 연구 태그가 없습니다.</option></select>';
    firstGrid?.prepend(wrap);
  }

  function saveTag(tagCard) {
    const desc = $('textarea', tagCard)?.value.trim() || '';
    const name = $('[data-role="tag-name"]', tagCard)?.value.trim() || $$('input', tagCard)[0]?.value.trim();
    if (!name) return toast('태그명을 입력하세요.', 'gray');
    const status = $('[data-role="tag-status"]', tagCard)?.value || '준비 중';
    const color = $('[data-role="tag-color-text"]', tagCard)?.value.trim() || $('[data-role="tag-color"]', tagCard)?.value || '#0b8f8a';
    const irb = $('[data-role="tag-irb"]', tagCard)?.value.trim() || '';
    const matchUnit = $('[data-role="tag-match-unit"]', tagCard)?.value || '사람 단위';
    const editId = tagCard.dataset.editId;

    const currentState = readState();
    if (!editId && currentState.tags.some(t => t.name.toLowerCase() === name.toLowerCase())) {
      return toast('이미 같은 태그명이 있습니다.', 'yellow');
    }
    const state = patchState(s => {
      if (editId) {
        const target = s.tags.find(t => t.id === editId);
        if (target) Object.assign(target, { name, status, color, description: desc, irb, matchUnit, updatedAt: nowText() });
      } else {
        s.tags.unshift({ id: uid('TAG'), name, status, color, description: desc, irb, matchUnit, createdBy: USER, createdAt: nowText(), updatedAt: nowText() });
      }
    });
    delete tagCard.dataset.editId;
    $$('input, textarea', tagCard).forEach(el => {
      if (el.type === 'color') el.value = '#0b1f3a';
      else if (el.dataset.role === 'tag-color-text') el.value = '#0b1f3a';
      else el.value = '';
    });
    setTagColorInputs(tagCard, '#0b1f3a');
    renderTagManager(state);
    addAudit(editId ? 'tag update' : 'tag creation', 'research_tag', name);
    toast(editId ? '연구 태그를 수정했습니다.' : '연구 태그를 저장했습니다.');
  }

  function saveAxis(axisCard, valueOnly) {
    const tagId = $('[data-role="axis-tag-select"]', axisCard)?.value;
    if (!tagId) return toast('적용할 연구 태그를 먼저 선택하세요.', 'gray');
    const grids = $$('.grid', axisCard);
    const firstInputs = $$('input', grids[0] || axisCard);
    const selects = $$('select', grids[0] || axisCard);
    const secondInputs = $$('input', grids[1] || axisCard);
    const directInputs = $$('.direct-entry input', axisCard);

    const axisName = firstInputs[0]?.value.trim() || directInputs[0]?.value.trim();
    const inputMode = selects[1]?.value || selects[0]?.value || '드롭다운만 허용';
    const level = '';
    const standardValue = secondInputs[0]?.value.trim() || directInputs[1]?.value.trim();
    const synonyms = (secondInputs[1]?.value.trim() || directInputs[2]?.value.trim() || '').split(',').map(v => v.trim()).filter(Boolean);
    if (!axisName) return toast('분류축 이름을 입력하세요.', 'gray');
    if (valueOnly && !standardValue) return toast('표준 분류값을 입력하세요.', 'gray');

    const state = patchState(s => {
      let axis = s.axes.find(a => a.tagId === tagId && a.name.toLowerCase() === axisName.toLowerCase());
      if (!axis) {
        axis = { id: uid('AXIS'), tagId, name: axisName, inputMode, values: [], createdAt: nowText() };
        s.axes.unshift(axis);
      }
      axis.inputMode = inputMode;
      delete axis.level;
      if (standardValue && !axis.values.some(v => v.label.toLowerCase() === standardValue.toLowerCase())) {
        axis.values.push({ id: uid('VAL'), label: standardValue, synonyms });
      }
    });
    $$('input', axisCard).forEach(el => el.value = '');
    renderTagManager(state);
    addAudit('tag vocabulary update', 'tag_axis', axisName);
    toast(valueOnly ? '표준값을 저장했습니다.' : '분류축을 추가했습니다.');
  }

  function renderTagManager(state = readState()) {
    fillTagSelect($('[data-role="axis-tag-select"]'), '태그를 먼저 생성하세요.');
    setMetricByLabel('활성 연구 태그', `${state.tags.length}개`, state.tags.length ? '등록됨' : '대기');
    setMetricByLabel('연구 내 분류축', `${state.axes.length}개`, state.axes.length ? '등록됨' : '대기');
    const valueCount = state.axes.reduce((sum, a) => sum + (a.values?.length || 0), 0);
    setMetricByLabel('표준 분류값', `${valueCount}개`, valueCount ? '등록됨' : '대기');
    setMetricByLabel('미정리 자유입력값', `0개`, '대기');

    const tagBody = cardByHeading('연구 태그 목록')?.querySelector('tbody');
    if (tagBody) {
      if (!state.tags.length) setTableEmpty(tagBody, 9, '아직 생성된 연구 태그가 없습니다.', '연구를 구분할 큰 태그를 만든 뒤 내부 분류축을 설계합니다.');
      else tagBody.innerHTML = state.tags.map(t => {
        const axes = state.axes.filter(a => a.tagId === t.id);
        const vitalCount = state.vitalFiles.filter(f => (f.tagIds || []).includes(t.id)).length;
        const subjectCount = state.studyPatients.filter(sp => sp.tagId === t.id).length;
        return `<tr><td>${tagBadge(t)}</td><td>${colorSwatch(t.color)}</td><td>${escapeHtml(t.description || '-')}</td><td>${badge(t.status || '준비 중', 'gray')}</td><td>${subjectCount}명</td><td>${vitalCount}개</td><td>${axes.map(a => escapeHtml(a.name)).join(', ') || '-'}</td><td>${escapeHtml(t.updatedAt || t.createdAt)}</td><td><button class="btn ghost" data-edit-tag="${t.id}">수정</button> <button class="btn ghost" data-delete-tag="${t.id}">삭제</button></td></tr>`;
      }).join('');
    }
    const axisBody = (cardByHeading('연구 내 분류축 / 표준값 목록') || cardByHeading('내부 분류축 / 표준값 목록'))?.querySelector('tbody');
    if (axisBody) {
      const rows = state.axes.flatMap(a => {
        const tag = state.tags.find(t => t.id === a.tagId);
        if (!a.values?.length) return [`<tr><td>${escapeHtml(tag?.name || '-')}</td><td>${escapeHtml(a.name)}</td><td>-</td><td>-</td><td>${escapeHtml(a.inputMode)}</td><td><button class="btn ghost" data-delete-axis="${a.id}">삭제</button></td></tr>`];
        return a.values.map(v => `<tr><td>${escapeHtml(tag?.name || '-')}</td><td>${escapeHtml(a.name)}</td><td>${escapeHtml(v.label)}</td><td>${escapeHtml((v.synonyms || []).join(', ') || '-')}</td><td>${escapeHtml(a.inputMode)}</td><td><button class="btn ghost" data-delete-axis="${a.id}">삭제</button></td></tr>`);
      });
      axisBody.innerHTML = rows.join('') || `<tr class="empty-row"><td colspan="6"><strong>아직 등록된 연구 내 분류축이 없습니다.</strong><br><span>표준값을 정의하면 이곳에 표시됩니다.</span></td></tr>`;
    }
    renderTagStructurePreview(state);
    bindTagManagerActions();
  }

  function bindTagManagerActions() {
    const tagCard = cardByHeading('새 연구 태그 만들기');
    $$('[data-edit-tag]').forEach(btn => btn.addEventListener('click', () => {
      const state = readState();
      const t = state.tags.find(x => x.id === btn.dataset.editTag);
      if (!t || !tagCard) return;
      const inputs = $$('input', tagCard);
      const color = normalizeTagColor(t.color);
      const nameInput = $('[data-role="tag-name"]', tagCard) || inputs[0];
      if (nameInput) nameInput.value = t.name || '';
      if ($('[data-role="tag-status"]', tagCard)) $('[data-role="tag-status"]', tagCard).value = t.status || '준비 중';
      if ($('[data-role="tag-color"]', tagCard)) $('[data-role="tag-color"]', tagCard).value = color;
      if ($('[data-role="tag-color-text"]', tagCard)) $('[data-role="tag-color-text"]', tagCard).value = color;
      setTagColorInputs(tagCard, color);
      if ($('textarea', tagCard)) $('textarea', tagCard).value = t.description || '';
      if ($('[data-role="tag-irb"]', tagCard)) $('[data-role="tag-irb"]', tagCard).value = t.irb || '';
      if ($('[data-role="tag-match-unit"]', tagCard)) $('[data-role="tag-match-unit"]', tagCard).value = t.matchUnit || '사람 단위';
      tagCard.dataset.editId = t.id;
      toast('수정할 태그 정보를 위 입력칸에 불러왔습니다.');
      tagCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }));
    $$('[data-delete-tag]').forEach(btn => btn.addEventListener('click', () => {
      if (!confirm('이 연구 태그와 연결된 내부 분류축을 삭제할까요?')) return;
      patchState(s => {
        s.tags = s.tags.filter(t => t.id !== btn.dataset.deleteTag);
        s.axes = s.axes.filter(a => a.tagId !== btn.dataset.deleteTag);
        s.vitalFiles.forEach(f => f.tagIds = (f.tagIds || []).filter(id => id !== btn.dataset.deleteTag));
      });
      renderTagManager();
      toast('연구 태그를 삭제했습니다.');
    }));
    $$('[data-delete-axis]').forEach(btn => btn.addEventListener('click', () => {
      if (!confirm('이 연구 내 분류축을 삭제할까요?')) return;
      patchState(s => { s.axes = s.axes.filter(a => a.id !== btn.dataset.deleteAxis); });
      renderTagManager();
      toast('연구 내 분류축을 삭제했습니다.');
    }));
  }


  function populatePatientInternalSelects(tagId) {
    const card = cardByHeading('연구 내 분류값 선택') || cardByHeading('태그 안에서 구분값 선택');
    if (!card) return;
    const selects = $$('select', card);
    if (selects[0]) selects[0].innerHTML = axisValueOptions(tagId, ['관찰구간', 'timepoint', 'day', 'visit', '시간', '방문'], '등록된 관찰구간/Timepoint 없음');
    if (selects[1]) selects[1].innerHTML = axisValueOptions(tagId, ['비교군', 'group', '군', '그룹', 'cohort'], '등록된 비교군 없음');
    if (selects[2]) selects[2].innerHTML = axisValueOptions(tagId, ['자료영역', 'stage', '상태', 'outcome', 'domain', 'section'], '등록된 자료영역/상태 없음');
  }


  function resetVariableForm() {
    ['newVarName', 'newVarUnit'].forEach(id => {
      const el = $('#' + id);
      if (el) el.value = '';
    });
    const type = $('#newVarType');
    if (type) type.value = '숫자';
  }

  function saveVariableDefinition() {
    const tagSelect = cardByHeading('연구 태그 선택')?.querySelector('select');
    const tagId = tagSelect?.value || '';
    const tag = readState().tags.find(t => t.id === tagId);
    const name = ($('#newVarName')?.value || '').trim();
    const type = $('#newVarType')?.value || '숫자';
    const unit = ($('#newVarUnit')?.value || '').trim();
    const valueRule = '직접 입력 허용';
    const level = '분류값 연결 전';
    const description = '';

    if (!name) {
      toast('저장할 변수명을 입력하세요.', 'yellow');
      return;
    }

    const state = patchState(s => {
      const exists = (s.variableDefinitions || []).find(v =>
        (v.name || '').toLowerCase() === name.toLowerCase() && (v.tagId || '') === tagId
      );
      if (exists) {
        exists.type = type;
        exists.unit = unit;
        exists.valueRule = valueRule;
        exists.level = level;
        exists.description = description;
        exists.tagName = tag?.name || '공통 변수';
        exists.updatedAt = nowText();
      } else {
        s.variableDefinitions = s.variableDefinitions || [];
        s.variableDefinitions.unshift({
          id: uid('VDEF'),
          tagId,
          tagName: tag?.name || '공통 변수',
          name,
          type,
          unit,
          valueRule,
          level,
          description,
          createdAt: nowText(),
          updatedAt: nowText()
        });
      }
    });

    renderVariableLibrary(state);
    addAudit('variable definition save', 'variable', `${name} 변수 사전 저장`);
    toast('변수를 저장했습니다. 계속 추가할 수 있습니다.');
    resetVariableForm();
    $('#newVarName')?.focus();
  }

  function renderVariableLibrary(state = readState()) {
    const body = $('#variableLibraryBody');
    if (!body) return;
    const tagId = cardByHeading('연구 태그 선택')?.querySelector('select')?.value || '';
    const defs = (state.variableDefinitions || []).filter(v => !tagId || !v.tagId || v.tagId === tagId);
    if (!defs.length) {
      return setTableEmpty(body, 5, '저장된 변수가 없습니다.', '변수명, 자료형, 단위만 입력한 뒤 계속 저장하세요.');
    }
    body.innerHTML = defs.map(v => `<tr>
      <td><strong>${escapeHtml(v.name)}</strong></td>
      <td>${escapeHtml(v.type)}</td>
      <td>${escapeHtml(v.unit || '-')}</td>
      <td>${escapeHtml(v.tagName || '공통 변수')}</td>
      <td><button class="btn ghost" data-use-vdef="${v.id}">입력 예정에 추가</button> <button class="btn ghost" data-del-vdef="${v.id}">삭제</button></td>
    </tr>`).join('');

    $$('[data-use-vdef]', body).forEach(btn => btn.addEventListener('click', () => addClinicalVariable(btn.dataset.useVdef)));
    $$('[data-del-vdef]', body).forEach(btn => btn.addEventListener('click', () => {
      patchState(s => { s.variableDefinitions = (s.variableDefinitions || []).filter(v => v.id !== btn.dataset.delVdef); });
      renderVariableLibrary();
      toast('저장된 변수를 삭제했습니다.');
    }));
  }

  function addClinicalVariable(variableDefinitionId = null) {
    const tagSelect = cardByHeading('연구 태그 선택')?.querySelector('select');
    const tagId = tagSelect?.value;
    const stateBefore = readState();
    const tag = stateBefore.tags.find(t => t.id === tagId);
    if (!tag) return toast('연구 태그를 먼저 선택하세요.', 'gray');
    const classCard = cardByHeading('연구 내 분류값 선택') || cardByHeading('태그 안에서 구분값 선택');
    const classSelects = $$('select', classCard);
    const directClass = $$('.direct-entry input', classCard).map(i => i.value.trim());

    const itemCard = cardByHeading('입력할 자료 항목 직접 고르기');
    const checked = $$('input[type="checkbox"]:checked', itemCard).map(i => i.closest('.mini-item')?.querySelector('strong')?.textContent.trim().replace(/^\s*/, '')).filter(Boolean);
    const customInputs = $$('.direct-entry input', itemCard).map(i => i.value.trim());
    const rule = $('.direct-entry textarea', itemCard)?.value.trim() || '';

    const varCard = cardByHeading('새 변수 만들기');
    const vInputs = $$('input', varCard);
    const vSelects = $$('select', varCard);
    const variableName = sourceDefinition?.name || vInputs[0]?.value.trim() || customInputs[0] || checked[0];
    if (!variableName) return toast('추가할 자료 항목 또는 변수명을 입력하거나, 변수 사전에서 항목을 선택하세요.', 'gray');

    const state = patchState(s => {
      s.variables.unshift({
        id: uid('VAR'),
        tagId,
        tagName: tag.name,
        categories: checked,
        name: variableName,
        kind: customInputs[1] || 'custom',
        type: sourceDefinition?.type || vSelects[0]?.value || '숫자',
        unit: sourceDefinition?.unit || vInputs[1]?.value.trim() || customInputs[2] || '',
        valueRule: sourceDefinition?.valueRule || vSelects[1]?.value || '직접 입력 허용',
        level: sourceDefinition?.level || vSelects[2]?.value || '환자 단위',
        matching: cardByHeading('연구 태그 선택')?.querySelectorAll('select')[1]?.value || '가명 연구대상자 ID',
        internal: {
          day: classSelects[0]?.value === '__direct__' ? directClass[0] : selectedText(classSelects[0]) || directClass[0] || '',
          group: classSelects[1]?.value === '__direct__' ? directClass[1] : selectedText(classSelects[1]) || directClass[1] || '',
          stage: classSelects[2]?.value === '__direct__' ? directClass[2] : selectedText(classSelects[2]) || directClass[2] || ''
        },
        rule: sourceDefinition?.description || rule,
        variableDefinitionId: sourceDefinition?.id || '',
        status: '저장 대기',
        createdAt: nowText()
      });
    });
    $$('input[type="checkbox"]', itemCard).forEach(i => i.checked = false);
    $$('input, textarea', itemCard).forEach(i => { if (i.type !== 'checkbox') i.value = ''; });
    $$('input', varCard).forEach(i => i.value = '');
    renderClinicalVariables(state);
    addAudit('clinical variable create', 'variable', variableName);
    toast('입력 예정 자료 항목을 추가했습니다.');
  }

  function renderClinicalVariables(state = readState()) {
    setMetricByLabel('선택된 변수', `${state.variables.length}개`, state.variables.length ? '등록됨' : '대기');
    const currentTagId = cardByHeading('연구 태그 선택')?.querySelector('select')?.value || '';
    const assignedSubjects = currentTagId ? state.studyPatients.filter(sp => sp.tagId === currentTagId).length : 0;
    setMetricByLabel('선택된 대상자', `${assignedSubjects}명`, assignedSubjects ? '배정됨' : '대기');
    setMetricByLabel('저장 대기 자료', `${state.variables.filter(v => v.status === '저장 대기').length}건`, state.variables.length ? '확인' : '대기');
    const body = cardByHeading('입력 예정 자료')?.querySelector('tbody');
    if (!body) return;
    if (!state.variables.length) return setTableEmpty(body, 8, '아직 추가된 입력 항목이 없습니다.', '연구 태그, 연구 내 분류값, 변수를 선택해 추가하세요.');
    body.innerHTML = state.variables.map(v => `<tr>
      <td><input type="checkbox" checked></td><td>${escapeHtml(v.tagName)}</td><td>${escapeHtml([v.internal?.day, v.internal?.group, v.internal?.stage].filter(Boolean).join(' / ') || '-')}</td>
      <td>${escapeHtml(v.name)}</td><td>${escapeHtml(v.type)}</td><td>${escapeHtml(v.unit || '-')}</td><td>${escapeHtml(v.matching)}</td><td>${badge(v.status, 'yellow')} <button class="btn ghost" data-delete-var="${v.id}">삭제</button></td>
    </tr>`).join('');
    $$('[data-delete-var]', body).forEach(btn => btn.addEventListener('click', () => {
      patchState(s => { s.variables = s.variables.filter(v => v.id !== btn.dataset.deleteVar); });
      renderClinicalVariables();
      toast('입력 예정 자료 항목을 삭제했습니다.');
    }));
  }

  function initTagAssignment() {
    const firstCard = cardByHeading('연구 태그 선택');
    const tagSelect = firstCard?.querySelector('select');
    fillTagSelect(tagSelect, '등록된 연구 태그가 없습니다.');
    tagSelect?.addEventListener('change', () => { populateAssignmentInternalSelects(tagSelect.value); renderAssignmentTargets(); updateAssignmentSummary(); });
    populateAssignmentInternalSelects(tagSelect?.value || '');

    const saveBtn = cardByHeading('대상 선택')?.querySelector('button');
    removeDisabledAction(saveBtn);
    saveBtn?.addEventListener('click', saveAssignments);
    renderAssignmentTargets();
    updateAssignmentSummary();
  }

  function populateAssignmentInternalSelects(tagId) {
    const card = cardByHeading('연구 내 분류값 입력') || cardByHeading('태그 내부 구분값 입력');
    if (!card) return;
    const selects = $$('select', card);
    if (selects[0]) selects[0].innerHTML = axisValueOptions(tagId, ['관찰구간', 'timepoint', 'day', 'visit', '시간', '방문'], '등록된 관찰구간/Timepoint 없음');
    if (selects[1]) selects[1].innerHTML = axisValueOptions(tagId, ['비교군', 'group', '군', '그룹', 'cohort'], '등록된 비교군 없음');
    if (selects[2]) selects[2].innerHTML = axisValueOptions(tagId, ['자료영역', 'stage', '상태', 'outcome', 'domain', 'section'], '등록된 자료영역/상태 없음');
  }

  function renderAssignmentTargets() {
    const state = readState();
    const body = cardByHeading('대상 선택')?.querySelector('tbody');
    if (!body) return;
    const targets = [
      ...state.studyPatients.map(sp => ({ id: sp.id, label: sp.pseudoId || sp.patientId || sp.id, type: '사람, 연구대상자', tagIds: [sp.tagId], status: '대상자 배정' })),
      ...state.patients.map(p => ({ id: p.id, label: p.pseudoId || ('****' + String(p.registrationNo || '').slice(-4)), type: '사람 master', tagIds: [], status: '환자 등록' })),
      ...state.vitalFiles.map(f => ({ id: f.id, label: f.name, type: '사람 + raw CSV/QC 파일', tagIds: f.tagIds || [], status: f.uploadStatus })),
      ...state.variables.map(v => ({ id: v.id, label: v.name, type: '사람 + 검사/임상자료', tagIds: [v.tagId], status: v.status }))
    ];
    if (!targets.length) return setTableEmpty(body, 9, '태그를 부여할 대상이 없습니다.', '환자 master, 연구대상자, raw CSV/QC 파일 또는 검사기록을 먼저 추가하세요.');
    body.innerHTML = targets.map(t => `<tr>
      <td><input type="checkbox" data-target-id="${escapeHtml(t.id)}" data-target-type="${escapeHtml(t.type)}"></td><td>${escapeHtml(t.label)}</td><td>${escapeHtml(t.type)}</td>
      <td>${(t.tagIds || []).length ? badge('태그 있음', 'blue') : badge('미태그', 'gray')}</td><td class="assign-day">-</td><td class="assign-group">-</td><td class="assign-stage">-</td><td>${badge('없음', 'green')}</td><td>${escapeHtml(t.status || '-')}</td>
    </tr>`).join('');
    $$('[data-target-id]', body).forEach(box => box.addEventListener('change', updateAssignmentSummary));
  }

  function saveAssignments() {
    const tagSelect = cardByHeading('연구 태그 선택')?.querySelector('select');
    const tagId = tagSelect?.value;
    const state = readState();
    const tag = state.tags.find(t => t.id === tagId);
    if (!tag) return toast('연구 태그를 먼저 선택하세요.', 'gray');
    const checked = $$('[data-target-id]:checked');
    if (!checked.length) return toast('태그를 부여할 대상을 선택하세요.', 'gray');
    const classCard = cardByHeading('연구 내 분류값 입력') || cardByHeading('태그 내부 구분값 입력');
    const selects = $$('select', classCard);
    const direct = $$('.direct-entry input', classCard).map(i => i.value.trim());
    const internal = {
      day: selects[0]?.value === '__direct__' ? direct[0] : selectedText(selects[0]) || direct[0] || '',
      group: selects[1]?.value === '__direct__' ? direct[1] : selectedText(selects[1]) || direct[1] || '',
      stage: selects[2]?.value === '__direct__' ? direct[2] : selectedText(selects[2]) || direct[2] || ''
    };
    const note = classCard?.querySelector('.field[style] input')?.value.trim() || '';
    const next = patchState(s => {
      checked.forEach(box => {
        const targetId = box.dataset.targetId;
        const targetType = box.dataset.targetType;
        const vf = s.vitalFiles.find(f => f.id === targetId);
        if (vf && !(vf.tagIds || []).includes(tagId)) vf.tagIds = [...(vf.tagIds || []), tagId];
        s.assignments.unshift({ id: uid('MAP'), tagId, tagName: tag.name, targetId, targetType, internal, note, assignedBy: USER, assignedAt: nowText() });
      });
      // 자유 입력된 내부 구분값을 해당 태그의 표준 후보로도 저장합니다.
      [['관찰구간 / Timepoint', internal.day], ['비교군', internal.group], ['자료영역 / 상태', internal.stage]].forEach(([axisName, val]) => {
        if (!val || val === '선택 안 함') return;
        let axis = s.axes.find(a => a.tagId === tagId && a.name.toLowerCase() === axisName.toLowerCase());
        if (!axis) {
          axis = { id: uid('AXIS'), tagId, name: axisName, inputMode: '드롭다운 + 관리자 새 값 추가', values: [] };
          s.axes.push(axis);
        }
        if (!axis.values.some(v => v.label.toLowerCase() === val.toLowerCase())) axis.values.push({ id: uid('VAL'), label: val, synonyms: [] });
      });
    });
    renderAssignmentTargets();
    populateAssignmentInternalSelects(tagId);
    updateAssignmentSummary(next);
    addAudit('tag assignment', 'data_tag_mapping', `${tag.name} → ${checked.length}건`);
    toast('연구 태그와 내부 구분값을 저장했습니다.');
  }

  function updateAssignmentSummary(state = readState()) {
    const tagSelect = cardByHeading('연구 태그 선택')?.querySelector('select');
    const tag = state.tags.find(t => t.id === tagSelect?.value);
    const dds = $$('.preview-card .kv dd');
    if (dds[0]) dds[0].textContent = tag?.name || '없음';
    const classCard = cardByHeading('연구 내 분류값 입력') || cardByHeading('태그 내부 구분값 입력');
    const internal = $$('select', classCard).map(selectedText).filter(Boolean).join(' / ');
    if (dds[1]) dds[1].textContent = internal || '없음';
    if (dds[2]) dds[2].textContent = `${$$('[data-target-id]:checked').length}건`;
    if (dds[3]) dds[3].textContent = '0건';
  }

  function initTagDetail() {
    const select = $('.preview-card select');
    fillTagSelect(select, '등록된 연구 태그가 없습니다.');
    select?.addEventListener('change', () => renderTagDetail(select.value));
    renderTagDetail(select?.value || '');
  }

  function renderTagDetail(tagId) {
    const state = readState();
    const tag = state.tags.find(t => t.id === tagId);
    const kv = $$('dl.kv dd');
    if (kv[0]) kv[0].textContent = tag?.name || '선택된 태그 없음';
    if (kv[1]) kv[1].textContent = tag?.description || '없음';
    if (kv[2]) kv[2].textContent = tag?.status || '없음';
    if (kv[3]) kv[3].textContent = tag?.matchUnit || '없음';
    if (kv[4]) kv[4].textContent = tag?.irb || '없음';

    const axisBody = cardByHeading('태그 내부 분류 구조')?.querySelector('tbody');
    const axes = state.axes.filter(a => a.tagId === tagId);
    if (axisBody) {
      const rows = axes.flatMap(a => (a.values?.length ? a.values : [{ label: '-', synonyms: [] }]).map(v => `<tr><td>${escapeHtml(a.name)}</td><td>${escapeHtml(v.label)}</td><td>${escapeHtml((v.synonyms || []).join(', ') || '-')}</td><td>${escapeHtml(a.inputMode)}</td></tr>`));
      axisBody.innerHTML = rows.join('') || `<tr class="empty-row"><td colspan="4"><strong>선택된 연구 태그의 내부 분류축이 없습니다.</strong><br><span>태그 관리에서 Day/group 같은 내부 구조를 추가하세요.</span></td></tr>`;
    }
    const matrixBody = cardByHeading('태그에 포함된 데이터 매트릭스')?.querySelector('tbody');
    if (matrixBody) {
      const assigned = state.assignments.filter(a => a.tagId === tagId);
      if (!assigned.length) return setTableEmpty(matrixBody, 8, '선택된 태그 또는 포함된 데이터가 없습니다.', '태그 부여 화면에서 대상과 내부 구분값을 저장하면 표시됩니다.');
      matrixBody.innerHTML = assigned.map(a => `<tr><td>${escapeHtml(a.targetId)}</td><td>${escapeHtml(a.targetType)}</td><td>${String(a.targetType || '').includes('raw CSV') ? escapeHtml(a.targetId) : '-'}</td><td>${escapeHtml(a.internal?.day || '-')}</td><td>${escapeHtml(a.internal?.group || '-')}</td><td>${state.variables.filter(v => v.tagId === tagId).length}</td><td>-</td><td>${escapeHtml(a.assignedAt)}</td></tr>`).join('');
    }
  }

  const ANALYSIS_SCOPE_LABELS = {
    'within-file': '한 CSV 내부 구간 비교',
    'within-patient': '한 환자의 여러 CSV 연결 추세',
    'between-patient': '여러 환자의 반복측정 비교',
    'event-aligned': 'ECMO 이벤트 기준 전후 비교',
    'ecmo-outcome': 'ECMO 생존군–사망군 비교'
  };

  const ANALYSIS_METHOD_LABELS = {
    descriptive: '기술통계·품질 요약',
    window: '구간·이벤트 전후 비교',
    trajectory: '궤적·기울기 비교',
    lmm: '반복측정 혼합모형'
  };

  function patientShortLabel(patient) {
    if (!patient) return '환자 미선택';
    return `${patient.initials || patient.patientInitials || '이니셜 미입력'} · ${patientMaskedRegistration(patient.registrationNo)}`;
  }

  function analysisSelectedMethods() {
    return $$('input[name="analysisMethod"]:checked').map(input => input.value);
  }

  function analysisSelectedOutputs() {
    return $$('input[name="analysisOutput"]:checked').map(input => input.value);
  }

  function setAnalysisChecks(name, values) {
    $$(`input[name="${name}"]`).forEach(input => { input.checked = values.includes(input.value); });
  }







  function initAnalysisResults() {
    const state = readState();
    const body = cardByHeading('분석 결과 목록')?.querySelector('tbody');
    if (!body) return;
    if (!state.analyses.length) return setTableEmpty(body, 8, '아직 저장된 분석 결과가 없습니다.', '통계 분석 화면에서 분석 설정을 저장하세요.');
    body.innerHTML = state.analyses.map(a => `<tr><td>${escapeHtml(a.id)}</td><td>${escapeHtml(a.name)}</td><td>${escapeHtml(a.tagName)}</td><td>${escapeHtml(a.method)}</td><td>0명</td><td>${readState().vitalFiles.filter(f => (f.tagIds || []).includes(a.tagId)).length}개</td><td>${badge(a.status, 'blue')}</td><td><button class="btn ghost" data-analysis-id="${a.id}">상세</button></td></tr>`).join('');
  }

  function initAuditLog() {
    const body = $('tbody');
    const state = readState();
    if (!body) return;
    if (!state.audit.length) return;
    body.innerHTML = state.audit.map(a => `<tr><td>${escapeHtml(a.id)}</td><td>${escapeHtml(a.time)}</td><td>${escapeHtml(a.user)}</td><td>Member</td><td>${escapeHtml(a.action)}</td><td>${escapeHtml(a.target)}</td><td>-</td><td>${escapeHtml(a.description)}</td><td>local</td><td>${badge(a.status, 'green')}</td></tr>`).join('');
  }


  function initPatientMatching() {
    const fileCard = cardByHeading('1단계. 매칭할 Vital 파일 선택') || cardByHeading('매칭할 Vital 파일');
    const targetCard = cardByHeading('1단계. 대상자 선택') || cardByHeading('대상자 선택');
    const saveBtn = $('.preview-card button.btn.teal');
    if (!fileCard || !targetCard) return;
    fillTagSelect(targetCard.querySelector('[data-role="match-tag"]') || targetCard.querySelector('select'), '등록된 태그가 없습니다.');
    removeDisabledAction(saveBtn);

    const emptyState = $('.empty-state', targetCard);
    if (emptyState && !targetCard.querySelector('[data-role="manual-match-form"]')) {
      emptyState.outerHTML = `<div class="direct-entry" data-role="manual-match-form" style="margin-top:14px">
        <div class="direct-entry-title"><strong>직접 대상자 매칭</strong><span class="badge teal">1단계</span></div>
        <div class="grid two">
          <div class="field"><label>가명 연구대상자 ID</label><input class="input" data-role="match-patient" placeholder="예: P001"></div>
        </div>
        <div class="helper">이 단계에서는 Vital 파일을 대상자에게만 연결합니다. Pre/Post, Day 2, ECMO episode 같은 관찰시점 정보는 아래 2단계에서 파일별로 따로 배정합니다.</div>
      </div>`;
    }

    $('[data-role="match-patient"]')?.addEventListener('input', updateMatchingSummary);
    saveBtn?.addEventListener('click', savePatientMatches);
    $('[data-role="save-observation"]')?.addEventListener('click', saveObservationBundle);
    $('[data-role="go-tag-assignment"]')?.addEventListener('click', () => { location.href = 'tag-assignment.html'; });
    renderMatchingFiles();
    renderObservationFileOptions();
    renderObservationSummary();
  }

  function renderMatchingFiles() {
    const state = readState();
    const body = cardByHeading('1단계. 매칭할 Vital 파일 선택')?.querySelector('tbody') || cardByHeading('매칭할 Vital 파일')?.querySelector('tbody');
    if (!body) return;
    const files = state.vitalFiles.filter(f => f.uploadStatus !== '오류');
    if (!files.length) return setTableEmpty(body, 5, '매칭 대기 중인 Vital 파일이 없습니다.', 'Vital 파일을 먼저 업로드하세요.');
    body.innerHTML = files.map(f => `<tr>
      <td><input type="checkbox" data-match-file="${escapeHtml(f.id)}"></td>
      <td>${escapeHtml(f.name)}</td>
      <td>${escapeHtml(f.recordingStart || '미입력')}</td>
      <td>${escapeHtml(f.recordingEnd || '미입력')}</td>
      <td>${f.patientId ? `${badge('대상자 매칭됨', 'green')}<br><span class="muted">${escapeHtml(f.patientId)}</span>` : badge('대상자 미매칭', 'yellow')}</td>
    </tr>`).join('');
    $$('[data-match-file]', body).forEach(box => box.addEventListener('change', updateMatchingSummary));
    updateMatchingSummary();
  }

  function updateMatchingSummary() {
    const selected = $$('[data-match-file]:checked').length;
    const patientId = $('[data-role="match-patient"]')?.value.trim() || '';
    const dds = $$('.preview-card .kv dd');
    if (dds[0]) dds[0].textContent = `${selected}개`;
    if (dds[1]) dds[1].textContent = patientId || '미선택';
    if (dds[2]) dds[2].textContent = `${selected && patientId ? selected : 0}건`;
    if (dds[3]) dds[3].textContent = '관찰시점 배정';
  }

  function savePatientMatches() {
    const selected = $$('[data-match-file]:checked').map(x => x.dataset.matchFile);
    if (!selected.length) return toast('대상자와 연결할 Vital 파일을 선택하세요.', 'gray');
    const patientId = $('[data-role="match-patient"]')?.value.trim();
    if (!patientId) return toast('가명 연구대상자 ID를 입력하세요.', 'gray');
    patchState(s => {
      s.vitalFiles.forEach(f => {
        if (selected.includes(f.id)) {
          f.patientId = patientId;
          delete f.matchKey;
          f.matchMethod = 'manual patient_id';
          f.patientMatchedAt = nowText();
        }
      });
    });
    addAudit('patient matching', 'vital_file', `${selected.length}개 파일을 대상자에 매칭`);
    renderMatchingFiles();
    renderObservationFileOptions();
    renderObservationSummary();
    toast('대상자 매칭을 저장했습니다. 이제 2단계에서 관찰시점을 배정하세요.');
  }

  function renderObservationFileOptions() {
    const select = $('[data-role="observation-file"]');
    if (!select) return;
    const state = readState();
    const current = select.value;
    const files = state.vitalFiles.filter(f => f.patientId && f.uploadStatus !== '오류');
    select.innerHTML = files.length
      ? option('', '파일 선택') + files.map(f => option(f.id, `${f.patientId} · ${f.name}${f.observationId ? ' · ' + f.observationId : ''}`)).join('')
      : option('', '대상자 매칭된 파일 없음');
    if (current && files.some(f => f.id === current)) select.value = current;
  }

  function saveObservationBundle() {
    const fileId = $('[data-role="observation-file"]')?.value || '';
    if (!fileId) return toast('관찰시점을 배정할 Vital 파일을 선택하세요.', 'gray');
    const observationId = $('[data-role="observation-id"]')?.value.trim() || '';
    const timepoint = $('[data-role="observation-timepoint"]')?.value.trim() || '';
    const phase = $('[data-role="observation-phase"]')?.value || '';
    const note = $('[data-role="observation-note"]')?.value.trim() || '';
    if (!observationId && !timepoint && !phase) return toast('자료묶음 ID, 관찰시점, 구간 중 하나 이상을 입력하세요.', 'gray');
    patchState(s => {
      s.vitalFiles.forEach(f => {
        if (f.id === fileId) {
          f.observationId = observationId || f.observationId || '';
          f.timepoint = timepoint || f.timepoint || '';
          f.observationPhase = phase || f.observationPhase || '';
          f.observationNote = note || f.observationNote || '';
          f.eventId = f.observationId || f.timepoint || f.eventId || '';
          f.observationAssignedAt = nowText();
        }
      });
    });
    addAudit('observation assignment', 'vital_file', `${fileId} 관찰시점/자료묶음 배정`);
    renderObservationFileOptions();
    renderObservationSummary();
    renderMatchingFiles();
    toast('관찰시점/자료묶음 배정을 저장했습니다.');
  }

  function renderObservationSummary() {
    const body = $('[data-role="observation-summary"]');
    if (!body) return;
    const files = readState().vitalFiles.filter(f => f.patientId && (f.observationId || f.timepoint || f.observationPhase));
    if (!files.length) return setTableEmpty(body, 5, '아직 배정된 관찰시점이 없습니다.', '대상자 매칭 후 2단계에서 저장하세요.');
    body.innerHTML = files.map(f => `<tr>
      <td>${escapeHtml(f.name)}</td>
      <td>${escapeHtml(f.patientId || '-')}</td>
      <td>${escapeHtml(f.observationId || '-')}</td>
      <td>${escapeHtml(f.timepoint || '-')}</td>
      <td>${escapeHtml(f.observationPhase || '-')}</td>
    </tr>`).join('');
  }


  // ============================================================
  // Raw CSV -> 공란 없는 coding-ready 1분 feature CSV 변환
  // 사용자가 .vital에서 추출한 raw CSV를 업로드하면 브라우저에서 바로
  // 1분 단위 ML feature table과 신호 궤적 QC를 생성합니다.
  // ============================================================
  function initCsvFeatureConverter() {
    const card = $('#csvConverterCard');
    if (!card) return;
    const fileInput = $('#csvRawInput');
    const selectBtn = $('#csvSelectBtn');
    const convertBtn = $('#csvConvertBtn');
    const featureBtn = $('#csvDownloadFeaturesBtn');
    const dictBtn = $('#csvDownloadDictBtn');
    const fileName = $('#csvSelectedFileName');
    [selectBtn, convertBtn, featureBtn, dictBtn].forEach(removeDisabledAction);

    let selectedFile = null;
    window.__exciteCsvConversion = null;
    window.__exciteVitalConversion = null;

    selectBtn?.addEventListener('click', () => fileInput?.click());
    fileInput?.addEventListener('change', () => {
      selectedFile = fileInput.files?.[0] || null;
      if (fileName) fileName.textContent = selectedFile ? `${selectedFile.name} · ${formatBytes(selectedFile.size)}` : '선택된 raw CSV 없음';
      setCsvStatus(selectedFile ? 'raw CSV 파일이 선택되었습니다. 설정을 확인한 뒤 1분 feature CSV로 변환하세요.' : '선택된 raw CSV 없음', selectedFile ? 'teal' : 'gray');
      window.__exciteCsvConversion = null;
      window.__exciteVitalConversion = null;
    });

    convertBtn?.addEventListener('click', async () => {
      if (!selectedFile) return toast('변환할 raw CSV 파일을 먼저 선택하세요.', 'gray');
      if (!selectedFile.name.toLowerCase().endsWith('.csv')) return toast('이번 모드는 raw CSV만 변환합니다. .vital은 서버 파서 연결 후 처리하세요.', 'yellow');
      convertBtn.disabled = true;
      setCsvStatus('raw CSV를 읽고 있습니다. 컬럼, 시간축, segment를 자동 탐색합니다...', 'teal');
      try {
        const result = await convertRawVitalCsvFile(selectedFile);
        result.sourceFile = selectedFile.name;
        result.sourceType = 'raw CSV';
        result.outputName = `${result.caseId}_ml_features.csv`;
        result.dictionaryName = `${result.caseId}_column_dictionary.csv`;
        window.__exciteCsvConversion = result;
        window.__exciteVitalConversion = result;
        renderCsvConversionResult(result);
        patchState(s => {
          if (!Array.isArray(s.csvConversions)) s.csvConversions = [];
          s.csvConversions.unshift({
            id: uid('CSVCONV'),
            sourceFile: selectedFile.name,
            caseId: result.caseId,
            status: '변환 완료',
            rowsRead: result.rowsRead,
            featureRows: result.features.length,
            columns: result.columns.length,
            segmentCount: result.segmentCount,
            createdAt: nowText(),
            output: result.outputName
          });
          s.csvConversions = s.csvConversions.slice(0, 50);
        });
        addAudit('raw csv conversion', 'raw_csv', `${selectedFile.name} -> ${result.outputName}`);
        toast('raw CSV → 공란 없는 1분 feature CSV 변환이 완료되었습니다.');
      } catch (error) {
        console.error(error);
        setCsvStatus(error.message || 'CSV 변환 중 오류가 발생했습니다.', 'red');
        toast(error.message || 'CSV 변환 중 오류가 발생했습니다.', 'red');
      } finally {
        convertBtn.disabled = false;
      }
    });

    featureBtn?.addEventListener('click', () => {
      const result = window.__exciteCsvConversion || window.__exciteVitalConversion;
      if (!result || !Array.isArray(result.features)) return toast('먼저 raw CSV를 변환하세요.', 'gray');
      downloadText(result.outputName || `${result.caseId}_ml_features.csv`, '\uFEFF' + toCsv(result.features), 'text/csv;charset=utf-8');
      addExportRow(result.outputName || `${result.caseId}_ml_features.csv`, 'CSV');
    });

    dictBtn?.addEventListener('click', () => {
      const result = window.__exciteCsvConversion || window.__exciteVitalConversion;
      if (!result || !Array.isArray(result.dictionary)) return toast('먼저 raw CSV를 변환하세요.', 'gray');
      downloadText(result.dictionaryName || `${result.caseId}_column_dictionary.csv`, '\uFEFF' + toCsv(result.dictionary), 'text/csv;charset=utf-8');
      addExportRow(result.dictionaryName || `${result.caseId}_column_dictionary.csv`, 'CSV');
    });
  }

  function buildVitalConversionJob(file) {
    const settings = getCsvSettings();
    const caseId = makeCaseIdFromName(file.name, true);
    const baseVitalCols = ['HR','MAP','SBP','DBP','SpO2','PI','RR'];
    const columns = [
      'case_id','segment_id','segment_num','Minute','Minute_start_datetime_iso','Minute_end_datetime_iso','minute_duration_sec','n_rows_with_any_vital',
      ...baseVitalCols.flatMap(v => [`${v}_mean`, `${v}_min`, `${v}_max`, `${v}_std`, `${v}_median`, `${v}_count`, `${v}_expected_count_per_min`, `${v}_valid_ratio`, `${v}_missing_rate`, `${v}_flatline_flag`]),
      `n_MAP_below_${settings.mapThreshold}`, `n_MAP_below_${settings.mapThreshold}_ratio`, 'n_SpO2_below_90', 'n_SpO2_below_90_ratio', 'n_HR_below_40', 'n_HR_below_40_ratio', 'n_HR_above_130', 'n_HR_above_130_ratio', 'n_RR_below_8', 'n_RR_below_8_ratio', 'n_RR_above_30', 'n_RR_above_30_ratio',
      `label_next_${settings.futureHorizonMin}min_MAP_below_${settings.mapThreshold}`
    ];
    return {
      jobId: uid('VITALCONV'), caseId, sourceFile: file.name, sourceSize: file.size,
      sourceType: 'raw .vital', outputType: 'coding-ready 1min feature CSV', blankPolicy: '공란 제거: 원본 sampling gap은 count/valid_ratio/missing_rate/value_age로 표현',
      segmentGapSec: settings.segmentGapSec, timeBinSec: 60,
      futureHorizonMin: settings.futureHorizonMin, mapThreshold: settings.mapThreshold,
      requiresBackendParser: true,
      parserPlan: ['vitaldb Python package로 .vital 원본 읽기', 'numeric trend만 1분 bin으로 요약', 'waveform은 기본 제외 또는 summary 옵션', 'interpolation 기본 금지', 'forward-fill 사용 시 value_age/observed flag 기록', '공란 없는 ML feature table 생성'],
      columns,
      dictionary: columns.map(c => ({ column: c, description: describeFeatureColumn(c) || 'vital 원본에서 생성될 coding-ready feature column' }))
    };
  }

  function setCsvStatus(message, tone = 'gray') {
    const el = $('#csvConversionStatus');
    if (!el) return;
    el.className = `callout ${tone === 'red' ? 'dangerbox' : tone === 'yellow' ? 'warning' : ''}`;
    el.textContent = message;
  }

  async function readFileTextWithEncodingGuess(file) {
    const buffer = await file.arrayBuffer();
    const labels = ['utf-8', 'euc-kr', 'windows-949', 'latin1'];
    let best = { text: '', encoding: 'utf-8', badness: Infinity };
    for (const label of labels) {
      try {
        const text = new TextDecoder(label, { fatal: false }).decode(buffer);
        const badness = (text.match(/�/g) || []).length;
        if (badness < best.badness) best = { text, encoding: label, badness };
        if (badness === 0) break;
      } catch (_) {}
    }
    return best;
  }

  function detectSeparatorAndHeader(text) {
    const lines = text.split(/\r?\n/).slice(0, 200);
    const seps = [',', '\t', ';', '|'];
    const sep = seps.reduce((best, s) => {
      const score = lines.reduce((sum, line) => sum + countCharOutsideQuotes(line, s), 0);
      return score > best.score ? { sep: s, score } : best;
    }, { sep: ',', score: -1 }).sep;
    const keywords = ['TIME','DATE','DATETIME','TIMESTAMP','ECG','HR','HEART','ABP','ART','IBP','MAP','MEAN','SYS','DIA','PLETH','SPO2','SAT','RESP','RR','PERF','PI'];
    let bestIdx = 0;
    let bestScore = -1;
    lines.forEach((line, idx) => {
      const upper = line.toUpperCase();
      const keywordScore = keywords.reduce((sum, k) => sum + (upper.includes(k) ? 1 : 0), 0);
      const sepScore = countCharOutsideQuotes(line, sep);
      const score = keywordScore * 10 + sepScore;
      if (score > bestScore) { bestScore = score; bestIdx = idx; }
    });
    return { sep, headerIdx: bestIdx };
  }

  function countCharOutsideQuotes(line, ch) {
    let count = 0, inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i + 1] === '"') i++;
        else inQuotes = !inQuotes;
      } else if (!inQuotes && c === ch) count++;
    }
    return count;
  }

  function parseDelimited(text, sep, headerIdx) {
    const lines = text.split(/\r?\n/).slice(headerIdx).filter(line => line.trim() !== '');
    if (!lines.length) throw new Error('CSV header를 찾지 못했습니다.');
    const headers = parseDelimitedLine(lines[0], sep).map(h => String(h).trim()).filter(h => !/^Unnamed/i.test(h));
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const cells = parseDelimitedLine(lines[i], sep);
      const obj = {};
      headers.forEach((h, j) => { obj[h] = cells[j] ?? ''; });
      if (Object.values(obj).some(v => String(v).trim() !== '')) rows.push(obj);
    }
    return { headers, rows };
  }

  function parseDelimitedLine(line, sep) {
    const out = [];
    let cur = '', inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"') {
        if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (!inQuotes && c === sep) {
        out.push(cur); cur = '';
      } else cur += c;
    }
    out.push(cur);
    return out;
  }

  function makeCaseIdFromName(filename, useShort = true) {
    const stem = filename.replace(/\.[^.]+$/, '');
    if (useShort) {
      const m = stem.match(/(.+_\d{6})_\d{6}$/);
      if (m) return m[1];
    }
    return stem;
  }

  function parseStartDateTimeFromName(filename) {
    const stem = filename.replace(/\.[^.]+$/, '');
    const m = stem.match(/_(\d{6})_(\d{6})$/);
    if (!m) return null;
    const d = m[1], t = m[2];
    const year = 2000 + Number(d.slice(0, 2));
    const month = Number(d.slice(2, 4)) - 1;
    const day = Number(d.slice(4, 6));
    const hour = Number(t.slice(0, 2));
    const min = Number(t.slice(2, 4));
    const sec = Number(t.slice(4, 6));
    const dt = new Date(year, month, day, hour, min, sec);
    return Number.isNaN(dt.getTime()) ? null : dt;
  }

  function normalizeColname(value) {
    return String(value ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  }

  function isMonitorMetaColumn(col) {
    const n = normalizeColname(col);
    return ['TIME','DATE','DATETIME','TIMESTAMP','EVENT'].includes(n)
      || n.includes('ALARM')
      || n.includes('MESSAGE')
      || n.includes('MSG')
      || n.includes('STATUS')
      || n.includes('FLAG');
  }

  function numericCountForColumn(rows, col) {
    if (!col) return 0;
    let count = 0;
    const limit = Math.min(rows.length, 12000);
    for (let i = 0; i < limit; i++) {
      if (Number.isFinite(numericClean(rows[i]?.[col]))) count += 1;
    }
    return count;
  }

  function findColumn(headers, patternGroups, rows = null) {
    const normMap = headers.map(col => [col, normalizeColname(col)]);
    for (const patterns of patternGroups) {
      const normalized = patterns.map(normalizeColname);
      const candidates = [];
      for (const [col, norm] of normMap) {
        if (normalized.every(p => norm.includes(p))) candidates.push(col);
      }
      if (!candidates.length) continue;
      const usable = candidates
        .filter(col => !isMonitorMetaColumn(col))
        .map(col => ({ col, count: rows ? numericCountForColumn(rows, col) : 1 }))
        .filter(x => x.count > 0)
        .sort((a, b) => b.count - a.count);
      if (usable.length) return usable[0].col;
      if (!rows) return candidates.find(col => !isMonitorMetaColumn(col)) || null;
    }
    return null;
  }

  function detectVitalColumns(headers, rows = []) {
    const patterns = {
      HR: [['ECG','HR'], ['ABP','HR'], ['PLETH','HR'], ['HEART','RATE'], ['HEARTRATE'], ['HR']],
      MAP: [['ABP','MEAN'], ['ART','MEAN'], ['IBP','MEAN'], ['ART','MBP'], ['ABP','MBP'], ['MEAN','BP'], ['MAP'], ['MBP']],
      SBP: [['ABP','SYS'], ['ART','SYS'], ['IBP','SYS'], ['ART','SBP'], ['SYSTOLIC'], ['SBP']],
      DBP: [['ABP','DIA'], ['ART','DIA'], ['IBP','DIA'], ['ART','DBP'], ['DIASTOLIC'], ['DBP']],
      SpO2: [['PLETH','SPO2'], ['PLETH','SATO2'], ['SPO2'], ['SATO2'], ['SAT','O2']],
      PI: [['PLETH','PERF'], ['PERF','REL'], ['PERFUSION'], ['PI']],
      RR: [['RESP','RATE'], ['RESP','RR'], ['RESPRATE'], ['INTELLIVUE','RR'], ['RR']]
    };
    const out = {};
    Object.entries(patterns).forEach(([name, p]) => out[name] = findColumn(headers, p, rows));
    return out;
  }

  function signalNameFromHeader(header, usedNames = new Set()) {
    const last = String(header || '').split('/').pop() || String(header || 'signal');
    let base = last.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'signal';
    if (/^[0-9]/.test(base)) base = `X_${base}`;
    let name = base;
    let i = 2;
    while (usedNames.has(name)) {
      name = `${base}_${i}`;
      i += 1;
    }
    usedNames.add(name);
    return name;
  }

  function detectAuxiliaryNumericSignals(headers, rows, detectedCols) {
    const usedSource = new Set(Object.values(detectedCols || {}).filter(Boolean));
    const usedNames = new Set(Object.keys(detectedCols || {}));
    const out = [];
    headers.forEach(header => {
      if (!header || usedSource.has(header)) return;
      if (isMonitorMetaColumn(header)) return;
      const n = normalizeColname(header);
      if (['TIME','DATE','DATETIME','TIMESTAMP'].includes(n)) return;
      const count = numericCountForColumn(rows, header);
      if (count <= 0) return;
      const signal = signalNameFromHeader(header, usedNames);
      out.push({ signal, source: header, count });
    });
    return out.sort((a, b) => a.signal.localeCompare(b.signal));
  }

  function findTimeColumns(headers) {
    const norm = headers.map(col => [col, normalizeColname(col)]);
    let datetimeCol = null, dateCol = null, timeCol = null;
    for (const [col, n] of norm) {
      if (['DATETIME','TIMESTAMP','DATEANDTIME'].includes(n)) datetimeCol = col;
      else if (n === 'DATE') dateCol = col;
      else if (['TIME','CLOCKTIME'].includes(n)) timeCol = col;
    }
    if (!datetimeCol) datetimeCol = norm.find(([, n]) => n.includes('DATETIME') || n.includes('TIMESTAMP'))?.[0] || null;
    if (!dateCol) dateCol = norm.find(([, n]) => n.startsWith('DATE'))?.[0] || null;
    if (!timeCol) timeCol = norm.find(([, n]) => n.startsWith('TIME'))?.[0] || null;
    return { datetimeCol, dateCol, timeCol };
  }

  function numericClean(value) {
    const s = String(value ?? '').trim().replaceAll(',', '').replaceAll("'", '');
    if (!s || ['nan','NaN','None','null','--','---'].includes(s)) return NaN;
    const n = Number(s);
    return Number.isFinite(n) ? n : NaN;
  }

  function median(values) {
    const arr = values.filter(Number.isFinite).sort((a, b) => a - b);
    if (!arr.length) return NaN;
    const mid = Math.floor(arr.length / 2);
    return arr.length % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
  }

  function quantile(values, q) {
    const arr = values.filter(Number.isFinite).sort((a, b) => a - b);
    if (!arr.length) return NaN;
    const pos = (arr.length - 1) * q;
    const base = Math.floor(pos);
    const rest = pos - base;
    return arr[base + 1] !== undefined ? arr[base] + rest * (arr[base + 1] - arr[base]) : arr[base];
  }

  function mean(values) {
    const arr = values.filter(Number.isFinite);
    return arr.length ? arr.reduce((s, v) => s + v, 0) / arr.length : NaN;
  }

  function stdSample(values) {
    const arr = values.filter(Number.isFinite);
    if (arr.length < 2) return NaN;
    const m = mean(arr);
    return Math.sqrt(arr.reduce((s, v) => s + (v - m) ** 2, 0) / (arr.length - 1));
  }

  function parseDateTimeString(value) {
    const s = String(value ?? '').trim();
    if (!s) return null;
    const normalized = s.replace(/\//g, '-').replace(' ', 'T');
    const direct = new Date(normalized);
    if (!Number.isNaN(direct.getTime())) return direct;
    const parsed = Date.parse(s);
    return Number.isNaN(parsed) ? null : new Date(parsed);
  }

  function parseTimeToSeconds(value) {
    const s = String(value ?? '').trim();
    const m = s.match(/^(\d{1,2}):(\d{2})(?::(\d{2}(?:\.\d+)?))?$/);
    if (!m) return NaN;
    return Number(m[1]) * 3600 + Number(m[2]) * 60 + Number(m[3] || 0);
  }

  function buildDateTimes(rows, headers, filename) {
    const start = parseStartDateTimeFromName(filename);
    const { datetimeCol, dateCol, timeCol } = findTimeColumns(headers);
    const n = rows.length;

    if (datetimeCol) {
      const nums = rows.map(r => numericClean(r[datetimeCol]));
      if (start && nums.filter(Number.isFinite).length / n > 0.5 && median(nums) < 10000000) {
        return nums.map(v => Number.isFinite(v) ? new Date(start.getTime() + v * 1000) : null);
      }
      const dts = rows.map(r => parseDateTimeString(r[datetimeCol]));
      if (dts.filter(Boolean).length / n > 0.5) return dts;
    }

    if (dateCol && timeCol) {
      const dts = rows.map(r => parseDateTimeString(`${r[dateCol]} ${r[timeCol]}`));
      if (dts.filter(Boolean).length / n > 0.5) return dts;
    }

    if (timeCol) {
      const nums = rows.map(r => numericClean(r[timeCol]));
      if (start && nums.filter(Number.isFinite).length / n > 0.5 && median(nums) < 10000000) {
        return nums.map(v => Number.isFinite(v) ? new Date(start.getTime() + v * 1000) : null);
      }
      const seconds = rows.map(r => parseTimeToSeconds(r[timeCol]));
      if (start && seconds.filter(Number.isFinite).length / n > 0.5) {
        const base = new Date(start.getFullYear(), start.getMonth(), start.getDate()).getTime();
        let last = null, dayOffset = 0;
        return seconds.map(sec => {
          if (!Number.isFinite(sec)) return null;
          let ms = base + dayOffset * 86400000 + sec * 1000;
          if (last !== null && ms - last < -3600000) {
            dayOffset += 1;
            ms += 86400000;
          }
          last = ms;
          return new Date(ms);
        });
      }
      const dts = rows.map(r => parseDateTimeString(r[timeCol]));
      if (dts.filter(Boolean).length / n > 0.5) return dts;
    }

    if (start) return rows.map((_, i) => new Date(start.getTime() + i * 1000));
    const fallback = new Date(2026, 0, 1, 0, 0, 0);
    return rows.map((_, i) => new Date(fallback.getTime() + i * 1000));
  }

  async function convertRawVitalCsvFile(file) {
    const settings = getCsvSettings();
    const { text, encoding } = await readFileTextWithEncodingGuess(file);
    const detected = detectSeparatorAndHeader(text);
    const parsed = parseDelimited(text, detected.sep, detected.headerIdx);
    const headers = parsed.headers;
    const rows = parsed.rows;
    if (!rows.length) throw new Error('CSV에서 데이터 행을 찾지 못했습니다.');

    const caseId = makeCaseIdFromName(file.name, true);
    const startFromName = parseStartDateTimeFromName(file.name);
    const detectedCols = detectVitalColumns(headers, rows);
    const auxiliarySignals = detectAuxiliaryNumericSignals(headers, rows, detectedCols);
    const dateTimes = buildDateTimes(rows, headers, file.name);
    const coreOrder = ['HR','MAP','SBP','DBP','SpO2','PI','RR'];
    const signalSources = [];
    coreOrder.forEach(signal => {
      const source = detectedCols[signal];
      if (source && numericCountForColumn(rows, source) > 0) signalSources.push({ signal, source, core: true });
      else detectedCols[signal] = null;
    });
    auxiliarySignals.forEach(item => signalSources.push({ signal: item.signal, source: item.source, core: false }));

    if (!signalSources.length) {
      throw new Error('수치형 trend 컬럼을 찾지 못했습니다. MSG/ALARM/STATUS/FLAG만 있는 CSV는 feature를 만들 수 없습니다.');
    }

    const vitalCols = signalSources.map(item => item.signal);
    const sourceBySignal = Object.fromEntries(signalSources.map(item => [item.signal, item.source]));
    const ranges = { HR:[20,250], MAP:[0,200], SBP:[0,300], DBP:[0,200], SpO2:[0,100], PI:[0,100], RR:[3,80] };

    let vital = rows.map((row, i) => {
      const out = { case_id: caseId, datetime: dateTimes[i] };
      signalSources.forEach(({ signal, source, core }) => {
        let value = source ? numericClean(row[source]) : NaN;
        const range = core ? ranges[signal] : null;
        if (range && Number.isFinite(value) && (value < range[0] || value > range[1])) value = NaN;
        out[signal] = value;
      });
      return out;
    }).filter(r => r.datetime instanceof Date && !Number.isNaN(r.datetime.getTime()));

    if (vitalCols.includes('RR')) {
      const rrVals = vital.map(r => r.RR).filter(Number.isFinite);
      if (rrVals.length && (median(rrVals) < 5 || quantile(rrVals, 0.95) > 80)) vital.forEach(r => r.RR = NaN);
    }

    if (settings.filterByFilenameTime && startFromName) {
      const lower = startFromName.getTime() - 3600000;
      const upper = startFromName.getTime() + settings.maxHours * 3600000;
      vital = vital.filter(r => r.datetime.getTime() >= lower && r.datetime.getTime() <= upper);
    }
    vital = vital.filter(r => vitalCols.some(c => Number.isFinite(r[c]))).sort((a, b) => a.datetime - b.datetime);
    if (!vital.length) {
      const mapped = signalSources.map(item => `${item.signal}←${item.source}`).join(', ');
      throw new Error(`컬럼은 감지했지만 유효한 수치값이 없습니다. 감지 결과: ${mapped || '없음'}`);
    }

    let segmentNum = 0;
    let prevMs = null;
    let segmentStartMs = null;
    vital.forEach(r => {
      const ms = r.datetime.getTime();
      if (prevMs === null || (ms - prevMs) / 1000 > settings.segmentGapSec || ms < prevMs) {
        segmentNum += 1;
        segmentStartMs = ms;
      }
      r.segment_num = segmentNum;
      r.segment_id = `${caseId}_seg_${String(segmentNum).padStart(3, '0')}`;
      r.elapsed_sec_in_segment = (ms - segmentStartMs) / 1000;
      r.Minute = Math.floor(r.elapsed_sec_in_segment / 60);
      prevMs = ms;
    });

    const groups = new Map();
    vital.forEach(r => {
      const key = `${r.case_id}|${r.segment_id}|${r.segment_num}|${r.Minute}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(r);
    });

    let features = Array.from(groups.values()).map(group => {
      const first = group[0];
      const times = group.map(r => r.datetime.getTime());
      const row = {
        case_id: first.case_id,
        segment_id: first.segment_id,
        segment_num: first.segment_num,
        Minute: first.Minute,
        _start_ms: Math.min(...times),
        _end_ms: Math.max(...times),
        n_rows_with_any_vital: group.length
      };
      vitalCols.forEach(col => {
        const vals = group.map(r => r[col]).filter(Number.isFinite);
        row[`${col}_mean`] = mean(vals);
        row[`${col}_min`] = vals.length ? Math.min(...vals) : NaN;
        row[`${col}_max`] = vals.length ? Math.max(...vals) : NaN;
        row[`${col}_std`] = stdSample(vals);
        row[`${col}_median`] = median(vals);
        row[`${col}_count`] = vals.length;
      });
      if (vitalCols.includes('MAP')) row[`n_MAP_below_${settings.mapThreshold}`] = group.filter(r => Number.isFinite(r.MAP) && r.MAP < settings.mapThreshold).length;
      if (vitalCols.includes('SpO2')) row.n_SpO2_below_90 = group.filter(r => Number.isFinite(r.SpO2) && r.SpO2 < 90).length;
      if (vitalCols.includes('HR')) {
        row.n_HR_below_40 = group.filter(r => Number.isFinite(r.HR) && r.HR < 40).length;
        row.n_HR_above_130 = group.filter(r => Number.isFinite(r.HR) && r.HR > 130).length;
      }
      if (vitalCols.includes('RR')) {
        row.n_RR_below_8 = group.filter(r => Number.isFinite(r.RR) && r.RR < 8).length;
        row.n_RR_above_30 = group.filter(r => Number.isFinite(r.RR) && r.RR > 30).length;
      }
      return row;
    }).sort((a, b) => a.segment_num - b.segment_num || a.Minute - b.Minute);

    const expectedCounts = {};
    vitalCols.forEach(col => {
      const counts = features.map(r => r[`${col}_count`]).filter(v => Number.isFinite(v) && v > 0);
      const expected = counts.length ? Math.max(quantile(counts, 0.75), 1) : NaN;
      expectedCounts[col] = expected;
      features.forEach(r => {
        r[`${col}_expected_count_per_min`] = expected;
        if (!Number.isFinite(expected) || expected === 0) {
          r[`${col}_valid_ratio`] = NaN;
          r[`${col}_missing_rate`] = NaN;
        } else {
          const ratio = Math.min(Math.max((r[`${col}_count`] || 0) / expected, 0), 1);
          r[`${col}_valid_ratio`] = ratio;
          r[`${col}_missing_rate`] = 1 - ratio;
        }
      });
    });

    const flatThresholds = { HR:0.1, MAP:0.1, SBP:0.1, DBP:0.1, SpO2:0.05, PI:0.001, RR:0.1 };
    vitalCols.forEach(col => {
      const expected = expectedCounts[col];
      const minCount = (!Number.isFinite(expected) || expected === 0) ? 5 : Math.max(5, expected * 0.5);
      const threshold = flatThresholds[col] ?? 1e-9;
      features.forEach(r => {
        const sd = Number.isFinite(r[`${col}_std`]) ? r[`${col}_std`] : 0;
        r[`${col}_flatline_flag`] = ((r[`${col}_count`] || 0) >= minCount && sd <= threshold) ? 1 : 0;
      });
    });

    const eventCols = [];
    if (vitalCols.includes('MAP')) eventCols.push(`n_MAP_below_${settings.mapThreshold}`);
    if (vitalCols.includes('SpO2')) eventCols.push('n_SpO2_below_90');
    if (vitalCols.includes('HR')) eventCols.push('n_HR_below_40', 'n_HR_above_130');
    if (vitalCols.includes('RR')) eventCols.push('n_RR_below_8', 'n_RR_above_30');
    features.forEach(r => eventCols.forEach(c => r[`${c}_ratio`] = r.n_rows_with_any_vital ? r[c] / r.n_rows_with_any_vital : NaN));

    if (settings.makeFutureLabel && vitalCols.includes('MAP')) {
      const labelCol = `label_next_${settings.futureHorizonMin}min_MAP_below_${settings.mapThreshold}`;
      const bySeg = groupBy(features, r => String(r.segment_num));
      Object.values(bySeg).forEach(segRows => {
        segRows.sort((a, b) => a.Minute - b.Minute);
        const eventVals = segRows.map(r => r[`n_MAP_below_${settings.mapThreshold}`] > 0 ? 1 : 0);
        segRows.forEach((r, i) => {
          const window = eventVals.slice(i + 1, i + 1 + settings.futureHorizonMin);
          if (window.length < settings.futureHorizonMin && settings.labelIncompleteAsNa) r[labelCol] = NaN;
          else r[labelCol] = window.length ? (Math.max(...window) > 0 ? 1 : 0) : NaN;
        });
      });
    }

    const segMinuteCounts = groupBy(features, r => r.segment_id);
    const validSegments = new Set(Object.entries(segMinuteCounts).filter(([, arr]) => new Set(arr.map(r => r.Minute)).size >= settings.minSegmentMinutes).map(([id]) => id));
    features = features.filter(r => validSegments.has(r.segment_id));

    features.forEach(r => {
      r.Minute_start_datetime_iso = formatDateTime(new Date(r._start_ms));
      r.Minute_end_datetime_iso = formatDateTime(new Date(r._end_ms));
      r.minute_duration_sec = (r._end_ms - r._start_ms) / 1000;
      delete r._start_ms;
      delete r._end_ms;
    });

    const frontCols = ['case_id','segment_id','segment_num','Minute','Minute_start_datetime_iso','Minute_end_datetime_iso','minute_duration_sec','n_rows_with_any_vital'];
    const labelCols = Object.keys(features[0] || {}).filter(c => c.startsWith('label_'));
    const middleCols = Object.keys(features[0] || {}).filter(c => !frontCols.includes(c) && !labelCols.includes(c));
    const orderedCols = [...frontCols, ...middleCols, ...labelCols];
    features = features.map(r => orderedCols.reduce((o, c) => { o[c] = csvSafeValue(r[c]); return o; }, {}));
    const dictionary = orderedCols.map(c => ({ column: c, description: describeFeatureColumn(c) || `1분 구간 ${c} feature` }));

    return {
      caseId, encoding, separator: detected.sep === '\t' ? 'tab' : detected.sep,
      headerIdx: detected.headerIdx, detectedCols, auxiliarySignals,
      detectedSignalNames: vitalCols, sourceBySignal, expectedCounts, rowsRead: rows.length,
      features, dictionary, columns: orderedCols,
      segmentCount: new Set(features.map(r => r.segment_id)).size
    };
  }

  function getCsvSettings() {
    return {
      segmentGapSec: Number($('#csvSegmentGapSec')?.value || 300),
      filterByFilenameTime: $('#csvFilterByFilenameTime')?.checked ?? true,
      maxHours: Number($('#csvMaxHours')?.value || 24),
      makeFutureLabel: $('#csvFutureLabel')?.checked ?? true,
      futureHorizonMin: Number($('#csvFutureHorizon')?.value || 5),
      mapThreshold: Number($('#csvMapThreshold')?.value || 65),
      labelIncompleteAsNa: $('#csvIncompleteFutureNa')?.checked ?? true,
      minSegmentMinutes: Number($('#csvMinSegmentMinutes')?.value || 1)
    };
  }

  function groupBy(arr, keyFn) {
    return arr.reduce((acc, item) => {
      const key = keyFn(item);
      (acc[key] ||= []).push(item);
      return acc;
    }, {});
  }

  function formatDateTime(date) {
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
  }

  function csvSafeValue(value) {
    if (value === null || value === undefined || value === '') return 'NA';
    if (typeof value === 'number') return Number.isFinite(value) ? Number(value.toFixed(6)) : 'NA';
    return value;
  }

  function describeFeatureColumn(col) {
    if (col === 'case_id') return '분석 case ID. 예: SICU12_260619';
    if (col === 'segment_id') return '5분 이상 끊김 기준으로 나눈 segment ID';
    if (col === 'segment_num') return 'segment 번호';
    if (col === 'Minute') return 'segment 시작 후 몇 번째 minute인지';
    if (['Minute_start_datetime_iso','Minute_end_datetime_iso'].includes(col)) return '해당 1분 구간의 시작/끝 시각';
    if (col === 'minute_duration_sec') return '해당 minute 구간 내 실제 관측 시간 길이';
    if (col === 'n_rows_with_any_vital') return '해당 minute에서 하나 이상의 vital 값이 존재한 행 수';
    if (col.endsWith('_mean')) return '1분 구간 평균값';
    if (col.endsWith('_min')) return '1분 구간 최솟값';
    if (col.endsWith('_max')) return '1분 구간 최댓값';
    if (col.endsWith('_std')) return '1분 구간 표준편차';
    if (col.endsWith('_median')) return '1분 구간 중앙값';
    if (col.endsWith('_count')) return '1분 구간 해당 신호의 유효 측정 개수';
    if (col.endsWith('_expected_count_per_min')) return '해당 신호의 1분당 기대 측정 개수';
    if (col.endsWith('_valid_ratio')) return '해당 신호의 1분 구간 유효 측정 비율';
    if (col.endsWith('_missing_rate')) return '해당 신호의 1분 구간 결측 비율';
    if (col.endsWith('_flatline_flag')) return '해당 신호가 1분 동안 거의 변하지 않는지 여부';
    if (col.startsWith('n_') && col.endsWith('_ratio')) return '특정 이상 조건 발생 비율';
    if (col.startsWith('n_')) return '특정 이상 조건 발생 횟수';
    if (col.startsWith('label_')) return '미래 예측용 label. 모델 입력 X에는 넣으면 안 됨';
    return '';
  }


  function toFiniteNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n : NaN;
  }

  function downsampleFeatureRows(rows, maxPoints = 90) {
    const arr = Array.isArray(rows) ? rows : [];
    if (arr.length <= maxPoints) return arr;
    const step = Math.ceil(arr.length / maxPoints);
    return arr.filter((_, idx) => idx % step === 0);
  }

  function buildSignalTrajectorySvg(rows, config = {}) {
    const chartSignals = config.signals || ['HR', 'MAP', 'SpO2', 'RR'];
    const colors = { HR:'#1d5d9b', MAP:'#0b8f8a', SpO2:'#6d5dfc', RR:'#f59e0b', SBP:'#175cd3', DBP:'#9a5b00' };
    const palette = ['#1d5d9b','#0b8f8a','#6d5dfc','#f59e0b','#9a5b00','#475467','#175cd3','#0e9384'];
    const colorForSignal = (signal, idx) => colors[signal] || palette[idx % palette.length];
    const usableRows = downsampleFeatureRows(rows || [], 90);
    const width = 620, height = 260;
    const pad = { left: 42, right: 16, top: 22, bottom: 34 };
    const plotW = width - pad.left - pad.right;
    const plotH = height - pad.top - pad.bottom;

    const series = chartSignals.map(signal => {
      const key = `${signal}_mean`;
      const vals = usableRows.map((row, idx) => ({
        idx,
        minute: toFiniteNumber(row.Minute ?? row.minute ?? idx),
        value: toFiniteNumber(row[key] ?? row[signal] ?? row.value),
      })).filter(point => Number.isFinite(point.value));

      const lineColor = colorForSignal(signal, chartSignals.indexOf(signal));
      if (vals.length < 2) return { signal, points:'', dots:'', color: lineColor, min: NaN, max: NaN };
      const min = Math.min(...vals.map(v => v.value));
      const max = Math.max(...vals.map(v => v.value));
      const span = max - min || 1;
      const xDen = Math.max(1, usableRows.length - 1);
      const xy = vals.map(point => {
        const x = pad.left + (point.idx / xDen) * plotW;
        const y = pad.top + (1 - ((point.value - min) / span)) * plotH;
        return { x, y };
      });
      const pointText = xy.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
      const dotStep = Math.max(1, Math.ceil(xy.length / 18));
      const dots = xy.filter((_, i) => i % dotStep === 0).map(p => `<circle class="signal-trajectory-dot" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3.4" fill="${lineColor}"/>`).join('');
      return { signal, points: pointText, dots, color: lineColor, min, max };
    });

    const hasAnyLine = series.some(s => s.points);
    const gridLines = [0,1,2,3,4].map(i => {
      const y = pad.top + (i / 4) * plotH;
      return `<line class="signal-trajectory-grid" x1="${pad.left}" y1="${y.toFixed(1)}" x2="${width - pad.right}" y2="${y.toFixed(1)}" />`;
    }).join('');
    const polylines = series.filter(s => s.points).map(s => `<polyline class="signal-trajectory-line" points="${s.points}" stroke="${s.color}"/>${s.dots}`).join('');
    const legend = series.map(s => {
      const range = Number.isFinite(s.min) ? `${Number(s.min).toFixed(1)}–${Number(s.max).toFixed(1)}` : '데이터 없음';
      return `<span class="signal-legend-chip"><span class="signal-legend-color" style="background:${s.color}"></span>${escapeHtml(s.signal)} <span style="color:#94a3b8">${escapeHtml(range)}</span></span>`;
    }).join('');
    const lastMinute = rows?.length ? (rows[rows.length - 1].Minute ?? rows.length - 1) : 0;
    const emptyText = config.emptyText || '궤적을 그릴 수 있는 feature row가 아직 없습니다.';

    return `<div class="signal-trajectory-card">
      <div class="signal-trajectory-head"><div><strong>${escapeHtml(config.title || '신호 궤적 요약')}</strong><span>${escapeHtml(config.subtitle || '각 신호는 패널 안에서 개별 정규화되어 QC용 흐름만 빠르게 확인합니다.')}</span></div>${config.badge ? badge(config.badge, 'teal') : ''}</div>
      <svg class="signal-trajectory-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="신호별 시간 궤적">
        ${gridLines}
        <line class="signal-trajectory-grid" x1="${pad.left}" y1="${height - pad.bottom}" x2="${width - pad.right}" y2="${height - pad.bottom}" />
        <text class="signal-trajectory-axis" x="${pad.left}" y="${height - 10}">0 min</text>
        <text class="signal-trajectory-axis" x="${width - 76}" y="${height - 10}">${escapeHtml(lastMinute)} min</text>
        <text class="signal-trajectory-axis" x="8" y="${pad.top + 8}">높음</text>
        <text class="signal-trajectory-axis" x="8" y="${height - pad.bottom}">낮음</text>
        ${hasAnyLine ? polylines : `<text class="signal-trajectory-empty" x="${width/2}" y="${height/2}" text-anchor="middle">${escapeHtml(emptyText)}</text>`}
      </svg>
      <div class="signal-trajectory-legend">${legend}</div>
    </div>`;
  }

  function summarizeFeatureRowsForTrajectory(rows, signals = ['HR','MAP','SpO2','RR']) {
    const arr = Array.isArray(rows) ? rows : [];
    const validity = signals.map(signal => {
      const ratios = arr.map(row => toFiniteNumber(row[`${signal}_valid_ratio`])).filter(Number.isFinite);
      const ratio = ratios.length ? ratios.reduce((a,b)=>a+b,0) / ratios.length : NaN;
      return { signal, ratio };
    });
    const eventKeys = Object.keys(arr[0] || {}).filter(k => k.startsWith('n_') && !k.endsWith('_ratio'));
    const events = eventKeys.map(key => ({ key, total: arr.reduce((sum, row) => sum + (toFiniteNumber(row[key]) || 0), 0) }))
      .filter(item => item.total > 0).sort((a,b) => b.total - a.total).slice(0, 6);
    return { validity, events };
  }

  function renderSignalTrajectoryPanel(container, rows, fileName, config = {}) {
    if (!container) return;
    const arr = Array.isArray(rows) ? rows : [];
    const availableSignals = config.signals && config.signals.length
      ? config.signals
      : ['HR','MAP','SpO2','RR'].filter(sig => arr.some(row => Number.isFinite(toFiniteNumber(row[`${sig}_mean`] ?? row[sig]))));
    const signals = availableSignals.length ? availableSignals : ['HR','MAP','SpO2','RR'];
    if (!arr.length) {
      container.innerHTML = buildSignalTrajectorySvg([], {
        title: config.title || '신호 궤적 요약',
        subtitle: config.subtitle || '실제 feature row가 연결되면 HR, MAP, SpO2, RR 흐름을 보여줍니다.',
        emptyText: config.emptyText || '아직 표시할 실제 데이터가 없습니다.',
        badge: config.badge || 'QC preview',
        signals
      });
      return;
    }
    const summary = summarizeFeatureRowsForTrajectory(arr, signals);
    const validTags = summary.validity.map(item => {
      const pct = Number.isFinite(item.ratio) ? Math.round(item.ratio * 100) + '%' : 'NA';
      return `<span class="signal-event-tag">${escapeHtml(item.signal)} valid ${escapeHtml(pct)}</span>`;
    }).join('');
    const eventTags = summary.events.length ? summary.events.map(item => `<span class="signal-event-tag warn">${escapeHtml(item.key.replaceAll('_',' '))}: ${Number(item.total).toLocaleString()}</span>`).join('') : '<span class="signal-event-tag">이벤트 없음</span>';
    container.innerHTML = buildSignalTrajectorySvg(arr, {
      title: config.title || '신호 궤적 요약',
      subtitle: config.subtitle || `${fileName || 'feature rows'} · ${arr.length.toLocaleString()} minute rows · QC용 정규화 궤적`,
      badge: config.badge || 'QC preview',
      signals
    }) + `<div class="signal-event-tags">${validTags}${eventTags}</div>`;
  }

  function renderCsvConversionResult(result) {
    if (result?.sourceType === 'raw .vital') {
      setCsvStatus(`변환 작업 생성: ${result.sourceFile} → ${result.caseId}_coding_ready_1min_features.csv`, 'teal');
      const summary = $('#csvFeatureSummary');
      if (summary) {
        summary.innerHTML = `<dl class="kv"><dt>case_id</dt><dd>${escapeHtml(result.caseId)}</dd><dt>원본 형식</dt><dd>.vital</dd><dt>출력 형식</dt><dd>공란 없는 1분 coding-ready CSV</dd><dt>예상 컬럼 수</dt><dd>${result.columns.length.toLocaleString()}개</dd><dt>time bin</dt><dd>${result.timeBinSec}초</dd><dt>상태</dt><dd>백엔드 파서 연결 대기</dd></dl>`;
      }
      const mapBody = $('#csvColumnMapBody');
      if (mapBody) {
        const rows = ['HR','MAP','SBP','DBP','SpO2','PI','RR'].map(v => `<tr><td>${v}</td><td>.vital track 자동 탐색</td><td>${badge('파서에서 매칭', 'blue')}</td></tr>`).join('');
        mapBody.innerHTML = rows;
      }
      const head = $('#csvFeaturePreviewHead');
      const previewBody = $('#csvFeaturePreviewBody');
      if (head) head.innerHTML = '<tr><th>출력 컬럼</th><th>설명</th></tr>';
      if (previewBody) previewBody.innerHTML = result.dictionary.slice(0, 12).map(row => `<tr><td>${escapeHtml(row.column)}</td><td>${escapeHtml(row.description)}</td></tr>`).join('');
      renderSignalTrajectoryPanel($('#vitalTrajectorySummary'), [], result.sourceFile, {title:'신호 궤적 QC', subtitle:'백엔드 .vital 파서가 1분 feature row를 반환하면 이 영역에 실제 궤적이 표시됩니다.', emptyText:'아직 실제 궤적 데이터가 없습니다.', badge:'.vital parser 대기'});
      return;
    }
    setCsvStatus(`변환 완료: ${result.features.length}분 row, ${result.columns.length}개 컬럼, ${result.segmentCount}개 segment 생성`, 'teal');
    const summary = $('#csvFeatureSummary');
    const detectedNames = result.detectedSignalNames || [];
    const detectedText = detectedNames.length ? detectedNames.join(', ') : '없음';
    if (summary) {
      summary.innerHTML = `<dl class="kv"><dt>case_id</dt><dd>${escapeHtml(result.caseId)}</dd><dt>읽은 행</dt><dd>${result.rowsRead.toLocaleString()}행</dd><dt>feature row</dt><dd>${result.features.length.toLocaleString()}행</dd><dt>컬럼 수</dt><dd>${result.columns.length.toLocaleString()}개</dd><dt>감지 신호</dt><dd>${escapeHtml(detectedText)}</dd><dt>encoding</dt><dd>${escapeHtml(result.encoding)}</dd><dt>separator</dt><dd>${escapeHtml(result.separator)}</dd></dl>`;
    }
    const mapBody = $('#csvColumnMapBody');
    if (mapBody) {
      const coreRows = Object.entries(result.detectedCols || {}).map(([std, src]) => `<tr><td>${escapeHtml(std)}</td><td>${escapeHtml(src || '미탐지')}</td><td>${src ? badge('사용', 'green') : badge('미사용', 'gray')}</td></tr>`).join('');
      const auxRows = (result.auxiliarySignals || []).map(item => `<tr><td>${escapeHtml(item.signal)}</td><td>${escapeHtml(item.source)}</td><td>${badge('auxiliary numeric', 'blue')}</td></tr>`).join('');
      mapBody.innerHTML = coreRows + auxRows;
    }
    const previewBody = $('#csvFeaturePreviewBody');
    if (previewBody) {
      const signalPreview = (result.detectedSignalNames || []).slice(0, 4).flatMap(sig => [`${sig}_mean`, `${sig}_count`]);
      const previewCols = ['case_id','segment_id','Minute','Minute_start_datetime_iso', ...signalPreview, `label_next_${getCsvSettings().futureHorizonMin}min_MAP_below_${getCsvSettings().mapThreshold}`].filter((c, idx, arr) => result.columns.includes(c) && arr.indexOf(c) === idx);
      const head = $('#csvFeaturePreviewHead');
      if (head) head.innerHTML = `<tr>${previewCols.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;
      previewBody.innerHTML = result.features.slice(0, 8).map(row => `<tr>${previewCols.map(c => `<td>${escapeHtml(row[c] ?? '')}</td>`).join('')}</tr>`).join('') || `<tr class="empty-row"><td colspan="10">미리보기할 행이 없습니다.</td></tr>`;
    }
    const core = ['HR','MAP','SBP','DBP','SpO2','PI','RR'].filter(v => result.detectedSignalNames?.includes(v));
    const aux = (result.auxiliarySignals || []).map(x => x.signal);
    const qcSignals = (core.length ? ['HR','MAP','SpO2','RR'].filter(v => core.includes(v)) : aux.slice(0, 4));
    const subtitle = core.length ? 'core vital trend를 기준으로 QC 궤적을 표시합니다.' : 'core vital trend가 없어 감지된 auxiliary numeric channel을 QC 궤적으로 표시합니다.';
    renderSignalTrajectoryPanel($('#vitalTrajectorySummary'), result.features, result.caseId, {title:'신호 궤적 QC', subtitle, badge:'변환 완료', signals: qcSignals});
  }

  function initExportCenter() {
    initCsvFeatureConverter();
    const card = cardByHeading('내보내기 대상');
    if (!card) return;
    const selects = $$('select', card);
    const exportBtn = $('button', card);
    removeDisabledAction(exportBtn);
    const updateOptions = () => {
      const state = readState();
      const targetType = selects[0]?.value || '';
      if (!selects[1]) return;
      if (targetType.includes('연구 태그')) {
        selects[1].innerHTML = option('', '전체 연구 태그') + state.tags.map(t => option(t.id, t.name)).join('');
      } else if (targetType.includes('Vital')) {
        selects[1].innerHTML = option('', '전체 Vital 파일') + state.vitalFiles.map(f => option(f.id, f.name)).join('');
      } else if (targetType.includes('분석')) {
        selects[1].innerHTML = option('', '전체 분석 결과') + state.analyses.map(a => option(a.id, a.name)).join('');
      } else {
        selects[1].innerHTML = option('', '전체 metadata');
      }
    };
    selects[0]?.addEventListener('change', updateOptions);
    updateOptions();
    exportBtn?.addEventListener('click', () => {
      const state = readState();
      const targetType = selects[0]?.value || 'metadata';
      const selectedId = selects[1]?.value || '';
      const fileFormat = selects[2]?.value || 'CSV';
      let rows = [];
      if (targetType.includes('Vital')) rows = state.vitalFiles.filter(f => !selectedId || f.id === selectedId);
      else if (targetType.includes('분석')) rows = state.analyses.filter(a => !selectedId || a.id === selectedId);
      else if (targetType.includes('audit')) rows = state.audit;
      else if (targetType.includes('연구 태그')) {
        rows = [
          ...state.variables.filter(v => !selectedId || v.tagId === selectedId).map(v => ({...v, internal: JSON.stringify(v.internal || {})})),
          ...(state.variableDefinitions || []).filter(v => !selectedId || !v.tagId || v.tagId === selectedId).map(v => ({...v, status: '변수 사전', internal: ''}))
        ];
      } else rows = [{ tags: state.tags.length, axes: state.axes.length, vitalFiles: state.vitalFiles.length, variables: state.variables.length, analyses: state.analyses.length }];
      if (!rows.length) return toast('내보낼 데이터가 없습니다.', 'gray');
      const ext = fileFormat.includes('JSON') ? 'json' : 'csv';
      const content = ext === 'json' ? JSON.stringify(rows, null, 2) : toCsv(rows.map(flattenForCsv));
      const filename = `excite_export_${Date.now()}.${ext}`;
      downloadText(filename, content, ext === 'json' ? 'application/json;charset=utf-8' : 'text/csv;charset=utf-8');
      addExportRow(filename, fileFormat);
      addAudit('analysis export', 'export', filename);
      toast('내보내기 파일을 생성했습니다.');
    });
  }

  function flattenForCsv(obj) {
    const out = {};
    Object.entries(obj || {}).forEach(([k, v]) => {
      out[k] = typeof v === 'object' && v !== null ? JSON.stringify(v) : v;
    });
    return out;
  }

  function addExportRow(filename, format) {
    const body = cardByHeading('최근 내보내기')?.querySelector('tbody');
    if (!body) return;
    if ($('.empty-row', body)) body.innerHTML = '';
    body.insertAdjacentHTML('afterbegin', `<tr><td>${escapeHtml(filename)}</td><td>${escapeHtml(format)}</td><td>${escapeHtml(USER)}</td><td>${badge('생성 완료', 'green')}</td></tr>`);
  }

  function toCsv(rows) {
    if (!rows.length) return '';
    const headers = Object.keys(rows[0]);
    const cell = v => `"${String(v ?? '').replaceAll('"', '""')}"`;
    return [headers.join(','), ...rows.map(row => headers.map(h => cell(row[h])).join(','))].join('\n');
  }

  function initResearchProjects() {
    const saveBtn = $('#projectSaveBtn');
    removeDisabledAction(saveBtn);
    saveBtn?.addEventListener('click', saveResearchProject);
    renderResearchProjects();
  }

  function saveResearchProject() {
    const card = cardByHeading('새 연구 기본정보');
    if (!card) return;
    const title = $('[data-project-field="title"]', card)?.value.trim() || '';
    const type = 'vital-db';
    const topic = $('[data-project-field="topic"]', card)?.value.trim() || '';
    const irb = $('[data-project-field="irb"]', card)?.value.trim() || '';
    const objective = $('[data-project-field="objective"]', card)?.value.trim() || '';
    const status = $('[data-project-field="status"]', card)?.value || '준비 중';
    if (!title) return toast('연구 제목을 입력하세요.', 'gray');
    const tagKeyword = title.replace(/\s+/g, '_').replace(/[^A-Za-z0-9_가-힣]/g, '').slice(0, 40) || uid('TAG');
    patchState(state => {
      const projectId = uid('PROJ');
      state.projects.unshift({ id: projectId, title, type, topic, objective, irb, status, createdAt: nowText(), createdBy: USER });
      if (!state.tags.some(tag => tag.name === tagKeyword)) {
        state.tags.unshift({ id: uid('TAG'), projectId, name: tagKeyword, status, color: '#0b8f8a', description: objective || topic, irb, matchUnit: '복합 단위', createdBy: USER, createdAt: nowText(), updatedAt: nowText() });
      }
    });
    $$('input, textarea', card).forEach(element => { element.value = ''; });
    const typeSelect = $('[data-project-field="type"]', card); if (typeSelect) typeSelect.value = 'vital-db';
    renderResearchProjects();
    addAudit('research project create', 'research_project', `${title} · ${type}`);
    toast('연구 기본정보와 연구 구분 태그를 저장했습니다.');
  }


  function projectTypeLabel() {
    return 'Vital DB 시계열 연구';
  }


  function renderResearchProjects(state = readState()) {
    const body = $('#researchProjectBody');
    if (!body) return;
    const projects = (state.projects || []).filter(project => !project.type || project.type === 'vital-db');
    if (!projects.length) return setTableEmpty(body, 8, '아직 생성된 연구가 없습니다.', '연구 제목과 목적을 저장하면 해당 연구를 구분하는 태그가 함께 생성됩니다.');
    body.innerHTML = projects.map(project => {
      const tag = state.tags.find(item => item.projectId === project.id || item.name === project.title.replace(/\s+/g, '_'));
      const subjectCount = state.studyPatients.filter(subject => subject.tagId === tag?.id).length;
      return `<tr><td>${escapeHtml(project.title)}</td><td>${badge(projectTypeLabel(project.type), 'blue')}</td><td>${escapeHtml(project.topic || '-')}</td><td>${escapeHtml(project.irb || '-')}</td><td>${badge(project.status || '준비 중','blue')}</td><td>${tag ? badge(tag.name,'teal') : badge('태그 없음','gray')}</td><td>${subjectCount}명</td><td><a class="btn ghost" href="patient-upload.html">대상자/자료</a></td></tr>`;
    }).join('');
  }














  // Optimized converter override: large raw CSV support without materializing every row as an object.
  // This keeps SICU high-frequency CSV and CCU Solar8000 ST-only CSV both usable in the browser prototype.
  function parseCsvDtStartMetadata(lines, sep, headerIdx) {
    const limit = Math.max(0, Math.min(headerIdx, 30));
    for (let i = 0; i < limit; i++) {
      const cells = parseDelimitedLine(lines[i] || '', sep);
      const key = String(cells[0] || '').trim().toLowerCase();
      if (key === '#dtstart' || key === 'dtstart') {
        const dt = parseDateTimeString(cells[1]);
        if (dt) return dt;
      }
    }
    return null;
  }

  function headerEntriesFromCells(cells) {
    return cells.map((name, index) => ({ name: String(name || '').trim(), index }))
      .filter(item => item.name && !/^Unnamed/i.test(item.name));
  }

  function sampleNumericCountsFromLines(lines, sep, headerIdx, headerEntries, limit = 18000) {
    const counts = new Map(headerEntries.map(h => [h.name, 0]));
    const rowsToUse = Math.min(lines.length, headerIdx + 1 + limit);
    let sampledRows = 0;
    for (let i = headerIdx + 1; i < rowsToUse; i++) {
      const line = lines[i];
      if (!line || !line.trim() || line.trim().startsWith('#')) continue;
      const cells = parseDelimitedLine(line, sep);
      sampledRows += 1;
      headerEntries.forEach(h => {
        if (Number.isFinite(numericClean(cells[h.index]))) counts.set(h.name, (counts.get(h.name) || 0) + 1);
      });
    }
    return { counts, sampledRows };
  }

  function optimizedFindColumn(headerEntries, patternGroups, sampleCounts) {
    const normMap = headerEntries.map(h => ({ ...h, norm: normalizeColname(h.name), count: sampleCounts.get(h.name) || 0 }));
    for (const patterns of patternGroups) {
      const normalized = patterns.map(normalizeColname);
      const usable = normMap
        .filter(h => normalized.every(p => h.norm.includes(p)))
        .filter(h => !isMonitorMetaColumn(h.name))
        .filter(h => h.count > 0)
        .sort((a, b) => b.count - a.count || a.index - b.index);
      if (usable.length) return usable[0];
    }
    return null;
  }

  function optimizedDetectVitalColumns(headerEntries, sampleCounts) {
    const patterns = {
      HR: [['ECG','HR'], ['ABP','HR'], ['PLETH','HR'], ['HEART','RATE'], ['HEARTRATE'], ['HR']],
      MAP: [['ABP','MEAN'], ['ART','MEAN'], ['IBP','MEAN'], ['ART','MBP'], ['ABP','MBP'], ['MEAN','BP'], ['MAP'], ['MBP']],
      SBP: [['ABP','SYS'], ['ART','SYS'], ['IBP','SYS'], ['ART','SBP'], ['SYSTOLIC'], ['SBP']],
      DBP: [['ABP','DIA'], ['ART','DIA'], ['IBP','DIA'], ['ART','DBP'], ['DIASTOLIC'], ['DBP']],
      SpO2: [['PLETH','SPO2'], ['PLETH','SATO2'], ['SPO2'], ['SATO2'], ['SAT','O2']],
      PI: [['PLETH','PERF'], ['PERF','REL'], ['PERFUSION'], ['PI']],
      RR: [['RESP','RATE'], ['RESP','RR'], ['RESPRATE'], ['INTELLIVUE','RR'], ['RR']]
    };
    const out = {};
    Object.entries(patterns).forEach(([signal, patternGroups]) => {
      const hit = optimizedFindColumn(headerEntries, patternGroups, sampleCounts);
      out[signal] = hit ? hit.name : null;
    });
    return out;
  }

  function optimizedAuxiliarySignals(headerEntries, sampleCounts, usedSources, usedNames, maxSignals = 12) {
    const blocked = new Set(usedSources.filter(Boolean));
    const names = new Set(usedNames);
    const candidates = headerEntries
      .filter(h => !blocked.has(h.name))
      .filter(h => !isMonitorMetaColumn(h.name))
      .filter(h => !['TIME','DATE','DATETIME','TIMESTAMP','DATEANDTIME','CLOCKTIME'].includes(normalizeColname(h.name)))
      .map(h => ({ ...h, count: sampleCounts.get(h.name) || 0 }))
      .filter(h => h.count > 0)
      .filter(h => {
        const n = normalizeColname(h.name);
        // Avoid obvious high-frequency waveform channels when possible; keep ST and numeric trend-like channels.
        if (n.includes('WAV') || n.endsWith('WAVE')) return false;
        return true;
      })
      .sort((a, b) => b.count - a.count || a.index - b.index)
      .slice(0, maxSignals);
    return candidates.map(h => ({ signal: signalNameFromHeader(h.name, names), source: h.name, index: h.index, count: h.count }));
  }

  function optimizedTimeColumnInfo(headerEntries) {
    const activeNames = headerEntries.map(h => h.name);
    const found = findTimeColumns(activeNames);
    const byName = Object.fromEntries(headerEntries.map(h => [h.name, h.index]));
    return {
      datetimeCol: found.datetimeCol,
      datetimeIdx: found.datetimeCol ? byName[found.datetimeCol] : null,
      dateCol: found.dateCol,
      dateIdx: found.dateCol ? byName[found.dateCol] : null,
      timeCol: found.timeCol,
      timeIdx: found.timeCol ? byName[found.timeCol] : null
    };
  }

  function optimizedDateTimeFromCells(cells, timeInfo, startDt, rowNumber, rolloverState) {
    if (timeInfo.datetimeIdx !== null && timeInfo.datetimeIdx !== undefined) {
      const raw = cells[timeInfo.datetimeIdx];
      const num = numericClean(raw);
      if (startDt && Number.isFinite(num) && num < 10000000) return new Date(startDt.getTime() + num * 1000);
      const dt = parseDateTimeString(raw);
      if (dt) return dt;
    }
    if (timeInfo.dateIdx !== null && timeInfo.dateIdx !== undefined && timeInfo.timeIdx !== null && timeInfo.timeIdx !== undefined) {
      const dt = parseDateTimeString(`${cells[timeInfo.dateIdx]} ${cells[timeInfo.timeIdx]}`);
      if (dt) return dt;
    }
    if (timeInfo.timeIdx !== null && timeInfo.timeIdx !== undefined) {
      const raw = cells[timeInfo.timeIdx];
      const num = numericClean(raw);
      if (startDt && Number.isFinite(num) && num < 10000000) return new Date(startDt.getTime() + num * 1000);
      const sec = parseTimeToSeconds(raw);
      if (startDt && Number.isFinite(sec)) {
        const base = new Date(startDt.getFullYear(), startDt.getMonth(), startDt.getDate()).getTime();
        let ms = base + (rolloverState.dayOffset || 0) * 86400000 + sec * 1000;
        if (rolloverState.lastWallMs !== null && ms - rolloverState.lastWallMs < -3600000) {
          rolloverState.dayOffset = (rolloverState.dayOffset || 0) + 1;
          ms += 86400000;
        }
        rolloverState.lastWallMs = ms;
        return new Date(ms);
      }
      const dt = parseDateTimeString(raw);
      if (dt) return dt;
    }
    if (startDt) return new Date(startDt.getTime() + rowNumber * 1000);
    return new Date(new Date(2026, 0, 1, 0, 0, 0).getTime() + rowNumber * 1000);
  }

  function createStreamingBucket(caseId, segmentNum, minute, ms, vitalCols) {
    const bucket = {
      case_id: caseId,
      segment_id: `${caseId}_seg_${String(segmentNum).padStart(3, '0')}`,
      segment_num: segmentNum,
      Minute: minute,
      startMs: ms,
      endMs: ms,
      n_rows_with_any_vital: 0,
      acc: {}
    };
    vitalCols.forEach(col => bucket.acc[col] = { values: [], count: 0, sum: 0, sumSq: 0, min: Infinity, max: -Infinity });
    return bucket;
  }

  function addStreamingValue(acc, value) {
    acc.values.push(value);
    acc.count += 1;
    acc.sum += value;
    acc.sumSq += value * value;
    acc.min = Math.min(acc.min, value);
    acc.max = Math.max(acc.max, value);
  }

  function finalizeStreamingAcc(acc) {
    if (!acc || acc.count === 0) return { mean: NaN, min: NaN, max: NaN, std: NaN, median: NaN, count: 0 };
    const avg = acc.sum / acc.count;
    const variance = acc.count > 1 ? Math.max(0, (acc.sumSq - (acc.sum * acc.sum / acc.count)) / (acc.count - 1)) : NaN;
    return {
      mean: avg,
      min: acc.min,
      max: acc.max,
      std: Number.isFinite(variance) ? Math.sqrt(variance) : NaN,
      median: median(acc.values),
      count: acc.count
    };
  }

  async function convertRawVitalCsvFile(file) {
    const settings = getCsvSettings();
    const { text, encoding } = await readFileTextWithEncodingGuess(file);
    const detected = detectSeparatorAndHeader(text);
    const lines = text.split(/\r?\n/);
    const headerCells = parseDelimitedLine(lines[detected.headerIdx] || '', detected.sep).map(h => String(h).trim());
    const headerEntries = headerEntriesFromCells(headerCells);
    if (!headerEntries.length) throw new Error('CSV header를 찾지 못했습니다.');

    const sample = sampleNumericCountsFromLines(lines, detected.sep, detected.headerIdx, headerEntries);
    const detectedCols = optimizedDetectVitalColumns(headerEntries, sample.counts);
    const coreSignals = ['HR','MAP','SBP','DBP','SpO2','PI','RR']
      .map(signal => {
        const h = headerEntries.find(x => x.name === detectedCols[signal]);
        const count = h ? sample.counts.get(h.name) || 0 : 0;
        return h && count > 0 ? { signal, source: h.name, index: h.index, core: true } : null;
      })
      .filter(Boolean);

    // If core vital exists, keep conversion focused on core vital for speed.
    // If not, fall back to numeric auxiliary channels such as Solar8000/ST_*.
    const auxiliarySignals = coreSignals.length
      ? []
      : optimizedAuxiliarySignals(headerEntries, sample.counts, Object.values(detectedCols), ['HR','MAP','SBP','DBP','SpO2','PI','RR'], 12);
    const signalSources = [...coreSignals, ...auxiliarySignals.map(x => ({ ...x, core: false }))];

    if (!signalSources.length) {
      throw new Error('수치형 trend 컬럼을 찾지 못했습니다. MSG/ALARM/STATUS/FLAG만 있는 CSV는 feature를 만들 수 없습니다.');
    }

    const caseId = makeCaseIdFromName(file.name, true);
    const metadataStart = parseCsvDtStartMetadata(lines, detected.sep, detected.headerIdx);
    const startFromName = parseStartDateTimeFromName(file.name);
    const startDt = metadataStart || startFromName;
    const timeInfo = optimizedTimeColumnInfo(headerEntries);
    const vitalCols = signalSources.map(item => item.signal);
    const sourceBySignal = Object.fromEntries(signalSources.map(item => [item.signal, item.source]));
    const ranges = { HR:[20,250], MAP:[0,200], SBP:[0,300], DBP:[0,200], SpO2:[0,100], PI:[0,100], RR:[3,80] };
    const coreSet = new Set(coreSignals.map(x => x.signal));
    const buckets = new Map();
    let segmentNum = 0;
    let segmentStartMs = null;
    let prevMs = null;
    let rowsRead = 0;
    let validSignalRows = 0;
    const rolloverState = { dayOffset: 0, lastWallMs: null };
    const rrValuesForCheck = [];

    const lowerMs = settings.filterByFilenameTime && startDt ? startDt.getTime() - 3600000 : null;
    const upperMs = settings.filterByFilenameTime && startDt ? startDt.getTime() + settings.maxHours * 3600000 : null;

    for (let i = detected.headerIdx + 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line || !line.trim() || line.trim().startsWith('#')) continue;
      const cells = parseDelimitedLine(line, detected.sep);
      rowsRead += 1;
      const dt = optimizedDateTimeFromCells(cells, timeInfo, startDt, rowsRead - 1, rolloverState);
      if (!(dt instanceof Date) || Number.isNaN(dt.getTime())) continue;
      const ms = dt.getTime();
      if (lowerMs !== null && (ms < lowerMs || ms > upperMs)) continue;

      const values = {};
      let hasAny = false;
      signalSources.forEach(({ signal, index, core }) => {
        let value = numericClean(cells[index]);
        const range = core ? ranges[signal] : null;
        if (range && Number.isFinite(value) && (value < range[0] || value > range[1])) value = NaN;
        if (Number.isFinite(value)) {
          values[signal] = value;
          hasAny = true;
          if (signal === 'RR') rrValuesForCheck.push(value);
        }
      });
      if (!hasAny) continue;

      if (prevMs === null || (ms - prevMs) / 1000 > settings.segmentGapSec || ms < prevMs) {
        segmentNum += 1;
        segmentStartMs = ms;
      }
      prevMs = ms;
      const elapsedSec = (ms - segmentStartMs) / 1000;
      const minute = Math.floor(elapsedSec / 60);
      const key = `${segmentNum}|${minute}`;
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = createStreamingBucket(caseId, segmentNum, minute, ms, vitalCols);
        buckets.set(key, bucket);
      }
      bucket.startMs = Math.min(bucket.startMs, ms);
      bucket.endMs = Math.max(bucket.endMs, ms);
      bucket.n_rows_with_any_vital += 1;
      validSignalRows += 1;
      vitalCols.forEach(signal => {
        if (Number.isFinite(values[signal])) addStreamingValue(bucket.acc[signal], values[signal]);
      });
    }

    if (!buckets.size) {
      const mapped = signalSources.map(item => `${item.signal}←${item.source}`).join(', ');
      throw new Error(`컬럼은 감지했지만 유효한 수치값이 없습니다. 감지 결과: ${mapped || '없음'}`);
    }

    // RR guard after streaming: if RR is not physiologic, clear RR-derived values.
    if (vitalCols.includes('RR') && rrValuesForCheck.length && (median(rrValuesForCheck) < 5 || quantile(rrValuesForCheck, 0.95) > 80)) {
      buckets.forEach(bucket => {
        bucket.acc.RR = { values: [], count: 0, sum: 0, sumSq: 0, min: Infinity, max: -Infinity };
      });
    }

    let features = Array.from(buckets.values()).map(bucket => {
      const row = {
        case_id: bucket.case_id,
        segment_id: bucket.segment_id,
        segment_num: bucket.segment_num,
        Minute: bucket.Minute,
        _start_ms: bucket.startMs,
        _end_ms: bucket.endMs,
        n_rows_with_any_vital: bucket.n_rows_with_any_vital
      };
      vitalCols.forEach(col => {
        const s = finalizeStreamingAcc(bucket.acc[col]);
        row[`${col}_mean`] = s.mean;
        row[`${col}_min`] = s.min;
        row[`${col}_max`] = s.max;
        row[`${col}_std`] = s.std;
        row[`${col}_median`] = s.median;
        row[`${col}_count`] = s.count;
      });
      if (vitalCols.includes('MAP')) row[`n_MAP_below_${settings.mapThreshold}`] = (bucket.acc.MAP.values || []).filter(v => v < settings.mapThreshold).length;
      if (vitalCols.includes('SpO2')) row.n_SpO2_below_90 = (bucket.acc.SpO2.values || []).filter(v => v < 90).length;
      if (vitalCols.includes('HR')) {
        row.n_HR_below_40 = (bucket.acc.HR.values || []).filter(v => v < 40).length;
        row.n_HR_above_130 = (bucket.acc.HR.values || []).filter(v => v > 130).length;
      }
      if (vitalCols.includes('RR')) {
        row.n_RR_below_8 = (bucket.acc.RR.values || []).filter(v => v < 8).length;
        row.n_RR_above_30 = (bucket.acc.RR.values || []).filter(v => v > 30).length;
      }
      return row;
    }).sort((a, b) => a.segment_num - b.segment_num || a.Minute - b.Minute);

    const expectedCounts = {};
    vitalCols.forEach(col => {
      const counts = features.map(r => r[`${col}_count`]).filter(v => Number.isFinite(v) && v > 0);
      const expected = counts.length ? Math.max(quantile(counts, 0.75), 1) : NaN;
      expectedCounts[col] = expected;
      features.forEach(r => {
        r[`${col}_expected_count_per_min`] = expected;
        if (!Number.isFinite(expected) || expected === 0) {
          r[`${col}_valid_ratio`] = NaN;
          r[`${col}_missing_rate`] = NaN;
        } else {
          const ratio = Math.min(Math.max((r[`${col}_count`] || 0) / expected, 0), 1);
          r[`${col}_valid_ratio`] = ratio;
          r[`${col}_missing_rate`] = 1 - ratio;
        }
      });
    });

    const flatThresholds = { HR:0.1, MAP:0.1, SBP:0.1, DBP:0.1, SpO2:0.05, PI:0.001, RR:0.1 };
    vitalCols.forEach(col => {
      const expected = expectedCounts[col];
      const minCount = (!Number.isFinite(expected) || expected === 0) ? 5 : Math.max(5, expected * 0.5);
      const threshold = flatThresholds[col] ?? 1e-9;
      features.forEach(r => {
        const sd = Number.isFinite(r[`${col}_std`]) ? r[`${col}_std`] : 0;
        r[`${col}_flatline_flag`] = ((r[`${col}_count`] || 0) >= minCount && sd <= threshold) ? 1 : 0;
      });
    });

    const eventCols = [];
    if (vitalCols.includes('MAP')) eventCols.push(`n_MAP_below_${settings.mapThreshold}`);
    if (vitalCols.includes('SpO2')) eventCols.push('n_SpO2_below_90');
    if (vitalCols.includes('HR')) eventCols.push('n_HR_below_40', 'n_HR_above_130');
    if (vitalCols.includes('RR')) eventCols.push('n_RR_below_8', 'n_RR_above_30');
    features.forEach(r => eventCols.forEach(c => r[`${c}_ratio`] = r.n_rows_with_any_vital ? r[c] / r.n_rows_with_any_vital : NaN));

    if (settings.makeFutureLabel && vitalCols.includes('MAP')) {
      const labelCol = `label_next_${settings.futureHorizonMin}min_MAP_below_${settings.mapThreshold}`;
      const bySeg = groupBy(features, r => String(r.segment_num));
      Object.values(bySeg).forEach(segRows => {
        segRows.sort((a, b) => a.Minute - b.Minute);
        const eventVals = segRows.map(r => r[`n_MAP_below_${settings.mapThreshold}`] > 0 ? 1 : 0);
        segRows.forEach((r, i) => {
          const window = eventVals.slice(i + 1, i + 1 + settings.futureHorizonMin);
          if (window.length < settings.futureHorizonMin && settings.labelIncompleteAsNa) r[labelCol] = NaN;
          else r[labelCol] = window.length ? (Math.max(...window) > 0 ? 1 : 0) : NaN;
        });
      });
    }

    const segMinuteCounts = groupBy(features, r => r.segment_id);
    const validSegments = new Set(Object.entries(segMinuteCounts).filter(([, arr]) => new Set(arr.map(r => r.Minute)).size >= settings.minSegmentMinutes).map(([id]) => id));
    features = features.filter(r => validSegments.has(r.segment_id));
    if (!features.length) throw new Error('유효 segment가 없습니다. segment 길이 기준을 낮추거나 파일 시간을 확인하세요.');

    features.forEach(r => {
      r.Minute_start_datetime_iso = formatDateTime(new Date(r._start_ms));
      r.Minute_end_datetime_iso = formatDateTime(new Date(r._end_ms));
      r.minute_duration_sec = (r._end_ms - r._start_ms) / 1000;
      delete r._start_ms;
      delete r._end_ms;
    });

    const frontCols = ['case_id','segment_id','segment_num','Minute','Minute_start_datetime_iso','Minute_end_datetime_iso','minute_duration_sec','n_rows_with_any_vital'];
    const labelCols = Object.keys(features[0] || {}).filter(c => c.startsWith('label_'));
    const middleCols = Object.keys(features[0] || {}).filter(c => !frontCols.includes(c) && !labelCols.includes(c));
    const orderedCols = [...frontCols, ...middleCols, ...labelCols];
    features = features.map(r => orderedCols.reduce((o, c) => { o[c] = csvSafeValue(r[c]); return o; }, {}));
    const dictionary = orderedCols.map(c => ({ column: c, description: describeFeatureColumn(c) || `1분 구간 ${c} feature` }));

    return {
      caseId,
      encoding,
      separator: detected.sep === '\t' ? 'tab' : detected.sep,
      headerIdx: detected.headerIdx,
      detectedCols,
      auxiliarySignals,
      detectedSignalNames: vitalCols,
      sourceBySignal,
      expectedCounts,
      rowsRead,
      validSignalRows,
      features,
      dictionary,
      columns: orderedCols,
      segmentCount: new Set(features.map(r => r.segment_id)).size,
      conversionMode: coreSignals.length ? 'core vital' : 'auxiliary numeric'
    };
  }


  /* Clinical patient/lab entry redesign: registration number only, fixed baseline history, multi-ECMO episode sheets, microbiology, and diagnostic lab records. */
  const CLINICAL_CONDITIONS = [
    { key: 'hypertension', label: '고혈압' },
    { key: 'diabetes', label: '당뇨' },
    { key: 'pulmonaryTb', label: '폐결핵' },
    { key: 'hepatitis', label: '간염' },
    { key: 'cancer', label: '암' },
    { key: 'operationHistory', label: '수술기왕력' },
    { key: 'stroke', label: '뇌졸중' },
    { key: 'hyperlipidemia', label: '고지혈증' },
    { key: 'padCarotid', label: '말초동맥 및 경동맥질환' },
    { key: 'allergy', label: '알레르기' },
    { key: 'medication', label: '투약' }
  ];

  const DEFAULT_ORGANISMS = [
    'Staphylococcus epidermidis',
    'Enterococcus faecalis',
    'Pseudomonas aeruginosa',
    'Corynebacterium striatum',
    'Acinetobacter baumannii',
    'Aerococcus urinae',
    'Fusobacterium varium',
    'Staphylococcus capitis',
    'Klebsiella pneumoniae',
    'Candida species',
    'Stenotrophomonas maltophilia',
    'Neisseria flavescens',
    'Staphylococcus caprae',
    'Bacillus megaterium',
    'Burkholderia cenocepacia',
    'Candida albicans',
    'Staphylococcus haemolyticus',
    'Escherichia coli',
    'Citrobacter freundii',
    'Streptococcus gallolyticus ssp gallolyticus'
  ];

  const MICRO_SPECIMEN_SITES = ['', '객담(호흡기)', '혈액', '스툴(대변)', '소변', '기타'];

  const DEFAULT_VENT_MODES = ['AC(VC)', 'SIMV(PC)', 'PC', 'Nasal prong', 'T-piece', 'O2 mask', 'High flow nasal cannula'];

  const PRE_ABGA_FIELDS = [
    ['preAbgaPh', 'pH'], ['preAbgaPco2', 'PCO2'], ['preAbgaPo2', 'PO2'], ['preAbgaHco3', 'HCO3'], ['preAbgaSao2', 'SaO2'], ['preAbgaLactate', 'Lactate']
  ];

  const PRE_LAB_FIELDS = [
    ['preLabCreatinine', 'Creatinine'], ['preLabHgb', 'Hgb'], ['preLabPlt', 'Plt'], ['preLabInr', 'INR'], ['preLabAppt', 'APPT'],
    ['preLabAst', 'AST'], ['preLabAlt', 'ALT'], ['preLabBilirubin', 'Bilirubin'], ['preLabAlbumin', 'Albumin'], ['preLabCrp', 'CRP'],
    ['preLabEsr', 'ESR'], ['preLabProBnp', 'proBNP'], ['preLabMyoglobin', 'Myoglobin'], ['preLabCkMb', 'CK-MB'],
    ['preLabTroponinI', 'Troponin I'], ['preLabTroponinT', 'Troponin T']
  ];

  const PRE_VENT_FLOW_VITAL_FIELDS = [
    ['preVentStatus', 'Vent'], ['preVentMode', 'Mode'], ['preVentFio2', 'FiO2'], ['preVentRr', 'RR'], ['preVentPeep', 'PEEP'],
    ['preFlowRate', 'Flow rate'], ['preO2', 'O2'], ['preO2Unit', 'O2 Unit'],
    ['preHemoSbp', 'SBP'], ['preHemoDbp', 'DBP'], ['preHemoMeanBp', 'Mean BP'], ['preHemoPr', 'PR']
  ];

  const DURING_ECMO_TIMEPOINTS = [
    { key: 'fourHour', prefix: 'during4h', label: '4시간 경과' },
    { key: 'twentyFourHour', prefix: 'during24h', label: '24시간 경과' }
  ];

  const DURING_ABGA_SUFFIXES = [['AbgaPh', 'pH'], ['AbgaPco2', 'PCO2'], ['AbgaPo2', 'PO2'], ['AbgaHco3', 'HCO3'], ['AbgaSao2', 'SaO2'], ['AbgaLactate', 'Lactate']];
  const DURING_VENT_SUFFIXES = [['VentMode', 'Mode'], ['VentFio2', 'FiO2'], ['VentRr', 'RR'], ['VentPeep', 'PEEP']];
  const DURING_HEMO_SUFFIXES = [['HemoSbp', 'SBP'], ['HemoDbp', 'DBP']];
  const DURING_PUMP_SUFFIXES = [['PumpRpm', 'RPM'], ['PumpFio2', 'FiO2'], ['SweepGas', 'Sweep gas']];
  const VENT_END_FIELDS = [['ventEndVent', 'Vent'], ['ventEndMode', 'Mode'], ['ventEndFio2', 'FiO2'], ['ventEndRr', 'RR'], ['ventEndPeep', 'PEEP'], ['ventEndPip', 'PIP']];

  const EPISODE_EVENT_FIELDS = [
    { id: 'intubationStartTime', key: 'intubationStartTime', label: 'Intubation start', kind: 'datetime', color: '#7c3aed' },
    { id: 'ecmoStartTime', key: 'ecmoStartTime', label: 'ECMO start', kind: 'datetime', color: '#0b8f8a' },
    { id: 'ecmoFinishTime', key: 'ecmoFinishTime', label: 'ECMO finish', kind: 'datetime', color: '#1d5d9b' },
    { id: 'extubationDateTime', key: 'extubationDateTime', label: 'Extubation', kind: 'datetime', color: '#0891b2' },
    { id: 'icuDischargeDateTime', key: 'icuDischargeDateTime', label: 'ICU discharge', kind: 'datetime', color: '#ca8a04' },
    { id: 'dischargeDate', key: 'dischargeDate', label: 'Discharge', kind: 'date', color: '#16a34a' },
    { id: 'deathDate', key: 'deathDate', label: 'Death', kind: 'date', color: '#dc2626' }
  ];

  let activeEpisodeId = null;
  let editingClinicalPatientId = null;

  function todayIsoDate() {
    const d = new Date();
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  }

  function normalizeOrganismName(name) {
    return String(name || '').replace(/\s+/g, ' ').trim();
  }

  function seedClinicalCollections(state) {
    if (!Array.isArray(state.patients)) state.patients = [];
    if (!Array.isArray(state.ecmoEpisodes)) state.ecmoEpisodes = [];
    if (!Array.isArray(state.microbiologyRecords)) state.microbiologyRecords = [];
    if (!Array.isArray(state.labRecords)) state.labRecords = [];
    if (!Array.isArray(state.organismTags)) state.organismTags = [];
    if (!Array.isArray(state.ventModeTags)) state.ventModeTags = [];
    const existingVent = new Set(state.ventModeTags.map(v => String(v.name || '').trim().toLowerCase()).filter(Boolean));
    DEFAULT_VENT_MODES.forEach(name => {
      const clean = String(name || '').trim();
      const key = clean.toLowerCase();
      if (clean && !existingVent.has(key)) {
        state.ventModeTags.push({ id: uid('VENT'), name: clean, type: 'vent_mode', source: 'preset', createdAt: nowText() });
        existingVent.add(key);
      }
    });
    const existing = new Set(state.organismTags.map(o => normalizeOrganismName(o.name).toLowerCase()).filter(Boolean));
    DEFAULT_ORGANISMS.forEach(name => {
      const clean = normalizeOrganismName(name);
      const key = clean.toLowerCase();
      if (!existing.has(key)) {
        state.organismTags.push({ id: uid('ORG'), name: clean, type: 'organism', source: 'preset', createdAt: nowText() });
        existing.add(key);
      }
    });
  }

  function ensureClinicalCollections() {
    return patchState(s => seedClinicalCollections(s));
  }

  function patientMaskedRegistration(regNo) {
    const value = String(regNo || '').trim();
    if (!value) return '-';
    return `****${value.slice(-4)}`;
  }

  function patientDisplayLabel(patient) {
    const initials = patient?.initials || patient?.patientInitials || '이니셜 미입력';
    return `${initials} · ${patientMaskedRegistration(patient?.registrationNo)}`;
  }

  function patientById(state, patientId) {
    return (state.patients || []).find(p => p.id === patientId) || null;
  }

  function episodeById(state, episodeId) {
    return (state.ecmoEpisodes || []).find(e => e.id === episodeId) || null;
  }

  function episodesForPatient(state, patientId) {
    return (state.ecmoEpisodes || [])
      .filter(e => e.patientId === patientId)
      .sort((a, b) => Number(a.sequence || 0) - Number(b.sequence || 0) || String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
  }

  function episodeDisplayLabel(episode) {
    if (!episode) return 'episode 선택 안 함';
    return episode.label || `${episode.sequence || 1}차 ECMO`;
  }

  function readBaselineConditions() {
    const result = {};
    $$('#baselineConditionGrid .condition-item').forEach(item => {
      const key = item.dataset.condition;
      const select = $('select', item);
      const note = $('input', item);
      const meta = CLINICAL_CONDITIONS.find(c => c.key === key);
      result[key] = {
        label: meta?.label || key,
        status: select?.value || '미상',
        note: note?.value.trim() || ''
      };
    });
    return result;
  }

  function resetBaselineForm() {
    ['patientRegNo', 'patientInitials', 'patientBirthDate', 'patientAdmissionDate', 'patientHeightCm', 'patientWeightKg'].forEach(id => { const el = $('#' + id); if (el) el.value = ''; });
    const sex = $('#patientSex');
    if (sex) sex.value = '';
    const date = $('#patientBaselineDate');
    if (date) date.value = todayIsoDate();
    $$('#baselineConditionGrid .condition-item').forEach(item => {
      const select = $('select', item);
      const input = $('input', item);
      if (select) select.value = '미상';
      if (input) input.value = '';
    });
  }

  function conditionSummary(conditions) {
    const values = Object.values(conditions || {});
    const yes = values.filter(v => v.status === '있음').length;
    const no = values.filter(v => v.status === '없음').length;
    const unknown = values.filter(v => v.status === '미상').length;
    return `${yes}개 있음 · ${no}개 없음 · ${unknown}개 미상`;
  }

  function namedConditionText(patient, key) {
    const item = patient?.baselineConditions?.[key];
    if (!item) return '-';
    const note = item.note ? ` · ${item.note}` : '';
    return `${item.status || '미상'}${note}`;
  }

  function fillClinicalPatientMasterForm(patient) {
    if (!patient) return;
    setClinicalValue('patientRegNo', patient.registrationNo || '');
    setClinicalValue('patientInitials', patient.initials || patient.patientInitials || '');
    setClinicalValue('patientSex', patient.sex || '');
    setClinicalValue('patientBirthDate', patient.birthDate || '');
    setClinicalValue('patientAdmissionDate', patient.admissionDate || patient.addmissionDate || '');
    setClinicalValue('patientHeightCm', patient.heightCm || '');
    setClinicalValue('patientWeightKg', patient.weightKg || '');
    setClinicalValue('patientBaselineDate', patient.baselineDate || '');
    $$('#baselineConditionGrid .condition-item').forEach(item => {
      const value = patient.baselineConditions?.[item.dataset.condition] || {};
      const select = $('select', item);
      const input = $('input', item);
      if (select) select.value = value.status || '미상';
      if (input) input.value = value.note || '';
    });
  }

  function updatePatientMasterEditState(patient = null) {
    const banner = $('#patientMasterEditBanner');
    const title = $('#patientMasterEditTitle');
    const save = $('#clinicalPatientSaveBtn');
    const cancel = $('#clinicalPatientCancelEditBtn');
    if (banner) banner.hidden = !patient;
    if (title && patient) title.textContent = `${patientDisplayLabel(patient)} 환자 master 수정 중`;
    if (save) save.textContent = patient ? '환자 master 변경사항 저장' : '환자 master 저장';
    if (cancel) cancel.hidden = !patient;
  }

  function beginClinicalPatientEdit(patientId, scroll = true) {
    const state = readState();
    const patient = patientById(state, patientId);
    if (!patient) return;
    editingClinicalPatientId = patient.id;
    const details = $('#singlePatientMasterDetails');
    if (details) details.open = true;
    fillClinicalPatientMasterForm(patient);
    updatePatientMasterEditState(patient);
    hidePatientDuplicate();
    renderClinicalPatients(state);
    if (scroll) $('#patient-master-step')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function cancelClinicalPatientEdit() {
    editingClinicalPatientId = null;
    resetBaselineForm();
    updatePatientMasterEditState(null);
    renderClinicalPatients(readState());
    toast('환자 master 수정을 취소했습니다.', 'gray');
  }

  function saveClinicalPatientMaster() {
    ensureClinicalCollections();
    const registrationNo = ($('#patientRegNo')?.value || '').trim();
    if (!registrationNo) return toast('등록번호를 입력하세요.', 'yellow');
    const initials = ($('#patientInitials')?.value || '').trim().toUpperCase();
    if (!initials) return toast('환자 이니셜을 입력하세요.', 'yellow');
    const admissionDate = $('#patientAdmissionDate')?.value || '';
    const sex = $('#patientSex')?.value || '';
    const birthDate = $('#patientBirthDate')?.value || '';
    const heightCm = ($('#patientHeightCm')?.value || '').trim();
    const weightKg = ($('#patientWeightKg')?.value || '').trim();
    const baselineDate = ($('#patientBaselineDate')?.value || todayIsoDate()).trim();
    const baselineConditions = readBaselineConditions();
    let savedPatientId = '';
    const wasEditing = Boolean(editingClinicalPatientId);
    const currentState = readState();
    const duplicate = (currentState.patients || []).find(p => p.id !== editingClinicalPatientId && String(p.registrationNo || '') === registrationNo);
    if (duplicate) return toast(`이미 등록된 환자입니다: ${patientDisplayLabel(duplicate)}`, 'yellow');

    const state = patchState(s => {
      seedClinicalCollections(s);
      const existing = editingClinicalPatientId ? s.patients.find(p => p.id === editingClinicalPatientId) : null;
      if (existing) {
        Object.assign(existing, { registrationNo, initials, admissionDate, sex, birthDate, heightCm, weightKg, baselineDate, baselineConditions, updatedAt: nowText() });
        delete existing.nameStored;
        delete existing.pseudoId;
        savedPatientId = existing.id;
      } else {
        const patient = { id: uid('PAT'), registrationNo, initials, admissionDate, sex, birthDate, heightCm, weightKg, baselineDate, baselineConditions, createdAt: nowText(), updatedAt: nowText() };
        s.patients.unshift(patient);
        savedPatientId = patient.id;
      }
    });
    editingClinicalPatientId = null;
    resetBaselineForm();
    updatePatientMasterEditState(null);
    renderClinicalEntry(state);
    ['episodePatientSelect', 'microPatientSelect', 'labPatientSelect'].forEach(id => {
      const select = $('#' + id);
      if (select && [...select.options].some(o => o.value === savedPatientId)) select.value = savedPatientId;
    });
    renderEpisodeWorkspace(readState());
    renderEpisodeSelects(readState());
    addAudit(wasEditing ? 'clinical patient master update' : 'clinical patient master save', 'patient', patientMaskedRegistration(registrationNo));
    toast(wasEditing ? '환자 Master 변경사항을 저장했습니다.' : '환자 Master와 baseline 세트를 저장했습니다.');
  }

  function renderClinicalPatients(state = readState()) {
    const body=$('#clinicalPatientBody');if(!body)return;const patients=state.patients||[];
    if(!patients.length)return setTableEmpty(body,9,'아직 등록된 자료가 없습니다.','Patient Master 시트에 환자와 ECMO 차수를 입력하세요.');
    const rows=[];patients.slice().sort((a,b)=>String(a.registrationNo||'').localeCompare(String(b.registrationNo||''),'ko-KR',{numeric:true})).forEach(patient=>{const eps=episodesForPatient(state,patient.id);(eps.length?eps:[{sequence:1,events:{},details:{}}]).forEach(ep=>rows.push({patient,ep}));});
    body.innerHTML=rows.map(({patient:p,ep})=>{const d=ep.details||{},e=ep.events||{};return `<tr><td><strong>${escapeHtml(p.initials||'-')}</strong></td><td>${escapeHtml(patientMaskedRegistration(p.registrationNo))}</td><td>${badge(`${ep.sequence||1}차`,'blue')}</td><td>${escapeHtml([e.ecmoStartTime,e.ecmoFinishTime].filter(Boolean).join(' → ')||'-')}</td><td>${escapeHtml(p.admissionDate||'-')}</td><td>${escapeHtml([p.sex,p.birthDate].filter(Boolean).join(' / ')||'-')}</td><td>${escapeHtml([d.indication,d.diagnosis].filter(Boolean).join(' / ')||'-')}</td><td>${escapeHtml([d.ecmoMode,d.drainSite,d.perfusionSite||d.returnSite].filter(Boolean).join(' / ')||'-')}</td><td><div class="master-row-actions"><button class="btn secondary" type="button" data-load-master-grid="${escapeHtml(p.id)}">표에서 수정</button><button class="btn ghost" type="button" data-delete-clinical-patient="${escapeHtml(p.id)}">환자 삭제</button></div></td></tr>`;}).join('');
    $$('[data-load-master-grid]',body).forEach(btn=>btn.addEventListener('click',()=>{activateClinicalSheet('master');loadPatientsIntoBulkGrid();$('#bulkPatientGridScroll')?.scrollIntoView({behavior:'smooth',block:'center'});}));
    $$('[data-delete-clinical-patient]',body).forEach(btn=>btn.addEventListener('click',event=>{event.stopPropagation();if(!confirm('이 환자 Master와 연결된 모든 ECMO 차수, 미생물검사, 진단검사 기록을 삭제할까요?'))return;const patientId=btn.dataset.deleteClinicalPatient;const next=patchState(s=>{s.patients=(s.patients||[]).filter(p=>p.id!==patientId);s.studyPatients=(s.studyPatients||[]).filter(sp=>sp.patientId!==patientId);s.ecmoEpisodes=(s.ecmoEpisodes||[]).filter(e=>e.patientId!==patientId);s.microbiologyRecords=(s.microbiologyRecords||[]).filter(r=>r.patientId!==patientId);s.labRecords=(s.labRecords||[]).filter(r=>r.patientId!==patientId);});if(activeEpisodeId&&!episodeById(next,activeEpisodeId))activeEpisodeId=null;renderClinicalEntry(next);toast('환자 Master와 연결 자료를 삭제했습니다.');}));
  }

  function patientOptions(state, placeholder = '환자를 선택하세요') {
    const patients = state.patients || [];
    if (!patients.length) return option('', '등록된 환자가 없습니다.');
    return option('', placeholder) + patients.map(p => option(p.id, patientDisplayLabel(p))).join('');
  }

  function renderClinicalPatientSelects(state = readState()) {
    ['episodePatientSelect', 'microPatientSelect', 'labPatientSelect'].forEach(id => {
      const select = $('#' + id);
      if (!select) return;
      const current = select.value;
      select.innerHTML = patientOptions(state);
      if ([...select.options].some(o => o.value === current)) select.value = current;
      if (!select.value && (state.patients || [])[0]) select.value = state.patients[0].id;
    });
  }

  function renderEpisodeSelectFor(patientSelectId, episodeSelectId, state = readState()) {
    const patientId = $('#' + patientSelectId)?.value || '';
    const select = $('#' + episodeSelectId);
    if (!select) return;
    const current = select.value;
    const episodes = episodesForPatient(state, patientId);
    select.innerHTML = option('', 'episode 선택 안 함') + episodes.map(e => option(e.id, episodeDisplayLabel(e))).join('');
    if ([...select.options].some(o => o.value === current)) select.value = current;
    else if (episodes[0]) select.value = episodes[0].id;
  }

  function renderEpisodeSelects(state = readState()) {
    renderEpisodeSelectFor('microPatientSelect', 'microEpisodeSelect', state);
    renderEpisodeSelectFor('labPatientSelect', 'labEpisodeSelect', state);
  }

  function clinicalNumberOrBlank(id) {
    const raw = ($('#' + id)?.value || '').trim();
    if (raw === '') return '';
    const n = Number(raw);
    return Number.isFinite(n) ? n : NaN;
  }

  function setClinicalValue(id, value) {
    const el = $('#' + id);
    if (el) el.value = value ?? '';
  }

  function collectFields(fieldPairs) {
    const out = {};
    fieldPairs.forEach(([id, key]) => {
      const el = $('#' + id);
      if (!el) return;
      const value = el.tagName === 'SELECT' || el.type === 'date' || el.type === 'datetime-local' ? (el.value || '') : clinicalNumberOrBlank(id);
      out[key] = value;
    });
    return out;
  }

  function fillFields(fieldPairs, values = {}) {
    fieldPairs.forEach(([id, key]) => setClinicalValue(id, values?.[key] ?? ''));
  }

  function clearEpisodeMeasurementForm() {
    setClinicalValue('preEcmoCheckDateTime', '');
    fillFields(PRE_VENT_FLOW_VITAL_FIELDS, {});
    fillFields(PRE_ABGA_FIELDS, {});
    fillFields(PRE_LAB_FIELDS, {});
    setClinicalValue('beforeGcsDateTime', '');
    setClinicalValue('beforeGcsPumpFlow', '');
    DURING_ECMO_TIMEPOINTS.forEach(tp => {
      setClinicalValue(`${tp.prefix}DateTime`, '');
      setClinicalValue(`${tp.prefix}PumpFlow`, '');
      fillFields(DURING_PUMP_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), {});
      fillFields(DURING_ABGA_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), {});
      fillFields(DURING_VENT_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), {});
      fillFields(DURING_HEMO_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), {});
    });
    fillFields(VENT_END_FIELDS, {});
    setClinicalValue('newVentModeName', '');
  }

  function collectEpisodeMeasurements() {
    const measurements = {
      preEcmo: {
        checkDateTime: $('#preEcmoCheckDateTime')?.value || '',
        vitalVentFlow: collectFields(PRE_VENT_FLOW_VITAL_FIELDS),
        abga: collectFields(PRE_ABGA_FIELDS),
        labs: collectFields(PRE_LAB_FIELDS)
      },
      duringEcmo: {
        beforeGcs: {
          label: 'GCS 전',
          checkDateTime: $('#beforeGcsDateTime')?.value || '',
          pumpFlow: clinicalNumberOrBlank('beforeGcsPumpFlow')
        }
      },
      ventEnd: collectFields(VENT_END_FIELDS)
    };
    DURING_ECMO_TIMEPOINTS.forEach(tp => {
      const pump = collectFields(DURING_PUMP_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]));
      pump.Flow = clinicalNumberOrBlank(`${tp.prefix}PumpFlow`);
      measurements.duringEcmo[tp.key] = {
        label: tp.label,
        checkDateTime: $(`#${tp.prefix}DateTime`)?.value || '',
        pumpFlow: pump.Flow,
        pump,
        abga: collectFields(DURING_ABGA_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key])),
        vent: collectFields(DURING_VENT_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key])),
        hemodynamics: collectFields(DURING_HEMO_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]))
      };
    });
    return measurements;
  }

  function legacyPreEcmoVitalVentFlow(episode) {
    const legacy = (episode?.timeEvents || []).find(event => /(^|\s)(pre[- ]?ecmo|ecmo 전|baseline)(\s|$)/i.test(String(event?.name || '')));
    if (!legacy) return {};
    return {
      Vent: legacy.vent || '', Mode: legacy.mode || '', FiO2: legacy.fio2 ?? '', RR: legacy.rr ?? '', PEEP: legacy.peep ?? '',
      'Flow rate': legacy.flowRate ?? '', O2: legacy.o2 ?? '', 'O2 Unit': legacy.o2Unit || '',
      SBP: legacy.sbp ?? '', DBP: legacy.dbp ?? '', 'Mean BP': legacy.meanBp ?? '', PR: legacy.pr ?? ''
    };
  }

  function fillEpisodeMeasurementForm(episode) {
    if (!episode) return clearEpisodeMeasurementForm();
    const m = episode.measurements || {};
    setClinicalValue('preEcmoCheckDateTime', m.preEcmo?.checkDateTime || '');
    fillFields(PRE_VENT_FLOW_VITAL_FIELDS, m.preEcmo?.vitalVentFlow || legacyPreEcmoVitalVentFlow(episode));
    fillFields(PRE_ABGA_FIELDS, m.preEcmo?.abga || {});
    fillFields(PRE_LAB_FIELDS, m.preEcmo?.labs || {});
    const beforeGcs = m.duringEcmo?.beforeGcs || {};
    setClinicalValue('beforeGcsDateTime', beforeGcs.checkDateTime || '');
    setClinicalValue('beforeGcsPumpFlow', beforeGcs.pumpFlow ?? beforeGcs.pump?.Flow ?? '');
    DURING_ECMO_TIMEPOINTS.forEach(tp => {
      const section = m.duringEcmo?.[tp.key] || {};
      const pump = section.pump || {};
      setClinicalValue(`${tp.prefix}DateTime`, section.checkDateTime || '');
      setClinicalValue(`${tp.prefix}PumpFlow`, pump.Flow ?? section.pumpFlow ?? '');
      fillFields(DURING_PUMP_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), pump);
      fillFields(DURING_ABGA_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), section.abga || {});
      fillFields(DURING_VENT_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), section.vent || {});
      fillFields(DURING_HEMO_SUFFIXES.map(([suffix, key]) => [`${tp.prefix}${suffix}`, key]), section.hemodynamics || {});
    });
    fillFields(VENT_END_FIELDS, m.ventEnd || {});
  }

  function clearEpisodeEventForm() {
    EPISODE_EVENT_FIELDS.forEach(f => { const el = $('#' + f.id); if (el) el.value = ''; });
    const alive = $('#dischargeAlive');
    if (alive) alive.value = '';
    const note = $('#episodeNote');
    if (note) note.value = '';
    const label = $('#activeEpisodeLabel');
    if (label) label.value = '';
    clearEpisodeMeasurementForm();
    if (typeof clearEpisodeAugmentedForm === 'function') clearEpisodeAugmentedForm();
  }

  function fillEpisodeEventForm(episode) {
    if (!episode) return clearEpisodeEventForm();
    const events = episode.events || {};
    EPISODE_EVENT_FIELDS.forEach(f => { const el = $('#' + f.id); if (el) el.value = events[f.key] || ''; });
    const alive = $('#dischargeAlive');
    if (alive) alive.value = episode.dischargeAlive || '';
    const note = $('#episodeNote');
    if (note) note.value = episode.note || '';
    const label = $('#activeEpisodeLabel');
    if (label) label.value = episodeDisplayLabel(episode);
    fillEpisodeMeasurementForm(episode);
    if (typeof fillEpisodeAugmentedForm === 'function') fillEpisodeAugmentedForm(episode);
  }

  function addEcmoEpisode() {
    ensureClinicalCollections();
    const patientId = $('#episodePatientSelect')?.value || '';
    if (!patientId) return toast('episode를 추가할 환자를 먼저 선택하세요.', 'yellow');
    const stateBefore = readState();
    const count = episodesForPatient(stateBefore, patientId).length + 1;
    let newEpisodeId = '';
    const state = patchState(s => {
      seedClinicalCollections(s);
      const patient = patientById(s, patientId);
      const episode = {
        id: uid('ECMO'),
        patientId,
        patientLabel: patientDisplayLabel(patient),
        sequence: count,
        label: `${count}차 ECMO`,
        events: {},
        measurements: {},
        dischargeAlive: '',
        note: '',
        createdAt: nowText(),
        updatedAt: nowText(),
        createdBy: USER
      };
      s.ecmoEpisodes.push(episode);
      newEpisodeId = episode.id;
    });
    activeEpisodeId = newEpisodeId;
    renderClinicalEntry(state);
    addAudit('ecmo episode add', 'episode', `${patientDisplayLabel(patientById(stateBefore, patientId))} ${count}차 ECMO`);
    toast(`${count}차 ECMO episode를 추가했습니다.`);
  }

  function renderEpisodeTabs(state = readState()) {
    const wrap = $('#episodeTabs');
    if (!wrap) return;
    const patientId = $('#episodePatientSelect')?.value || '';
    const episodes = episodesForPatient(state, patientId);
    if (!patientId) {
      wrap.innerHTML = '<span class="badge gray">환자를 선택하세요.</span>';
      clearEpisodeEventForm();
      return;
    }
    if (!episodes.length) {
      wrap.innerHTML = '<span class="badge gray">아직 episode가 없습니다. + 버튼으로 1차 ECMO를 추가하세요.</span>';
      activeEpisodeId = null;
      clearEpisodeEventForm();
      return;
    }
    if (!episodes.some(e => e.id === activeEpisodeId)) activeEpisodeId = episodes[0].id;
    wrap.innerHTML = episodes.map(e => `<button class="btn ${e.id === activeEpisodeId ? 'teal' : 'secondary'}" type="button" data-episode-tab="${escapeHtml(e.id)}">${escapeHtml(episodeDisplayLabel(e))}</button>`).join('');
    $$('[data-episode-tab]', wrap).forEach(btn => btn.addEventListener('click', () => {
      activeEpisodeId = btn.dataset.episodeTab;
      renderEpisodeWorkspace(readState());
    }));
    fillEpisodeEventForm(episodeById(state, activeEpisodeId));
    [['microPatientSelect', 'microEpisodeSelect'], ['labPatientSelect', 'labEpisodeSelect']].forEach(([patientSelectId, episodeSelectId]) => {
      const pSelect = $('#' + patientSelectId);
      const eSelect = $('#' + episodeSelectId);
      if (pSelect && eSelect && pSelect.value === patientId && activeEpisodeId && [...eSelect.options].some(o => o.value === activeEpisodeId)) {
        eSelect.value = activeEpisodeId;
      }
    });
  }

  function saveEpisodeEvents() {
    ensureClinicalCollections();
    if (!activeEpisodeId) return toast('저장할 ECMO episode를 먼저 추가하거나 선택하세요.', 'yellow');
    const events = {};
    EPISODE_EVENT_FIELDS.forEach(f => { events[f.key] = $('#' + f.id)?.value || ''; });
    const dischargeAlive = $('#dischargeAlive')?.value || '';
    const note = ($('#episodeNote')?.value || '').trim();
    const state = patchState(s => {
      seedClinicalCollections(s);
      const ep = episodeById(s, activeEpisodeId);
      if (!ep) return;
      ep.events = events;
      ep.dischargeAlive = dischargeAlive;
      ep.note = note;
      ep.updatedAt = nowText();
    });
    renderClinicalEntry(state);
    addAudit('ecmo episode update', 'episode', episodeDisplayLabel(episodeById(state, activeEpisodeId)));
    toast('현재 episode의 시간 이벤트를 저장했습니다.');
  }

  function saveEpisodeMeasurements() {
    ensureClinicalCollections();
    if (!activeEpisodeId) return toast('검사/vent/hemodynamics를 저장할 ECMO episode를 먼저 추가하거나 선택하세요.', 'yellow');
    const measurements = collectEpisodeMeasurements();
    if (typeof collectExtendedTests === 'function') measurements.preEcmo.extendedTests = collectExtendedTests();
    const enhancedDetails = typeof collectEpisodeDetails === 'function' ? collectEpisodeDetails() : {};
    const enhancedTimeEvents = typeof collectMajorEvents === 'function' ? collectMajorEvents() : [];
    const allNums = [];
    function crawl(obj) {
      Object.values(obj || {}).forEach(v => {
        if (Number.isNaN(v)) allNums.push(v);
        else if (v && typeof v === 'object') crawl(v);
      });
    }
    crawl(measurements);
    if (allNums.length) return toast('검사값과 flow, vent, hemodynamics 항목은 숫자로 입력하세요.', 'yellow');
    const state = patchState(s => {
      seedClinicalCollections(s);
      const ep = episodeById(s, activeEpisodeId);
      if (!ep) return;
      ep.measurements = measurements;
      ep.details = enhancedDetails;
      ep.timeEvents = enhancedTimeEvents;
      ep.updatedAt = nowText();
    });
    renderClinicalEntry(state);
    addAudit('ecmo episode measurement update', 'episode', episodeDisplayLabel(episodeById(state, activeEpisodeId)));
    toast('현재 episode의 Pre-ECMO 상태·검사/4h/24h/vent 종료 정보를 저장했습니다.');
  }

  function renderVentModeSelects(state = readState()) {
    const modes = [...(state.ventModeTags || [])].sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'ko'));
    $$('[data-vent-mode-select]').forEach(select => {
      const current = select.value;
      select.innerHTML = option('', '선택 안 함') + modes.map(m => option(m.name, m.name)).join('');
      if ([...select.options].some(o => o.value === current)) select.value = current;
    });
  }

  function addVentModeTag() {
    ensureClinicalCollections();
    const input = $('#newVentModeName');
    const name = String(input?.value || '').trim();
    if (!name) return toast('추가할 vent mode를 입력하세요.', 'yellow');
    const state = patchState(s => {
      seedClinicalCollections(s);
      const exists = (s.ventModeTags || []).some(v => String(v.name || '').trim().toLowerCase() === name.toLowerCase());
      if (!exists) s.ventModeTags.push({ id: uid('VENT'), name, type: 'vent_mode', source: 'user', createdAt: nowText() });
    });
    if (input) input.value = '';
    renderVentModeSelects(state);
    addAudit('vent mode add', 'clinical vocab', name);
    toast('Vent mode를 드롭다운에 추가했습니다.');
  }

  function deleteActiveEpisode() {
    if (!activeEpisodeId) return toast('삭제할 episode가 없습니다.', 'yellow');
    if (!confirm('현재 ECMO episode와 연결된 검사 기록의 episode 연결을 해제할까요? 환자 master는 삭제되지 않습니다.')) return;
    const deletedId = activeEpisodeId;
    const state = patchState(s => {
      s.ecmoEpisodes = (s.ecmoEpisodes || []).filter(e => e.id !== deletedId);
      (s.microbiologyRecords || []).forEach(r => { if (r.episodeId === deletedId) r.episodeId = ''; });
      (s.labRecords || []).forEach(r => { if (r.episodeId === deletedId) r.episodeId = ''; });
    });
    activeEpisodeId = null;
    renderClinicalEntry(state);
    toast('episode를 삭제하고 검사 기록 연결을 해제했습니다.');
  }

  function parseEventDate(value) {
    if (!value) return null;
    const normalized = String(value).includes('T') ? value : `${value}T12:00`;
    const d = new Date(normalized);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  function formatEventDate(value) {
    if (!value) return '-';
    return String(value).replace('T', ' ');
  }

  function renderEpisodeTimeline(state = readState()) {
    const wrap = $('#episodeTimeline');
    if (!wrap) return;
    const patientId = $('#episodePatientSelect')?.value || '';
    const episodes = episodesForPatient(state, patientId);
    if (!patientId) {
      wrap.innerHTML = '<div class="empty-row"><strong>환자를 선택하면 episode 타임라인이 표시됩니다.</strong></div>';
      return;
    }
    if (!episodes.length) {
      wrap.innerHTML = '<div class="empty-row"><strong>episode를 추가하면 타임라인이 표시됩니다.</strong><br><span>+ ECMO episode 추가 버튼을 누르세요.</span></div>';
      return;
    }

    const points = [];
    episodes.forEach(ep => {
      const events = ep.events || {};
      EPISODE_EVENT_FIELDS.forEach(f => {
        const date = parseEventDate(events[f.key]);
        if (date) points.push({ episode: ep, field: f, date, value: events[f.key] });
      });
    });
    if (!points.length) {
      wrap.innerHTML = `<div class="empty-row"><strong>저장된 날짜 이벤트가 없습니다.</strong><br><span>ECMO start, intubation, discharge, death 등 날짜를 저장하면 2D timeline이 표시됩니다.</span></div>`;
      return;
    }
    let min = Math.min(...points.map(p => p.date.getTime()));
    let max = Math.max(...points.map(p => p.date.getTime()));
    if (min === max) {
      min -= 24 * 3600 * 1000;
      max += 24 * 3600 * 1000;
    }
    const span = max - min || 1;
    const leftPct = date => Math.max(1, Math.min(99, ((date.getTime() - min) / span) * 100));
    const legend = EPISODE_EVENT_FIELDS.map(f => `<span class="legend-chip"><span class="dot" style="background:${f.color}"></span>${escapeHtml(f.label)}</span>`).join('');
    const rows = episodes.map(ep => {
      const epPoints = points.filter(p => p.episode.id === ep.id);
      const markers = epPoints.map(p => {
        const left = leftPct(p.date);
        return `<span class="timeline-marker" tabindex="0" style="left:${left}%;background:${p.field.color}" title="${escapeHtml(p.field.label)} · ${escapeHtml(formatEventDate(p.value))}"><b>${escapeHtml(p.field.label)}</b><small>${escapeHtml(formatEventDate(p.value))}</small></span>`;
      }).join('');
      const aliveText = ep.dischargeAlive === 'alive' ? '생존퇴원' : ep.dischargeAlive === 'dead' ? '사망' : ep.dischargeAlive === 'unknown' ? '미상' : '공란';
      return `<div class="timeline-row">
        <div class="timeline-label"><strong>${escapeHtml(episodeDisplayLabel(ep))}</strong><span>${escapeHtml(aliveText)}${ep.note ? ' · ' + escapeHtml(ep.note) : ''}</span></div>
        <div class="timeline-lane"><span class="timeline-rail"></span>${markers || '<span class="timeline-no-marker">저장된 이벤트 없음</span>'}</div>
      </div>`;
    }).join('');
    wrap.innerHTML = `<div class="timeline-scale"><span>${escapeHtml(new Date(min).toISOString().slice(0, 10))}</span><span>${escapeHtml(new Date(max).toISOString().slice(0, 10))}</span></div>${rows}<div class="timeline-legend">${legend}</div>`;
  }

  function renderEpisodeWorkspace(state = readState()) {
    renderEpisodeTabs(state);
    renderEpisodeTimeline(state);
    if (typeof renderEpisodeLinkedData === 'function') renderEpisodeLinkedData(state);
    if (typeof updateEpisodeEditBanner === 'function') updateEpisodeEditBanner(state);
  }

  function renderOrganismSelect(state = readState(), selectedName = '') {
    const select = $('#organismSelect');
    if (!select) return;
    const organisms = [...(state.organismTags || [])]
      .filter(o => normalizeOrganismName(o.name))
      .sort((a, b) => a.name.localeCompare(b.name));
    select.innerHTML = organisms.length
      ? option('', '균주 태그 선택') + organisms.map(o => option(o.name, o.name)).join('')
      : option('', '균주 태그 없음');
    if (selectedName && [...select.options].some(o => o.value === selectedName)) select.value = selectedName;
    const badgeEl = $('#organismCountBadge');
    if (badgeEl) badgeEl.textContent = `균주 태그 ${organisms.length}개`;
  }

  function addOrganismTag() {
    ensureClinicalCollections();
    const input = $('#newOrganismName');
    const name = normalizeOrganismName(input?.value || '');
    if (!name) return toast('추가할 균주 이름을 입력하세요.', 'yellow');
    const state = patchState(s => {
      seedClinicalCollections(s);
      const exists = (s.organismTags || []).some(o => normalizeOrganismName(o.name).toLowerCase() === name.toLowerCase());
      if (!exists) s.organismTags.push({ id: uid('ORG'), name, type: 'organism', source: 'user', createdAt: nowText() });
    });
    if (input) input.value = '';
    renderOrganismSelect(state, name);
    addAudit('organism tag add', 'tag', name);
    toast('균주 태그를 추가했습니다.');
  }

  let editingMicroRecordId = null;
  let pendingMicroDuplicate = null;
  let allowMicroDuplicateOnce = false;

  function microbiologyFormPayload() {
    return {
      patientId: $('#microPatientSelect')?.value || '',
      episodeId: $('#microEpisodeSelect')?.value || '',
      date: $('#microDate')?.value || '',
      specimenSite: $('#microSpecimenSite')?.value || '',
      organismName: $('#organismSelect')?.value || '',
      result: $('#microResult')?.value || '',
      collectionTime: $('#microCollectionTime')?.value || '',
      cultureSet: ($('#microCultureSet')?.value || '').trim(),
      susceptibility: ($('#microSusceptibility')?.value || '').trim(),
      labInstitute: ($('#microLabInstitute')?.value || '').trim()
    };
  }

  function findMicroDuplicate(state, payload) {
    return (state.microbiologyRecords || []).find(r => r.id !== editingMicroRecordId && r.patientId === payload.patientId && r.date === payload.date && String(r.organismName || '').toLowerCase() === String(payload.organismName || '').toLowerCase());
  }

  function showMicroDuplicate(record, payload) {
    pendingMicroDuplicate = { record, payload };
    const box = $('#microDuplicateNotice');
    const text = $('#microDuplicateText');
    if (box) box.hidden = false;
    if (text) text.textContent = `${record.patientLabel || '환자'} · ${record.date} · ${record.organismName}`;
    $('#microDuplicateReasonField')?.setAttribute('hidden', '');
  }

  function hideMicroDuplicate() {
    pendingMicroDuplicate = null;
    const box = $('#microDuplicateNotice');
    if (box) box.hidden = true;
    const reason = $('#microDuplicateReason'); if (reason) reason.value = '';
  }

  function loadMicroRecordToForm(record) {
    if (!record) return;
    editingMicroRecordId = record.id;
    setClinicalValue('microPatientSelect', record.patientId || '');
    renderEpisodeSelects(readState());
    setClinicalValue('microEpisodeSelect', record.episodeId || '');
    setClinicalValue('microDate', record.date || '');
    setClinicalValue('microSpecimenSite', record.specimenSite || '');
    renderOrganismSelect(readState(), record.organismName || '');
    setClinicalValue('microResult', record.result || 'R');
    setClinicalValue('microCollectionTime', record.collectionTime || '');
    setClinicalValue('microCultureSet', record.cultureSet || '');
    setClinicalValue('microSusceptibility', record.susceptibility || '');
    setClinicalValue('microLabInstitute', record.labInstitute || '');
    $('#microSaveBtn').textContent = '미생물검사 변경사항 저장';
    $('#clinical-entry-step')?.scrollIntoView({behavior:'smooth', block:'start'});
  }

  function saveMicrobiologyRecord() {
    ensureClinicalCollections();
    const stateBefore = readState();
    const payload = microbiologyFormPayload();
    if (!payload.patientId) return toast('미생물검사를 연결할 환자를 선택하세요.', 'yellow');
    if (!payload.date) return toast('미생물검사 시행 날짜를 선택하세요.', 'yellow');
    if (!payload.organismName) return toast('균주 태그를 선택하거나 신규 추가하세요.', 'yellow');
    if (!['R', 'U', 'B'].includes(payload.result)) return toast('검사 결과는 R, U, B 중 하나여야 합니다.', 'yellow');
    const duplicate = findMicroDuplicate(stateBefore, payload);
    if (duplicate && !allowMicroDuplicateOnce) {
      showMicroDuplicate(duplicate, payload);
      return toast('동일 환자·날짜·균주 기록이 이미 있습니다.', 'yellow');
    }
    const patient = patientById(stateBefore, payload.patientId);
    const episode = episodeById(stateBefore, payload.episodeId);
    const duplicateReason = allowMicroDuplicateOnce ? ($('#microDuplicateReason')?.value || '').trim() : '';
    if (allowMicroDuplicateOnce && !duplicateReason) return toast('관리자 중복 저장 사유를 입력하세요.', 'yellow');
    const state = patchState(s => {
      seedClinicalCollections(s);
      const base = {
        ...payload,
        episodeLabel: episodeDisplayLabel(episode),
        patientLabel: patientDisplayLabel(patient),
        updatedAt: nowText(), updatedBy: USER,
        duplicateOverride: !!allowMicroDuplicateOnce,
        duplicateReason
      };
      if (editingMicroRecordId) {
        const found = (s.microbiologyRecords || []).find(r => r.id === editingMicroRecordId);
        if (found) Object.assign(found, base);
      } else {
        s.microbiologyRecords.unshift({ id: uid('MIC'), ...base, createdAt: nowText(), createdBy: USER });
      }
    });
    editingMicroRecordId = null; allowMicroDuplicateOnce = false; hideMicroDuplicate();
    ['microCollectionTime','microCultureSet','microSusceptibility','microLabInstitute'].forEach(id=>setClinicalValue(id,''));
    $('#microSaveBtn').textContent = '미생물검사 저장';
    renderClinicalEntry(state);
    addAudit('microbiology save', 'clinical lab', `${patientDisplayLabel(patient)} ${episodeDisplayLabel(episode)} ${payload.organismName} ${payload.result}`);
    toast('미생물검사 기록을 저장했습니다.');
  }

  function renderMicrobiologyRecords(state = readState()) {
    const body = $('#microRecordBody');
    if (!body) return;
    const records = state.microbiologyRecords || [];
    if (!records.length) return setTableEmpty(body, 9, '저장된 미생물검사 기록이 없습니다.', '시행 날짜, 채취부위, 균주 태그, 결과를 저장하세요.');
    body.innerHTML = records.map(r => {
      const patient = patientById(state, r.patientId);
      const episode = episodeById(state, r.episodeId);
      return `<tr data-micro-row="${escapeHtml(r.id)}">
        <td>${escapeHtml(patient ? patientDisplayLabel(patient) : r.patientLabel || '-')}</td>
        <td>${escapeHtml(episode ? episodeDisplayLabel(episode) : r.episodeLabel || '-')}</td>
        <td>${escapeHtml(r.date || '-')}</td><td>${escapeHtml(r.specimenSite || '-')}</td>
        <td>${escapeHtml([r.collectionTime, r.cultureSet].filter(Boolean).join(' / ') || '-')}</td>
        <td><strong>${escapeHtml(r.organismName || '-')}</strong>${r.duplicateOverride ? '<br>'+badge('중복 승인','yellow') : ''}</td>
        <td>${badge(r.result || '-', r.result === 'R' ? 'red' : r.result === 'B' ? 'yellow' : 'gray')}</td>
        <td>${escapeHtml(r.labInstitute || '-')}</td>
        <td><button class="btn ghost" data-edit-micro="${escapeHtml(r.id)}">수정</button> <button class="btn ghost" data-delete-micro="${escapeHtml(r.id)}">삭제</button></td>
      </tr>`;
    }).join('');
    $$('[data-edit-micro]', body).forEach(btn => btn.addEventListener('click', () => loadMicroRecordToForm(records.find(r=>r.id===btn.dataset.editMicro))));
    $$('[data-delete-micro]', body).forEach(btn => btn.addEventListener('click', () => {
      const state = patchState(s => { s.microbiologyRecords = (s.microbiologyRecords || []).filter(r => r.id !== btn.dataset.deleteMicro); });
      renderClinicalEntry(state); toast('미생물검사 기록을 삭제했습니다.');
    }));
  }

  function asClinicalNumber(id) {
    const raw = ($('#' + id)?.value || '').trim();
    if (raw === '') return '';
    const n = Number(raw);
    return Number.isFinite(n) ? n : NaN;
  }

  function saveLabRecord() {
    ensureClinicalCollections();
    const stateBefore = readState();
    const patientId = $('#labPatientSelect')?.value || '';
    const episodeId = $('#labEpisodeSelect')?.value || '';
    const date = $('#labDate')?.value || '';
    const wbc = asClinicalNumber('labWbc');
    const crp = asClinicalNumber('labCrp');
    const pct = asClinicalNumber('labPct');
    if (!patientId) return toast('진단검사를 연결할 환자를 선택하세요.', 'yellow');
    if (!date) return toast('진단검사 날짜를 선택하세요.', 'yellow');
    if ([wbc, crp, pct].some(v => Number.isNaN(v))) return toast('WBC, CRP, procalcitonin은 숫자로 입력하세요.', 'yellow');
    if (wbc === '' && crp === '' && pct === '') return toast('WBC, CRP, procalcitonin 중 하나 이상 입력하세요.', 'yellow');
    const patient = patientById(stateBefore, patientId);
    const episode = episodeById(stateBefore, episodeId);
    const state = patchState(s => {
      seedClinicalCollections(s);
      s.labRecords.unshift({
        id: uid('LAB'),
        patientId,
        episodeId,
        episodeLabel: episodeDisplayLabel(episode),
        patientLabel: patientDisplayLabel(patient),
        date,
        WBC: wbc,
        CRP: crp,
        procalcitonin: pct,
        createdAt: nowText(),
        createdBy: USER
      });
    });
    ['labWbc', 'labCrp', 'labPct'].forEach(id => { const el = $('#' + id); if (el) el.value = ''; });
    renderClinicalEntry(state);
    addAudit('diagnostic lab save', 'clinical lab', `${patientDisplayLabel(patient)} ${episodeDisplayLabel(episode)}`);
    toast('진단검사 기록을 저장했습니다.');
  }

  function renderLabRecords(state = readState()) {
    const body = $('#labRecordBody');
    if (!body) return;
    const records = state.labRecords || [];
    if (!records.length) return setTableEmpty(body, 7, '저장된 진단검사 기록이 없습니다.', 'WBC, CRP, procalcitonin 값을 입력하세요.');
    const val = v => (v === '' || v === null || v === undefined) ? '-' : String(v);
    body.innerHTML = records.map(r => {
      const patient = patientById(state, r.patientId);
      const episode = episodeById(state, r.episodeId);
      return `<tr>
        <td>${escapeHtml(patient ? patientDisplayLabel(patient) : r.patientLabel || '-')}</td>
        <td>${escapeHtml(episode ? episodeDisplayLabel(episode) : r.episodeLabel || '-')}</td>
        <td>${escapeHtml(r.date || '-')}</td>
        <td>${escapeHtml(val(r.WBC))}</td>
        <td>${escapeHtml(val(r.CRP))}</td>
        <td>${escapeHtml(val(r.procalcitonin))}</td>
        <td><button class="btn ghost" data-delete-lab="${escapeHtml(r.id)}">삭제</button></td>
      </tr>`;
    }).join('');
    $$('[data-delete-lab]', body).forEach(btn => btn.addEventListener('click', () => {
      const state = patchState(s => { s.labRecords = (s.labRecords || []).filter(r => r.id !== btn.dataset.deleteLab); });
      renderClinicalEntry(state);
      toast('진단검사 기록을 삭제했습니다.');
    }));
  }

  function updateClinicalMetrics(state = readState()) {
    const patients = state.patients || [];
    const episodes = state.ecmoEpisodes || [];
    const micro = state.microbiologyRecords || [];
    const labs = state.labRecords || [];
    const baselineSets = patients.filter(p => p.baselineConditions && Object.keys(p.baselineConditions).length).length;
    if ($('#metricPatientCount')) $('#metricPatientCount').textContent = `${patients.length}명`;
    if ($('#metricBaselineCount')) $('#metricBaselineCount').textContent = `${baselineSets}세트`;
    if ($('#metricEpisodeCount')) $('#metricEpisodeCount').textContent = `${episodes.length}개`;
    if ($('#metricClinicalRecordCount')) $('#metricClinicalRecordCount').textContent = `${micro.length + labs.length}건`;
  }


  const BULK_PATIENT_COLUMNS = [
    { key:'initials', label:'환자 이니셜', group:'master', required:true, aliases:['initials','이니셜','환자 initials'] },
    { key:'registrationNo', label:'등록번호', group:'master', required:true, aliases:['등록 번호','patient no','patient number','mrn','병록번호'] },
    { key:'episodeSequence', label:'ECMO 차수', group:'episode', required:true, numeric:true, aliases:['episode','차수','n차'] },
    { key:'ecmoStartTime', label:'ECMO Start Time', group:'episode', aliases:['ecmo start','start time'] },
    { key:'ecmoFinishTime', label:'ECMO Finish Time', group:'episode', aliases:['ecmo finish','finish time'] },
    { key:'intubationStartTime', label:'Intubation Start Time', group:'episode' },
    { key:'admissionDate', label:'Admission date', group:'master', aliases:['addmission date','입원일'] },
    { key:'sex', label:'Gender', group:'master', listId:'bulkGenderList', aliases:['성별','sex'] },
    { key:'birthDate', label:'Birth date', group:'master', aliases:['생년월일','dob','birthday'] },
    { key:'heightCm', label:'Height', group:'master', numeric:true, aliases:['height cm','키'] },
    { key:'weightKg', label:'Weight', group:'master', numeric:true, aliases:['weight kg','체중','몸무게'] },
    { key:'hypertension', label:'고혈압', group:'history', condition:true, aliases:['htn','hypertension'] },
    { key:'diabetes', label:'당뇨', group:'history', condition:true, aliases:['dm','diabetes'] },
    { key:'pulmonaryTb', label:'폐결핵', group:'history', condition:true, aliases:['pulmonary tb','tuberculosis','tb'] },
    { key:'hepatitis', label:'간염', group:'history', condition:true },
    { key:'cancer', label:'암', group:'history', condition:true, aliases:['malignancy'] },
    { key:'operationHistory', label:'수술 기왕력', group:'history', condition:true, aliases:['수술기왕력','operation history','surgery history'] },
    { key:'stroke', label:'뇌졸중', group:'history', condition:true, aliases:['뇌졸증','stroke','cva'] },
    { key:'hyperlipidemia', label:'고지혈증', group:'history', condition:true, aliases:['dyslipidemia'] },
    { key:'padCarotid', label:'말초동맥 및 경동맥질환', group:'history', condition:true, aliases:['pad carotid','pad','carotid disease'] },
    { key:'allergy', label:'알레르기', group:'history', condition:true, aliases:['allergies'] },
    { key:'medication', label:'투약', group:'history', condition:true, aliases:['medications','약물','복용약'] },
    { key:'otherHistory', label:'기타 병력', group:'history', aliases:['기타','other history'] },
    { key:'indication', label:'적응증', group:'episode' },
    { key:'diagnosis', label:'진단명', group:'episode', aliases:['diagnosis'] },
    { key:'department', label:'진료과', group:'episode', aliases:['department'] },
    { key:'location', label:'진료장소', group:'episode', listId:'bulkLocationList', aliases:['시행 장소','location'] },
    { key:'ecmoType', label:'종류', group:'episode', listId:'bulkEcmoTypeList', aliases:['ecmo 종류','type'] },
    { key:'ecmoMode', label:'Mode', group:'episode', listId:'bulkEcmoModeList', aliases:['ecmo mode','모드'] },
    { key:'drainSite', label:'Drain', group:'episode', listId:'bulkDrainList', aliases:['drain site','drain 부위'] },
    { key:'drainCannula', label:'Drain Cannula', group:'episode', aliases:['drain cannula size'] },
    { key:'perfusionSite', label:'Perfusion', group:'episode', listId:'bulkPerfusionList', aliases:['return site','perfusion site'] },
    { key:'returnCannula', label:'Perfusion Cannula', group:'episode', aliases:['return cannula','perfusion cannula size'] },
    { key:'closureMethod', label:'Manual compression', group:'episode', listId:'bulkClosureList', aliases:['closure method','device closure'] }
  ];

  const BULK_CONDITION_KEYS = BULK_PATIENT_COLUMNS.filter(column => column.condition).map(column => column.key);
  let bulkPatientGridReady = false;
  function bulkHeaderToken(value){return String(value||'').toLowerCase().replace(/[\s_()\[\]{}.,·:/\\-]+/g,'');}
  function bulkColumnFromHeader(value){const token=bulkHeaderToken(value);if(!token)return null;return BULK_PATIENT_COLUMNS.find(column=>[column.label,column.key,...(column.aliases||[])].some(alias=>bulkHeaderToken(alias)===token))||null;}
  function bulkEscapeValue(value){return escapeHtml(value===null||value===undefined?'':String(value));}
  function bulkConditionText(patient,key){const item=patient?.baselineConditions?.[key];if(!item)return'';const status=item.status||'미상';return item.note?`${status}: ${item.note}`:status;}
  function bulkPatientToRow(patient,episode){const d=episode?.details||{};const row={initials:patient.initials||patient.patientInitials||'',registrationNo:patient.registrationNo||'',episodeSequence:episode?.sequence||1,ecmoStartTime:episode?.events?.ecmoStartTime||'',ecmoFinishTime:episode?.events?.ecmoFinishTime||'',intubationStartTime:episode?.events?.intubationStartTime||'',admissionDate:patient.admissionDate||patient.addmissionDate||'',sex:patient.sex||patient.gender||'',birthDate:patient.birthDate||'',heightCm:patient.heightCm??patient.height??'',weightKg:patient.weightKg??patient.weight??'',otherHistory:patient.otherHistory||'',indication:d.indication||'',diagnosis:d.diagnosis||'',department:d.department||'',location:d.location||'',ecmoType:d.ecmoType||'',ecmoMode:d.ecmoMode||'',drainSite:d.drainSite||'',drainCannula:d.drainCannula||'',perfusionSite:d.perfusionSite||d.returnSite||'',returnCannula:d.returnCannula||'',closureMethod:d.closureMethod||d.managementMethod||''};BULK_CONDITION_KEYS.forEach(key=>row[key]=bulkConditionText(patient,key));return row;}
  function bulkRowHtml(values={}){const cells=BULK_PATIENT_COLUMNS.map((column,columnIndex)=>{const hint=column.condition?'<span class="bulk-master-condition-hint">없음 / 미상 / 있음: 메모</span>':'';const placeholder=column.required?'필수':column.condition?'미상':'';const list=column.listId?` list="${column.listId}"`:'';const fixed=['initials','registrationNo','episodeSequence'].includes(column.key)?` bulk-fixed-${column.key}`:'';return `<td class="${fixed}"><input class="bulk-master-cell" data-field="${column.key}" data-col-index="${columnIndex}" data-condition="${column.condition?'true':'false'}" value="${bulkEscapeValue(values[column.key]??'')}" placeholder="${placeholder}" aria-label="${bulkEscapeValue(column.label)}"${list}>${hint}</td>`;}).join('');return `<tr data-bulk-patient-row><td class="bulk-row-select"><input type="checkbox" data-bulk-row-check aria-label="행 선택"></td><td class="bulk-row-number"></td><td class="bulk-status-cell"><span class="bulk-row-state is-empty">빈 행</span></td>${cells}</tr>`;}
  function renderBulkPatientHead(){const head=$('#bulkPatientGridHead');if(!head)return;head.innerHTML=`<tr><th class="bulk-row-select-head"><input type="checkbox" id="bulkSelectAllRows" aria-label="전체 행 선택"></th><th class="bulk-row-number-head">연번</th><th class="bulk-status-head">상태</th>${BULK_PATIENT_COLUMNS.map(column=>{const cls=column.group==='history'?'bulk-group-baseline':column.group==='episode'?'bulk-group-episode':'bulk-group-master';const fixed=['initials','registrationNo','episodeSequence'].includes(column.key)?` bulk-fixed-${column.key}`:'';return `<th class="${cls}${fixed}">${escapeHtml(column.label)}${column.required?' *':''}${column.condition?'<span class="bulk-master-condition-hint">상태: 메모</span>':''}</th>`;}).join('')}</tr>`;$('#bulkSelectAllRows')?.addEventListener('change',event=>{$$('[data-bulk-row-check]',$('#bulkPatientGridBody')).forEach(check=>check.checked=event.target.checked);refreshBulkPatientSummary();});}
  function bulkRows(){return $$('[data-bulk-patient-row]',$('#bulkPatientGridBody'));}
  function addBulkPatientRows(count=1,rows=[]){const body=$('#bulkPatientGridBody');if(!body)return;const amount=Math.max(Number(count)||0,rows.length);let html='';for(let index=0;index<amount;index+=1)html+=bulkRowHtml(rows[index]||{});body.insertAdjacentHTML('beforeend',html);renumberBulkPatientRows();refreshBulkPatientRowStates();}
  function renumberBulkPatientRows(){bulkRows().forEach((row,index)=>{row.dataset.rowIndex=String(index);const number=$('.bulk-row-number',row);if(number)number.textContent=String(index+1);$$('[data-col-index]',row).forEach(input=>input.dataset.rowIndex=String(index));});}
  function bulkRowValues(row){const values={};BULK_PATIENT_COLUMNS.forEach(column=>values[column.key]=($(`[data-field="${column.key}"]`,row)?.value||'').trim());return values;}
  function bulkRowHasData(values){return Object.values(values).some(value=>String(value||'').trim()!=='');}
  function normalizeBulkDate(value){const raw=String(value||'').trim();if(!raw)return'';if(/^\d{5}(?:\.\d+)?$/.test(raw)){const serial=Number(raw);if(serial>20000&&serial<80000){const date=new Date(Date.UTC(1899,11,30)+Math.floor(serial)*86400000);return date.toISOString().slice(0,10);}}const match=raw.match(/^(\d{4})[.\/-](\d{1,2})[.\/-](\d{1,2})$/);if(match)return`${match[1]}-${match[2].padStart(2,'0')}-${match[3].padStart(2,'0')}`;const compact=raw.match(/^(\d{4})(\d{2})(\d{2})$/);if(compact)return`${compact[1]}-${compact[2]}-${compact[3]}`;return raw;}
  function normalizeBulkDateTime(value){const raw=String(value||'').trim();if(!raw)return'';if(/^\d{5}(?:\.\d+)?$/.test(raw)){const serial=Number(raw);if(serial>20000&&serial<80000){const millis=Date.UTC(1899,11,30)+serial*86400000;return new Date(millis).toISOString().slice(0,16);}}const normalized=raw.replace(/\./g,'-').replace(/\//g,'-').replace(/\s+/,'T');const m=normalized.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:T(\d{1,2}):(\d{1,2}))?/);if(m)return`${m[1]}-${m[2].padStart(2,'0')}-${m[3].padStart(2,'0')}${m[4]!==undefined?`T${m[4].padStart(2,'0')}:${m[5].padStart(2,'0')}`:''}`;return raw;}
  function normalizeBulkSex(value){const raw=String(value||'').trim().toLowerCase();if(!raw)return'';if(['m','male','남','남자','1'].includes(raw))return'남자';if(['f','female','여','여자','2'].includes(raw))return'여자';return String(value).trim();}
  function parseBulkCondition(value){const raw=String(value||'').trim();if(!raw)return null;const normalized=raw.replace(/^유$/i,'있음').replace(/^무$/i,'없음').replace(/^unknown$/i,'미상').replace(/^yes$/i,'있음').replace(/^no$/i,'없음');const matched=normalized.match(/^(있음|없음|미상)\s*(?:[:|;／/]\s*(.*))?$/i);if(matched)return{status:matched[1],note:(matched[2]||'').trim()};return{status:'있음',note:raw};}
  function bulkEpisodeKey(values){return`${String(values.registrationNo||'').trim()}|${Number(values.episodeSequence)||0}`;}
  function bulkDuplicateEpisodeKeys(){const counts=new Map();bulkRows().forEach(row=>{const values=bulkRowValues(row);if(values.registrationNo&&values.episodeSequence){const key=bulkEpisodeKey(values);counts.set(key,(counts.get(key)||0)+1);}});return new Set([...counts.entries()].filter(([,count])=>count>1).map(([key])=>key));}
  function bulkValidation(values,state,duplicates){if(!bulkRowHasData(values))return{type:'empty',label:'빈 행',detail:''};if(!values.initials)return{type:'error',label:'이니셜 없음',detail:'환자 이니셜은 필수입니다.'};if(!values.registrationNo)return{type:'error',label:'등록번호 없음',detail:'등록번호는 필수입니다.'};const seq=Number(values.episodeSequence);if(!Number.isInteger(seq)||seq<1)return{type:'error',label:'차수 확인',detail:'ECMO 차수는 1 이상의 정수입니다.'};if(duplicates.has(bulkEpisodeKey(values)))return{type:'error',label:'표 안 중복',detail:'같은 등록번호와 ECMO 차수가 두 번 있습니다.'};const badDate=['birthDate','admissionDate'].find(key=>values[key]&&!/^\d{4}-\d{2}-\d{2}$/.test(normalizeBulkDate(values[key])));if(badDate)return{type:'error',label:'날짜 확인',detail:'Birth/Admission date는 YYYY-MM-DD 형식으로 입력하세요.'};const badNumber=['heightCm','weightKg'].find(key=>values[key]&&!Number.isFinite(Number(String(values[key]).replace(/,/g,''))));if(badNumber)return{type:'error',label:'숫자 확인',detail:'Height와 Weight는 숫자로 입력하세요.'};const patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);const episode=patient?episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===seq):null;if(episode)return{type:'existing',label:'기존 차수 수정',detail:`${seq}차 ECMO`,patient,episode};if(patient)return{type:'new',label:'새 차수',detail:`기존 환자에 ${seq}차 ECMO 추가`,patient};return{type:'new',label:'신규',detail:'새 환자와 ECMO 차수 생성'};}
  function refreshBulkPatientRowStates(){const state=readState(),duplicates=bulkDuplicateEpisodeKeys();bulkRows().forEach(row=>{const status=bulkValidation(bulkRowValues(row),state,duplicates),badgeEl=$('.bulk-row-state',row);if(badgeEl){badgeEl.className=`bulk-row-state is-${status.type}`;badgeEl.textContent=status.label;badgeEl.title=status.detail||'';}row.classList.toggle('is-invalid',status.type==='error');row.classList.toggle('is-existing',status.type==='existing');row.classList.toggle('is-duplicate',status.label==='표 안 중복');});refreshBulkPatientSummary();}
  function refreshBulkPatientSummary(){const rows=bulkRows(),filled=rows.filter(row=>bulkRowHasData(bulkRowValues(row))).length,selected=rows.filter(row=>$('[data-bulk-row-check]',row)?.checked).length,errors=rows.filter(row=>row.classList.contains('is-invalid')).length;const summary=$('#bulkPatientGridSummary');if(summary)summary.textContent=`전체 ${rows.length}행 · 입력 ${filled}개 차수 · 오류 ${errors}행${selected?` · 선택 ${selected}행`:''}`;}
  function ensureBulkPatientRows(requiredCount){const missing=requiredCount-bulkRows().length;if(missing>0)addBulkPatientRows(missing);}
  function setBulkCell(rowIndex,columnIndex,value){ensureBulkPatientRows(rowIndex+1);const row=bulkRows()[rowIndex],input=row?$(`[data-col-index="${columnIndex}"]`,row):null;if(input)input.value=value??'';}
  function parseBulkClipboard(text){return String(text||'').replace(/\r/g,'').split('\n').filter((line,index,array)=>!(index===array.length-1&&line==='')).map(line=>line.split('\t'));}
  function pasteBulkPatientGrid(event,target){const text=event.clipboardData?.getData('text/plain');if(!text||(!text.includes('\t')&&!text.includes('\n')))return;event.preventDefault();const matrix=parseBulkClipboard(text);if(!matrix.length)return;const recognizedHeaders=matrix[0].map(value=>bulkColumnFromHeader(value)),recognizedCount=recognizedHeaders.filter(Boolean).length,hasHeader=recognizedCount>=2&&recognizedHeaders.some(column=>column?.key==='registrationNo');const startRow=Number(target.dataset.rowIndex||0),startColumn=Number(target.dataset.colIndex||0),dataRows=hasHeader?matrix.slice(1):matrix;ensureBulkPatientRows(startRow+dataRows.length);dataRows.forEach((values,rowOffset)=>values.forEach((value,sourceColumnIndex)=>{const destinationColumn=hasHeader?BULK_PATIENT_COLUMNS.findIndex(column=>column.key===recognizedHeaders[sourceColumnIndex]?.key):startColumn+sourceColumnIndex;if(destinationColumn>=0&&destinationColumn<BULK_PATIENT_COLUMNS.length)setBulkCell(startRow+rowOffset,destinationColumn,value);}));renumberBulkPatientRows();refreshBulkPatientRowStates();$(`[data-col-index="${startColumn}"]`,bulkRows()[startRow])?.focus();const result=$('#bulkPatientSaveResult');if(result){result.className='bulk-save-result';result.textContent=`${dataRows.length}개 ECMO 차수 행을 붙여넣었습니다${hasHeader?' · 열 제목 자동 인식':''}.`;}}
  function moveBulkGridFocus(target,rowDelta,columnDelta){let rowIndex=Number(target.dataset.rowIndex||0)+rowDelta,columnIndex=Number(target.dataset.colIndex||0)+columnDelta;if(columnIndex>=BULK_PATIENT_COLUMNS.length){rowIndex+=1;columnIndex=0;}if(columnIndex<0){rowIndex-=1;columnIndex=BULK_PATIENT_COLUMNS.length-1;}if(rowIndex<0)rowIndex=0;ensureBulkPatientRows(rowIndex+1);$(`[data-col-index="${columnIndex}"]`,bulkRows()[rowIndex])?.focus();}
  function handleBulkGridKeydown(event){const target=event.target.closest('.bulk-master-cell');if(!target)return;if(event.key==='Enter'){event.preventDefault();moveBulkGridFocus(target,event.shiftKey?-1:1,0);}else if(event.key==='Tab'){event.preventDefault();moveBulkGridFocus(target,0,event.shiftKey?-1:1);}else if(event.key==='ArrowDown'&&!event.altKey){event.preventDefault();moveBulkGridFocus(target,1,0);}else if(event.key==='ArrowUp'&&!event.altKey){event.preventDefault();moveBulkGridFocus(target,-1,0);}}
  function clearBulkPatientGrid(confirmNeeded=true){const hasInput=bulkRows().some(row=>bulkRowHasData(bulkRowValues(row)));if(confirmNeeded&&hasInput&&!confirm('현재 입력표의 내용을 모두 비울까요? 저장된 자료는 삭제되지 않습니다.'))return;const body=$('#bulkPatientGridBody');if(body)body.innerHTML='';addBulkPatientRows(10);const selectAll=$('#bulkSelectAllRows');if(selectAll)selectAll.checked=false;const result=$('#bulkPatientSaveResult');if(result)result.textContent='';}
  function deleteSelectedBulkPatientRows(){const selected=bulkRows().filter(row=>$('[data-bulk-row-check]',row)?.checked);if(!selected.length)return toast('삭제할 행을 선택하세요.','gray');selected.forEach(row=>row.remove());if(bulkRows().length<5)addBulkPatientRows(10-bulkRows().length);renumberBulkPatientRows();refreshBulkPatientRowStates();const selectAll=$('#bulkSelectAllRows');if(selectAll)selectAll.checked=false;}
  function loadPatientsIntoBulkGrid(){const state=readState();if(!(state.patients||[]).length)return toast('불러올 기존 환자가 없습니다.','gray');if(bulkRows().some(row=>bulkRowHasData(bulkRowValues(row)))&&!confirm('현재 입력표를 비우고 저장 자료를 불러올까요?'))return;const rows=[];(state.patients||[]).slice().sort((a,b)=>String(a.registrationNo||'').localeCompare(String(b.registrationNo||''),'ko-KR',{numeric:true})).forEach(patient=>{const eps=episodesForPatient(state,patient.id);if(eps.length)eps.forEach(ep=>rows.push(bulkPatientToRow(patient,ep)));else rows.push(bulkPatientToRow(patient,{sequence:1,events:{},details:{}}));});const body=$('#bulkPatientGridBody');if(body)body.innerHTML='';addBulkPatientRows(rows.length,rows);refreshBulkPatientRowStates();$('#bulkPatientGridScroll')?.scrollTo({top:0,left:0});const result=$('#bulkPatientSaveResult');if(result){result.className='bulk-save-result';result.textContent=`저장된 환자·ECMO 차수 ${rows.length}행을 불러왔습니다.`;}}
  function bulkHeadersText(){return BULK_PATIENT_COLUMNS.map(column=>column.label).join('\t');}
  async function copyBulkPatientHeaders(){try{await navigator.clipboard.writeText(bulkHeadersText());}catch(error){const area=document.createElement('textarea');area.value=bulkHeadersText();document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();}toast('Patient Master 열 제목을 복사했습니다.');}
  function downloadBulkPatientTemplate(){const anchor=document.createElement('a');anchor.href='templates/EXCITE_clinical_workbook_template.xlsx';anchor.download=`EXCITE_clinical_workbook_template_${todayIsoDate().replaceAll('-','')}.xlsx`;document.body.appendChild(anchor);anchor.click();anchor.remove();toast('5개 시트가 포함된 임상자료 Excel 템플릿을 저장했습니다.');}
  function keepText(value,old=''){return value===''?(old??''):String(value).trim();}
  function keepNumber(value,old=''){return value===''?(old??''):numberOrBlank(value);}
  function saveBulkPatientMasters(){ensureClinicalCollections();const stateBefore=readState(),duplicates=bulkDuplicateEpisodeKeys(),entries=bulkRows().map(row=>({row,values:bulkRowValues(row)})).filter(entry=>bulkRowHasData(entry.values));if(!entries.length)return toast('저장할 행을 입력하세요.','gray');const valid=[];let invalid=0;entries.forEach(entry=>{const check=bulkValidation(entry.values,stateBefore,duplicates);if(check.type==='error')invalid+=1;else valid.push(entry);});if(!valid.length){refreshBulkPatientRowStates();return toast('저장 가능한 행이 없습니다. 오류를 확인하세요.','yellow');}let newPatients=0,newEpisodes=0,updatedEpisodes=0;const next=patchState(state=>{seedClinicalCollections(state);valid.forEach(({values})=>{let patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);if(!patient){patient={id:uid('PAT'),registrationNo:values.registrationNo,initials:String(values.initials||'').trim().toUpperCase(),sex:'',birthDate:'',admissionDate:'',heightCm:'',weightKg:'',baselineConditions:{},createdAt:nowText(),updatedAt:nowText()};state.patients.unshift(patient);newPatients+=1;}patient.initials=String(values.initials||patient.initials||'').trim().toUpperCase();if(values.sex!=='')patient.sex=normalizeBulkSex(values.sex);if(values.birthDate!=='')patient.birthDate=normalizeBulkDate(values.birthDate);if(values.admissionDate!=='')patient.admissionDate=normalizeBulkDate(values.admissionDate);if(values.heightCm!=='')patient.heightCm=String(values.heightCm).replace(/,/g,'');if(values.weightKg!=='')patient.weightKg=String(values.weightKg).replace(/,/g,'');if(values.otherHistory!=='')patient.otherHistory=values.otherHistory;patient.baselineConditions=patient.baselineConditions||{};BULK_CONDITION_KEYS.forEach(key=>{const parsed=parseBulkCondition(values[key]);if(parsed)patient.baselineConditions[key]={label:CLINICAL_CONDITIONS.find(item=>item.key===key)?.label||key,...parsed};});delete patient.nameStored;delete patient.pseudoId;const seq=Number(values.episodeSequence),existing=episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===seq),ep=ensureEpisodeForSequence(state,patient,seq);if(existing)updatedEpisodes+=1;else newEpisodes+=1;ep.events.ecmoStartTime=keepText(values.ecmoStartTime,ep.events.ecmoStartTime);ep.events.ecmoFinishTime=keepText(values.ecmoFinishTime,ep.events.ecmoFinishTime);ep.events.intubationStartTime=keepText(values.intubationStartTime,ep.events.intubationStartTime);const fields=['indication','diagnosis','department','location','ecmoType','ecmoMode','drainSite','drainCannula','perfusionSite','returnCannula','closureMethod'];fields.forEach(key=>{if(values[key]!=='')ep.details[key]=values[key];});if(values.perfusionSite!=='')ep.details.returnSite=values.perfusionSite;if(values.closureMethod!=='')ep.details.managementMethod=values.closureMethod;ep.patientLabel=patientDisplayLabel(patient);ep.updatedAt=nowText();patient.updatedAt=nowText();});});valid.forEach(entry=>entry.row.remove());if(bulkRows().length<10)addBulkPatientRows(10-bulkRows().length);renumberBulkPatientRows();renderClinicalEntry(next);refreshBulkPatientRowStates();const result=$('#bulkPatientSaveResult');if(result){result.className=`bulk-save-result${invalid?' is-error':''}`;result.textContent=`저장 완료 · 신규 환자 ${newPatients}명 · 새 ECMO 차수 ${newEpisodes}개 · 수정 ${updatedEpisodes}개${invalid?` · 오류 ${invalid}행 제외`:''}`;}addAudit('bulk patient episode master save','patient',`신규 환자 ${newPatients} · 새 차수 ${newEpisodes} · 수정 ${updatedEpisodes}`);toast(`Patient Master ${valid.length}행을 저장했습니다.${invalid?` 오류 ${invalid}행은 표에 남았습니다.`:''}`,invalid?'yellow':'teal');}
  function initBulkPatientMasterGrid(){if(bulkPatientGridReady||!$('#bulkPatientGrid'))return;bulkPatientGridReady=true;renderBulkPatientHead();addBulkPatientRows(10);const body=$('#bulkPatientGridBody');body?.addEventListener('paste',event=>{const target=event.target.closest('.bulk-master-cell');if(target)pasteBulkPatientGrid(event,target);});body?.addEventListener('keydown',handleBulkGridKeydown);body?.addEventListener('input',event=>{if(event.target.closest('.bulk-master-cell'))refreshBulkPatientRowStates();});body?.addEventListener('change',event=>{if(event.target.matches('[data-bulk-row-check]'))refreshBulkPatientSummary();});$('#bulkAdd10RowsBtn')?.addEventListener('click',()=>addBulkPatientRows(10));$('#bulkLoadPatientsBtn')?.addEventListener('click',loadPatientsIntoBulkGrid);$('#bulkDeleteRowsBtn')?.addEventListener('click',deleteSelectedBulkPatientRows);$('#bulkClearRowsBtn')?.addEventListener('click',()=>clearBulkPatientGrid(true));$('#bulkCopyHeaderBtn')?.addEventListener('click',copyBulkPatientHeaders);$('#bulkDownloadTemplateBtn')?.addEventListener('click',downloadBulkPatientTemplate);$('#bulkSavePatientsBtn')?.addEventListener('click',saveBulkPatientMasters);refreshBulkPatientRowStates();}

  const IDENTIFIER_COLUMNS=[
    {key:'registrationNo',label:'Patient 등록번호',required:true,fixed:true,aliases:['등록번호','mrn','병록번호']},
    {key:'initials',label:'환자 이니셜',required:true,fixed:true,aliases:['initials','이니셜']},
    {key:'episodeSequence',label:'ECMO 차수',required:true,fixed:true,numeric:true,aliases:['episode','차수','n차']}
  ];
  const CLINICAL_SHEET_CONFIG={
    pre:{title:'n차 Pre-ECMO',columns:[...IDENTIFIER_COLUMNS,
      {key:'preCheckDateTime',label:'Pre-ECMO 기준 일시'},
      {key:'ph',label:'PH',numeric:true},{key:'pco2',label:'PCO2',numeric:true},{key:'po2',label:'PO2',numeric:true},{key:'hco3',label:'HCO3',numeric:true},{key:'sao2',label:'SaO2',numeric:true},{key:'lactate',label:'Lactate',numeric:true},
      {key:'creatinine',label:'Creatinine',numeric:true},{key:'hgb',label:'Hgb',numeric:true},{key:'plt',label:'Plt',numeric:true},{key:'inr',label:'INR',numeric:true},{key:'aptt',label:'APTT',numeric:true,aliases:['APPT']},{key:'ast',label:'AST',numeric:true},{key:'alt',label:'ALT',numeric:true},{key:'bilirubin',label:'Bilirubin',numeric:true},{key:'albumin',label:'Albumin',numeric:true},{key:'crp',label:'CRP',numeric:true},{key:'esr',label:'ESR',numeric:true},{key:'proBnp',label:'proBNP',numeric:true},{key:'myoglobin',label:'Myoglobin',numeric:true},{key:'ckMb',label:'CK-MB',numeric:true},{key:'troponinI',label:'Troponin I',numeric:true},{key:'troponinT',label:'Troponin T',numeric:true},
      {key:'sbp',label:'SBP',numeric:true},{key:'dbp',label:'DBP',numeric:true},{key:'meanBp',label:'Mean BP',numeric:true},{key:'pr',label:'PR',numeric:true},
      {key:'ventMode',label:'Mode'},{key:'ventFio2',label:'FiO2',numeric:true},{key:'ventRr',label:'RR',numeric:true},{key:'ventPeep',label:'PEEP',numeric:true},{key:'flowRate',label:'Flow rate',numeric:true},{key:'o2',label:'O2',numeric:true}
    ]},
    intra:{title:'n차 Intra-ECMO',columns:[...IDENTIFIER_COLUMNS,
      {key:'pumpFlow',label:'Pump flow',numeric:true},{key:'gcsBefore',label:'GCS (전)',numeric:true},{key:'gcs4h',label:'GCS 4h',numeric:true},{key:'gcs24h',label:'GCS 24h',numeric:true},{key:'rpm24h',label:'RPM (24h)',numeric:true},{key:'fio224h',label:'FiO2 (24h)',numeric:true},{key:'sweepGas24h',label:'Sweep Gas (24h)',numeric:true},
      {key:'postAbga24hDateTime',label:'Post_ABGA_24h'},{key:'ph24h',label:'PH_24h',numeric:true},{key:'pco224h',label:'PCO2_24h',numeric:true},{key:'po224h',label:'PO2_24h',numeric:true},{key:'hco324h',label:'HCO3_24h',numeric:true},{key:'sao224h',label:'SaO2_24h',numeric:true},{key:'lactate24h',label:'Lactate_24h',numeric:true},
      {key:'sbp',label:'SBP',numeric:true},{key:'dbp',label:'DBP',numeric:true},{key:'ventMode',label:'Mode'},{key:'ventFio2',label:'FiO2',numeric:true},{key:'ventRr',label:'RR',numeric:true},{key:'ventPeep',label:'PEEP',numeric:true}
    ]},
    outcome:{title:'n차 Outcome',columns:[...IDENTIFIER_COLUMNS,
      {key:'intubationStartTime',label:'Intubation Start Time'},{key:'extubationDateTime',label:'Extubation date and time'},{key:'dischargeAlive',label:'Discharge alive (1)',listId:'bulkOutcomeList',aliases:['discharge alive']},{key:'icuAdmissionDate',label:'ICU Admission date'},{key:'icuDischargeDateTime',label:'ICU Discharge date and time'},{key:'dischargeDate',label:'Discharge date'},{key:'deathDate',label:'Death date'}
    ]},
    micro:{title:'n차 Microbiology',allowDuplicateEpisode:true,columns:[...IDENTIFIER_COLUMNS,
      {key:'collectionDateTime',label:'채취 일시',required:true},{key:'specimenSite',label:'검체',required:true,listId:'microSpecimenList',aliases:['specimen']},{key:'organismName',label:'균종',required:true,listId:'microOrganismList',aliases:['organism','균주']},{key:'result',label:'결과',listId:'microResultList'},{key:'cultureSet',label:'배양 세트'},{key:'susceptibility',label:'감수성 결과'},{key:'labInstitute',label:'검사기관'},{key:'note',label:'비고'}
    ]}
  };
  function sheetConfig(name){return CLINICAL_SHEET_CONFIG[name];}
  function sheetBody(name){return document.querySelector(`[data-sheet-body="${name}"]`);}
  function sheetRows(name){return $$(`[data-sheet-row="${name}"]`,sheetBody(name));}
  function sheetValues(name,row){const values={};sheetConfig(name).columns.forEach(c=>values[c.key]=($(`[data-sheet-field="${c.key}"]`,row)?.value||'').trim());return values;}
  function sheetHasData(values){return Object.values(values).some(v=>String(v||'').trim());}
  function sheetHeaderToken(value){return String(value||'').toLowerCase().replace(/[\s_()\[\]{}.,·:/\\-]+/g,'');}
  function sheetColumnFromHeader(name,value){const token=sheetHeaderToken(value);return sheetConfig(name).columns.find(c=>[c.label,c.key,...(c.aliases||[])].some(a=>sheetHeaderToken(a)===token))||null;}
  function sheetCellValue(value){return escapeHtml(value===null||value===undefined?'':String(value));}
  function sheetRowHtml(name,values={}){const cells=sheetConfig(name).columns.map((c,i)=>{const list=c.listId?` list="${c.listId}"`:'';const fixed=c.fixed?` clinical-fixed-col clinical-fixed-${c.key}`:'';return `<td class="${fixed}"><input class="bulk-master-cell clinical-sheet-cell" data-sheet-field="${c.key}" data-col-index="${i}" value="${sheetCellValue(values[c.key]??'')}" placeholder="${c.required?'필수':''}" aria-label="${escapeHtml(c.label)}"${list}></td>`;}).join('');return `<tr data-sheet-row="${name}"><td class="bulk-row-select"><input type="checkbox" data-sheet-row-check aria-label="행 선택"></td><td class="bulk-row-number"></td><td class="bulk-status-cell"><span class="bulk-row-state is-empty">빈 행</span></td>${cells}</tr>`;}
  function renderSheetHead(name){const head=document.querySelector(`[data-sheet-head="${name}"]`);if(!head)return;head.innerHTML=`<tr><th class="bulk-row-select-head"><input type="checkbox" data-sheet-select-all="${name}" aria-label="전체 행 선택"></th><th class="bulk-row-number-head">연번</th><th class="bulk-status-head">상태</th>${sheetConfig(name).columns.map(c=>`<th class="bulk-group-master${c.fixed?` clinical-fixed-col clinical-fixed-${c.key}`:''}">${escapeHtml(c.label)}${c.required?' *':''}</th>`).join('')}</tr>`;document.querySelector(`[data-sheet-select-all="${name}"]`)?.addEventListener('change',e=>{sheetRows(name).forEach(r=>{const check=$('[data-sheet-row-check]',r);if(check)check.checked=e.target.checked;});refreshSheetSummary(name);});}
  function renumberSheetRows(name){sheetRows(name).forEach((row,i)=>{row.dataset.rowIndex=String(i);const num=$('.bulk-row-number',row);if(num)num.textContent=String(i+1);$$('[data-col-index]',row).forEach(input=>input.dataset.rowIndex=String(i));});}
  function addSheetRows(name,count=10,rows=[]){const body=sheetBody(name);if(!body)return;const amount=Math.max(Number(count)||0,rows.length);let html='';for(let i=0;i<amount;i++)html+=sheetRowHtml(name,rows[i]||{});body.insertAdjacentHTML('beforeend',html);renumberSheetRows(name);refreshSheetStates(name);}
  function numberOrBlank(value){if(value===''||value===null||value===undefined)return'';const n=Number(String(value).replace(/,/g,''));return Number.isFinite(n)?n:NaN;}
  function normalizeOutcome(value){const raw=String(value||'').trim().toLowerCase();if(!raw)return'';if(['alive','yes','y','생존','생존퇴원','1'].includes(raw))return'alive';if(['dead','no','n','사망','0'].includes(raw))return'dead';if(['unknown','미상'].includes(raw))return'unknown';return String(value).trim();}
  function sheetEpisodeKey(values){return`${String(values.registrationNo||'').trim()}|${Number(values.episodeSequence)||0}`;}
  function duplicateSheetKeys(name){if(sheetConfig(name).allowDuplicateEpisode)return new Set();const counts=new Map();sheetRows(name).forEach(row=>{const values=sheetValues(name,row);if(values.registrationNo&&values.episodeSequence){const key=sheetEpisodeKey(values);counts.set(key,(counts.get(key)||0)+1);}});return new Set([...counts.entries()].filter(([,count])=>count>1).map(([key])=>key));}
  function sheetValidation(name,values,state,duplicates=new Set()){if(!sheetHasData(values))return{type:'empty',label:'빈 행'};if(!values.registrationNo)return{type:'error',label:'등록번호 없음',detail:'등록번호는 필수입니다.'};if(!values.initials)return{type:'error',label:'이니셜 없음',detail:'환자 이니셜은 필수입니다.'};const sequence=Number(values.episodeSequence);if(!Number.isInteger(sequence)||sequence<1)return{type:'error',label:'차수 확인',detail:'ECMO 차수는 1 이상의 정수입니다.'};if(duplicates.has(sheetEpisodeKey(values)))return{type:'error',label:'표 안 중복',detail:'같은 등록번호와 ECMO 차수가 두 번 있습니다.'};const patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);if(!patient)return{type:'error',label:'환자 없음',detail:'Patient Master를 먼저 저장하세요.'};const missing=sheetConfig(name).columns.find(c=>c.required&&!String(values[c.key]||'').trim());if(missing)return{type:'error',label:`${missing.label} 없음`,detail:`${missing.label}은 필수입니다.`};const bad=sheetConfig(name).columns.find(c=>c.numeric&&values[c.key]!==''&&!Number.isFinite(numberOrBlank(values[c.key])));if(bad)return{type:'error',label:'숫자 확인',detail:`${bad.label} 값을 확인하세요.`};const ep=episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===sequence);return ep?{type:'existing',label:'기존 차수 수정',patient,episode:ep}:{type:'new',label:'새 차수 연결',patient};}
  function refreshSheetStates(name){const state=readState(),duplicates=duplicateSheetKeys(name);sheetRows(name).forEach(row=>{const result=sheetValidation(name,sheetValues(name,row),state,duplicates),badgeEl=$('.bulk-row-state',row);if(badgeEl){badgeEl.className=`bulk-row-state is-${result.type}`;badgeEl.textContent=result.label;badgeEl.title=result.detail||'';}row.classList.toggle('is-invalid',result.type==='error');row.classList.toggle('is-existing',result.type==='existing');row.classList.toggle('is-duplicate',result.label==='표 안 중복');});refreshSheetSummary(name);}
  function refreshSheetSummary(name){const rows=sheetRows(name),filled=rows.filter(r=>sheetHasData(sheetValues(name,r))).length,errors=rows.filter(r=>r.classList.contains('is-invalid')).length,selected=rows.filter(r=>$('[data-sheet-row-check]',r)?.checked).length;const el=document.querySelector(`[data-sheet-summary="${name}"]`);if(el)el.textContent=`전체 ${rows.length}행 · 입력 ${filled}행 · 오류 ${errors}행${selected?` · 선택 ${selected}행`:''}`;}
  function ensureSheetRows(name,count){if(sheetRows(name).length<count)addSheetRows(name,count-sheetRows(name).length);}
  function moveSheetFocus(name,target,rowDelta,colDelta){let r=Number(target.dataset.rowIndex)+rowDelta,c=Number(target.dataset.colIndex)+colDelta;if(c>=sheetConfig(name).columns.length){r+=1;c=0;}if(c<0){r-=1;c=sheetConfig(name).columns.length-1;}if(r<0)r=0;ensureSheetRows(name,r+1);$(`[data-col-index="${c}"]`,sheetRows(name)[r])?.focus();}
  function handleSheetKey(name,event){const target=event.target.closest('.clinical-sheet-cell');if(!target)return;if(event.key==='Enter'){event.preventDefault();moveSheetFocus(name,target,event.shiftKey?-1:1,0);}else if(event.key==='Tab'){event.preventDefault();moveSheetFocus(name,target,0,event.shiftKey?-1:1);}else if(event.key==='ArrowDown'){event.preventDefault();moveSheetFocus(name,target,1,0);}else if(event.key==='ArrowUp'){event.preventDefault();moveSheetFocus(name,target,-1,0);}}
  function pasteSheetGrid(name,event,target){const text=event.clipboardData?.getData('text/plain');if(!text)return;event.preventDefault();const matrix=text.replace(/\r/g,'').split('\n').filter((line,i,arr)=>line!==''||i<arr.length-1).map(line=>line.split('\t'));const recognized=matrix[0].map(v=>sheetColumnFromHeader(name,v)),hasHeader=recognized.filter(Boolean).length>=2,data=hasHeader?matrix.slice(1):matrix;const startRow=Number(target.dataset.rowIndex),startCol=Number(target.dataset.colIndex);while(sheetRows(name).length<startRow+data.length)addSheetRows(name,10);data.forEach((values,ri)=>{const row=sheetRows(name)[startRow+ri];values.forEach((value,ci)=>{const column=hasHeader?recognized[ci]:sheetConfig(name).columns[startCol+ci];if(!column)return;const input=$(`[data-sheet-field="${column.key}"]`,row);if(input)input.value=String(value||'').trim();});});refreshSheetStates(name);const result=document.querySelector(`[data-sheet-result="${name}"]`);if(result){result.className='bulk-save-result';result.textContent=`${data.length}개 행을 붙여넣었습니다${hasHeader?' · 열 제목 자동 인식':''}.`;}}
  function clearSheet(name,ask=true){const has=sheetRows(name).some(r=>sheetHasData(sheetValues(name,r)));if(ask&&has&&!confirm('현재 입력표를 모두 비울까요? 저장된 자료는 삭제되지 않습니다.'))return;const body=sheetBody(name);if(body)body.innerHTML='';addSheetRows(name,10);}
  function deleteSheetRows(name){const selected=sheetRows(name).filter(r=>$('[data-sheet-row-check]',r)?.checked);if(!selected.length)return toast('삭제할 행을 선택하세요.','gray');selected.forEach(r=>r.remove());if(sheetRows(name).length<5)addSheetRows(name,10-sheetRows(name).length);renumberSheetRows(name);refreshSheetStates(name);}
  async function copySheetHeaders(name){const text=sheetConfig(name).columns.map(c=>c.label).join('\t');try{await navigator.clipboard.writeText(text);}catch(e){const area=document.createElement('textarea');area.value=text;document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();}toast(`${sheetConfig(name).title} 열 제목을 복사했습니다.`);}
  function ensureEpisodeForSequence(state,patient,sequence){let episode=episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===Number(sequence));if(!episode){episode={id:uid('ECMO'),patientId:patient.id,patientLabel:patientDisplayLabel(patient),sequence:Number(sequence),label:`${Number(sequence)}차 ECMO`,events:{},measurements:{},details:{},dischargeAlive:'',note:'',createdAt:nowText(),updatedAt:nowText(),createdBy:USER};state.ecmoEpisodes.push(episode);}episode.events=episode.events||{};episode.measurements=episode.measurements||{};episode.details=episode.details||{};return episode;}
  function preRowFromEpisode(patient,ep){const m=ep.measurements?.preEcmo||{},v=m.vitalVentFlow||{},a=m.abga||{},l=m.labs||{};return{registrationNo:patient.registrationNo||'',initials:patient.initials||'',episodeSequence:ep.sequence||1,preCheckDateTime:m.checkDateTime||'',ph:a.pH??'',pco2:a.PCO2??'',po2:a.PO2??'',hco3:a.HCO3??'',sao2:a.SaO2??'',lactate:a.Lactate??'',creatinine:l.Creatinine??'',hgb:l.Hgb??'',plt:l.Plt??'',inr:l.INR??'',aptt:l.APTT??l.APPT??'',ast:l.AST??'',alt:l.ALT??'',bilirubin:l.Bilirubin??'',albumin:l.Albumin??'',crp:l.CRP??'',esr:l.ESR??'',proBnp:l.proBNP??'',myoglobin:l.Myoglobin??'',ckMb:l['CK-MB']??'',troponinI:l['Troponin I']??'',troponinT:l['Troponin T']??'',sbp:v.SBP??'',dbp:v.DBP??'',meanBp:v['Mean BP']??'',pr:v.PR??'',ventMode:v.Mode||'',ventFio2:v.FiO2??'',ventRr:v.RR??'',ventPeep:v.PEEP??'',flowRate:v['Flow rate']??'',o2:v.O2??''};}
  function intraRowFromEpisode(patient,ep){const d=ep.measurements?.duringEcmo||{},b=d.beforeGcs||{},f=d.fourHour||{},h=d.twentyFourHour||{},p=h.pump||{},a=h.abga||{},v=h.vent||{},he=h.hemodynamics||{};return{registrationNo:patient.registrationNo||'',initials:patient.initials||'',episodeSequence:ep.sequence||1,pumpFlow:h.pumpFlow??p.Flow??b.pumpFlow??'',gcsBefore:b.gcs??b.GCS??'',gcs4h:f.gcs??f.GCS??'',gcs24h:h.gcs??h.GCS??'',rpm24h:p.RPM??'',fio224h:p.FiO2??'',sweepGas24h:p['Sweep gas']??p.SweepGas??'',postAbga24hDateTime:h.checkDateTime||'',ph24h:a.pH??'',pco224h:a.PCO2??'',po224h:a.PO2??'',hco324h:a.HCO3??'',sao224h:a.SaO2??'',lactate24h:a.Lactate??'',sbp:he.SBP??'',dbp:he.DBP??'',ventMode:v.Mode||'',ventFio2:v.FiO2??'',ventRr:v.RR??'',ventPeep:v.PEEP??''};}
  function outcomeRowFromEpisode(patient,ep){return{registrationNo:patient.registrationNo||'',initials:patient.initials||'',episodeSequence:ep.sequence||1,intubationStartTime:ep.events?.intubationStartTime||'',extubationDateTime:ep.events?.extubationDateTime||'',dischargeAlive:ep.dischargeAlive||'',icuAdmissionDate:ep.events?.icuAdmissionDate||'',icuDischargeDateTime:ep.events?.icuDischargeDateTime||'',dischargeDate:ep.events?.dischargeDate||'',deathDate:ep.events?.deathDate||''};}
  function microRowFromRecord(state,record){const patient=patientById(state,record.patientId),episode=episodeById(state,record.episodeId);return{registrationNo:patient?.registrationNo||'',initials:patient?.initials||'',episodeSequence:episode?.sequence||1,collectionDateTime:record.collectionDateTime||[record.date,record.collectionTime].filter(Boolean).join('T'),specimenSite:record.specimenSite||'',organismName:record.organismName||'',result:record.result||'',cultureSet:record.cultureSet||'',susceptibility:record.susceptibility||'',labInstitute:record.labInstitute||'',note:record.note||''};}
  function loadSheetData(name){const state=readState(),rows=[];if(name==='micro'){(state.microbiologyRecords||[]).forEach(record=>rows.push(microRowFromRecord(state,record)));}else{(state.patients||[]).slice().sort((a,b)=>String(a.registrationNo||'').localeCompare(String(b.registrationNo||''),'ko-KR',{numeric:true})).forEach(patient=>episodesForPatient(state,patient.id).forEach(ep=>{if(name==='pre')rows.push(preRowFromEpisode(patient,ep));if(name==='intra')rows.push(intraRowFromEpisode(patient,ep));if(name==='outcome')rows.push(outcomeRowFromEpisode(patient,ep));}));}if(!rows.length)return toast('불러올 저장 자료가 없습니다.','gray');if(sheetRows(name).some(r=>sheetHasData(sheetValues(name,r)))&&!confirm('현재 입력표를 비우고 저장 자료를 불러올까요?'))return;sheetBody(name).innerHTML='';addSheetRows(name,rows.length,rows);document.querySelector(`[data-sheet-grid="${name}"]`)?.closest('.bulk-master-scroll')?.scrollTo({top:0,left:0});}
  function saveClinicalSheet(name){const stateBefore=readState(),entries=sheetRows(name).map(row=>({row,values:sheetValues(name,row)})).filter(x=>sheetHasData(x.values)),duplicates=duplicateSheetKeys(name);if(!entries.length)return toast('저장할 행을 입력하세요.','gray');let invalid=0,saved=0;const valid=entries.filter(entry=>{const result=sheetValidation(name,entry.values,stateBefore,duplicates);if(result.type==='error'){invalid+=1;return false;}return true;});if(!valid.length){refreshSheetStates(name);return toast('저장 가능한 행이 없습니다. 오류를 확인하세요.','yellow');}const next=patchState(state=>{seedClinicalCollections(state);valid.forEach(({values})=>{const patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);if(!patient)return;patient.initials=String(values.initials||patient.initials||'').trim().toUpperCase();delete patient.nameStored;delete patient.pseudoId;const sequence=Number(values.episodeSequence),ep=ensureEpisodeForSequence(state,patient,sequence);if(name==='pre'){const old=ep.measurements.preEcmo||{},ov=old.vitalVentFlow||{},oa=old.abga||{},ol=old.labs||{};ep.measurements.preEcmo={...old,checkDateTime:keepText(values.preCheckDateTime,old.checkDateTime),vitalVentFlow:{...ov,SBP:keepNumber(values.sbp,ov.SBP),DBP:keepNumber(values.dbp,ov.DBP),'Mean BP':keepNumber(values.meanBp,ov['Mean BP']),PR:keepNumber(values.pr,ov.PR),Mode:keepText(values.ventMode,ov.Mode),FiO2:keepNumber(values.ventFio2,ov.FiO2),RR:keepNumber(values.ventRr,ov.RR),PEEP:keepNumber(values.ventPeep,ov.PEEP),'Flow rate':keepNumber(values.flowRate,ov['Flow rate']),O2:keepNumber(values.o2,ov.O2)},abga:{...oa,pH:keepNumber(values.ph,oa.pH),PCO2:keepNumber(values.pco2,oa.PCO2),PO2:keepNumber(values.po2,oa.PO2),HCO3:keepNumber(values.hco3,oa.HCO3),SaO2:keepNumber(values.sao2,oa.SaO2),Lactate:keepNumber(values.lactate,oa.Lactate)},labs:{...ol,Creatinine:keepNumber(values.creatinine,ol.Creatinine),Hgb:keepNumber(values.hgb,ol.Hgb),Plt:keepNumber(values.plt,ol.Plt),INR:keepNumber(values.inr,ol.INR),APTT:keepNumber(values.aptt,ol.APTT??ol.APPT),AST:keepNumber(values.ast,ol.AST),ALT:keepNumber(values.alt,ol.ALT),Bilirubin:keepNumber(values.bilirubin,ol.Bilirubin),Albumin:keepNumber(values.albumin,ol.Albumin),CRP:keepNumber(values.crp,ol.CRP),ESR:keepNumber(values.esr,ol.ESR),proBNP:keepNumber(values.proBnp,ol.proBNP),Myoglobin:keepNumber(values.myoglobin,ol.Myoglobin),'CK-MB':keepNumber(values.ckMb,ol['CK-MB']),'Troponin I':keepNumber(values.troponinI,ol['Troponin I']),'Troponin T':keepNumber(values.troponinT,ol['Troponin T'])}};}else if(name==='intra'){const old=ep.measurements.duringEcmo||{},before=old.beforeGcs||{},four=old.fourHour||{},h24=old.twentyFourHour||{},pump=h24.pump||{},abga=h24.abga||{},vent=h24.vent||{},hemo=h24.hemodynamics||{};ep.measurements.duringEcmo={...old,beforeGcs:{...before,label:'GCS 전',gcs:keepNumber(values.gcsBefore,before.gcs??before.GCS)},fourHour:{...four,label:'4시간 경과',gcs:keepNumber(values.gcs4h,four.gcs??four.GCS)},twentyFourHour:{...h24,label:'24시간 경과',checkDateTime:keepText(values.postAbga24hDateTime,h24.checkDateTime),gcs:keepNumber(values.gcs24h,h24.gcs??h24.GCS),pumpFlow:keepNumber(values.pumpFlow,h24.pumpFlow??pump.Flow),pump:{...pump,Flow:keepNumber(values.pumpFlow,pump.Flow??h24.pumpFlow),RPM:keepNumber(values.rpm24h,pump.RPM),FiO2:keepNumber(values.fio224h,pump.FiO2),'Sweep gas':keepNumber(values.sweepGas24h,pump['Sweep gas']??pump.SweepGas)},abga:{...abga,pH:keepNumber(values.ph24h,abga.pH),PCO2:keepNumber(values.pco224h,abga.PCO2),PO2:keepNumber(values.po224h,abga.PO2),HCO3:keepNumber(values.hco324h,abga.HCO3),SaO2:keepNumber(values.sao224h,abga.SaO2),Lactate:keepNumber(values.lactate24h,abga.Lactate)},vent:{...vent,Mode:keepText(values.ventMode,vent.Mode),FiO2:keepNumber(values.ventFio2,vent.FiO2),RR:keepNumber(values.ventRr,vent.RR),PEEP:keepNumber(values.ventPeep,vent.PEEP)},hemodynamics:{...hemo,SBP:keepNumber(values.sbp,hemo.SBP),DBP:keepNumber(values.dbp,hemo.DBP)}}};}else if(name==='outcome'){ep.events.intubationStartTime=keepText(values.intubationStartTime,ep.events.intubationStartTime);ep.events.extubationDateTime=keepText(values.extubationDateTime,ep.events.extubationDateTime);ep.events.icuAdmissionDate=keepText(values.icuAdmissionDate,ep.events.icuAdmissionDate);ep.events.icuDischargeDateTime=keepText(values.icuDischargeDateTime,ep.events.icuDischargeDateTime);ep.events.dischargeDate=keepText(values.dischargeDate,ep.events.dischargeDate);ep.events.deathDate=keepText(values.deathDate,ep.events.deathDate);if(values.dischargeAlive!=='')ep.dischargeAlive=normalizeOutcome(values.dischargeAlive);}else if(name==='micro'){const collection=normalizeBulkDateTime(values.collectionDateTime),date=collection.slice(0,10),time=collection.includes('T')?collection.slice(11,16):'';let record=(state.microbiologyRecords||[]).find(r=>r.patientId===patient.id&&r.episodeId===ep.id&&String(r.date||'')===date&&String(r.specimenSite||'')===values.specimenSite&&String(r.organismName||'').toLowerCase()===String(values.organismName||'').toLowerCase());const payload={patientId:patient.id,episodeId:ep.id,patientLabel:patientDisplayLabel(patient),episodeLabel:episodeDisplayLabel(ep),collectionDateTime:collection,date,collectionTime:time,specimenSite:values.specimenSite,organismName:values.organismName,result:values.result,cultureSet:values.cultureSet,susceptibility:values.susceptibility,labInstitute:values.labInstitute,note:values.note,updatedAt:nowText(),updatedBy:USER};if(record)Object.assign(record,payload);else state.microbiologyRecords.unshift({id:uid('MIC'),...payload,createdAt:nowText(),createdBy:USER});if(values.organismName&&!(state.organismTags||[]).some(o=>String(o.name||'').toLowerCase()===values.organismName.toLowerCase()))state.organismTags.push({id:uid('ORG'),name:values.organismName,type:'organism',source:'bulk',createdAt:nowText()});}ep.patientLabel=patientDisplayLabel(patient);ep.updatedAt=nowText();patient.updatedAt=nowText();saved+=1;});});valid.forEach(x=>x.row.remove());if(sheetRows(name).length<10)addSheetRows(name,10-sheetRows(name).length);renumberSheetRows(name);refreshSheetStates(name);renderClinicalEntry(next);const result=document.querySelector(`[data-sheet-result="${name}"]`);if(result){result.className=`bulk-save-result${invalid?' is-error':''}`;result.textContent=`저장 완료 · ${saved}행${invalid?` · 오류 ${invalid}행 제외`:''}`;}addAudit('clinical workbook bulk save',name,`${sheetConfig(name).title} ${saved}행`);toast(`${sheetConfig(name).title} ${saved}행을 저장했습니다.${invalid?` 오류 ${invalid}행은 표에 남았습니다.`:''}`,invalid?'yellow':'teal');}
  function initEpisodeBulkSheets(){Object.keys(CLINICAL_SHEET_CONFIG).forEach(name=>{renderSheetHead(name);addSheetRows(name,10);const body=sheetBody(name);body?.addEventListener('paste',e=>{const target=e.target.closest('.clinical-sheet-cell');if(target)pasteSheetGrid(name,e,target);});body?.addEventListener('keydown',e=>handleSheetKey(name,e));body?.addEventListener('input',e=>{if(e.target.closest('.clinical-sheet-cell'))refreshSheetStates(name);});body?.addEventListener('change',e=>{if(e.target.matches('[data-sheet-row-check]'))refreshSheetSummary(name);});const panel=document.querySelector(`[data-bulk-sheet="${name}"]`);panel?.querySelector('[data-sheet-action="add"]')?.addEventListener('click',()=>addSheetRows(name,10));panel?.querySelector('[data-sheet-action="load"]')?.addEventListener('click',()=>loadSheetData(name));panel?.querySelector('[data-sheet-action="delete"]')?.addEventListener('click',()=>deleteSheetRows(name));panel?.querySelector('[data-sheet-action="clear"]')?.addEventListener('click',()=>clearSheet(name,true));panel?.querySelector('[data-sheet-action="copy-header"]')?.addEventListener('click',()=>copySheetHeaders(name));panel?.querySelector('[data-sheet-action="save"]')?.addEventListener('click',()=>saveClinicalSheet(name));});}
  function activateClinicalSheet(name){const descriptions={master:'ECMO 한 차수를 한 행으로 입력합니다.',pre:'차수별 Pre-ECMO 검사·Vital·Vent 자료입니다.',intra:'차수별 Intra-ECMO 24시간 자료입니다.',outcome:'차수별 Intubation·ICU·퇴원·사망 자료입니다.',micro:'차수별 미생물 결과를 여러 행으로 입력합니다.'};$$('[data-clinical-sheet]').forEach(button=>{const active=button.dataset.clinicalSheet===name;button.classList.toggle('active',active);button.setAttribute('aria-selected',String(active));});$$('[data-clinical-sheet-panel]').forEach(panel=>panel.hidden=panel.dataset.clinicalSheetPanel!==name);if($('#clinicalSheetTitle'))$('#clinicalSheetTitle').textContent=name==='master'?'Patient Master':sheetConfig(name)?.title||'';if($('#clinicalSheetDescription'))$('#clinicalSheetDescription').textContent=descriptions[name]||'';sessionStorage.setItem('excite_clinical_sheet',name);}
  function initClinicalSheetWorkbook(){const initial=sessionStorage.getItem('excite_clinical_sheet')||'master',allowed=['master','pre','intra','outcome','micro'];$$('[data-clinical-sheet]').forEach(button=>button.addEventListener('click',()=>activateClinicalSheet(button.dataset.clinicalSheet)));activateClinicalSheet(allowed.includes(initial)?initial:'master');$('#advancedClinicalToggleBtn')?.addEventListener('click',()=>{const open=document.body.classList.toggle('show-advanced-clinical'),btn=$('#advancedClinicalToggleBtn');if(btn){btn.setAttribute('aria-expanded',String(open));btn.textContent=open?'상세 입력 화면 닫기':'상세 입력 화면 열기';}});}

  function renderClinicalEntry(state = readState()) {
    seedClinicalCollections(state);
    renderClinicalPatients(state);
    renderClinicalPatientSelects(state);
    renderEpisodeSelects(state);
    renderVentModeSelects(state);
    renderEpisodeWorkspace(state);
    renderOrganismSelect(state, $('#organismSelect')?.value || '');
    renderMicrobiologyRecords(state);
    renderLabRecords(state);
    updateClinicalMetrics(state);
    if (typeof CLINICAL_SHEET_CONFIG !== 'undefined') Object.keys(CLINICAL_SHEET_CONFIG).forEach(name => { if (sheetBody(name)) refreshSheetStates(name); });
  }

  function initPatientUpload() {
    const state = ensureClinicalCollections();
    const baselineDate = $('#patientBaselineDate');
    const microDate = $('#microDate');
    const labDate = $('#labDate');
    if (baselineDate && !baselineDate.value) baselineDate.value = todayIsoDate();
    if (microDate && !microDate.value) microDate.value = todayIsoDate();
    if (labDate && !labDate.value) labDate.value = todayIsoDate();

    $('#clinicalPatientSaveBtn')?.addEventListener('click', saveClinicalPatientMaster);
    $('#goEpisodeEntryBtn')?.addEventListener('click', () => { document.body.classList.add('show-advanced-clinical'); const btn = $('#advancedClinicalToggleBtn'); if (btn) { btn.setAttribute('aria-expanded', 'true'); btn.textContent = '상세 입력 화면 닫기'; } $('#episode-entry-step')?.scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('#addEcmoEpisodeBtn')?.addEventListener('click', addEcmoEpisode);
    $('#episodeSaveBtn')?.addEventListener('click', saveEpisodeEvents);
    $('#episodeMeasurementSaveBtn')?.addEventListener('click', saveEpisodeMeasurements);
    $('#episodeDeleteBtn')?.addEventListener('click', deleteActiveEpisode);
    $('#ventModeAddBtn')?.addEventListener('click', addVentModeTag);
    $('#newVentModeName')?.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); addVentModeTag(); } });
    $('#episodePatientSelect')?.addEventListener('change', () => { activeEpisodeId = null; renderEpisodeWorkspace(readState()); renderEpisodeSelects(readState()); });
    $('#microPatientSelect')?.addEventListener('change', () => renderEpisodeSelects(readState()));
    $('#labPatientSelect')?.addEventListener('change', () => renderEpisodeSelects(readState()));
    $('#organismAddBtn')?.addEventListener('click', addOrganismTag);
    $('#newOrganismName')?.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); addOrganismTag(); } });
    $('#microSaveBtn')?.addEventListener('click', saveMicrobiologyRecord);
    $('#labSaveBtn')?.addEventListener('click', saveLabRecord);
    initBulkPatientMasterGrid();
    initEpisodeBulkSheets();
    initClinicalSheetWorkbook();

    renderClinicalEntry(state);
  }


  /* Tree classification, enhanced episode editor, and integrated patient-CSV workspace. */
  const EXTENDED_PRE_ECMO_TESTS = [
    {key:'Creatinine',unit:'mg/dL'},{key:'APTT',unit:'sec'},{key:'ALT',unit:'U/L'},{key:'CRP',unit:'mg/dL'},{key:'ESR',unit:'mm/h'},
    {key:'proBNP',unit:'pg/mL'},{key:'Myoglobin',unit:'ng/mL'},{key:'CK-MB',unit:'ng/mL'},{key:'Troponin I',unit:'ng/mL'},{key:'Troponin T',unit:'ng/mL'}
  ];
  let episodeDraftTimeEvents = [];
  let treeSelectedNodeId = null;
  let treePendingParentId = null;
  let treeDraggedNodeId = null;
  let treeEntitySelection = new Set();
  let treeEntitySearch = '';
  let conditionalSelections = {};
  let integratedSelectedPatientId = null;
  let integratedMatchFileId = null;

  function ensureTagTreesState(state) {
    if (!Array.isArray(state.tagTrees)) state.tagTrees = [];
    if (!state.tagTreeView || typeof state.tagTreeView !== 'object') state.tagTreeView = { showPatients: true, showCsv: true };
    if (typeof state.tagTreeView.showPatients !== 'boolean') state.tagTreeView.showPatients = true;
    if (typeof state.tagTreeView.showCsv !== 'boolean') state.tagTreeView.showCsv = true;
    if (!state.tagTrees.length && (state.tags || []).length) {
      (state.tags || []).forEach(tag => {
        const root = {id:tag.id, tagId:tag.id, parentId:null, name:tag.name, type:'tag', description:tag.description||'', color:normalizeTagColor(tag.color), order:state.tagTrees.length, collapsed:false, createdAt:tag.createdAt||nowText(), updatedAt:tag.updatedAt||nowText()};
        state.tagTrees.push(root);
        (state.axes || []).filter(a=>a.tagId===tag.id).forEach((axis,ai)=>{
          const q={id:axis.id,tagId:tag.id,parentId:root.id,name:axis.name,type:'question',selectionMode:(axis.inputMode||'').includes('여러')?'multiple':'single',order:ai,collapsed:false,createdAt:axis.createdAt||nowText(),updatedAt:nowText()};
          state.tagTrees.push(q);
          (axis.values||[]).forEach((v,vi)=>state.tagTrees.push({id:v.id||uid('TREE'),tagId:tag.id,parentId:q.id,name:v.label,type:'value',order:vi,collapsed:false,createdAt:nowText(),updatedAt:nowText()}));
        });
      });
    }
    return state;
  }

  function treeChildren(state,parentId){return (state.tagTrees||[]).filter(n=>n.parentId===parentId).sort((a,b)=>(a.order||0)-(b.order||0));}
  function treeNode(state,id){return (state.tagTrees||[]).find(n=>n.id===id)||null;}
  function treeRootFor(state,node){let cur=node; while(cur?.parentId) cur=treeNode(state,cur.parentId); return cur?.type==='tag'?cur:null;}
  function treeDescendant(state,ancestorId,nodeId){let cur=treeNode(state,nodeId); while(cur?.parentId){if(cur.parentId===ancestorId)return true;cur=treeNode(state,cur.parentId);}return false;}
  function treeDepth(state,node){let d=0,cur=node;while(cur?.parentId){d++;cur=treeNode(state,cur.parentId);}return d;}
  function normalizeTreeOrders(state,parentId){treeChildren(state,parentId).forEach((n,i)=>n.order=i);}


  function treeRootIdForNode(state,node){return treeRootFor(state,node)?.id||'';}
  function treeSelectionValues(assignment){return Object.values(assignment?.treeSelections||{}).flatMap(v=>Array.isArray(v)?v:[v]).filter(Boolean);}
  function treeAssignmentMatchesNode(state,assignment,node){
    if(!assignment||!node||!Array.isArray(assignment.path))return false;
    const root=treeRootFor(state,node);if(!root||assignment.tagId!==root.id)return false;
    if(node.type==='tag')return true;
    const values=treeSelectionValues(assignment);
    if(node.type==='value')return values.includes(node.id);
    return values.some(valueId=>valueId===node.id||treeDescendant(state,node.id,valueId));
  }
  function treeNodePath(state,node){
    const parts=[];let cur=node;
    while(cur){parts.unshift(cur);cur=cur.parentId?treeNode(state,cur.parentId):null;}
    return parts;
  }
  function treeNodePathText(state,node,includeRoot=true){
    const parts=treeNodePath(state,node).filter((item,index)=>includeRoot||index>0).map(item=>item.name);
    return parts.join(' → ');
  }
  function treeAssignmentForEntity(state,type,id,rootId){
    return (state.assignments||[]).find(a=>a.targetType===type&&a.targetId===id&&a.tagId===rootId&&Array.isArray(a.path))||null;
  }
  function treeNodeEntityCounts(state,node){
    const patientIds=new Set(),csvIds=new Set();
    (state.assignments||[]).filter(a=>treeAssignmentMatchesNode(state,a,node)).forEach(a=>{
      if(a.targetType==='patient')patientIds.add(a.targetId);
      if(a.targetType==='csv')csvIds.add(a.targetId);
    });
    if(node.type==='tag'){
      (state.vitalFiles||[]).filter(file=>(file.tagIds||[]).includes(node.id)).forEach(file=>csvIds.add(file.id));
    }
    return {patients:patientIds.size,csv:csvIds.size};
  }
  function treeValueMoveOptions(state,node){
    const root=treeRootFor(state,node);if(!root)return [];
    return (state.tagTrees||[]).filter(item=>item.type==='value'&&treeRootFor(state,item)?.id===root.id).sort((a,b)=>treeNodePathText(state,a).localeCompare(treeNodePathText(state,b),'ko'));
  }
  function selectionsForTreeValue(state,valueNode){
    const selections={};
    treeNodePath(state,valueNode).forEach(node=>{
      if(node.type!=='value')return;
      const question=treeNode(state,node.parentId);
      if(question?.type==='question')selections[question.id]=question.selectionMode==='multiple'?[node.id]:node.id;
    });
    return selections;
  }
  function moveTreeEntities(entityKeys,targetValueId){
    const currentState=readState();ensureTagTreesState(currentState);
    const target=treeNode(currentState,targetValueId);
    if(!target||target.type!=='value')return toast('환자나 CSV는 “선택할 수 있는 값” 항목으로 이동하세요.','yellow');
    const sourceNode=treeNode(currentState,treeSelectedNodeId);
    const sourceRoot=treeRootFor(currentState,sourceNode),targetRoot=treeRootFor(currentState,target);
    if(sourceRoot&&targetRoot&&sourceRoot.id!==targetRoot.id)return toast('다른 연구 태그로는 바로 이동할 수 없습니다. 같은 연구 태그 안의 하위그룹을 선택하세요.','yellow');
    const valid=(entityKeys||[]).map(key=>{const split=String(key).indexOf(':');return split>0?{type:String(key).slice(0,split),id:String(key).slice(split+1)}:null;}).filter(item=>item&&['patient','csv'].includes(item.type));
    if(!valid.length)return toast('이동할 환자 또는 CSV를 선택하세요.','yellow');
    const selections=selectionsForTreeValue(currentState,target);
    const path=conditionalPath(currentState,targetRoot.id,selections);
    const next=patchState(state=>{
      ensureTagTreesState(state);
      valid.forEach(entity=>{
        const previous=(state.assignments||[]).find(a=>a.targetType===entity.type&&a.targetId===entity.id&&a.tagId===targetRoot.id&&Array.isArray(a.path));
        state.assignments=(state.assignments||[]).filter(a=>!(a.targetType===entity.type&&a.targetId===entity.id&&a.tagId===targetRoot.id&&Array.isArray(a.path)));
        state.assignments.unshift({...(previous||{}),id:previous?.id||uid('MAP'),tagId:targetRoot.id,tagName:targetRoot.name,targetId:entity.id,targetType:entity.type,treeSelections:{...selections},path:[...path],note:previous?.note||'',assignedAt:nowText(),assignedBy:USER});
        if(entity.type==='csv'){
          const file=(state.vitalFiles||[]).find(item=>item.id===entity.id);
          if(file&&!file.tagIds?.includes(targetRoot.id))file.tagIds=[...(file.tagIds||[]),targetRoot.id];
        }
      });
      state.audit.unshift({id:uid('AUDIT'),time:nowText(),user:USER,action:'tree entity move',target:'tag_tree',description:`${valid.length}개 항목을 ${treeNodePathText(state,target)} 경로로 이동`,status:'success'});
    });
    treeEntitySelection.clear();treeSelectedNodeId=target.id;
    renderTagTreeManager(next);selectTreeNode(target.id,{preserveSelection:true});
    toast(`${valid.length}개 항목을 “${target.name}” 하위그룹으로 이동했습니다.`);
  }
  function treePatientEntries(state,node){
    const root=treeRootFor(state,node);if(!root)return [];
    if(node.type==='tag'){
      return (state.patients||[]).map(patient=>({patient,assignment:treeAssignmentForEntity(state,'patient',patient.id,root.id)}));
    }
    const ids=new Set((state.assignments||[]).filter(a=>a.targetType==='patient'&&treeAssignmentMatchesNode(state,a,node)).map(a=>a.targetId));
    return (state.patients||[]).filter(patient=>ids.has(patient.id)).map(patient=>({patient,assignment:treeAssignmentForEntity(state,'patient',patient.id,root.id)}));
  }
  function treeCsvEntries(state,node,patientEntries){
    const root=treeRootFor(state,node);if(!root)return [];
    const patientIds=new Set(patientEntries.filter(entry=>entry.assignment&&treeAssignmentMatchesNode(state,entry.assignment,node)).map(entry=>entry.patient.id));
    return (state.vitalFiles||[]).map(file=>{
      const direct=treeAssignmentForEntity(state,'csv',file.id,root.id);
      if(node.type==='tag'){
        if(!direct&&!(file.tagIds||[]).includes(root.id))return null;
        return {file,assignment:direct,mode:direct?'direct':'root'};
      }
      if(direct&&treeAssignmentMatchesNode(state,direct,node))return {file,assignment:direct,mode:'direct'};
      if(!direct&&file.patientId&&patientIds.has(file.patientId)&&(file.tagIds||[]).includes(root.id))return {file,assignment:null,mode:'linked'};
      return null;
    }).filter(Boolean);
  }
  function updateTreeEntitySelectionCount(){const el=$('#treeDataSelectionCount');if(el)el.textContent=`${treeEntitySelection.size}개`;}
  function bindTreeEntityCards(){
    $$('[data-tree-entity]').forEach(card=>{
      const key=`${card.dataset.treeEntity}:${card.dataset.entityId}`;
      card.addEventListener('dragstart',event=>{event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('application/x-excite-tree-entity',JSON.stringify({type:card.dataset.treeEntity,id:card.dataset.entityId}));event.dataTransfer.setData('text/plain',key);});
      const checkbox=$('input[type="checkbox"]',card);
      checkbox?.addEventListener('change',()=>{if(checkbox.checked)treeEntitySelection.add(key);else treeEntitySelection.delete(key);updateTreeEntitySelectionCount();});
    });
  }
  function renderTagTreeNodeContents(state=readState()){
    const patientsBox=$('#treeNodePatients'),csvBox=$('#treeNodeCsv');if(!patientsBox||!csvBox)return;
    ensureTagTreesState(state);
    const view=state.tagTreeView||{showPatients:true,showCsv:true};
    if($('#treeShowPatients'))$('#treeShowPatients').checked=view.showPatients!==false;
    if($('#treeShowCsv'))$('#treeShowCsv').checked=view.showCsv!==false;
    if($('#treePatientPanel'))$('#treePatientPanel').hidden=view.showPatients===false;
    if($('#treeCsvPanel'))$('#treeCsvPanel').hidden=view.showCsv===false;
    $('.tree-data-grid')?.classList.toggle('single-panel',(view.showPatients===false)!==(view.showCsv===false));
    const node=treeNode(state,treeSelectedNodeId);
    if(!node){
      patientsBox.innerHTML='<div class="empty-state"><strong>트리 항목을 선택하세요.</strong><span>연구 태그 또는 하위그룹을 누르면 환자가 표시됩니다.</span></div>';
      csvBox.innerHTML='<div class="empty-state"><strong>트리 항목을 선택하세요.</strong><span>선택한 분류에 태그된 CSV가 표시됩니다.</span></div>';
      if($('#treeDataSelectedBadge'))$('#treeDataSelectedBadge').textContent='트리 항목을 선택하세요';
      if($('#treeDataPath'))$('#treeDataPath').textContent='-';
      if($('#treeDataPatientCount'))$('#treeDataPatientCount').textContent='0명';
      if($('#treeDataCsvCount'))$('#treeDataCsvCount').textContent='0개';
      if($('#treeMoveTargetSelect'))$('#treeMoveTargetSelect').innerHTML=option('','이동할 하위그룹 선택');
      updateTreeEntitySelectionCount();return;
    }
    const root=treeRootFor(state,node),query=treeEntitySearch.trim().toLowerCase();
    let patientEntries=treePatientEntries(state,node);
    let csvEntries=treeCsvEntries(state,node,patientEntries);
    if(query){
      patientEntries=patientEntries.filter(({patient})=>[patient.initials,patient.patientInitials,patient.registrationNo,String(patient.registrationNo||'').slice(-4),patientDisplayLabel(patient)].some(value=>String(value||'').toLowerCase().includes(query)));
      csvEntries=csvEntries.filter(({file})=>[file.name,file.caseId,file.patientId,file.monitorNumber,file.timepointLabel].some(value=>String(value||'').toLowerCase().includes(query)));
    }
    const patientHtml=patientEntries.length?patientEntries.map(({patient,assignment})=>{
      const key=`patient:${patient.id}`,assigned=Boolean(assignment),path=assignment?.path?.join(' → ')||`${root.name} · 미분류`;
      return `<article class="tree-entity-card" draggable="true" data-tree-entity="patient" data-entity-id="${escapeHtml(patient.id)}"><label class="tree-entity-check"><input type="checkbox" ${treeEntitySelection.has(key)?'checked':''}><span></span></label><div class="tree-entity-main"><strong>${escapeHtml(patient.initials||patient.patientInitials||patientMaskedRegistration(patient.registrationNo))}</strong><span>${escapeHtml(patientDisplayLabel(patient))}</span><small>${escapeHtml(path)}</small></div><div class="tree-entity-badges">${assigned?badge('분류됨','green'):badge('미분류','yellow')}${badge('환자','teal')}</div><span class="tree-drag-hint">⋮⋮</span></article>`;
    }).join(''):'<div class="empty-state"><strong>표시할 환자가 없습니다.</strong><span>이 분류에 배정된 환자가 없거나 검색 조건과 일치하지 않습니다.</span></div>';
    const csvHtml=csvEntries.length?csvEntries.map(({file,assignment,mode})=>{
      const key=`csv:${file.id}`,patient=(state.patients||[]).find(item=>item.id===file.patientId),path=assignment?.path?.join(' → ')||(mode==='linked'?`${patient?.initials||patient?.patientInitials||patient?.pseudoId||'환자'} 분류를 따라 연결`:`${root.name} 태그`);
      return `<article class="tree-entity-card csv" draggable="true" data-tree-entity="csv" data-entity-id="${escapeHtml(file.id)}"><label class="tree-entity-check"><input type="checkbox" ${treeEntitySelection.has(key)?'checked':''}><span></span></label><div class="tree-entity-main"><strong>${escapeHtml(file.name||file.caseId||'CSV')}</strong><span>${escapeHtml(patient?patientDisplayLabel(patient):(file.patientId||'환자 미매칭'))}</span><small>${escapeHtml(path)}</small></div><div class="tree-entity-badges">${mode==='direct'?badge('직접 태그','blue'):mode==='linked'?badge('환자 연결','gray'):badge('태그됨','teal')}${badge(file.uploadStatus||'업로드됨',file.uploadStatus==='오류'?'red':'green')}</div><span class="tree-drag-hint">⋮⋮</span></article>`;
    }).join(''):'<div class="empty-state"><strong>태그된 CSV가 없습니다.</strong><span>CSV에 이 연구 태그와 하위 분류 경로를 부여하면 여기에 표시됩니다.</span></div>';
    patientsBox.innerHTML=patientHtml;csvBox.innerHTML=csvHtml;
    if($('#treeDataSelectedBadge'))$('#treeDataSelectedBadge').textContent=node.name;
    if($('#treeDataPath'))$('#treeDataPath').textContent=treeNodePathText(state,node);
    if($('#treeDataPatientCount'))$('#treeDataPatientCount').textContent=`${patientEntries.length}명`;
    if($('#treeDataCsvCount'))$('#treeDataCsvCount').textContent=`${csvEntries.length}개`;
    const move=$('#treeMoveTargetSelect');if(move){const current=move.value;const values=treeValueMoveOptions(state,node);move.innerHTML=option('','이동할 하위그룹 선택')+values.map(value=>option(value.id,treeNodePathText(state,value,false))).join('');if(values.some(value=>value.id===current))move.value=current;}
    bindTreeEntityCards();updateTreeEntitySelectionCount();
  }
  function toggleVisibleTreeEntities(type){
    const cards=$$(`[data-tree-entity="${type}"]`);if(!cards.length)return;
    const keys=cards.map(card=>`${type}:${card.dataset.entityId}`),allSelected=keys.every(key=>treeEntitySelection.has(key));
    keys.forEach(key=>allSelected?treeEntitySelection.delete(key):treeEntitySelection.add(key));
    renderTagTreeNodeContents(readState());
  }

  function syncTreeCompatibility(state){
    const roots=treeChildren(state,null).filter(n=>n.type==='tag');
    state.tags=roots.map(root=>{
      const old=(state.tags||[]).find(t=>t.id===root.id)||{};
      return {...old,id:root.id,name:root.name,color:root.color||'#0b8f8a',description:root.description||'',status:old.status||'활성',createdAt:root.createdAt||old.createdAt||nowText(),updatedAt:root.updatedAt||nowText(),createdBy:old.createdBy||USER};
    });
    const axes=[];
    (state.tagTrees||[]).filter(n=>n.type==='question').forEach(q=>{
      const root=treeRootFor(state,q); if(!root)return;
      const values=treeChildren(state,q.id).filter(n=>n.type==='value').map(v=>({id:v.id,label:v.name,synonyms:[]}));
      axes.push({id:q.id,tagId:root.id,name:q.name,inputMode:q.selectionMode==='multiple'?'여러 개 선택':'하나만 선택',values,createdAt:q.createdAt||nowText()});
    });
    state.axes=axes;
  }

  function treeTypeLabel(type){return type==='tag'?'연구 태그':type==='question'?'환자를 나눌 기준':'선택할 수 있는 값';}
  function renderTreeNodeHtml(state,node){
    const children=treeChildren(state,node.id),selected=node.id===treeSelectedNodeId,counts=treeNodeEntityCounts(state,node);
    const countHtml=`<span class="tree-node-stats">${counts.patients?`<em>${counts.patients}명</em>`:''}${counts.csv?`<em>${counts.csv} CSV</em>`:''}</span>`;
    return `<li data-tree-li="${escapeHtml(node.id)}"><div class="tag-tree-node-row ${selected?'selected':''}" draggable="true" data-tree-node="${escapeHtml(node.id)}">
      <button class="tree-toggle" data-tree-toggle="${escapeHtml(node.id)}">${children.length?(node.collapsed?'▸':'▾'):'·'}</button><button class="tree-handle" title="드래그해서 이동">⋮⋮</button>
      <div class="tree-node-title"><strong>${escapeHtml(node.name)}</strong><span>${escapeHtml(node.description||'')}</span>${countHtml}</div><span class="tree-type-badge ${node.type}">${treeTypeLabel(node.type)}</span></div>
      ${children.length&&!node.collapsed?`<ul class="tag-tree-list">${children.map(c=>renderTreeNodeHtml(state,c)).join('')}</ul>`:''}</li>`;
  }

  function renderTagTreeManager(state=readState()){
    ensureTagTreesState(state);
    const editor=$('#tagTreeEditor'); if(!editor)return;
    const roots=treeChildren(state,null).filter(n=>n.type==='tag');
    editor.innerHTML=roots.length?`<ul class="tag-tree-list">${roots.map(r=>renderTreeNodeHtml(state,r)).join('')}</ul>`:'<div class="empty-state"><strong>연구 태그를 추가하세요.</strong><span>예: EPBM 정리 → ECMO 여부 → ECMO/비ECMO</span></div>';
    const questions=(state.tagTrees||[]).filter(n=>n.type==='question'), values=(state.tagTrees||[]).filter(n=>n.type==='value');
    if($('#treeMetricTags'))$('#treeMetricTags').textContent=`${roots.length}개`; if($('#treeMetricQuestions'))$('#treeMetricQuestions').textContent=`${questions.length}개`; if($('#treeMetricValues'))$('#treeMetricValues').textContent=`${values.length}개`;
    const maxDepth=Math.max(0,...(state.tagTrees||[]).map(n=>treeDepth(state,n))); if($('#treeMetricDepth'))$('#treeMetricDepth').textContent=`${maxDepth+1}단계`;
    bindTreeRows(); renderTagTreePreview(state); renderTreeTagSelect(state); renderTagTreeSummary(state); renderTagTreeNodeContents(state);
  }

  function bindTreeRows(){
    $$('[data-tree-node]').forEach(row=>{
      row.addEventListener('click',e=>{if(e.target.closest('[data-tree-toggle]'))return;selectTreeNode(row.dataset.treeNode);});
      row.addEventListener('dragstart',event=>{treeDraggedNodeId=row.dataset.treeNode;event.dataTransfer.effectAllowed='move';event.dataTransfer.setData('application/x-excite-tree-node',row.dataset.treeNode);});
      row.addEventListener('dragover',e=>{e.preventDefault();row.classList.add('drag-over');});row.addEventListener('dragleave',()=>row.classList.remove('drag-over'));
      row.addEventListener('drop',e=>{
        e.preventDefault();row.classList.remove('drag-over');
        const entityRaw=e.dataTransfer.getData('application/x-excite-tree-entity');
        if(entityRaw){try{const entity=JSON.parse(entityRaw);moveTreeEntities([`${entity.type}:${entity.id}`],row.dataset.treeNode);}catch(_){toast('이동할 항목 정보를 읽지 못했습니다.','yellow');}return;}
        const plain=e.dataTransfer.getData('text/plain');
        if(/^(patient|csv):/.test(plain)){moveTreeEntities([plain],row.dataset.treeNode);return;}
        const source=e.dataTransfer.getData('application/x-excite-tree-node')||treeDraggedNodeId;
        moveTreeNodeByDrop(source,row.dataset.treeNode);
      });
    });
    $$('[data-tree-toggle]').forEach(btn=>btn.addEventListener('click',e=>{e.stopPropagation();const st=patchState(s=>{ensureTagTreesState(s);const n=treeNode(s,btn.dataset.treeToggle);if(n)n.collapsed=!n.collapsed;});renderTagTreeManager(st);}));
  }

  function selectTreeNode(id,options={}){const changed=treeSelectedNodeId!==id;treeSelectedNodeId=id;if(changed&&!options.preserveSelection)treeEntitySelection.clear();const st=readState();ensureTagTreesState(st);const n=treeNode(st,id);if(!n)return;$('#treeNodeId').value=n.id;$('#treeNodeName').value=n.name||'';$('#treeNodeType').value=n.type;$('#treeSelectionMode').value=n.selectionMode||'single';$('#treeNodeDescription').value=n.description||'';$('#treeNodeColor').value=normalizeTagColor(n.color);$('#treeNodeColorText').value=normalizeTagColor(n.color);$('#treeSelectedBadge').textContent=treeTypeLabel(n.type);$('#treeSelectionModeField').hidden=n.type!=='question';renderTagTreeManager(st);}
  function resetTreeForm(){treeSelectedNodeId=null;treePendingParentId=null;treeEntitySelection.clear();['treeNodeId','treeNodeName','treeNodeDescription'].forEach(id=>{const e=$('#'+id);if(e)e.value='';});$('#treeNodeType').value='tag';$('#treeSelectionMode').value='single';$('#treeSelectedBadge').textContent='선택 없음';$('#treeSelectionModeField').hidden=true;renderTagTreeManager(readState());}
  function createTreeDraft(kind){const st=readState();ensureTagTreesState(st);let parent=null;if(kind==='child'){parent=treeNode(st,treeSelectedNodeId);if(!parent)return toast('하위 항목을 추가할 상위 항목을 선택하세요.','yellow');treePendingParentId=parent.id;$('#treeNodeType').value=parent.type==='question'?'value':'question';}else if(kind==='sibling'){const selected=treeNode(st,treeSelectedNodeId);if(!selected)return toast('같은 단계에 추가할 기준 항목을 선택하세요.','yellow');treePendingParentId=selected.parentId;$('#treeNodeType').value=selected.type;}else{treePendingParentId=null;$('#treeNodeType').value='tag';}treeSelectedNodeId=null;$('#treeNodeId').value='';$('#treeNodeName').value='';$('#treeNodeDescription').value='';$('#treeFormTitle').textContent='새 항목 추가';$('#treeSelectionModeField').hidden=$('#treeNodeType').value!=='question';$('#treeNodeName').focus();}
  function saveTreeNode(){const name=($('#treeNodeName')?.value||'').trim();if(!name)return toast('항목명을 입력하세요.','yellow');const type=$('#treeNodeType').value;const id=$('#treeNodeId').value;const st=patchState(s=>{ensureTagTreesState(s);if(id){const n=treeNode(s,id);if(n)Object.assign(n,{name,type,selectionMode:$('#treeSelectionMode').value,description:($('#treeNodeDescription').value||'').trim(),color:$('#treeNodeColorText').value||$('#treeNodeColor').value,updatedAt:nowText()});}else{let parentId=treePendingParentId;if(type==='tag')parentId=null;const parent=treeNode(s,parentId);const tagId=type==='tag'?uid('TAG'):(treeRootFor(s,parent)?.id||parent?.tagId||'');const nodeId=type==='tag'?tagId:uid('TREE');s.tagTrees.push({id:nodeId,tagId,parentId,name,type,selectionMode:$('#treeSelectionMode').value,description:($('#treeNodeDescription').value||'').trim(),color:$('#treeNodeColorText').value||$('#treeNodeColor').value,order:treeChildren(s,parentId).length,collapsed:false,createdAt:nowText(),updatedAt:nowText()});treeSelectedNodeId=nodeId;}syncTreeCompatibility(s);});treePendingParentId=null;renderTagTreeManager(st);selectTreeNode(treeSelectedNodeId||id);toast('트리 항목을 저장했습니다.');}
  function deleteTreeNode(){if(!treeSelectedNodeId)return toast('삭제할 항목을 선택하세요.','yellow');if(!confirm('선택한 항목과 모든 하위 항목을 삭제할까요?'))return;const st=patchState(s=>{ensureTagTreesState(s);const ids=new Set([treeSelectedNodeId]);let changed=true;while(changed){changed=false;(s.tagTrees||[]).forEach(n=>{if(n.parentId&&ids.has(n.parentId)&&!ids.has(n.id)){ids.add(n.id);changed=true;}});}const parent=treeNode(s,treeSelectedNodeId)?.parentId;s.tagTrees=s.tagTrees.filter(n=>!ids.has(n.id));normalizeTreeOrders(s,parent);syncTreeCompatibility(s);});resetTreeForm();renderTagTreeManager(st);toast('트리 항목을 삭제했습니다.');}
  function moveTreeNodeByDrop(sourceId,targetId){if(!sourceId||!targetId||sourceId===targetId)return;const st=patchState(s=>{ensureTagTreesState(s);const source=treeNode(s,sourceId),target=treeNode(s,targetId);if(!source||!target||treeDescendant(s,sourceId,targetId))return;if(source.type==='tag'){if(target.type!=='tag')return;const tmp=source.order;source.order=target.order;target.order=tmp;syncTreeCompatibility(s);return;}const oldParent=source.parentId;source.parentId=target.id;source.tagId=treeRootFor(s,target)?.id||target.tagId;source.order=treeChildren(s,target.id).length;normalizeTreeOrders(s,oldParent);normalizeTreeOrders(s,target.id);syncTreeCompatibility(s);});treeSelectedNodeId=sourceId;renderTagTreeManager(st);}
  function moveSelectedTree(direction){if(!treeSelectedNodeId)return;const st=patchState(s=>{ensureTagTreesState(s);const n=treeNode(s,treeSelectedNodeId);if(!n)return;const siblings=treeChildren(s,n.parentId),i=siblings.findIndex(x=>x.id===n.id),j=direction==='up'?i-1:i+1;if(j<0||j>=siblings.length)return;const other=siblings[j],tmp=n.order;n.order=other.order;other.order=tmp;syncTreeCompatibility(s);});renderTagTreeManager(st);}
  function indentSelectedTree(outdent=false){if(!treeSelectedNodeId)return;const st=patchState(s=>{ensureTagTreesState(s);const n=treeNode(s,treeSelectedNodeId);if(!n||n.type==='tag')return;const old=n.parentId;if(outdent){const parent=treeNode(s,n.parentId);if(!parent||parent.type==='tag')return;n.parentId=parent.parentId;n.order=treeChildren(s,n.parentId).length;}else{const siblings=treeChildren(s,n.parentId),i=siblings.findIndex(x=>x.id===n.id);if(i<=0)return;const prev=siblings[i-1];if(prev.type==='value'&&n.type==='value')return;n.parentId=prev.id;n.order=treeChildren(s,prev.id).length;}normalizeTreeOrders(s,old);syncTreeCompatibility(s);});renderTagTreeManager(st);}
  function collapseTreeAll(value){const st=patchState(s=>{ensureTagTreesState(s);s.tagTrees.forEach(n=>n.collapsed=value);});renderTagTreeManager(st);}
  function renderPreviewBranch(state,node){const children=treeChildren(state,node.id);return `<div class="preview-tree-item"><strong><span class="tree-type-badge ${node.type}">${treeTypeLabel(node.type)}</span>${escapeHtml(node.name)}</strong>${children.length?`<div class="preview-tree-branch">${children.map(c=>renderPreviewBranch(state,c)).join('')}</div>`:''}</div>`;}
  function renderTagTreePreview(state=readState()){const box=$('#tagTreePreview');if(!box)return;ensureTagTreesState(state);const roots=treeChildren(state,null).filter(n=>n.type==='tag');box.innerHTML=roots.length?roots.map(r=>renderPreviewBranch(state,r)).join(''):'<div class="empty-state"><strong>미리볼 트리가 없습니다.</strong></div>';}
  function renderTreeTagSelect(state=readState()){const sel=$('#treePreviewTagSelect');if(!sel)return;const current=sel.value;const roots=treeChildren(state,null).filter(n=>n.type==='tag');sel.innerHTML=option('','연구 태그 선택')+roots.map(r=>option(r.id,r.name)).join('');if(roots.some(r=>r.id===current))sel.value=current;else if(roots[0])sel.value=roots[0].id;renderConditionalTreePreview();}
  function renderTagTreeSummary(state=readState()){const body=$('#tagTreeSummaryBody');if(!body)return;const roots=treeChildren(state,null).filter(n=>n.type==='tag');body.innerHTML=roots.length?roots.map(r=>{const nodes=(state.tagTrees||[]).filter(n=>n.id===r.id||treeDescendant(state,r.id,n.id));const q=nodes.filter(n=>n.type==='question').length,v=nodes.filter(n=>n.type==='value').length,d=Math.max(1,...nodes.map(n=>treeDepth(state,n)+1));return `<tr><td>${tagBadge({name:r.name,color:r.color})}</td><td>${q}</td><td>${v}</td><td>${d}단계</td><td>${escapeHtml(r.updatedAt||r.createdAt||'-')}</td><td><button class="btn ghost" data-summary-select="${r.id}">열기</button></td></tr>`;}).join(''):'<tr class="empty-row"><td colspan="6"><strong>연구 태그가 없습니다.</strong></td></tr>';$$('[data-summary-select]',body).forEach(b=>b.addEventListener('click',()=>selectTreeNode(b.dataset.summarySelect)));}
  function renderConditionalQuestions(container,rootId,selections,onChange){
    const st=readState(); ensureTagTreesState(st);
    function questionHtml(q){
      const vals=treeChildren(st,q.id).filter(n=>n.type==='value');
      const selectedRaw=selections[q.id] ?? (q.selectionMode==='multiple'?[]:'');
      const selectedList=Array.isArray(selectedRaw)?selectedRaw:[selectedRaw].filter(Boolean);
      const opts=vals.map(v=>`<label class="conditional-option"><input type="${q.selectionMode==='multiple'?'checkbox':'radio'}" name="q_${q.id}" value="${v.id}" ${selectedList.includes(v.id)?'checked':''}>${escapeHtml(v.name)}</label>`).join('');
      const nested=selectedList.flatMap(vid=>treeChildren(st,vid).filter(n=>n.type==='question')).map(questionHtml).join('');
      return `<div class="conditional-question-card" data-question-card="${q.id}"><h4>${escapeHtml(q.name)}</h4><div class="conditional-options">${opts||'<span class="muted">선택값 없음</span>'}</div>${nested}</div>`;
    }
    const questions=treeChildren(st,rootId).filter(n=>n.type==='question');
    container.innerHTML=questions.length?questions.map(questionHtml).join(''):'<div class="empty-state"><strong>등록된 질문이 없습니다.</strong></div>';
    $$('input',container).forEach(input=>input.addEventListener('change',()=>{
      const qid=input.name.replace('q_',''), q=treeNode(st,qid);
      if(q?.selectionMode==='multiple'){
        const checked=$$(`input[name="q_${qid}"]:checked`,container).map(x=>x.value);
        selections[qid]=checked;
      }else selections[qid]=input.value;
      onChange?.();
    }));
  }

  function renderConditionalTreePreview(){const box=$('#conditionalClassificationPreview'),tagId=$('#treePreviewTagSelect')?.value;if(!box)return;if(!tagId){box.innerHTML='<div class="empty-state"><strong>연구 태그를 선택하세요.</strong></div>';return;}renderConditionalQuestions(box,tagId,conditionalSelections,renderConditionalTreePreview);}
  function seedEpbmTree(){
    const exists=(readState().tagTrees||[]).some(n=>n.type==='tag'&&n.name==='EPBM 정리');
    if(exists)return toast('이미 EPBM 정리 트리가 있습니다.','yellow');
    const st=patchState(s=>{ensureTagTreesState(s);const tagId=uid('TAG'),q1=uid('TREE'),vNon=uid('TREE'),vEcmo=uid('TREE'),q2=uid('TREE');s.tagTrees.push(
      {id:tagId,tagId,parentId:null,name:'EPBM 정리',type:'tag',color:'#0b8f8a',order:treeChildren(s,null).length,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:q1,tagId,parentId:tagId,name:'ECMO 여부',type:'question',selectionMode:'single',order:0,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:vNon,tagId,parentId:q1,name:'비ECMO',type:'value',order:0,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:vEcmo,tagId,parentId:q1,name:'ECMO',type:'value',order:1,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:q2,tagId,parentId:vEcmo,name:'생존 여부',type:'question',selectionMode:'single',order:0,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:uid('TREE'),tagId,parentId:q2,name:'생존',type:'value',order:0,collapsed:false,createdAt:nowText(),updatedAt:nowText()},
      {id:uid('TREE'),tagId,parentId:q2,name:'사망',type:'value',order:1,collapsed:false,createdAt:nowText(),updatedAt:nowText()}
    );syncTreeCompatibility(s);});renderTagTreeManager(st);toast('EPBM 예시 트리를 만들었습니다.');
  }

  function initTagTreeManager(){
    if($('#treeSelectionModeField'))$('#treeSelectionModeField').hidden=$('#treeNodeType')?.value!=='question';
    const st=patchState(s=>{ensureTagTreesState(s);syncTreeCompatibility(s);});
    $('#treeAddRootBtn')?.addEventListener('click',()=>createTreeDraft('root'));$('#treeAddChildBtn')?.addEventListener('click',()=>createTreeDraft('child'));$('#treeAddSiblingBtn')?.addEventListener('click',()=>createTreeDraft('sibling'));$('#treeSaveNodeBtn')?.addEventListener('click',saveTreeNode);$('#treeResetFormBtn')?.addEventListener('click',resetTreeForm);$('#treeDeleteNodeBtn')?.addEventListener('click',deleteTreeNode);$('#treeMoveUpBtn')?.addEventListener('click',()=>moveSelectedTree('up'));$('#treeMoveDownBtn')?.addEventListener('click',()=>moveSelectedTree('down'));$('#treeOutdentBtn')?.addEventListener('click',()=>indentSelectedTree(true));$('#treeIndentBtn')?.addEventListener('click',()=>indentSelectedTree(false));$('#treeCollapseAllBtn')?.addEventListener('click',()=>collapseTreeAll(true));$('#treeExpandAllBtn')?.addEventListener('click',()=>collapseTreeAll(false));
    $('#treeNodeType')?.addEventListener('change',()=>$('#treeSelectionModeField').hidden=$('#treeNodeType').value!=='question');$('#treePreviewTagSelect')?.addEventListener('change',()=>{conditionalSelections={};renderConditionalTreePreview();});
    $$('#treeColorPalette [data-color]').forEach(btn=>btn.addEventListener('click',()=>{$$('#treeColorPalette [data-color]').forEach(x=>x.classList.toggle('active',x===btn));$('#treeNodeColor').value=btn.dataset.color;$('#treeNodeColorText').value=btn.dataset.color;}));$('#treeNodeColor')?.addEventListener('input',()=>$('#treeNodeColorText').value=$('#treeNodeColor').value);$('#treeNodeColorText')?.addEventListener('input',()=>{if(/^#[0-9a-f]{6}$/i.test($('#treeNodeColorText').value))$('#treeNodeColor').value=$('#treeNodeColorText').value;});
    $('#treeShowPatients')?.addEventListener('change',()=>{treeEntitySelection=new Set([...treeEntitySelection].filter(key=>!key.startsWith('patient:')));const next=patchState(state=>{ensureTagTreesState(state);state.tagTreeView.showPatients=$('#treeShowPatients').checked;});renderTagTreeManager(next);});
    $('#treeShowCsv')?.addEventListener('change',()=>{treeEntitySelection=new Set([...treeEntitySelection].filter(key=>!key.startsWith('csv:')));const next=patchState(state=>{ensureTagTreesState(state);state.tagTreeView.showCsv=$('#treeShowCsv').checked;});renderTagTreeManager(next);});
    $('#treeEntitySearch')?.addEventListener('input',event=>{treeEntitySearch=event.target.value||'';renderTagTreeNodeContents(readState());});
    $('#treeMoveEntitiesBtn')?.addEventListener('click',()=>moveTreeEntities([...treeEntitySelection],$('#treeMoveTargetSelect')?.value));
    $('#treeSelectAllPatientsBtn')?.addEventListener('click',()=>toggleVisibleTreeEntities('patient'));$('#treeSelectAllCsvBtn')?.addEventListener('click',()=>toggleVisibleTreeEntities('csv'));
    renderTagTreeManager(st);
  }

  function conditionalTargetOptions(unit,state){if(unit==='patient')return (state.patients||[]).map(p=>({id:p.id,label:patientDisplayLabel(p)}));if(unit==='episode')return (state.ecmoEpisodes||[]).map(e=>({id:e.id,label:`${e.patientLabel||''} · ${episodeDisplayLabel(e)}`}));if(unit==='lab')return [...(state.labRecords||[]).map(r=>({id:r.id,label:`${r.patientLabel||''} · 검사 ${r.date}`})),...(state.microbiologyRecords||[]).map(r=>({id:r.id,label:`${r.patientLabel||''} · ${r.organismName} ${r.date}`}))];return (state.vitalFiles||[]).map(f=>({id:f.id,label:`${f.patientId||'미매칭'} · ${f.name}`}));}
  function renderConditionalTargets(){const sel=$('#conditionalTargetSelect');if(!sel)return;const opts=conditionalTargetOptions($('#assignmentTargetUnit')?.value||'patient',readState());sel.innerHTML=option('','대상 선택')+opts.map(o=>option(o.id,o.label)).join('');}
  function renderConditionalTagOptions(){const st=readState();ensureTagTreesState(st);const sel=$('#conditionalTagSelect');if(!sel)return;sel.innerHTML=option('','연구 태그 선택')+treeChildren(st,null).filter(n=>n.type==='tag').map(r=>option(r.id,r.name)).join('');}
  function conditionalPath(state,tagId,selections){
    const root=treeNode(state,tagId),parts=root?[root.name]:[];
    function walk(parentId){
      treeChildren(state,parentId).filter(n=>n.type==='question').forEach(q=>{
        const raw=selections[q.id]; const vids=Array.isArray(raw)?raw:[raw].filter(Boolean);
        vids.forEach(vid=>{const v=treeNode(state,vid); if(v){parts.push(v.name); walk(vid);}});
      });
    }
    walk(tagId); return parts.filter(Boolean);
  }

  function renderConditionalAssignmentForm(){const box=$('#conditionalAssignmentForm'),tagId=$('#conditionalTagSelect')?.value;if(!box)return;if(!tagId){box.innerHTML='<div class="empty-state"><strong>연구 태그를 선택하세요.</strong></div>';return;}renderConditionalQuestions(box,tagId,conditionalSelections,()=>{renderConditionalAssignmentForm();const st=readState();$('#conditionalTagPath').textContent=conditionalPath(st,tagId,conditionalSelections).join(' → ')||'선택된 경로 없음';});const st=readState();$('#conditionalTagPath').textContent=conditionalPath(st,tagId,conditionalSelections).join(' → ')||'선택된 경로 없음';}
  function saveConditionalAssignment(){const st=readState(),unit=$('#assignmentTargetUnit').value,targetId=$('#conditionalTargetSelect').value,tagId=$('#conditionalTagSelect').value;if(!targetId||!tagId)return toast('대상과 연구 태그를 선택하세요.','yellow');const path=conditionalPath(st,tagId,conditionalSelections);if(path.length<2)return toast('분류 질문의 선택값을 하나 이상 선택하세요.','yellow');const tag=treeNode(st,tagId);const next=patchState(s=>{ensureTagTreesState(s);s.assignments.unshift({id:uid('MAP'),tagId,tagName:tag?.name||'',targetId,targetType:unit,treeSelections:{...conditionalSelections},path,note:($('#conditionalAssignmentNote').value||'').trim(),assignedAt:nowText(),assignedBy:USER});const vf=(s.vitalFiles||[]).find(f=>f.id===targetId);if(vf&&!vf.tagIds?.includes(tagId))vf.tagIds=[...(vf.tagIds||[]),tagId];});renderConditionalAssignments(next);toast('태그와 조건부 분류 경로를 저장했습니다.');}
  function renderConditionalAssignments(state=readState()){const body=$('#conditionalAssignmentBody');if(!body)return;const rows=(state.assignments||[]).filter(a=>Array.isArray(a.path));body.innerHTML=rows.length?rows.map(a=>`<tr><td>${escapeHtml(a.targetId)}</td><td>${escapeHtml(a.targetType)}</td><td>${escapeHtml(a.tagName)}</td><td>${escapeHtml(a.path.join(' → '))}</td><td>${escapeHtml(a.note||'-')}</td><td>${escapeHtml(a.assignedAt||'-')}</td><td><button class="btn ghost" data-delete-cond-assignment="${a.id}">삭제</button></td></tr>`).join(''):'<tr class="empty-row"><td colspan="7"><strong>저장된 분류 경로가 없습니다.</strong></td></tr>';$$('[data-delete-cond-assignment]',body).forEach(b=>b.addEventListener('click',()=>{const st=patchState(s=>s.assignments=(s.assignments||[]).filter(a=>a.id!==b.dataset.deleteCondAssignment));renderConditionalAssignments(st);}));}
  function initConditionalTagAssignment(){patchState(s=>ensureTagTreesState(s));renderConditionalTargets();renderConditionalTagOptions();renderConditionalAssignments();$('#assignmentTargetUnit')?.addEventListener('change',renderConditionalTargets);$('#conditionalTagSelect')?.addEventListener('change',()=>{conditionalSelections={};renderConditionalAssignmentForm();});$('#conditionalAssignmentSaveBtn')?.addEventListener('click',saveConditionalAssignment);renderConditionalAssignmentForm();}

  function extendedTestRows(values=[]){const map=new Map((values||[]).map(x=>[x.test,x]));return EXTENDED_PRE_ECMO_TESTS.map(t=>{const v=map.get(t.key)||{};return `<tr data-extended-test="${escapeHtml(t.key)}"><td><strong>${escapeHtml(t.key)}</strong></td><td><input class="input" data-field="value" type="number" step="any" value="${escapeHtml(v.value??'')}"></td><td><input class="input" data-field="unit" value="${escapeHtml(v.unit||t.unit)}"></td><td><input class="input" data-field="dateTime" type="datetime-local" value="${escapeHtml(v.dateTime||'')}"></td><td><input class="input" data-field="reference" placeholder="예: ECMO start 이전" value="${escapeHtml(v.reference||'')}"></td><td><select data-field="sourceLinked"><option value="">미확인</option><option value="yes" ${v.sourceLinked==='yes'?'selected':''}>연결됨</option><option value="no" ${v.sourceLinked==='no'?'selected':''}>연결 안 됨</option></select></td><td><input class="input" data-field="note" value="${escapeHtml(v.note||'')}"></td></tr>`;}).join('');}
  function renderExtendedTests(values=[]){const body=$('#preEcmoExtendedBody');if(body)body.innerHTML=extendedTestRows(values);}
  function collectExtendedTests(){return $$('#preEcmoExtendedBody [data-extended-test]').map(row=>({test:row.dataset.extendedTest,value:$('[data-field="value"]',row)?.value||'',unit:$('[data-field="unit"]',row)?.value||'',dateTime:$('[data-field="dateTime"]',row)?.value||'',reference:$('[data-field="reference"]',row)?.value||'',sourceLinked:$('[data-field="sourceLinked"]',row)?.value||'',note:$('[data-field="note"]',row)?.value||''}));}
  const EPISODE_DETAIL_IDS=['episodeEcmoType','episodeEcmoMode','episodeLocation','episodeManagementMethod','episodeDrainSite','episodeReturnSite','episodeDrainCannula','episodeReturnCannula','episodeTotalPerfusion','episodeCircuitChangeCount','episodeCrpFlag','episodeCrrtFlag','episodeCreatinine28d','episodeCreatinine28dUnit','episodeLastFollowupDate','episodeCrrtStart','episodeCrrtEnd','episodeCrrtMode','episodeCrrtNote','episodeComplications','episodeCircuitChangeNote','episodeFollowupNote'];
  function collectEpisodeDetails(){const o={};EPISODE_DETAIL_IDS.forEach(id=>o[id.replace('episode','').replace(/^./,c=>c.toLowerCase())]=$('#'+id)?.value||'');return o;}
  function fillEpisodeDetails(values={}){EPISODE_DETAIL_IDS.forEach(id=>setClinicalValue(id,values[id.replace('episode','').replace(/^./,c=>c.toLowerCase())]||''));toggleCrrtDetails();}
  function toggleCrrtDetails(){const box=$('#crrtDetailFields');if(box)box.hidden=$('#episodeCrrtFlag')?.value!=='yes';}
  function normalizedEventMatchText(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9가-힣]/g, '');
  }

  function filesMatchedToMajorEvent(event, state = readState()) {
    if (!activeEpisodeId) return [];
    const episode = episodeById(state, activeEpisodeId);
    if (!episode) return [];
    const eventName = normalizedEventMatchText(event?.name);
    const eventTime = safeDate(event?.dateTime)?.getTime();
    return (state.vitalFiles || []).filter(file => {
      if (file.patientId !== episode.patientId) return false;
      if (file.episodeId && file.episodeId !== episode.id) return false;
      const label = normalizedEventMatchText(file.timepointLabel || file.observationPhase || file.timepoint || '');
      const semanticMatch = [
        ['pre', 'pre'], ['ecmo전', 'pre'], ['baseline', 'pre'],
        ['4시간', '4시간'], ['6시간', '6시간'], ['24시간', '24시간'],
        ['ecmo시작', 'ecmo시작'], ['ecmostart', 'ecmo시작'],
        ['ecmo종료', 'ecmo종료'], ['ecmofinish', 'ecmo종료'],
        ['cannula', 'cannula'], ['캐뉼라', 'cannula'], ['weaning', 'weaning']
      ].some(([token, group]) => {
        const eventHas = eventName.includes(token) || (group !== token && eventName.includes(group));
        const labelHas = label.includes(token) || (group !== token && label.includes(group));
        return eventHas && labelHas;
      });
      const labelMatch = Boolean(eventName && label && (label.includes(eventName) || eventName.includes(label) || semanticMatch));
      const fileTime = safeDate(file.matchedTime || file.recordingStart)?.getTime();
      const timeMatch = Number.isFinite(eventTime) && Number.isFinite(fileTime) && Math.abs(eventTime - fileTime) <= 60 * 60 * 1000;
      return labelMatch || timeMatch || file.eventId === event.id;
    }).sort((a,b) => Number(a.linkedOrder || 9999) - Number(b.linkedOrder || 9999));
  }

  function eventFileGraph(file) {
    const variable = ['MAP','HR','SpO2','RR','SBP','DBP'].find(name => extractPreviewSeries(file, name, 'all').length) || '';
    const data = variable ? extractPreviewSeries(file, variable, 'all') : [];
    return `<div class="major-event-csv-graph"><div class="major-event-csv-graph-head"><strong>${escapeHtml(file.name || '연결 CSV')}</strong>${badge(file.timepointLabel || '이벤트 매칭', 'blue')}</div><div class="event-qc-chart">${data.length ? drawQcSvg(data, variable, file.name || '') : `<div class="empty-state compact"><strong>그래프 데이터가 없습니다.</strong><span>CSV 매칭은 완료됐지만, 이 파일은 기존 업로드라 preview 데이터가 저장되지 않았습니다. Raw CSV를 다시 업로드하면 그래프가 표시됩니다.</span></div>`}</div></div>`;
  }

  function majorEventTemplate(event={}){
    const id=event.id||uid('EVT');
    const files=filesMatchedToMajorEvent({...event,id});
    return `<div class="major-event-card" data-major-event="${id}"><div class="major-event-head"><strong>시간 이벤트</strong><button class="btn ghost" data-remove-major-event="${id}" type="button">삭제</button></div><div class="major-event-grid compact"><div class="field"><label>이벤트명</label><input class="input" data-me="name" list="majorEventNames" value="${escapeHtml(event.name||'')}"></div><div class="field"><label>일시</label><input class="input" data-me="dateTime" type="datetime-local" value="${escapeHtml(event.dateTime||'')}"></div><div class="field major-event-note-field"><label>내용 / 비고</label><input class="input" data-me="note" value="${escapeHtml(event.note||'')}" placeholder="예: Cannula 교체, weaning 조건, 장비 변경 내용"></div></div>${files.length ? `<div class="major-event-csv-graphs"><div class="major-event-csv-graph-head"><strong>이 이벤트에 매칭된 CSV 그래프</strong>${badge(`${files.length}개`, 'teal')}</div>${files.map(eventFileGraph).join('')}</div>` : ''}</div>`;
  }
  function renderMajorEvents(events=episodeDraftTimeEvents){
    episodeDraftTimeEvents=events||[];
    const box=$('#majorTimeEventList');if(!box)return;
    box.innerHTML=episodeDraftTimeEvents.length?episodeDraftTimeEvents.map(majorEventTemplate).join(''):'<div class="empty-state"><strong>등록된 시간 이벤트가 없습니다.</strong><span>+ 시간 이벤트 추가 버튼을 누르세요.</span></div>';
    $$('[data-remove-major-event]',box).forEach(b=>b.addEventListener('click',()=>{episodeDraftTimeEvents=collectMajorEvents().filter(e=>e.id!==b.dataset.removeMajorEvent);renderMajorEvents();}));
    $$('[data-major-event] [data-me="name"], [data-major-event] [data-me="dateTime"]',box).forEach(input=>input.addEventListener('change',()=>{episodeDraftTimeEvents=collectMajorEvents();renderMajorEvents();}));
  }
  function collectMajorEvents(){return $$('#majorTimeEventList [data-major-event]').map(card=>{const o={id:card.dataset.majorEvent};$$('[data-me]',card).forEach(el=>o[el.dataset.me]=el.value);return o;});}
  function addMajorEvent(){episodeDraftTimeEvents=collectMajorEvents();episodeDraftTimeEvents.push({id:uid('EVT'),name:'',dateTime:''});renderMajorEvents();}
  function clearEpisodeAugmentedForm(){renderExtendedTests([]);fillEpisodeDetails({});episodeDraftTimeEvents=[];renderMajorEvents([]);updateEpisodeEditBanner(readState());renderEpisodeLinkedData(readState());}
  function fillEpisodeAugmentedForm(ep){renderExtendedTests(ep?.measurements?.preEcmo?.extendedTests||[]);fillEpisodeDetails(ep?.details||{});episodeDraftTimeEvents=(ep?.timeEvents||[]).map(e=>({...e}));renderMajorEvents(episodeDraftTimeEvents);updateEpisodeEditBanner(readState());renderEpisodeLinkedData(readState());}
  function saveEpisodeAllEnhanced(){if(!activeEpisodeId)return toast('저장할 ECMO episode를 선택하세요.','yellow');const events={};EPISODE_EVENT_FIELDS.forEach(f=>events[f.key]=$('#'+f.id)?.value||'');const measurements=collectEpisodeMeasurements();measurements.preEcmo.extendedTests=collectExtendedTests();const details=collectEpisodeDetails(),timeEvents=collectMajorEvents();const st=patchState(s=>{const ep=episodeById(s,activeEpisodeId);if(!ep)return;ep.events=events;ep.dischargeAlive=$('#dischargeAlive')?.value||'';ep.note=($('#episodeNote')?.value||'').trim();ep.measurements=measurements;ep.details=details;ep.timeEvents=timeEvents;ep.updatedAt=nowText();});renderClinicalEntry(st);toast('현재 ECMO episode의 변경사항을 저장했습니다.');}
  function updateEpisodeEditBanner(state=readState()){const box=$('#episodeEditBanner'),title=$('#episodeEditTitle'),ep=episodeById(state,activeEpisodeId);if(!box)return;box.hidden=!ep;if(title&&ep)title.textContent=`${episodeDisplayLabel(ep)} 에피소드 수정 중`;}
  function renderEpisodeLinkedData(state=readState()){const box=$('#episodeLinkedData');if(!box)return;const ep=episodeById(state,activeEpisodeId);if(!ep){box.innerHTML='<div class="empty-state"><strong>episode를 선택하세요.</strong></div>';return;}const files=(state.vitalFiles||[]).filter(f=>f.patientId===ep.patientId&&(f.episodeId===ep.id||!f.episodeId));const micro=(state.microbiologyRecords||[]).filter(r=>r.episodeId===ep.id);const assigns=(state.assignments||[]).filter(a=>a.targetId===ep.id||a.targetId===ep.patientId);box.innerHTML=`<div class="episode-linked-card"><h4>연결된 CSV</h4>${files.length?files.map(f=>`<div>${escapeHtml(f.name)}</div>`).join(''):'<span class="muted">없음</span>'}</div><div class="episode-linked-card"><h4>연결된 미생물 결과</h4>${micro.length?micro.map(r=>`<div>${escapeHtml(r.date)} · ${escapeHtml(r.organismName)}</div>`).join(''):'<span class="muted">없음</span>'}</div><div class="episode-linked-card"><h4>연결된 태그/분류</h4>${assigns.length?assigns.map(a=>`<div>${escapeHtml((a.path||[a.tagName]).join(' → '))}</div>`).join(''):'<span class="muted">없음</span>'}</div>`;}
  function initEpisodeEnhancements(){const initialEpisode=episodeById(readState(),activeEpisodeId);if(initialEpisode)fillEpisodeAugmentedForm(initialEpisode);else{renderExtendedTests([]);renderMajorEvents([]);}$('#addMajorTimeEventBtn')?.addEventListener('click',addMajorEvent);$('#episodeCrrtFlag')?.addEventListener('change',toggleCrrtDetails);$('#episodeSaveAllBtn')?.addEventListener('click',saveEpisodeAllEnhanced);$('#episodeCloseWithoutSaveBtn')?.addEventListener('click',()=>{activeEpisodeId=null;clearEpisodeEventForm();const banner=$('#episodeEditBanner');if(banner)banner.hidden=true;$$('[data-episode-tab]').forEach(b=>b.classList.remove('teal'));toast('저장하지 않고 편집 화면을 닫았습니다.','gray');});$('#episodeDeleteTopBtn')?.addEventListener('click',deleteActiveEpisode);$('#patientRegNo')?.addEventListener('blur',checkPatientDuplicate);$('#openExistingPatientBtn')?.addEventListener('click',()=>openDuplicatePatient(false));$('#addExistingPatientDataBtn')?.addEventListener('click',()=>openDuplicatePatient(true));$('#cancelDuplicatePatientBtn')?.addEventListener('click',()=>{setClinicalValue('patientRegNo','');hidePatientDuplicate();});$('#cancelPatientMasterEditBtn')?.addEventListener('click',cancelClinicalPatientEdit);$('#clinicalPatientCancelEditBtn')?.addEventListener('click',cancelClinicalPatientEdit);$('#microViewExistingBtn')?.addEventListener('click',()=>{const id=pendingMicroDuplicate?.record?.id;hideMicroDuplicate();document.querySelector(`[data-micro-row="${id}"]`)?.scrollIntoView({behavior:'smooth',block:'center'});});$('#microEditExistingBtn')?.addEventListener('click',()=>{const r=pendingMicroDuplicate?.record;hideMicroDuplicate();loadMicroRecordToForm(r);});$('#microDuplicateCancelBtn')?.addEventListener('click',hideMicroDuplicate);$('#microAdminDuplicateBtn')?.addEventListener('click',()=>{if(!pendingMicroDuplicate)return;$('#microDuplicateReasonField').hidden=false;allowMicroDuplicateOnce=true;toast('중복 저장 사유를 입력한 뒤 다시 저장하세요.','yellow');});const preset=sessionStorage.getItem('excite_open_episode_id');const patient=sessionStorage.getItem('excite_open_patient_id');if(patient){const sel=$('#episodePatientSelect');if(sel&&[...sel.options].some(o=>o.value===patient))sel.value=patient;}if(preset){activeEpisodeId=preset;sessionStorage.removeItem('excite_open_episode_id');sessionStorage.removeItem('excite_open_patient_id');renderEpisodeWorkspace(readState());}}
  function checkPatientDuplicate(){const reg=($('#patientRegNo')?.value||'').trim(),box=$('#patientDuplicateNotice'),txt=$('#patientDuplicateText');if(!reg||!box)return hidePatientDuplicate();const p=(readState().patients||[]).find(x=>x.id!==editingClinicalPatientId&&String(x.registrationNo||'')===reg);if(!p)return hidePatientDuplicate();box.hidden=false;box.dataset.patientId=p.id;if(txt)txt.textContent=`${patientDisplayLabel(p)} · 최근 수정 ${p.updatedAt||p.createdAt||'-'}`;}
  function hidePatientDuplicate(){const box=$('#patientDuplicateNotice');if(box){box.hidden=true;delete box.dataset.patientId;}}
  function openDuplicatePatient(goEpisode){
    const id=$('#patientDuplicateNotice')?.dataset.patientId,st=readState(),p=patientById(st,id);
    if(!p)return;
    hidePatientDuplicate();
    if(goEpisode){
      editingClinicalPatientId=null;
      resetBaselineForm();
      updatePatientMasterEditState(null);
      setClinicalValue('episodePatientSelect',p.id);
      renderEpisodeWorkspace(st);
      $('#episode-entry-step')?.scrollIntoView({behavior:'smooth'});
      return;
    }
    beginClinicalPatientEdit(p.id,true);
  }

  function patientOutcome(state,p){const eps=episodesForPatient(state,p.id);if(eps.some(e=>e.dischargeAlive==='dead'||e.events?.deathDate))return'dead';if(eps.some(e=>e.dischargeAlive==='alive'))return'alive';return'unknown';}
  function patientTags(state,p){return (state.assignments||[]).filter(a=>a.targetId===p.id).map(a=>(a.path||[a.tagName]).join(' → '));}
  function integratedFilteredPatients(state){
    let rows=[...(state.patients||[])];
    const q=($('#integratedPatientSearch')?.value||'').trim().toLowerCase(),ef=$('#integratedEcmoFilter')?.value||'',mf=$('#integratedEcmoModeFilter')?.value||'',of=$('#integratedOutcomeFilter')?.value||'',tf=$('#integratedTagFilter')?.value||'',cf=$('#integratedCsvFilter')?.value||'',sort=$('#integratedSort')?.value||'updated-desc';
    if(q)rows=rows.filter(p=>[p.initials,p.patientInitials,p.registrationNo?.slice(-4),p.birthDate].some(v=>String(v||'').toLowerCase().includes(q)));
    if(ef)rows=rows.filter(p=>(episodesForPatient(state,p.id).length>0)===(ef==='yes'));
    if(mf)rows=rows.filter(p=>episodesForPatient(state,p.id).some(e=>(e.details?.ecmoMode||'')===mf));
    if(of)rows=rows.filter(p=>patientOutcome(state,p)===of);
    if(tf)rows=rows.filter(p=>(state.assignments||[]).some(a=>a.targetId===p.id&&a.tagId===tf));
    if(cf)rows=rows.filter(p=>{const linked=(state.vitalFiles||[]).filter(f=>f.patientId===p.id).length;if(cf==='linked')return linked>0;if(cf==='none')return linked===0;return (state.vitalFiles||[]).some(f=>!f.patientId);});
    const uploadDate=p=>{const vals=(state.vitalFiles||[]).filter(f=>f.patientId===p.id).map(f=>f.uploadedAt||'').sort();return vals.at(-1)||'';};
    const cmp={
      'reg-asc':(a,b)=>String(a.registrationNo||'').localeCompare(String(b.registrationNo||'')),
      'birth-asc':(a,b)=>String(a.birthDate||'').localeCompare(String(b.birthDate||'')),
      'birth-desc':(a,b)=>String(b.birthDate||'').localeCompare(String(a.birthDate||'')),
      'ecmo-first':(a,b)=>episodesForPatient(state,b.id).length-episodesForPatient(state,a.id).length,
      'non-ecmo-first':(a,b)=>episodesForPatient(state,a.id).length-episodesForPatient(state,b.id).length,
      'dead-first':(a,b)=>(patientOutcome(state,b)==='dead')-(patientOutcome(state,a)==='dead'),
      'alive-first':(a,b)=>(patientOutcome(state,b)==='alive')-(patientOutcome(state,a)==='alive'),
      'upload-desc':(a,b)=>uploadDate(b).localeCompare(uploadDate(a)),
      'upload-asc':(a,b)=>uploadDate(a).localeCompare(uploadDate(b)),
      'updated-desc':(a,b)=>String(b.updatedAt||b.createdAt||'').localeCompare(String(a.updatedAt||a.createdAt||''))
    }[sort]; return rows.sort(cmp);
  }

  function renderIntegratedPatients(){const st=readState(),box=$('#integratedPatientList');if(!box)return;const pts=integratedFilteredPatients(st);$('#integratedPatientCount').textContent=`${pts.length}명`;if(!pts.length){box.innerHTML='<div class="empty-state"><strong>조건에 맞는 환자가 없습니다.</strong></div>';return;}if(!pts.some(p=>p.id===integratedSelectedPatientId))integratedSelectedPatientId=pts[0].id;box.innerHTML=pts.map(p=>{const eps=episodesForPatient(st,p.id),files=(st.vitalFiles||[]).filter(f=>f.patientId===p.id),out=patientOutcome(st,p),tags=patientTags(st,p);return `<article class="integrated-patient-card ${p.id===integratedSelectedPatientId?'selected':''}" data-integrated-patient="${p.id}"><div class="patient-card-head"><div><strong>${escapeHtml(p.initials||p.patientInitials||p.pseudoId||'이니셜 미입력')}</strong><div class="muted">${escapeHtml('')}${escapeHtml(patientMaskedRegistration(p.registrationNo))} · ${escapeHtml(p.birthDate||'생년월일 미입력')} · ${escapeHtml(p.sex||'성별 미입력')}</div></div><span class="badge ${out==='dead'?'red':out==='alive'?'green':'gray'}">${out==='dead'?'사망':out==='alive'?'생존':'미상'}</span></div><div class="patient-card-meta">${eps.length?badge(`ECMO ${eps.length}회`,'teal'):badge('비ECMO','gray')}${badge(`CSV ${files.length}개`,'blue')}${tags.slice(0,2).map(t=>badge(t,'gray')).join('')}</div></article>`;}).join('');$$('[data-integrated-patient]',box).forEach(card=>{card.addEventListener('click',()=>{integratedSelectedPatientId=card.dataset.integratedPatient;renderIntegratedWorkspace();});card.addEventListener('dragover',e=>{e.preventDefault();card.classList.add('drag-over');});card.addEventListener('dragleave',()=>card.classList.remove('drag-over'));card.addEventListener('drop',e=>{e.preventDefault();card.classList.remove('drag-over');matchFileToPatient(e.dataTransfer.getData('text/plain'),card.dataset.integratedPatient,'');});});}
  function renderIntegratedDetail() {
    const state = readState();
    const box = $('#integratedPatientDetail');
    const patient = patientById(state, integratedSelectedPatientId);
    if (!box) return;
    if (!patient) {
      box.innerHTML = '<div class="empty-state"><strong>좌측에서 환자를 선택하세요.</strong></div>';
      return;
    }
    $('#integratedSelectedPatient').textContent = patient.initials || patient.patientInitials || patientMaskedRegistration(patient.registrationNo);
    const episodes = episodesForPatient(state, patient.id);
    const files = (state.vitalFiles || []).filter(file => file.patientId === patient.id);
    const tags = patientTags(state, patient);
    const majorEventHtml = episodes.length ? episodes.map(episode => {
      const items = episodeMajorEventItems(episode);
      return `<article class="integrated-event-episode"><div class="integrated-event-head"><div><strong>${escapeHtml(episodeDisplayLabel(episode))}</strong><span>${escapeHtml(episode.events?.ecmoStartTime || '시작일 미입력')} → ${escapeHtml(episode.events?.ecmoFinishTime || '종료일 미입력')}</span></div><button class="btn ghost compact-btn" type="button" data-open-integrated-episode="${escapeHtml(episode.id)}">열기/수정</button></div><div class="registry-major-event-list">${items.length ? items.map(item => `<div class="registry-major-event-item"><i style="background:${escapeHtml(item.color)}"></i><div><strong>${escapeHtml(item.name)}</strong><time>${escapeHtml(formatEventDate(item.dateTime))}</time>${item.note ? `<p>${escapeHtml(item.note)}</p>` : ''}</div></div>`).join('') : '<div class="empty-state compact"><strong>저장된 주요 시간 이벤트가 없습니다.</strong></div>'}</div></article>`;
    }).join('') : '<span class="muted">ECMO episode 없음</span>';

    box.innerHTML = `<div class="patient-detail-section"><h4>기본정보</h4><div class="patient-detail-grid"><div class="detail-kv"><span>환자 이니셜</span><strong>${escapeHtml(patient.initials || patient.patientInitials || '-')}</strong></div><div class="detail-kv"><span>등록번호</span><strong>${escapeHtml(patientMaskedRegistration(patient.registrationNo))}</strong></div><div class="detail-kv"><span>입원일</span><strong>${escapeHtml(patient.admissionDate || patient.addmissionDate || '-')}</strong></div><div class="detail-kv"><span>생년월일/성별</span><strong>${escapeHtml(patient.birthDate || '-')} / ${escapeHtml(patient.sex || '-')}</strong></div><div class="detail-kv"><span>생존 상태</span><strong>${patientOutcome(state, patient) === 'dead' ? '사망' : patientOutcome(state, patient) === 'alive' ? '생존' : '미상'}</strong></div></div></div>
      <div class="patient-detail-section"><h4>연구 태그 및 분류</h4>${tags.length ? tags.map(tag => `<div class="tag-path-display">${escapeHtml(tag)}</div>`).join('') : '<span class="muted">적용된 태그 없음</span>'}</div>
      <div class="patient-detail-section"><h4>ECMO 에피소드</h4>${episodes.length ? episodes.map(episode => `<div class="episode-summary-row"><div><strong>${escapeHtml(episodeDisplayLabel(episode))}</strong><div class="muted">${escapeHtml(episode.events?.ecmoStartTime || '시작일 미입력')} → ${escapeHtml(episode.events?.ecmoFinishTime || '종료일 미입력')}</div></div><button class="btn ghost" data-open-integrated-episode="${escapeHtml(episode.id)}">열기/수정</button></div>`).join('') : '<span class="muted">ECMO episode 없음</span>'}</div>
      <div class="patient-detail-section"><div class="toolbar"><h4>ECMO 주요 시간 이벤트</h4><span class="badge blue">환자 선택 연동</span></div>${majorEventHtml}</div>
      <div class="patient-detail-section" data-patient-file-drop="${escapeHtml(patient.id)}"><h4>연결된 CSV</h4>${files.length ? files.map(file => `<div class="linked-file-row"><div><strong>${escapeHtml(file.name)}</strong><div class="muted">${escapeHtml(file.episodeId ? episodeDisplayLabel(episodeById(state, file.episodeId)) : '환자에만 연결')} · ${escapeHtml(file.uploadedAt || '-')}</div></div><div><a class="btn ghost" href="vital-detail.html">CSV 열기</a> <button class="btn ghost" data-change-match="${escapeHtml(file.id)}">매칭 변경</button> <button class="btn ghost" data-unlink-file="${escapeHtml(file.id)}">연결 해제</button></div></div>`).join('') : '<span class="muted">연결된 CSV 없음 · 우측 CSV를 이 영역으로 드래그하세요.</span>'}</div>`;

    $$('[data-open-integrated-episode]', box).forEach(button => button.addEventListener('click', () => {
      sessionStorage.setItem('excite_open_patient_id', patient.id);
      sessionStorage.setItem('excite_open_episode_id', button.dataset.openIntegratedEpisode);
      location.href = 'patient-upload.html';
    }));
    $$('[data-change-match]', box).forEach(button => button.addEventListener('click', () => openIntegratedMatchModal(button.dataset.changeMatch)));
    $$('[data-unlink-file]', box).forEach(button => button.addEventListener('click', () => {
      const nextState = patchState(current => {
        const file = (current.vitalFiles || []).find(item => item.id === button.dataset.unlinkFile);
        if (file) {
          file.patientId = '';
          file.episodeId = '';
          file.matchStatus = '미매칭';
        }
      });
      renderIntegratedWorkspace(nextState);
    }));
    const drop = $('[data-patient-file-drop]', box);
    drop?.addEventListener('dragover', event => event.preventDefault());
    drop?.addEventListener('drop', event => {
      event.preventDefault();
      openIntegratedMatchModal(event.dataTransfer.getData('text/plain'), patient.id);
    });
  }

  function suggestedPatientForFile(state,file){const token=String(file.caseId||file.name||'').replace(/\D/g,'');if(!token)return null;return (state.patients||[]).find(p=>{const reg=String(p.registrationNo||'').replace(/\D/g,'');return reg&&token.includes(reg);})||null;}
  function sameCsvDuplicateSignature(left,right){
    if(!left||!right)return false;
    const sameName=Boolean(left.name&&right.name&&left.name===right.name);
    const leftSize=Number(left.size||0),rightSize=Number(right.size||0);
    const sameSize=leftSize>0&&rightSize>0&&leftSize===rightSize;
    if(sameName&&(!leftSize||!rightSize||sameSize))return true;
    const sameCase=Boolean(left.caseId&&right.caseId&&left.caseId===right.caseId);
    const sameStart=Boolean(left.recordingStart&&right.recordingStart&&left.recordingStart===right.recordingStart);
    const sameEnd=Boolean(left.recordingEnd&&right.recordingEnd&&left.recordingEnd===right.recordingEnd);
    const sameDate=Boolean(left.recordingDate&&right.recordingDate&&left.recordingDate===right.recordingDate);
    return sameCase&&sameSize&&((sameStart&&sameEnd)||(!left.recordingStart&&!right.recordingStart&&sameDate));
  }
  function duplicateCsvMatches(state,file){return (state.vitalFiles||[]).filter(item=>item.id!==file.id&&sameCsvDuplicateSignature(file,item));}
  function duplicateCsvReason(file,matches){
    if(matches.some(item=>item.name&&item.name===file.name))return '동일 파일명·파일 크기';
    if(matches.some(item=>item.caseId&&file.caseId&&item.caseId===file.caseId&&item.recordingStart===file.recordingStart&&item.recordingEnd===file.recordingEnd))return '동일 case ID·기록 구간·파일 크기';
    return '동일 case ID·기록일·파일 크기';
  }
  function isDuplicateCsv(state,file){return duplicateCsvMatches(state,file).length>0;}
  function unmatchedCsvSearchText(file) {
    return [
      file?.name,
      file?.caseId,
      file?.uploadedAt,
      file?.recordingDate,
      file?.recordingStart,
      file?.recordingEnd,
      file?.monitorRoom,
      file?.monitorNumber,
      file?.monitorKey,
      file?.autoMatchStatus,
      file?.processStatus,
      file?.previewStatus
    ].filter(Boolean).join(' ').toLowerCase();
  }

  function deleteUnmatchedCsv(fileId, duplicateOnly = false) {
    const state = readState();
    const file = (state.vitalFiles || []).find(item => item.id === fileId);
    if (!file || file.patientId) return toast('매칭되지 않은 CSV만 이 목록에서 삭제할 수 있습니다.', 'yellow');
    const matches = duplicateCsvMatches(state, file);
    if (duplicateOnly && !matches.length) return toast('중복으로 확인된 CSV만 중복 삭제할 수 있습니다.', 'yellow');
    const duplicateReason = matches.length ? duplicateCsvReason(file, matches) : '';
    const comparison = matches.slice(0, 3).map(item => `• ${item.name || '-'} · ${item.uploadedAt || '-'}`).join('\n');
    const details = matches.length
      ? `\n중복 기준: ${duplicateReason}\n비교 기록:\n${comparison}`
      : `\n업로드 일시: ${file.uploadedAt || '-'}\n기록 구간: ${file.recordingStart || '-'} ~ ${file.recordingEnd || '-'}`;
    if (!confirm(`이 미매칭 CSV를 삭제할까요?\n\n삭제 대상: ${file.name || '-'}${details}\n\n업로드 및 미매칭 목록에서 함께 제거됩니다.`)) return;
    patchState(current => {
      current.vitalFiles = (current.vitalFiles || []).filter(item => item.id !== fileId);
      current.assignments = (current.assignments || []).filter(item => item.targetId !== fileId && item.fileId !== fileId);
      current.audit = Array.isArray(current.audit) ? current.audit : [];
      current.audit.unshift({
        id: uid('AUDIT'),
        time: nowText(),
        user: USER,
        action: matches.length ? 'duplicate csv delete' : 'unmatched csv delete',
        target: 'vital_file',
        description: `${file.name || fileId} · ${matches.length ? duplicateReason : '사용자 직접 삭제'} · 미매칭 CSV 삭제`,
        status: 'success'
      });
      current.audit = current.audit.slice(0, 200);
    });
    if (integratedMatchFileId === fileId) closeIntegratedMatchModal();
    renderIntegratedWorkspace();
    toast(matches.length ? '중복 미매칭 CSV를 삭제했습니다.' : '미매칭 CSV를 삭제했습니다.', 'teal');
  }

  function deleteDuplicateUnmatchedCsv(fileId) {
    deleteUnmatchedCsv(fileId, true);
  }

  function renderUnmatchedCsv() {
    const st = readState(), box = $('#integratedUnmatchedList');
    if (!box) return;
    const allFiles = (st.vitalFiles || []).filter(file => !file.patientId);
    const query = String($('#integratedUnmatchedSearch')?.value || '').trim().toLowerCase();
    const files = query ? allFiles.filter(file => unmatchedCsvSearchText(file).includes(query)) : allFiles;
    const count = $('#integratedUnmatchedCount');
    if (count) count.textContent = query ? `${files.length}/${allFiles.length}개` : `${allFiles.length}개`;
    box.innerHTML = files.length ? files.map(file => {
      const suggested = suggestedPatientForFile(st, file);
      const matches = duplicateCsvMatches(st, file);
      const duplicate = matches.length > 0;
      const duplicateReason = duplicate ? duplicateCsvReason(file, matches) : '';
      const monitorText = [file.monitorRoom, file.monitorNumber].filter(Boolean).join(' ') || file.monitorKey || '';
      return `<article class="unmatched-csv-card" draggable="true" data-unmatched-file="${file.id}">
        <div class="csv-card-head"><div><strong>${escapeHtml(file.name)}</strong><div class="muted">${escapeHtml(file.uploadedAt || '-')} · ${escapeHtml(file.caseId || '환자번호 없음')}</div></div>${badge(duplicate ? '중복 확인' : '미매칭', duplicate ? 'red' : 'yellow')}</div>
        <div class="csv-card-meta">${badge(`${file.rowCount || file.featureRowCount || 0}행`, 'gray')}${badge(file.recordingStart && file.recordingEnd ? `${file.recordingStart}~${file.recordingEnd}` : '기간 미확인', 'gray')}${monitorText ? badge(monitorText, 'blue') : ''}</div>
        <div class="muted" style="margin-top:8px">실패 사유: ${escapeHtml(duplicate ? `${duplicateReason} 기록 ${matches.length}개 존재` : (!file.caseId ? '환자번호 없음' : '환자 또는 episode 확인 필요'))}</div>
        ${duplicate ? `<div class="duplicate-csv-compare"><strong>중복 비교</strong>${matches.slice(0, 2).map(item => `<span>${escapeHtml(item.name || '-')} · ${escapeHtml(item.uploadedAt || '-')}</span>`).join('')}</div>` : ''}
        ${suggested ? `<div class="tag-path-display" style="margin-top:8px">예상 환자: ${escapeHtml(patientDisplayLabel(suggested))} · 일치도 높음</div>` : ''}
        <div class="unmatched-csv-actions"><button class="btn secondary" data-open-match-modal="${file.id}">환자 선택 후 매칭</button>${duplicate ? `<button class="btn danger" type="button" data-delete-duplicate-csv="${file.id}">중복 CSV 삭제</button>` : `<button class="btn danger" type="button" data-delete-unmatched-csv="${file.id}">CSV 삭제</button>`}</div>
      </article>`;
    }).join('') : `<div class="empty-state"><strong>${query ? '검색 조건에 맞는 미매칭 CSV가 없습니다.' : '미매칭 CSV가 없습니다.'}</strong>${query ? '<span>파일명, 환자번호, 기록일 또는 모니터명을 다시 입력해보세요.</span>' : ''}</div>`;
    $$('[data-unmatched-file]', box).forEach(card => card.addEventListener('dragstart', event => event.dataTransfer.setData('text/plain', card.dataset.unmatchedFile)));
    $$('[data-open-match-modal]', box).forEach(button => button.addEventListener('click', () => openIntegratedMatchModal(button.dataset.openMatchModal)));
    $$('[data-delete-duplicate-csv]', box).forEach(button => button.addEventListener('click', event => { event.stopPropagation(); deleteDuplicateUnmatchedCsv(button.dataset.deleteDuplicateCsv); }));
    $$('[data-delete-unmatched-csv]', box).forEach(button => button.addEventListener('click', event => { event.stopPropagation(); deleteUnmatchedCsv(button.dataset.deleteUnmatchedCsv); }));
  }
  function renderIntegratedWorkspace(){renderIntegratedPatients();renderIntegratedDetail();renderUnmatchedCsv();}
  function openIntegratedMatchModal(fileId,patientId=''){integratedMatchFileId=fileId;const st=readState(),f=(st.vitalFiles||[]).find(x=>x.id===fileId);if(!f)return;$('#integratedMatchFileName').value=f.name||'';const psel=$('#integratedMatchPatientSelect');psel.innerHTML=option('','환자 선택')+(st.patients||[]).map(p=>option(p.id,patientDisplayLabel(p))).join('');const suggested=suggestedPatientForFile(st,f);psel.value=patientId||suggested?.id||integratedSelectedPatientId||'';renderIntegratedEpisodeOptions();$('#integratedMatchModal').classList.add('open');}
  function renderIntegratedEpisodeOptions(){const st=readState(),pid=$('#integratedMatchPatientSelect')?.value||'',sel=$('#integratedMatchEpisodeSelect'),eps=episodesForPatient(st,pid);if(sel)sel.innerHTML=option('','episode 선택 안 함')+eps.map(e=>option(e.id,episodeDisplayLabel(e))).join('');}
  function closeIntegratedMatchModal(){$('#integratedMatchModal')?.classList.remove('open');integratedMatchFileId=null;}
  function matchFileToPatient(fileId,patientId,episodeId){if(!fileId||!patientId)return;const st=patchState(s=>{const f=(s.vitalFiles||[]).find(x=>x.id===fileId);if(f){f.patientId=patientId;f.episodeId=episodeId||'';f.matchStatus='매칭 완료';f.matchedAt=nowText();f.matchNote=($('#integratedMatchNote')?.value||'').trim();}});integratedSelectedPatientId=patientId;closeIntegratedMatchModal();renderIntegratedWorkspace(st);toast('CSV를 환자/episode에 연결했습니다.');}
  function initIntegratedPatientMatching(){const tagFilter=$('#integratedTagFilter');if(tagFilter){const st=readState();tagFilter.innerHTML=option('','전체 태그')+(st.tags||[]).map(t=>option(t.id,t.name)).join('');}['integratedPatientSearch','integratedEcmoFilter','integratedEcmoModeFilter','integratedOutcomeFilter','integratedTagFilter','integratedCsvFilter','integratedSort','integratedUnmatchedSearch'].forEach(id=>$('#'+id)?.addEventListener('input',renderIntegratedWorkspace));$('#integratedResetBtn')?.addEventListener('click',()=>{setClinicalValue('integratedPatientSearch','');setClinicalValue('integratedUnmatchedSearch','');['integratedEcmoFilter','integratedEcmoModeFilter','integratedOutcomeFilter','integratedTagFilter','integratedCsvFilter'].forEach(id=>setClinicalValue(id,''));setClinicalValue('integratedSort','updated-desc');renderIntegratedWorkspace();});$('#integratedMatchPatientSelect')?.addEventListener('change',renderIntegratedEpisodeOptions);$('#integratedMatchModalClose')?.addEventListener('click',closeIntegratedMatchModal);$('#integratedMatchSaveBtn')?.addEventListener('click',()=>{const pid=$('#integratedMatchPatientSelect').value;if(!pid)return toast('환자를 선택하세요.','yellow');matchFileToPatient(integratedMatchFileId,pid,$('#integratedMatchEpisodeSelect').value);});renderIntegratedWorkspace();}

  /* 2026-07 linked CSV order, collapsible preview, result actions, and ECMO calendar */
  let linkedFileDragId = null;
  let selectedAnalysisResultId = null;
  let analysisEditingId = null;
  let registryCalendarAnchor = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
  let registryCalendarFocusDate = null;
  let registrySelectedPatientId = '';
  let registrySelectedEpisodeId = '';

  function safeDate(value) {
    if (!value) return null;
    const normalized = String(value).trim().replace(' ', 'T');
    const date = new Date(normalized);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function dateKey(date) {
    if (!(date instanceof Date) || Number.isNaN(date.getTime())) return '';
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  }

  function toDatetimeLocalValue(value) {
    const date = safeDate(value);
    if (!date) return '';
    const pad = n => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function linkedFilesForPatient(state, patientId) {
    return (state.vitalFiles || []).filter(file => file.patientId === patientId).sort((a, b) => {
      const ao = Number.isFinite(Number(a.linkedOrder)) ? Number(a.linkedOrder) : 999999;
      const bo = Number.isFinite(Number(b.linkedOrder)) ? Number(b.linkedOrder) : 999999;
      if (ao !== bo) return ao - bo;
      const at = safeDate(a.matchedTime || a.recordingStart || a.uploadedAt)?.getTime() || 0;
      const bt = safeDate(b.matchedTime || b.recordingStart || b.uploadedAt)?.getTime() || 0;
      if (at !== bt) return at - bt;
      return String(a.name || '').localeCompare(String(b.name || ''));
    });
  }

  function nextLinkedOrder(state, patientId) {
    const orders = (state.vitalFiles || []).filter(file => file.patientId === patientId).map(file => Number(file.linkedOrder || 0));
    return orders.length ? Math.max(...orders, 0) + 1 : 1;
  }

  function linkedEpisodeOptions(state, patientId, selectedId) {
    return option('', '환자에만 연결') + episodesForPatient(state, patientId).map(ep => option(ep.id, episodeDisplayLabel(ep), ep.id === selectedId)).join('');
  }

  function saveLinkedFileMapping(fileId) {
    const row = document.querySelector(`[data-linked-file-row="${fileId}"]`);
    if (!row) return;
    const time = row.querySelector('[data-linked-time]')?.value || '';
    const label = row.querySelector('[data-linked-label]')?.value.trim() || '';
    const episodeId = row.querySelector('[data-linked-episode]')?.value || '';
    patchState(state => {
      const file = (state.vitalFiles || []).find(item => item.id === fileId);
      if (!file) return;
      file.matchedTime = time;
      file.timepointLabel = label;
      file.episodeId = episodeId;
      file.matchStatus = '매칭 완료';
      file.updatedAt = nowText();
    });
    renderIntegratedDetail();
    toast('CSV의 시간 순서와 매칭 정보를 저장했습니다.');
  }

  function reorderLinkedFiles(patientId, sourceId, targetId) {
    if (!patientId || !sourceId || !targetId || sourceId === targetId) return;
    patchState(state => {
      const ordered = linkedFilesForPatient(state, patientId);
      const from = ordered.findIndex(file => file.id === sourceId);
      const to = ordered.findIndex(file => file.id === targetId);
      if (from < 0 || to < 0) return;
      const [moved] = ordered.splice(from, 1);
      ordered.splice(to, 0, moved);
      ordered.forEach((file, index) => { file.linkedOrder = index + 1; });
    });
    renderIntegratedDetail();
    toast('연결된 CSV 순서를 변경했습니다.');
  }

  function renderIntegratedDetail() {
    const state = readState();
    const box = $('#integratedPatientDetail');
    const patient = patientById(state, integratedSelectedPatientId);
    if (!box) return;
    if (!patient) {
      box.innerHTML = '<div class="empty-state"><strong>좌측에서 환자를 선택하세요.</strong></div>';
      return;
    }
    $('#integratedSelectedPatient').textContent = patient.initials || patient.patientInitials || patientMaskedRegistration(patient.registrationNo);
    const episodes = episodesForPatient(state, patient.id);
    const files = linkedFilesForPatient(state, patient.id);
    const tags = patientTags(state, patient);
    box.innerHTML = `<div class="patient-detail-section"><h4>기본정보</h4><div class="patient-detail-grid"><div class="detail-kv"><span>환자 이니셜</span><strong>${escapeHtml(patient.initials || patient.patientInitials || '-')}</strong></div><div class="detail-kv"><span>등록번호</span><strong>${escapeHtml(patientMaskedRegistration(patient.registrationNo))}</strong></div><div class="detail-kv"><span>생년월일/성별</span><strong>${escapeHtml(patient.birthDate || '-')} / ${escapeHtml(patient.sex || '-')}</strong></div><div class="detail-kv"><span>생존 상태</span><strong>${patientOutcome(state, patient) === 'dead' ? '사망' : patientOutcome(state, patient) === 'alive' ? '생존' : '미상'}</strong></div></div></div>
      <div class="patient-detail-section"><h4>연구 태그 및 분류</h4>${tags.length ? tags.map(tag => `<div class="tag-path-display">${escapeHtml(tag)}</div>`).join('') : '<span class="muted">적용된 태그 없음</span>'}</div>
      <div class="patient-detail-section"><h4>ECMO 에피소드</h4>${episodes.length ? episodes.map(ep => `<div class="episode-summary-row"><div><strong>${escapeHtml(episodeDisplayLabel(ep))}</strong><div class="muted">${escapeHtml(ep.events?.ecmoStartTime || '시작일 미입력')} → ${escapeHtml(ep.events?.ecmoFinishTime || '종료일 미입력')}</div></div><button class="btn ghost" data-open-integrated-episode="${escapeHtml(ep.id)}">열기/수정</button></div>`).join('') : '<span class="muted">ECMO episode 없음</span>'}</div>
      <div class="patient-detail-section linked-csv-section" data-patient-file-drop="${escapeHtml(patient.id)}">
        <div class="toolbar"><div><h4>연결된 CSV 시간 순서</h4><p class="muted">왼쪽 손잡이로 위·아래 이동하고, 기준 일시와 시점명을 입력한 뒤 episode에 연결하세요.</p></div>${badge(`${files.length}개`, 'blue')}</div>
        <div class="linked-csv-sort-list">${files.length ? files.map((file, index) => `<article class="linked-csv-sort-row" draggable="true" data-linked-file-row="${escapeHtml(file.id)}">
          <div class="linked-csv-drag"><button type="button" class="drag-handle" title="드래그하여 순서 변경">⋮⋮</button><span>${index + 1}</span></div>
          <div class="linked-csv-content"><div class="linked-csv-title"><div><strong>${escapeHtml(file.name)}</strong><div class="muted">${escapeHtml(file.uploadedAt || '-')} · ${escapeHtml(file.caseId || 'case ID 없음')}</div></div>${badge(file.timepointLabel || '시점 미입력', file.timepointLabel ? 'teal' : 'gray')}</div>
            <div class="linked-csv-mapping-grid"><div class="field"><label>기준 일시</label><input class="input" type="datetime-local" data-linked-time value="${escapeHtml(toDatetimeLocalValue(file.matchedTime || file.recordingStart))}"></div><div class="field"><label>시점 이름</label><input class="input" data-linked-label value="${escapeHtml(file.timepointLabel || '')}" placeholder="예: Pre ECMO, 6시간 후"></div><div class="field"><label>ECMO episode</label><select data-linked-episode>${linkedEpisodeOptions(state, patient.id, file.episodeId)}</select></div></div>
          </div>
          <div class="linked-csv-actions"><button class="btn teal" type="button" data-save-linked-file="${escapeHtml(file.id)}">순서·매칭 저장</button><a class="btn ghost" href="vital-detail.html">CSV 열기</a><button class="btn ghost" type="button" data-change-match="${escapeHtml(file.id)}">환자 변경</button><button class="btn ghost danger-text" type="button" data-unlink-file="${escapeHtml(file.id)}">연결 해제</button></div>
        </article>`).join('') : '<div class="empty-state"><strong>연결된 CSV가 없습니다.</strong><span>우측 CSV를 이 영역으로 드래그하세요.</span></div>'}</div>
      </div>`;

    $$('[data-open-integrated-episode]', box).forEach(button => button.addEventListener('click', () => {
      sessionStorage.setItem('excite_open_patient_id', patient.id);
      sessionStorage.setItem('excite_open_episode_id', button.dataset.openIntegratedEpisode);
      location.href = 'patient-upload.html';
    }));
    $$('[data-save-linked-file]', box).forEach(button => button.addEventListener('click', () => saveLinkedFileMapping(button.dataset.saveLinkedFile)));
    $$('[data-change-match]', box).forEach(button => button.addEventListener('click', () => openIntegratedMatchModal(button.dataset.changeMatch, patient.id)));
    $$('[data-unlink-file]', box).forEach(button => button.addEventListener('click', () => {
      if (!confirm('이 CSV와 환자/episode 연결을 해제할까요?')) return;
      patchState(state => {
        const file = (state.vitalFiles || []).find(item => item.id === button.dataset.unlinkFile);
        if (file) {
          file.patientId = '';
          file.episodeId = '';
          file.matchStatus = '미매칭';
          file.linkedOrder = null;
        }
        linkedFilesForPatient(state, patient.id).forEach((item, index) => { item.linkedOrder = index + 1; });
      });
      renderIntegratedWorkspace();
    }));
    $$('.linked-csv-sort-row', box).forEach(row => {
      row.addEventListener('dragstart', event => {
        if (!event.target.closest('.drag-handle')) { event.preventDefault(); return; }
        linkedFileDragId = row.dataset.linkedFileRow;
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/linked-csv', linkedFileDragId);
        row.classList.add('dragging');
      });
      row.addEventListener('dragend', () => { row.classList.remove('dragging'); linkedFileDragId = null; });
      row.addEventListener('dragover', event => { event.preventDefault(); row.classList.add('drag-over'); });
      row.addEventListener('dragleave', () => row.classList.remove('drag-over'));
      row.addEventListener('drop', event => {
        event.preventDefault();
        row.classList.remove('drag-over');
        const sourceId = event.dataTransfer.getData('text/linked-csv') || linkedFileDragId;
        reorderLinkedFiles(patient.id, sourceId, row.dataset.linkedFileRow);
      });
    });
    const drop = $('[data-patient-file-drop]', box);
    drop?.addEventListener('dragover', event => event.preventDefault());
    drop?.addEventListener('drop', event => {
      const unmatchedId = event.dataTransfer.getData('text/plain');
      if (!unmatchedId) return;
      event.preventDefault();
      openIntegratedMatchModal(unmatchedId, patient.id);
    });
  }

  function matchFileToPatient(fileId, patientId, episodeId) {
    if (!fileId || !patientId) return;
    patchState(state => {
      const file = (state.vitalFiles || []).find(item => item.id === fileId);
      if (!file) return;
      const patientChanged = file.patientId !== patientId;
      const nextOrder = nextLinkedOrder(state, patientId);
      file.patientId = patientId;
      file.episodeId = episodeId || '';
      file.matchStatus = '매칭 완료';
      file.matchSource = 'manual';
      file.monitorAssignmentId = '';
      file.autoMatchStatus = '수동 매칭';
      file.matchedAt = nowText();
      file.matchNote = ($('#integratedMatchNote')?.value || '').trim();
      if (patientChanged || !Number.isFinite(Number(file.linkedOrder))) file.linkedOrder = nextOrder;
      if (!file.matchedTime && file.recordingStart) file.matchedTime = toDatetimeLocalValue(file.recordingStart);
    });
    integratedSelectedPatientId = patientId;
    closeIntegratedMatchModal();
    renderIntegratedWorkspace();
    toast('CSV를 환자/episode에 연결했습니다. 연결된 CSV 목록에서 시간 순서를 조정할 수 있습니다.');
  }

  function initAnalysisPreviewPage() {
    const button = $('#analysisPreviewToggle');
    const content = $('#analysisPreviewContent');
    if (!button || !content) return;
    const key = 'excite_analysis_preview_collapsed';
    const apply = collapsed => {
      content.classList.toggle('collapsed', collapsed);
      button.textContent = collapsed ? '미리보기 펼치기' : '미리보기 접기';
      button.setAttribute('aria-expanded', String(!collapsed));
    };
    apply(localStorage.getItem(key) === '1');
    button.addEventListener('click', () => {
      const collapsed = !content.classList.contains('collapsed');
      localStorage.setItem(key, collapsed ? '1' : '0');
      apply(collapsed);
    });
  }

  function analysisFiles(state, analysis) {
    const explicitIds = [analysis.sourceAId].filter(Boolean);
    let files = (state.vitalFiles || []).filter(file => file.uploadStatus !== '오류');
    if (explicitIds.length) files = files.filter(file => explicitIds.includes(file.id));
    else if (analysis.tagId) files = files.filter(file => (file.tagIds || []).includes(analysis.tagId));
    if (analysis.patientId) files = files.filter(file => file.patientId === analysis.patientId);
    return files;
  }


  function analysisGraphSvg(analysis, state = readState()) {
    const width = 920, height = 430, left = 72, right = 24, top = 72, bottom = 62;
    const series = analysisGraphSeries(state, analysis);
    const title = analysis.name || '분석 결과';
    const subtitle = `${analysis.signal || analysis.y || '신호 미선택'} · ${analysis.scopeLabel || analysis.scope || '분석 범위 미선택'} · ${analysis.method || '방법 미선택'}`;
    if (!series.length) {
      return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(title)}"><rect width="100%" height="100%" fill="#ffffff"/><text x="48" y="48" font-size="22" font-weight="800" fill="#0b1f3a">${escapeHtml(title)}</text><text x="48" y="75" font-size="13" fill="#64748b">${escapeHtml(subtitle)}</text><rect x="48" y="104" width="824" height="250" rx="18" fill="#f8fafc" stroke="#dbe2ee" stroke-dasharray="7 7"/><text x="460" y="218" text-anchor="middle" font-size="20" font-weight="800" fill="#475569">다운로드할 실제 그래프 데이터가 없습니다.</text><text x="460" y="250" text-anchor="middle" font-size="13" fill="#64748b">분석 엔진 또는 CSV preview data가 연결되면 이 영역에 그래프가 표시됩니다.</text><text x="48" y="398" font-size="12" fill="#94a3b8">EXCITE plus · ${escapeHtml(analysis.createdAt || '')}</text></svg>`;
    }
    const all = series.flatMap(item => item.points);
    const xs = all.map(point => Number(point.minute));
    const ys = all.map(point => Number(point.value));
    let xMin = Math.min(...xs), xMax = Math.max(...xs), yMin = Math.min(...ys), yMax = Math.max(...ys);
    if (xMin === xMax) xMax = xMin + 1;
    if (yMin === yMax) { yMin -= 1; yMax += 1; }
    const yPad = (yMax - yMin) * .1;
    yMin -= yPad; yMax += yPad;
    const sx = x => left + ((x - xMin) / (xMax - xMin)) * (width - left - right);
    const sy = y => top + (1 - ((y - yMin) / (yMax - yMin))) * (height - top - bottom);
    const palette = ['#0b8f8a', '#1d5d9b', '#6d5dfc', '#f59e0b', '#dc2626', '#475569'];
    const yTicks = Array.from({ length: 5 }, (_, index) => yMin + ((yMax - yMin) * index / 4));
    const xTicks = Array.from({ length: 5 }, (_, index) => xMin + ((xMax - xMin) * index / 4));
    const paths = series.map((item, index) => {
      const d = item.points.map((point, pointIndex) => `${pointIndex ? 'L' : 'M'}${sx(point.minute).toFixed(1)},${sy(point.value).toFixed(1)}`).join(' ');
      return `<path d="${d}" fill="none" stroke="${palette[index % palette.length]}" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>`;
    }).join('');
    const legends = series.map((item, index) => `<g transform="translate(${left + index * 132},54)"><line x1="0" y1="0" x2="20" y2="0" stroke="${palette[index % palette.length]}" stroke-width="4"/><text x="26" y="4" font-size="11" fill="#475569">${escapeHtml(String(item.name).slice(0, 16))}</text></g>`).join('');
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(title)}"><rect width="100%" height="100%" fill="#ffffff"/><text x="${left}" y="30" font-size="21" font-weight="800" fill="#0b1f3a">${escapeHtml(title)}</text><text x="${left}" y="50" font-size="12" fill="#64748b">${escapeHtml(subtitle)}</text>${legends}${yTicks.map(tick => `<line x1="${left}" x2="${width-right}" y1="${sy(tick).toFixed(1)}" y2="${sy(tick).toFixed(1)}" stroke="#e2e8f0"/><text x="${left-12}" y="${(sy(tick)+4).toFixed(1)}" text-anchor="end" font-size="11" fill="#64748b">${tick.toFixed(1)}</text>`).join('')}${xTicks.map(tick => `<text x="${sx(tick).toFixed(1)}" y="${height-28}" text-anchor="middle" font-size="11" fill="#64748b">${Math.round(tick)}</text>`).join('')}<line x1="${left}" x2="${left}" y1="${top}" y2="${height-bottom}" stroke="#94a3b8"/><line x1="${left}" x2="${width-right}" y1="${height-bottom}" y2="${height-bottom}" stroke="#94a3b8"/>${paths}<text x="${(left+width-right)/2}" y="${height-8}" text-anchor="middle" font-size="12" fill="#475569">${escapeHtml(analysis.x || '시간')}</text><text transform="translate(18 ${(top+height-bottom)/2}) rotate(-90)" text-anchor="middle" font-size="12" fill="#475569">${escapeHtml(analysis.signal || analysis.y || '값')}</text></svg>`;
  }

  function sanitizeFilename(value) {
    return String(value || 'analysis_graph').replace(/[\\/:*?"<>|]+/g, '_').replace(/\s+/g, '_').slice(0, 80);
  }

  function downloadAnalysisGraph(analysisId) {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === analysisId);
    if (!analysis) return toast('분석 결과를 찾을 수 없습니다.', 'yellow');
    const svg = analysisGraphSvg(analysis, state);
    const svgBlob = new Blob([svg], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const image = new Image();
    image.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = 1840;
      canvas.height = 860;
      const context = canvas.getContext('2d');
      context.fillStyle = '#ffffff';
      context.fillRect(0, 0, canvas.width, canvas.height);
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      canvas.toBlob(blob => {
        if (!blob) return downloadText(`${sanitizeFilename(analysis.name)}.svg`, svg, 'image/svg+xml;charset=utf-8');
        const pngUrl = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = pngUrl;
        anchor.download = `${sanitizeFilename(analysis.name)}.png`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(pngUrl);
      }, 'image/png');
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      downloadText(`${sanitizeFilename(analysis.name)}.svg`, svg, 'image/svg+xml;charset=utf-8');
    };
    image.src = url;
  }

  function renderAnalysisResultDetail(analysisId) {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === analysisId);
    const detail = $('#analysisResultDetail');
    const environment = $('#analysisEnvironmentRecord');
    if (!detail || !environment) return;
    if (!analysis) {
      $('#selectedAnalysisBadge').textContent = '선택 없음';
      detail.innerHTML = '<div class="empty-state"><strong>표시할 결과가 없습니다.</strong></div>';
      return;
    }
    selectedAnalysisResultId = analysis.id;
    $('#selectedAnalysisBadge').textContent = analysis.name;
    const files = analysisFiles(state, analysis);
    const modelFormula = analysis.model ? `${analysis.signal || 'outcome'} ~ ${analysis.model.fixedEffects || 'time'}${analysis.model.interactions ? ' + ' + analysis.model.interactions : ''}${analysis.model.covariates ? ' + ' + analysis.model.covariates : ''}` : `${analysis.y || analysis.signal || 'y'} ~ ${analysis.x || 'time'}${analysis.group && analysis.group !== '그룹 없음' ? ' + ' + analysis.group : ''}`;
    detail.innerHTML = `<div class="analysis-detail-summary"><div class="detail-kv"><span>분석 범위</span><strong>${escapeHtml(analysis.scopeLabel || analysis.scope || '-')}</strong></div><div class="detail-kv"><span>신호</span><strong>${escapeHtml(analysis.signal || analysis.y || '-')}</strong></div><div class="detail-kv"><span>분석 방법</span><strong>${escapeHtml(analysis.method || '-')}</strong></div><div class="detail-kv"><span>연결 파일</span><strong>${files.length}개</strong></div></div><div class="analysis-result-graph">${analysisGraphSvg(analysis, state)}</div>${analysis.note ? `<div class="callout"><strong>비고</strong><br>${escapeHtml(analysis.note)}</div>` : ''}`;
    environment.innerHTML = `<dl class="kv"><dt>Python</dt><dd>${escapeHtml(analysis.pythonVersion || '분석 엔진 연결 후 기록')}</dd><dt>패키지</dt><dd>${escapeHtml(analysis.packageVersions || '분석 엔진 연결 후 기록')}</dd><dt>모델식</dt><dd>${escapeHtml(modelFormula)}</dd><dt>정렬/간격</dt><dd>${escapeHtml(analysis.preprocessing ? `${analysis.preprocessing.alignment || '-'} / ${analysis.preprocessing.resample || '-'}` : '-')}</dd><dt>연구/태그</dt><dd>${escapeHtml(analysis.projectName || analysis.tagName || '-')}</dd><dt>생성일</dt><dd>${escapeHtml(analysis.createdAt || '-')}</dd><dt>최근 수정</dt><dd>${escapeHtml(analysis.updatedAt || '-')}</dd></dl>`;
  }

  function renderAnalysisResults() {
    const state = readState();
    const body = $('#analysisResultBody') || cardByHeading('분석 결과 목록')?.querySelector('tbody');
    if (!body) return;
    if (!(state.analyses || []).length) {
      setTableEmpty(body, 8, '아직 저장된 분석 결과가 없습니다.', '통계 분석 화면에서 분석 설정을 저장하세요.');
      renderAnalysisResultDetail(null);
      return;
    }
    if (!selectedAnalysisResultId || !(state.analyses || []).some(item => item.id === selectedAnalysisResultId)) selectedAnalysisResultId = state.analyses[0].id;
    body.innerHTML = state.analyses.map(analysis => {
      const files = analysisFiles(state, analysis);
      const patients = new Set(files.map(file => file.patientId).filter(Boolean)).size;
      return `<tr class="${analysis.id === selectedAnalysisResultId ? 'selected-result-row' : ''}"><td>${escapeHtml(analysis.id)}</td><td><strong>${escapeHtml(analysis.name)}</strong>${analysis.note ? `<div class="muted">${escapeHtml(analysis.note)}</div>` : ''}</td><td>${escapeHtml(analysis.projectName || analysis.tagName || '-')}<br><span class="muted">${escapeHtml(analysis.scopeLabel || analysis.scope || '-')}</span></td><td><strong>${escapeHtml(analysis.signal || analysis.y || '-')}</strong><br><span class="muted">${escapeHtml(analysis.method || '-')}</span></td><td>${patients}명</td><td>${files.length}개</td><td>${badge(analysis.status || '설정 저장됨', analysis.status === '분석 완료' ? 'green' : analysis.status === '확인 필요' ? 'yellow' : 'blue')}</td><td><div class="analysis-result-actions"><button class="btn ghost" type="button" data-analysis-detail="${escapeHtml(analysis.id)}">상세</button><button class="btn ghost" type="button" data-analysis-edit="${escapeHtml(analysis.id)}">수정</button><button class="btn ghost" type="button" data-analysis-download="${escapeHtml(analysis.id)}">그래프 다운로드</button><button class="btn ghost danger-text" type="button" data-analysis-delete="${escapeHtml(analysis.id)}">삭제</button></div></td></tr>`;
    }).join('');
    $$('[data-analysis-detail]', body).forEach(button => button.addEventListener('click', () => { renderAnalysisResultDetail(button.dataset.analysisDetail); renderAnalysisResults(); }));
    $$('[data-analysis-edit]', body).forEach(button => button.addEventListener('click', () => openAnalysisEditModal(button.dataset.analysisEdit)));
    $$('[data-analysis-download]', body).forEach(button => button.addEventListener('click', () => downloadAnalysisGraph(button.dataset.analysisDownload)));
    $$('[data-analysis-delete]', body).forEach(button => button.addEventListener('click', () => deleteAnalysisResult(button.dataset.analysisDelete)));
    renderAnalysisResultDetail(selectedAnalysisResultId);
  }

  function openAnalysisEditModal(analysisId) {
    const analysis = (readState().analyses || []).find(item => item.id === analysisId);
    if (!analysis) return;
    analysisEditingId = analysisId;
    $('#analysisEditName').value = analysis.name || '';
    $('#analysisEditMethod').value = analysis.method || '';
    $('#analysisEditStatus').value = analysis.status || '설정 저장됨';
    $('#analysisEditNote').value = analysis.note || '';
    $('#analysisEditModal').classList.add('open');
  }

  function closeAnalysisEditModal() {
    $('#analysisEditModal')?.classList.remove('open');
    analysisEditingId = null;
  }

  function saveAnalysisResultEdit() {
    if (!analysisEditingId) return;
    const name = $('#analysisEditName')?.value.trim();
    if (!name) return toast('분석명을 입력하세요.', 'yellow');
    patchState(state => {
      const analysis = (state.analyses || []).find(item => item.id === analysisEditingId);
      if (!analysis) return;
      analysis.name = name;
      analysis.method = $('#analysisEditMethod')?.value.trim() || analysis.method;
      analysis.status = $('#analysisEditStatus')?.value || analysis.status;
      analysis.note = $('#analysisEditNote')?.value.trim() || '';
      analysis.updatedAt = nowText();
    });
    selectedAnalysisResultId = analysisEditingId;
    closeAnalysisEditModal();
    renderAnalysisResults();
    toast('분석 결과 정보를 수정했습니다.');
  }

  function deleteAnalysisResult(analysisId) {
    const analysis = (readState().analyses || []).find(item => item.id === analysisId);
    if (!analysis || !confirm(`“${analysis.name}” 분석 결과를 삭제할까요?`)) return;
    patchState(state => { state.analyses = (state.analyses || []).filter(item => item.id !== analysisId); });
    if (selectedAnalysisResultId === analysisId) selectedAnalysisResultId = null;
    renderAnalysisResults();
    toast('분석 결과를 삭제했습니다.', 'gray');
  }

  function initAnalysisResults() {
    $('#analysisResultRefreshBtn')?.addEventListener('click', renderAnalysisResults);
    $('#analysisEditCloseBtn')?.addEventListener('click', closeAnalysisEditModal);
    $('#analysisEditSaveBtn')?.addEventListener('click', saveAnalysisResultEdit);
    $('#analysisEditModal')?.addEventListener('click', event => { if (event.target.id === 'analysisEditModal') closeAnalysisEditModal(); });
    renderAnalysisResults();
  }

  function episodeDateRange(episode) {
    const start = safeDate(episode?.events?.ecmoStartTime || episode?.ecmoStartTime || episode?.startTime || episode?.startDate);
    const end = safeDate(episode?.events?.ecmoFinishTime || episode?.ecmoFinishTime || episode?.endTime || episode?.endDate) || start;
    if (!start) return null;
    const dayStart = new Date(start.getFullYear(), start.getMonth(), start.getDate());
    const dayEndRaw = end || start;
    const dayEnd = new Date(dayEndRaw.getFullYear(), dayEndRaw.getMonth(), dayEndRaw.getDate());
    return { start: dayStart, end: dayEnd < dayStart ? dayStart : dayEnd };
  }

  function assignmentTagForTarget(state, targetIds) {
    const assignment = (state.assignments || []).find(item => targetIds.includes(item.targetId) && item.tagId);
    if (!assignment) return null;
    return (state.tags || []).find(tag => tag.id === assignment.tagId) || (state.tagTrees || []).find(node => node.id === assignment.tagId && node.type === 'tag') || { id: assignment.tagId, name: assignment.tagName || '연구 태그', color: '#0b8f8a' };
  }

  function episodeCalendarTag(state, episode, patient) {
    let tag = assignmentTagForTarget(state, [episode.id, patient?.id].filter(Boolean));
    if (tag) return tag;
    const linked = (state.vitalFiles || []).filter(file => file.episodeId === episode.id || (!file.episodeId && file.patientId === patient?.id));
    const tagId = linked.flatMap(file => file.tagIds || [])[0];
    tag = (state.tags || []).find(item => item.id === tagId) || (state.tagTrees || []).find(node => node.id === tagId && node.type === 'tag');
    return tag || { id: 'untagged', name: '태그 미지정', color: '#66768c' };
  }

  function monitorCalendarColor(room) {
    const palette = ['#7c3aed', '#c2410c', '#0369a1', '#be123c', '#4d7c0f', '#0f766e', '#a16207'];
    const text = normalizeMonitorPart(room || 'MONITOR');
    let hash = 0;
    for (let index = 0; index < text.length; index += 1) hash = ((hash << 5) - hash + text.charCodeAt(index)) | 0;
    return palette[Math.abs(hash) % palette.length];
  }

  function registryCalendarEvents(state) {
    const patientEvents = (state.ecmoEpisodes || []).map(episode => {
      const range = episodeDateRange(episode);
      const patient = patientById(state, episode.patientId);
      if (!range || !patient) return null;
      const tag = episodeCalendarTag(state, episode, patient);
      return {
        id: episode.id,
        eventType: 'patient',
        episode,
        patient,
        start: range.start,
        end: range.end,
        color: normalizeTagColor(tag.color),
        tagName: tag.name || '태그 미지정',
        initials: patient.initials || patient.patientInitials || patient.pseudoId || `P${String(patient.registrationNo || '').slice(-4)}`
      };
    }).filter(Boolean);

    const monitorEvents = (state.monitorAssignments || []).map(assignment => {
      const range = monitorAssignmentRange(assignment);
      if (!range) return null;
      const start = new Date(range.start.getFullYear(), range.start.getMonth(), range.start.getDate());
      const endsAtMidnight = range.end.getHours() === 0 && range.end.getMinutes() === 0 && range.end.getSeconds() === 0;
      const calendarEndSource = endsAtMidnight && range.end > range.start ? new Date(range.end.getTime() - 1) : range.end;
      const end = new Date(calendarEndSource.getFullYear(), calendarEndSource.getMonth(), calendarEndSource.getDate());
      const patient = patientById(state, assignment.patientId);
      return {
        id: `MONITOR_${assignment.id}`,
        eventType: 'monitor',
        assignment,
        patient,
        start,
        end: end < start ? start : end,
        exactStart: range.start,
        exactEnd: range.end,
        color: monitorCalendarColor(assignment.room),
        monitorLabel: `${assignment.room || ''} ${assignment.monitorNumber || ''}`.trim(),
        roomName: assignment.room || '기타',
        timeLabel: `${normalizeTimeText(assignment.startTime, '00:00')}–${normalizeTimeText(assignment.endTime, '23:59')}`
      };
    }).filter(Boolean);

    return [...patientEvents, ...monitorEvents].sort((a, b) => a.start - b.start || a.end - b.end || String(a.eventType).localeCompare(String(b.eventType)));
  }

  function addMonths(date, amount) {
    return new Date(date.getFullYear(), date.getMonth() + amount, 1);
  }

  function monthEnd(date) {
    return new Date(date.getFullYear(), date.getMonth() + 1, 0);
  }

  function clampDate(date, min, max) {
    return date < min ? min : date > max ? max : date;
  }

  function allocateEventLanes(events, monthStart, monthLast) {
    const visible = events.filter(event => event.end >= monthStart && event.start <= monthLast).map(event => ({ ...event, visibleStart: clampDate(event.start, monthStart, monthLast), visibleEnd: clampDate(event.end, monthStart, monthLast) }));
    const laneEnds = [];
    visible.forEach(event => {
      let lane = laneEnds.findIndex(end => end < event.visibleStart);
      if (lane < 0) lane = laneEnds.length;
      laneEnds[lane] = event.visibleEnd;
      event.lane = lane;
    });
    return { events: visible, laneCount: Math.max(1, laneEnds.length) };
  }

  function renderMonthCalendar(monthDate, events) {
    const monthStart = new Date(monthDate.getFullYear(), monthDate.getMonth(), 1);
    const monthLast = monthEnd(monthStart);
    const { events: monthEvents, laneCount } = allocateEventLanes(events, monthStart, monthLast);
    const firstWeekday = monthStart.getDay();
    const totalDays = monthLast.getDate();
    const cells = [];
    for (let index = 0; index < 42; index++) {
      const day = index - firstWeekday + 1;
      if (day < 1 || day > totalDays) {
        cells.push('<div class="registry-calendar-day outside"></div>');
        continue;
      }
      const date = new Date(monthStart.getFullYear(), monthStart.getMonth(), day);
      const key = dateKey(date);
      const active = monthEvents.filter(event => event.start <= date && event.end >= date);
      const segments = active.map(event => {
        const isStart = key === dateKey(event.visibleStart);
        const isEnd = key === dateKey(event.visibleEnd);
        const showLabel = isStart || date.getDay() === 0;
        if (event.eventType === 'monitor') {
          const patientLabel = event.patient ? patientDisplayLabel(event.patient) : '환자 미지정';
          const title = `${event.monitorLabel} · ${dateKey(event.exactStart)} ${normalizeTimeText(event.assignment.startTime, '00:00')} ~ ${dateKey(event.exactEnd)} ${normalizeTimeText(event.assignment.endTime, '23:59')} · ${patientLabel}`;
          const label = `${event.monitorLabel}${isStart ? ` ${event.timeLabel}` : ''}`;
          const startMinute = event.exactStart.getHours() * 60 + event.exactStart.getMinutes();
          const endMinute = event.exactEnd.getHours() * 60 + event.exactEnd.getMinutes();
          const leftPercent = key === dateKey(event.exactStart) ? Math.max(0, Math.min(98, startMinute / 1440 * 100)) : 0;
          const rightPercent = key === dateKey(event.exactEnd) ? Math.max(0, Math.min(98, 100 - endMinute / 1440 * 100)) : 0;
          return `<button type="button" class="ecmo-calendar-segment monitor-timeline ${isStart ? 'start' : ''} ${isEnd ? 'end' : ''}" style="--event-color:${escapeHtml(event.color)};--lane:${event.lane};--monitor-left:${leftPercent}%;--monitor-right:${rightPercent}%" title="${escapeHtml(title)}" data-calendar-monitor="${escapeHtml(event.assignment.id)}" data-calendar-monitor-patient="${escapeHtml(event.patient?.id || '')}">${showLabel ? `<b>${escapeHtml(label)}</b>` : ''}</button>`;
        }
        const selected = event.patient.id === registrySelectedPatientId && (!registrySelectedEpisodeId || event.episode.id === registrySelectedEpisodeId);
        const title = `${event.initials} · ${episodeDisplayLabel(event.episode)} · ${dateKey(event.start)} ~ ${dateKey(event.end)} · ${event.tagName}`;
        return `<button type="button" class="ecmo-calendar-segment patient-timeline ${isStart ? 'start' : ''} ${isEnd ? 'end' : ''} ${selected ? 'selected' : ''}" style="--event-color:${escapeHtml(event.color)};--lane:${event.lane}" title="${escapeHtml(title)}" data-calendar-patient="${escapeHtml(event.patient.id)}" data-calendar-episode="${escapeHtml(event.episode.id)}">${showLabel ? `<b>${escapeHtml(event.initials)}</b>` : ''}</button>`;
      }).join('');
      const isToday = key === dateKey(new Date());
      const isFocus = registryCalendarFocusDate && key === dateKey(registryCalendarFocusDate);
      cells.push(`<div class="registry-calendar-day ${isToday ? 'today' : ''} ${isFocus ? 'selected-date' : ''}" data-calendar-date="${key}"><button class="registry-day-number" type="button" data-calendar-date-button="${key}" title="${key} 선택">${day}</button>${segments}</div>`);
    }
    const monthName = new Intl.DateTimeFormat('ko-KR', { year: 'numeric', month: 'long' }).format(monthStart);
    return `<article class="registry-month-card" style="--calendar-lanes:${laneCount}"><h4>${escapeHtml(monthName)}</h4><div class="registry-weekdays">${['일','월','화','수','목','금','토'].map(day => `<span>${day}</span>`).join('')}</div><div class="registry-month-grid">${cells.join('')}</div></article>`;
  }

  function episodeMajorEventItems(episode) {
    const fixed = EPISODE_EVENT_FIELDS.map(field => {
      const value = episode?.events?.[field.key] || '';
      if (!value) return null;
      return { id: `${episode.id}_${field.key}`, name: field.label, dateTime: value, note: '', color: field.color };
    }).filter(Boolean);
    const custom = (episode?.timeEvents || []).filter(item => item?.name || item?.dateTime || item?.note).map(item => ({
      id: item.id || uid('EVT'),
      name: item.name || '주요 시간 이벤트',
      dateTime: item.dateTime || '',
      note: item.note || '',
      color: '#475569'
    }));
    return [...fixed, ...custom].sort((a, b) => {
      const ad = safeDate(a.dateTime)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      const bd = safeDate(b.dateTime)?.getTime() ?? Number.MAX_SAFE_INTEGER;
      return ad - bd || String(a.name).localeCompare(String(b.name), 'ko');
    });
  }

  function renderRegistryPatientEvents() {
    const box = $('#registryPatientEventPanel');
    const state = readState();
    if (!box) return;
    const patient = patientById(state, registrySelectedPatientId);
    if (!patient) {
      box.innerHTML = '<div class="empty-state"><strong>환자를 선택하세요.</strong><span>달력의 ECMO 기간선을 누르거나 위의 환자 선택에서 사람을 고르면 주요 시간 이벤트가 표시됩니다.</span></div>';
      return;
    }
    const episodes = episodesForPatient(state, patient.id);
    const episodeCards = episodes.map(episode => {
      const items = episodeMajorEventItems(episode);
      const isSelected = !registrySelectedEpisodeId || registrySelectedEpisodeId === episode.id;
      return `<article class="registry-event-episode ${isSelected ? 'selected' : ''}">
        <div class="registry-event-episode-head"><div><h4>${escapeHtml(episodeDisplayLabel(episode))}</h4><p>${escapeHtml(episode.events?.ecmoStartTime || 'ECMO 시작일 미입력')} → ${escapeHtml(episode.events?.ecmoFinishTime || 'ECMO 종료일 미입력')}</p></div><button class="btn ghost compact-btn" type="button" data-registry-open-episode="${escapeHtml(episode.id)}">입력 화면에서 수정</button></div>
        <div class="registry-major-event-list">${items.length ? items.map(item => `<div class="registry-major-event-item"><i style="background:${escapeHtml(item.color)}"></i><div><strong>${escapeHtml(item.name)}</strong><time>${escapeHtml(formatEventDate(item.dateTime))}</time>${item.note ? `<p>${escapeHtml(item.note)}</p>` : ''}</div></div>`).join('') : '<div class="empty-state compact"><strong>저장된 주요 시간 이벤트가 없습니다.</strong></div>'}</div>
      </article>`;
    }).join('');
    box.innerHTML = `<div class="registry-selected-patient-head"><div><span>선택한 환자</span><strong>${escapeHtml(patientDisplayLabel(patient))}</strong></div><span class="badge teal">ECMO ${episodes.length}회</span></div>${episodeCards || '<div class="empty-state"><strong>ECMO episode가 없습니다.</strong></div>'}`;
    $$('[data-registry-open-episode]', box).forEach(button => button.addEventListener('click', () => {
      sessionStorage.setItem('excite_open_patient_id', patient.id);
      sessionStorage.setItem('excite_open_episode_id', button.dataset.registryOpenEpisode);
      location.href = 'patient-upload.html';
    }));
  }

  function bindRegistryCalendarInteractions() {
    $$('[data-calendar-patient]').forEach(segment => segment.addEventListener('click', event => {
      event.stopPropagation();
      registrySelectedPatientId = segment.dataset.calendarPatient || '';
      registrySelectedEpisodeId = segment.dataset.calendarEpisode || '';
      const patientInput = $('#registryCalendarPatientSearch');
      const patientIdInput = $('#registryCalendarPatientId');
      if (patientInput) patientInput.value = patientDisplayLabel(patientById(readState(), registrySelectedPatientId));
      if (patientIdInput) patientIdInput.value = registrySelectedPatientId;
      renderRegistryEcmoCalendar();
    }));
    $$('[data-calendar-monitor]').forEach(segment => segment.addEventListener('click', event => {
      event.stopPropagation();
      const patientId = segment.dataset.calendarMonitorPatient || '';
      if (patientId) {
        registrySelectedPatientId = patientId;
        registrySelectedEpisodeId = '';
        const patientInput = $('#registryCalendarPatientSearch');
        const patientIdInput = $('#registryCalendarPatientId');
        if (patientInput) patientInput.value = patientDisplayLabel(patientById(readState(), patientId));
        if (patientIdInput) patientIdInput.value = patientId;
      }
      renderRegistryEcmoCalendar();
    }));
    $$('[data-calendar-date-button]').forEach(button => button.addEventListener('click', () => {
      registryCalendarFocusDate = safeDate(button.dataset.calendarDateButton);
      const input = $('#registryCalendarDateInput');
      if (input) input.value = button.dataset.calendarDateButton || '';
      renderRegistryEcmoCalendar();
    }));
  }

  function renderRegistryEcmoCalendar() {
    const box = $('#registryEcmoCalendar');
    const legend = $('#registryCalendarLegend');
    if (!box || !legend) return;
    const state = readState();
    const events = registryCalendarEvents(state);
    const months = [addMonths(registryCalendarAnchor, -1), registryCalendarAnchor, addMonths(registryCalendarAnchor, 1)];
    box.innerHTML = months.map(month => renderMonthCalendar(month, events)).join('');
    const patientTags = [];
    const monitorRooms = [];
    events.forEach(event => {
      if (event.eventType === 'patient' && !patientTags.some(tag => tag.name === event.tagName && tag.color === event.color)) patientTags.push({ name: event.tagName, color: event.color });
      if (event.eventType === 'monitor' && !monitorRooms.some(room => room.name === event.roomName)) monitorRooms.push({ name: event.roomName, color: event.color });
    });
    const patientLegend = patientTags.length ? `<span class="legend-section-label">환자 ECMO</span>${patientTags.map(tag => `<span><i class="patient-legend-line" style="--legend-color:${escapeHtml(tag.color)}"></i>${escapeHtml(tag.name)}</span>`).join('')}` : '';
    const monitorLegend = monitorRooms.length ? `<span class="legend-section-label">모니터 사용</span>${monitorRooms.map(room => `<span><i class="monitor-legend-line" style="--legend-color:${escapeHtml(room.color)}"></i>${escapeHtml(room.name)}</span>`).join('')}` : '';
    legend.innerHTML = patientLegend || monitorLegend ? `${patientLegend}${monitorLegend}` : '<span class="muted">표시할 ECMO episode 또는 모니터 배정이 없습니다.</span>';
    const patientInput = $('#registryCalendarPatientSearch');
    const patientOptionsBox = $('#registryCalendarPatientOptions');
    const patientIdInput = $('#registryCalendarPatientId');
    if (patientOptionsBox) {
      const patientIds = (state.patients || []).map(patient => patient.id);
      patientOptionsBox.innerHTML = patientIds.map(id => {
        const patient = patientById(state, id);
        const label = patientDisplayLabel(patient);
        return `<option value="${escapeHtml(label)}">${escapeHtml(patient?.initials || patient?.patientInitials || '')}</option>`;
      }).join('');
      if (patientIdInput) patientIdInput.value = registrySelectedPatientId || '';
      if (patientInput && registrySelectedPatientId) patientInput.value = patientDisplayLabel(patientById(state, registrySelectedPatientId));
      if (patientInput && !registrySelectedPatientId && patientInput.dataset.autoFilled === '1') { patientInput.value = ''; delete patientInput.dataset.autoFilled; }
    }
    bindRegistryCalendarInteractions();
    renderRegistryPatientEvents();
  }

  function moveRegistryCalendarToDate() {
    const value = $('#registryCalendarDateInput')?.value || '';
    const date = safeDate(value);
    if (!date) return toast('이동할 날짜를 입력하세요.', 'yellow');
    registryCalendarFocusDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    registryCalendarAnchor = new Date(date.getFullYear(), date.getMonth(), 1);
    renderRegistryEcmoCalendar();
    $('#registryEcmoCalendar')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function findRegistryCalendarPatient(showMessage = true) {
    const query = ($('#registryCalendarPatientSearch')?.value || '').trim().toLowerCase();
    if (!query) {
      registrySelectedPatientId = '';
      registrySelectedEpisodeId = '';
      const hidden = $('#registryCalendarPatientId'); if (hidden) hidden.value = '';
      renderRegistryEcmoCalendar();
      return;
    }
    const state = readState();
    const normalized = query.replace(/[^a-z0-9가-힣]/g, '');
    const matches = (state.patients || []).filter(patient => {
      const values = [patient.initials, patient.patientInitials, patient.registrationNo, String(patient.registrationNo || '').slice(-4), patientMaskedRegistration(patient.registrationNo), patientDisplayLabel(patient)];
      return values.some(value => String(value || '').toLowerCase().replace(/[^a-z0-9가-힣]/g, '').includes(normalized));
    });
    if (!matches.length) { if (showMessage) toast('이니셜 또는 환자번호가 일치하는 환자가 없습니다.', 'yellow'); return; }
    if (matches.length > 1 && showMessage) toast(`${matches.length}명이 검색되었습니다. 더 많은 번호 또는 이니셜을 입력하세요.`, 'yellow');
    const patient = matches[0];
    registrySelectedPatientId = patient.id;
    registrySelectedEpisodeId = '';
    const input = $('#registryCalendarPatientSearch'); if (input) input.value = patientDisplayLabel(patient);
    const hidden = $('#registryCalendarPatientId'); if (hidden) hidden.value = patient.id;
    renderRegistryEcmoCalendar();
  }

  function initVitalRegistry() {
    populateRegistryFilters();
    renderVitalRegistry();
    renderRegistryEcmoCalendar();
    $('.filters button')?.addEventListener('click', renderVitalRegistry);
    $$('.filters input, .filters select').forEach(element => element.addEventListener('input', renderVitalRegistry));
    $('#registryCalendarPrev')?.addEventListener('click', () => { registryCalendarAnchor = addMonths(registryCalendarAnchor, -3); registryCalendarFocusDate = null; renderRegistryEcmoCalendar(); });
    $('#registryCalendarNext')?.addEventListener('click', () => { registryCalendarAnchor = addMonths(registryCalendarAnchor, 3); registryCalendarFocusDate = null; renderRegistryEcmoCalendar(); });
    $('#registryCalendarToday')?.addEventListener('click', () => { const today = new Date(); registryCalendarAnchor = new Date(today.getFullYear(), today.getMonth(), 1); registryCalendarFocusDate = new Date(today.getFullYear(), today.getMonth(), today.getDate()); const input = $('#registryCalendarDateInput'); if (input) input.value = dateKey(today); renderRegistryEcmoCalendar(); });
    $('#registryCalendarGoDate')?.addEventListener('click', moveRegistryCalendarToDate);
    $('#registryCalendarDateInput')?.addEventListener('change', moveRegistryCalendarToDate);
    $('#registryCalendarPatientFind')?.addEventListener('click', () => findRegistryCalendarPatient(true));
    $('#registryCalendarPatientSearch')?.addEventListener('change', () => findRegistryCalendarPatient(false));
    $('#registryCalendarPatientSearch')?.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); findRegistryCalendarPatient(true); } });
  }



  /* Simplified two-study analysis workflow and PowerPoint-style graph editor */
  function analysisSelectedMethods() {
    const scope = $('#analysisScopeSelect')?.value || '';
    return Array.from(new Set($$('input[name="analysisMethod"]:checked').filter(input => {
      const group = input.closest('[data-question-group]');
      return !group || group.dataset.questionGroup === scope;
    }).map(input => input.value)));
  }

  function analysisSelectedOutputs() {
    const scope = $('#analysisScopeSelect')?.value || '';
    return Array.from(new Set($$('input[name="analysisOutput"]:checked').filter(input => {
      const group = input.closest('[data-output-group]');
      return !group || group.dataset.outputGroup === scope;
    }).map(input => input.value)));
  }

  function groupLabelsForTag(state, tagId) {
    if (!tagId) return null;
    const axis = (state.axes || []).find(a => a.tagId === tagId);
    const labels = (axis?.values || []).map(v => v.label).filter(Boolean);
    return labels.length ? labels : null;
  }

  function renderDynamicStudyCards() {
    const grid = $('#analysisStudyGrid');
    const emptyHint = $('#analysisStudyEmptyHint');
    if (!grid) return;
    const state = readState();
    const builtIn = new Set(['ecmo-outcome']);
    $$('[data-dynamic-study]', grid).forEach(node => node.remove());
    const addCard = $('#analysisAddTagCard');
    const extraTags = (state.tags || []).filter(tag => !builtIn.has(tag.id));
    if (emptyHint) emptyHint.hidden = extraTags.length > 0;
    extraTags.forEach((tag, index) => {
      const labels = groupLabelsForTag(state, tag.id);
      const card = document.createElement('div');
      card.className = 'study-choice';
      card.dataset.dynamicStudy = '1';
      card.dataset.tagId = tag.id;
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.innerHTML = `<div class="study-choice-actions"><button type="button" class="icon-btn" data-edit-tag aria-label="${escapeHtml(tag.name)} 태그 수정" title="수정">✎</button><button type="button" class="icon-btn" data-delete-tag aria-label="${escapeHtml(tag.name)} 태그 삭제" title="삭제">✕</button></div><span class="study-number">${String(index + 1).padStart(2, '0')}</span><strong>${escapeHtml(tag.name)}</strong><span>${labels ? escapeHtml(labels.join(' vs ')) + ' 그룹으로 비교합니다.' : '그룹 값을 추가하면 자동으로 비교 그룹이 됩니다.'}</span>`;
      const selectThisTag = () => {
        if ($('#analysisTagSelect')) { populateAnalysisOptions(); $('#analysisTagSelect').value = tag.id; }
        applyAnalysisPreset('between-patient');
      };
      card.addEventListener('click', event => { if (event.target.closest('.icon-btn')) return; selectThisTag(); });
      card.addEventListener('keydown', event => { if ((event.key === 'Enter' || event.key === ' ') && !event.target.closest('.icon-btn')) { event.preventDefault(); selectThisTag(); } });
      card.querySelector('[data-edit-tag]').addEventListener('click', event => { event.stopPropagation(); editQuickTag(tag.id); });
      card.querySelector('[data-delete-tag]').addEventListener('click', event => { event.stopPropagation(); deleteQuickTag(tag.id); });
      if (addCard) grid.insertBefore(card, addCard); else grid.appendChild(card);
    });
  }

  function resetQuickTagForm() {
    if ($('#quickTagName')) $('#quickTagName').value = '';
    if ($('#quickTagQuestion')) $('#quickTagQuestion').value = '그룹';
    if ($('#quickTagValues')) $('#quickTagValues').value = '';
    if ($('#quickTagEditId')) $('#quickTagEditId').value = '';
    if ($('#quickTagSaveBtn')) $('#quickTagSaveBtn').textContent = '태그 추가';
  }

  function editQuickTag(tagId) {
    const state = readState();
    const tag = (state.tags || []).find(item => item.id === tagId);
    if (!tag) return;
    const axis = (state.axes || []).find(item => item.tagId === tagId);
    if ($('#quickTagName')) $('#quickTagName').value = tag.name;
    if ($('#quickTagQuestion')) $('#quickTagQuestion').value = axis?.name || '그룹';
    if ($('#quickTagValues')) $('#quickTagValues').value = (axis?.values || []).map(value => value.label).join(', ');
    if ($('#quickTagEditId')) $('#quickTagEditId').value = tagId;
    if ($('#quickTagSaveBtn')) $('#quickTagSaveBtn').textContent = '수정 저장';
    const box = $('#analysisQuickTagAdd');
    if (box) { box.hidden = false; }
    $('#quickTagName')?.focus();
  }

  function deleteQuickTag(tagId) {
    const state = readState();
    const tag = (state.tags || []).find(item => item.id === tagId);
    if (!confirm(`"${tag?.name || '이 연구 태그'}"를 삭제할까요? 태그에 속한 기준과 그룹 값도 함께 삭제되며 되돌릴 수 없습니다.`)) return;
    patchState(next => {
      ensureTagTreesState(next);
      const ids = new Set([tagId]);
      let changed = true;
      while (changed) {
        changed = false;
        (next.tagTrees || []).forEach(node => { if (node.parentId && ids.has(node.parentId) && !ids.has(node.id)) { ids.add(node.id); changed = true; } });
      }
      next.tagTrees = (next.tagTrees || []).filter(node => !ids.has(node.id));
      syncTreeCompatibility(next);
    });
    if ($('#analysisTagSelect')?.value === tagId) { $('#analysisTagSelect').value = ''; }
    if ($('#quickTagEditId')?.value === tagId) resetQuickTagForm();
    renderDynamicStudyCards();
    populateAnalysisOptions();
    updateAnalysisPreview();
    addAudit('research tag delete', 'tag', tag?.name || tagId);
    toast(`"${tag?.name || '연구 태그'}"를 삭제했습니다.`, 'gray');
  }

  function saveQuickResearchTag() {
    const editId = ($('#quickTagEditId')?.value || '').trim();
    const name = ($('#quickTagName')?.value || '').trim();
    const question = ($('#quickTagQuestion')?.value || '').trim() || '그룹';
    const values = ($('#quickTagValues')?.value || '').split(',').map(v => v.trim()).filter(Boolean);
    if (!name) return toast('연구 태그 이름을 입력하세요.', 'yellow');
    if (values.length < 2) return toast('비교할 그룹 값을 쉼표로 구분해 2개 이상 입력하세요. 예: 저체온, 정상체온', 'yellow');
    let tagId = editId;
    if (editId) {
      patchState(state => {
        ensureTagTreesState(state);
        const tagNode = treeNode(state, editId);
        if (tagNode) { tagNode.name = name; tagNode.updatedAt = nowText(); }
        let questionNode = treeChildren(state, editId).find(node => node.type === 'question');
        if (!questionNode) {
          questionNode = { id: uid('TREE'), tagId: editId, parentId: editId, name: question, type: 'question', selectionMode: 'single', order: 0, collapsed: false, createdAt: nowText(), updatedAt: nowText() };
          state.tagTrees.push(questionNode);
        } else { questionNode.name = question; questionNode.updatedAt = nowText(); }
        const oldValueIds = new Set(treeChildren(state, questionNode.id).filter(node => node.type === 'value').map(node => node.id));
        state.tagTrees = state.tagTrees.filter(node => !oldValueIds.has(node.id));
        values.forEach((label, index) => state.tagTrees.push({ id: uid('TREE'), tagId: editId, parentId: questionNode.id, name: label, type: 'value', order: index, collapsed: false, createdAt: nowText(), updatedAt: nowText() }));
        syncTreeCompatibility(state);
      });
    } else {
      tagId = uid('TAG');
      const qId = uid('TREE');
      patchState(state => {
        ensureTagTreesState(state);
        state.tagTrees.push({ id: tagId, tagId, parentId: null, name, type: 'tag', color: '#0E8174', description: '', order: (state.tagTrees || []).length, collapsed: false, createdAt: nowText(), updatedAt: nowText() });
        state.tagTrees.push({ id: qId, tagId, parentId: tagId, name: question, type: 'question', selectionMode: 'single', order: 0, collapsed: false, createdAt: nowText(), updatedAt: nowText() });
        values.forEach((label, index) => state.tagTrees.push({ id: uid('TREE'), tagId, parentId: qId, name: label, type: 'value', order: index, collapsed: false, createdAt: nowText(), updatedAt: nowText() }));
        syncTreeCompatibility(state);
      });
    }
    resetQuickTagForm();
    const box = $('#analysisQuickTagAdd'); if (box) box.hidden = true;
    renderDynamicStudyCards();
    populateAnalysisOptions();
    if ($('#analysisTagSelect')) $('#analysisTagSelect').value = tagId;
    applyAnalysisPreset('between-patient');
    addAudit(editId ? 'research tag update' : 'research tag create', 'tag', name);
    toast(editId ? `"${name}" 연구 태그를 수정했습니다.` : `"${name}" 연구 태그를 추가했습니다. 그룹: ${values.join(' vs ')}`);
  }

  function renderWithinPatientChain() {
    const container = $('#analysisWithinPatientChain');
    if (!container) return;
    const patientId = $('#analysisWithinPatientSelect')?.value || '';
    const state = readState();
    if (!patientId) { container.innerHTML = '<div class="empty-state">환자를 고르면 연결된 CSV가 시간 순서대로 나타납니다.</div>'; return; }
    const files = (state.vitalFiles || []).filter(file => file.patientId === patientId)
      .sort((a, b) => (a.patientOrder ?? a.order ?? 0) - (b.patientOrder ?? b.order ?? 0) || String(a.recordingStart || '').localeCompare(String(b.recordingStart || '')));
    if (!files.length) { container.innerHTML = '<div class="empty-state">이 환자에게 아직 연결된 CSV가 없습니다. 환자–CSV 통합 관리에서 먼저 연결하세요.</div>'; return; }
    container.innerHTML = files.map((file, index) => `<div class="mini-item"><strong>${index + 1}. ${escapeHtml(file.name)}</strong><span>${escapeHtml(file.timepointLabel || file.dataType || '시점 미지정')} · ${escapeHtml(file.recordingStart || '기록 일시 미상')}</span></div>`).join('');
  }

  function toggleSimpleAnalysisScope(scope) {
    $$('[data-scope-panel]').forEach(panel => { panel.hidden = panel.dataset.scopePanel !== scope; });
    $$('[data-question-group]').forEach(panel => { panel.hidden = panel.dataset.questionGroup !== scope; });
    $$('[data-output-group]').forEach(panel => { panel.hidden = panel.dataset.outputGroup !== scope; });
    $$('.study-choice, .analysis-preset').forEach(button => button.classList.toggle('active', button.dataset.analysisPreset === scope));
  }

  function applyAnalysisPreset(preset) {
    const scope = $('#analysisScopeSelect');
    if (scope) scope.value = preset;
    toggleSimpleAnalysisScope(preset);
    if (preset === 'ecmo-outcome') {
      if ($('#analysisFixedEffects')) $('#analysisFixedEffects').value = 'time, survival_group';
      if ($('#analysisInteractions')) $('#analysisInteractions').value = 'time×survival_group';
      if ($('#analysisRandomEffects')) $('#analysisRandomEffects').value = 'patient-slope';
      if ($('#analysisAlignment')) $('#analysisAlignment').value = 'ecmo-start';
      if ($('#analysisUnit')) $('#analysisUnit').value = 'window';
      if ($('#analysisMissing')) $('#analysisMissing').value = 'keep';
      $$('[data-question-group="ecmo-outcome"] input').forEach(input => { input.checked = true; });
      $$('[data-output-group="ecmo-outcome"] input').forEach(input => { input.checked = true; });
    } else if (preset === 'within-file') {
      if ($('#analysisFixedEffects')) $('#analysisFixedEffects').value = 'time';
      if ($('#analysisInteractions')) $('#analysisInteractions').value = '';
      if ($('#analysisRandomEffects')) $('#analysisRandomEffects').value = 'none';
      if ($('#analysisAlignment')) $('#analysisAlignment').value = 'file-start';
      if ($('#analysisUnit')) $('#analysisUnit').value = 'point';
      if ($('#analysisMissing')) $('#analysisMissing').value = 'keep';
      $$('[data-question-group="within-file"] input').forEach(input => { input.checked = true; });
      $$('[data-output-group="within-file"] input').forEach(input => { input.checked = true; });
    } else if (preset === 'within-patient') {
      if ($('#analysisFixedEffects')) $('#analysisFixedEffects').value = 'time, file_order';
      if ($('#analysisInteractions')) $('#analysisInteractions').value = 'time×file_order';
      if ($('#analysisRandomEffects')) $('#analysisRandomEffects').value = 'none';
      if ($('#analysisAlignment')) $('#analysisAlignment').value = 'file-start';
      if ($('#analysisUnit')) $('#analysisUnit').value = 'file';
      if ($('#analysisMissing')) $('#analysisMissing').value = 'keep';
      $$('[data-question-group="within-patient"] input').forEach(input => { input.checked = true; });
      $$('[data-output-group="within-patient"] input').forEach(input => { input.checked = true; });
      renderWithinPatientChain();
    } else if (preset === 'between-patient') {
      if ($('#analysisFixedEffects')) $('#analysisFixedEffects').value = 'time, group';
      if ($('#analysisInteractions')) $('#analysisInteractions').value = 'time×group';
      if ($('#analysisRandomEffects')) $('#analysisRandomEffects').value = 'patient-slope';
      if ($('#analysisAlignment')) $('#analysisAlignment').value = 'ecmo-start';
      if ($('#analysisUnit')) $('#analysisUnit').value = 'window';
      if ($('#analysisMissing')) $('#analysisMissing').value = 'keep';
      $$('[data-question-group="between-patient"] input').forEach(input => { input.checked = true; });
      $$('[data-output-group="between-patient"] input').forEach(input => { input.checked = true; });
    }
    populateAnalysisOptions();
    updateAnalysisPreview();
  }


  function initStatisticalAnalysis() {
    const setupPreviewButton = $('#analysisSetupPreviewToggle');
    const setupPreviewContent = $('#analysisSetupPreviewContent');
    if (setupPreviewButton && setupPreviewContent) {
      const key = 'excite_analysis_setup_preview_collapsed';
      const apply = collapsed => {
        setupPreviewContent.classList.toggle('collapsed', collapsed);
        setupPreviewButton.textContent = collapsed ? '펼치기' : '접기';
        setupPreviewButton.setAttribute('aria-expanded', String(!collapsed));
      };
      apply(localStorage.getItem(key) === '1');
      setupPreviewButton.addEventListener('click', () => {
        const collapsed = !setupPreviewContent.classList.contains('collapsed');
        localStorage.setItem(key, collapsed ? '1' : '0');
        apply(collapsed);
      });
    }
    toggleSimpleAnalysisScope($('#analysisScopeSelect')?.value || '');
    renderDynamicStudyCards();
    $$('.study-choice, .analysis-preset').forEach(button => { if (button.id !== 'analysisAddTagCard') button.addEventListener('click', () => applyAnalysisPreset(button.dataset.analysisPreset)); });
    $('#analysisAddTagCard')?.addEventListener('click', () => { const box = $('#analysisQuickTagAdd'); if (box) { box.hidden = !box.hidden; if (!box.hidden) $('#quickTagName')?.focus(); } });
    $('#analysisAddTagCard')?.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); $('#analysisAddTagCard').click(); } });
    $('#quickTagCancelBtn')?.addEventListener('click', () => { const box = $('#analysisQuickTagAdd'); if (box) box.hidden = true; resetQuickTagForm(); });
    $('#quickTagSaveBtn')?.addEventListener('click', saveQuickResearchTag);
    const watched = ['#analysisProjectSelect','#analysisTagSelect','#analysisScopeSelect','#analysisSignalSelect','#analysisTimeRange','#analysisResample','#analysisAlignment','#analysisTolerance','#analysisOffset','#analysisMissing','#analysisOutlier','#analysisSmoothing','#analysisUnit','#analysisFixedEffects','#analysisInteractions','#analysisRandomEffects','#analysisCovariates','#analysisCondition','#analysisBaseline','#analysisSingleFile','#analysisSingleRange','#analysisSingleEvent','#analysisWithinPatientSelect','#analysisWithinPatientRange','#analysisGroupBaseline','#analysisGroupTimeRange','#analysisGroupCovariates'];
    watched.forEach(selector => $(selector)?.addEventListener('input', () => {
      if (['#analysisProjectSelect','#analysisTagSelect','#analysisScopeSelect','#analysisWithinPatientSelect'].includes(selector)) populateAnalysisOptions();
      if (selector === '#analysisScopeSelect') toggleSimpleAnalysisScope($('#analysisScopeSelect').value);
      if (selector === '#analysisWithinPatientSelect') renderWithinPatientChain();
      updateAnalysisPreview();
    }));
    $$('input[name="analysisMethod"], input[name="analysisOutput"]').forEach(input => input.addEventListener('change', updateAnalysisPreview));
    $('#saveAnalysisSpecBtn')?.addEventListener('click', saveAnalysisJob);
    populateAnalysisOptions();
    updateAnalysisPreview();
  }


  function populateAnalysisOptions() {
    const state = readState();
    const preserve = selector => $(selector)?.value || '';
    const values = {
      project: preserve('#analysisProjectSelect'), tag: preserve('#analysisTagSelect'), signal: preserve('#analysisSignalSelect')
    };
    const projects = (state.projects || []).filter(project => !project.type || project.type === 'vital-db');
    if ($('#analysisProjectSelect')) $('#analysisProjectSelect').innerHTML = option('', '전체 연구') + projects.map(project => option(project.id, project.title, project.id === values.project)).join('');
    if ($('#analysisTagSelect')) $('#analysisTagSelect').innerHTML = option('', '전체 태그') + (state.tags || []).map(tag => option(tag.id, tag.name, tag.id === values.tag)).join('');
    if ($('#analysisWithinPatientSelect')) {
      const selectedPatient = preserve('#analysisWithinPatientSelect');
      $('#analysisWithinPatientSelect').innerHTML = option('', '환자 선택') + (state.patients || []).map(patient => option(patient.id, patientShortLabel(patient), patient.id === selectedPatient)).join('');
    }

    const tagId = $('#analysisTagSelect')?.value || values.tag;
    let vitalFiles = (state.vitalFiles || []).filter(file => file.uploadStatus !== '오류');
    if (tagId) vitalFiles = vitalFiles.filter(file => (file.tagIds || []).includes(tagId));
    if ($('#analysisSingleFile')) {
      const singleFileValue = preserve('#analysisSingleFile');
      const singleFilePool = tagId ? vitalFiles : (state.vitalFiles || []).filter(file => file.uploadStatus !== '오류');
      $('#analysisSingleFile').innerHTML = option('', 'CSV 선택') + singleFilePool.map(file => option(file.id, `${file.name}${file.recordingStart ? ' · ' + file.recordingStart : ''}`, file.id === singleFileValue)).join('');
    }
    renderWithinPatientChain();

    const commonSignals = ['SpO2','PR','HR','MAP','SBP','DBP','RR','PPG','PI','Lactate','Flow','RPM','Creatinine','Hgb','Plt','INR','APTT','AST','ALT','Bilirubin','Albumin','CRP','ESR','proBNP','Myoglobin','CK-MB','Troponin I','Troponin T'];
    const detected = vitalFiles.flatMap(file => Object.keys(file.previewData || {}).map(key => key.replace(/_(mean|median|min|max|count)$/i, '')));
    const signals = Array.from(new Set([...commonSignals, ...detected])).filter(Boolean);
    if ($('#analysisSignalSelect')) {
      $('#analysisSignalSelect').innerHTML = signals.map(signal => option(signal, signal, signal === values.signal)).join('');
      if (!$('#analysisSignalSelect').value) $('#analysisSignalSelect').value = 'SpO2';
    }
  }


  function updateAnalysisPreview() {
    const state = readState();
    const scope = $('#analysisScopeSelect')?.value || '';
    const scopeLabel = ANALYSIS_SCOPE_LABELS[scope] || '미선택';
    const signal = $('#analysisSignalSelect')?.value || '미선택';
    const patientId = $('#analysisWithinPatientSelect')?.value || '';
    const methods = analysisSelectedMethods();
    const tagId = $('#analysisTagSelect')?.value || '';
    let files = (state.vitalFiles || []).filter(file => file.uploadStatus !== '오류');
    if (tagId) files = files.filter(file => (file.tagIds || []).includes(tagId));
    if (patientId) files = files.filter(file => file.patientId === patientId);
    const patients = patientId ? 1 : new Set(files.map(file => file.patientId).filter(Boolean)).size;
    if ($('#analysisScopeBadge')) $('#analysisScopeBadge').textContent = scopeLabel;
    if ($('#analysisPreviewScope')) $('#analysisPreviewScope').textContent = scopeLabel;
    if ($('#analysisPreviewSignal')) { $('#analysisPreviewSignal').textContent = signal; $('#analysisPreviewSignal').className = `badge ${signal === '미선택' ? 'gray' : 'teal'}`; }
    if ($('#analysisPreviewPatients')) $('#analysisPreviewPatients').textContent = `${patients}명`;
    if ($('#analysisPreviewFiles')) $('#analysisPreviewFiles').textContent = `${files.length}개`;
    if ($('#analysisPreviewMethods')) { $('#analysisPreviewMethods').textContent = methods.length ? `${methods.length}개` : '미선택'; $('#analysisPreviewMethods').className = `badge ${methods.length ? 'blue' : 'gray'}`; }

    const groupLabels = groupLabelsForTag(state, tagId);
    if ($('#analysisGroupPreviewText')) {
      const tag = (state.tags || []).find(item => item.id === tagId);
      $('#analysisGroupPreviewText').textContent = groupLabels
        ? `"${tag?.name || '선택한 태그'}" 태그의 ${groupLabels.join(' vs ')} 그룹으로 자동으로 나눠 비교합니다.`
        : '위에서 연구 태그를 고르면 그 태그의 그룹(예: 생존/사망)으로 자동으로 나눠 비교합니다. 태그가 없으면 태그 관리에서 먼저 만드세요.';
    }

    let explanation = '분석 범위를 선택하면 필요한 분석을 자동으로 설정합니다.';
    if (scope === 'ecmo-outcome') explanation = `<strong>${escapeHtml(signal)}</strong> 값을 생존군과 사망군으로 나누어 비교합니다.<br>① 각 시점의 차이 ② 차이가 처음 나타난 시점 ③ 전체 변화 흐름의 차이 ④ 환자별 반복측정을 고려한 결과를 함께 확인합니다.`;
    if (scope === 'within-file') explanation = `선택한 CSV 한 개 안에서 <strong>${escapeHtml(signal)}</strong>의 구간 통계만 계산합니다.<br>다른 환자나 다른 CSV와는 비교하지 않고, 이 파일 내부의 값만 봅니다.`;
    if (scope === 'within-patient') explanation = `한 환자에게 연결된 CSV ${files.length}개를 순서대로 이어 붙여 <strong>${escapeHtml(signal)}</strong>의 전체 흐름을 봅니다.<br>파일 사이 공백·중복 시간과, 시간이 지나며 기울기가 어떻게 바뀌는지 함께 확인합니다.`;
    if (scope === 'between-patient') explanation = groupLabels
      ? `<strong>${escapeHtml(signal)}</strong> 값을 <strong>${escapeHtml(groupLabels.join(' vs '))}</strong> 그룹으로 나누어 비교합니다.<br>① 각 시점의 차이 ② 차이가 처음 나타난 시점 ③ 전체 변화 흐름의 차이 ④ 환자별 반복측정을 고려한 결과를 함께 확인합니다.`
      : `연구 태그를 고르면 그 태그의 그룹으로 나누어 <strong>${escapeHtml(signal)}</strong>을 비교합니다.`;
    if ($('#analysisPlainPreview')) $('#analysisPlainPreview').innerHTML = explanation;
    if ($('#analysisSaveSummary')) $('#analysisSaveSummary').textContent = scope ? `${scopeLabel} · ${signal} · 질문 ${methods.length}개` : '먼저 분석 범위를 선택하세요.';

    const covariatesField = scope === 'between-patient' ? '#analysisGroupCovariates' : '#analysisCovariates';
    const defaultFixed = scope === 'within-file' ? 'time' : scope === 'within-patient' ? 'time, file_order' : 'time, group';
    const defaultInteraction = scope === 'within-file' ? '' : scope === 'within-patient' ? 'time×file_order' : 'time×group';
    const fixed = ($('#analysisFixedEffects')?.value || defaultFixed).trim();
    const interaction = ($('#analysisInteractions')?.value || defaultInteraction).trim();
    const covariates = ($(covariatesField)?.value || '').trim();
    const randomTerm = scope === 'within-file' || scope === 'within-patient' ? '' : ' + (1 + time | patient)';
    const formula = `${signal} ~ ${fixed}${interaction ? ' + ' + interaction : ''}${covariates ? ' + ' + covariates : ''}${randomTerm}`;
    if ($('#analysisFormulaPreview')) $('#analysisFormulaPreview').textContent = `${formula}\n시간 정렬: ${selectedText($('#analysisAlignment')) || '-'}\n시간 간격: ${selectedText($('#analysisResample')) || '-'}\n실제 통계량은 Python 분석 서버에서 계산됩니다.`;
    renderWithinPatientChain();
  }


  function saveAnalysisJob() {
    const state = readState();
    const scope = $('#analysisScopeSelect')?.value || '';
    const methods = analysisSelectedMethods();
    const signal = $('#analysisSignalSelect')?.value || '';
    if (!scope) return toast('먼저 연구 태그 또는 분석 범위를 선택하세요.', 'yellow');
    if (!signal) return toast('확인할 지표를 선택하세요.', 'yellow');
    if (!methods.length) return toast('알고 싶은 내용을 하나 이상 선택하세요.', 'yellow');
    if (scope === 'within-file' && !$('#analysisSingleFile')?.value) return toast('분석할 CSV를 선택하세요.', 'yellow');
    if (scope === 'within-patient' && !$('#analysisWithinPatientSelect')?.value) return toast('분석할 환자를 선택하세요.', 'yellow');
    const project = (state.projects || []).find(item => item.id === ($('#analysisProjectSelect')?.value || ''));
    const tag = (state.tags || []).find(item => item.id === ($('#analysisTagSelect')?.value || ''));
    const groupLabels = groupLabelsForTag(state, tag?.id || '');
    const scopeLabel = ANALYSIS_SCOPE_LABELS[scope] || scope;
    const timeRange = scope === 'within-file' ? ($('#analysisSingleRange')?.value || '').trim()
      : scope === 'within-patient' ? ($('#analysisWithinPatientRange')?.value || '').trim()
      : scope === 'between-patient' ? ($('#analysisGroupTimeRange')?.value || '').trim()
      : ($('#analysisTimeRange')?.value || '').trim();
    const graphColors = scope === 'ecmo-outcome' ? ['#1d5d9b','#c2410c','#0b8f8a','#6d5dfc'] : ['#DE314E','#0E8174','#1d5d9b','#9a5b00'];
    const condition = scope === 'ecmo-outcome' ? '생존 vs 사망' : scope === 'between-patient' ? (groupLabels ? groupLabels.join(' vs ') : (tag?.name ? `${tag.name} 그룹` : '그룹 미지정')) : scope === 'within-patient' ? '해당 없음(단일 환자 추세)' : '해당 없음(단일 파일 통계)';
    const studyQuestion = scope === 'ecmo-outcome' ? 'ECMO 생존군과 사망군에서 지표 차이와 시간적 추세 확인'
      : scope === 'within-file' ? '선택한 CSV 한 개 내부의 구간 통계 확인'
      : scope === 'within-patient' ? '한 환자에게 연결된 CSV를 이어붙인 전체 추세 확인'
      : `${tag?.name || '선택한 태그'} 그룹 간 지표 차이와 시간적 추세 확인`;
    const analysis = {
      id: uid('ANALYSIS'),
      name: `${project?.title || tag?.name || scopeLabel}_${signal}_${nowText()}`,
      projectId: project?.id || '', projectName: project?.title || '', tagId: tag?.id || '', tagName: tag?.name || '',
      scope, scopeLabel,
      patientId: scope === 'within-patient' ? ($('#analysisWithinPatientSelect')?.value || '') : '',
      sourceAId: scope === 'within-file' ? ($('#analysisSingleFile')?.value || '') : '',
      signal,
      methods, method: methods.map(value => ANALYSIS_METHOD_LABELS[value] || value).join(' + '),
      studyQuestion,
      timeRange,
      preprocessing: { resample: $('#analysisResample')?.value, alignment: $('#analysisAlignment')?.value, tolerance: $('#analysisTolerance')?.value, offsetSec: $('#analysisOffset')?.value, missing: $('#analysisMissing')?.value, outlier: $('#analysisOutlier')?.value, smoothing: $('#analysisSmoothing')?.value, unit: $('#analysisUnit')?.value },
      model: { fixedEffects: $('#analysisFixedEffects')?.value, interactions: $('#analysisInteractions')?.value, randomEffects: $('#analysisRandomEffects')?.value, correlation: $('#analysisCorrelation')?.value, covariates: (scope === 'between-patient' ? $('#analysisGroupCovariates')?.value : $('#analysisCovariates')?.value), condition, baseline: (scope === 'between-patient' ? $('#analysisGroupBaseline')?.value : $('#analysisBaseline')?.value) },
      outputs: analysisSelectedOutputs(), graphStyle: { colors: graphColors, title: '', subtitle: '', xLabel: '시간', yLabel: signal, titleSize: 24, axisSize: 13, lineWidth: 3, fontFamily: 'Arial, sans-serif', showLegend: true, showGrid: true, transparent: false },
      status: '분석 사양 저장됨', createdAt: nowText(), createdBy: USER
    };
    patchState(next => { if (!Array.isArray(next.analyses)) next.analyses = []; next.analyses.unshift(analysis); });
    renderAnalysisResultTable(analysis);
    addAudit('analysis specification save', 'analysis_job', analysis.name);
    toast('분석 설정을 저장했습니다. 결과 화면에서 그래프 모양과 색상을 편집할 수 있습니다.');
  }


  function renderAnalysisResultTable(analysis) {
    const body = $('#analysisResultPreviewBody');
    if (!body) return;
    const labels = {
      'ecmo-outcome': ['생존군과 사망군의 차이·시점·추세', '시점별 비교 + 반복측정 추세 분석'],
      'within-file': ['한 CSV 내부의 구간 통계', '기술통계 + 구간·이벤트 분석'],
      'within-patient': ['한 환자의 연결된 CSV 전체 추세', '파일별 요약 + 연결 시간축 분석'],
      'between-patient': ['연구 태그 그룹 간 차이·시점·추세', '시점별 비교 + 반복측정 추세 분석']
    };
    const [question, auto] = labels[analysis.scope] || [analysis.studyQuestion || '저장된 분석 질문', analysis.method || '선택한 분석'];
    body.innerHTML = `<tr><td><strong>${escapeHtml(analysis.signal)}</strong></td><td>${escapeHtml(question)}</td><td>${escapeHtml(auto)}</td><td>${badge('저장 완료', 'green')}</td></tr>`;
  }


  function defaultAnalysisGraphStyle(analysis) {
    const scopeColors = analysis?.scope === 'ecmo-outcome' ? ['#1d5d9b','#c2410c','#0b8f8a','#6d5dfc','#f59e0b','#475569'] : ['#0b8f8a','#6d5dfc','#f59e0b','#dc2626','#1d5d9b','#475569'];
    const merged = Object.assign({
      title: analysis?.name || '분석 결과',
      subtitle: `${analysis?.signal || analysis?.y || '신호'} · ${analysis?.scopeLabel || analysis?.scope || ''}`,
      xLabel: analysis?.x || '시간', yLabel: analysis?.signal || analysis?.y || '값',
      titleSize: 24, axisSize: 13, lineWidth: 3, fontFamily: 'Arial, sans-serif',
      showLegend: true, showGrid: true, transparent: false, colors: scopeColors
    }, analysis?.graphStyle || {});
    if (!merged.title) merged.title = analysis?.name || '분석 결과';
    if (!merged.subtitle) merged.subtitle = `${analysis?.signal || analysis?.y || '신호'} · ${analysis?.scopeLabel || analysis?.scope || ''}`;
    if (!merged.xLabel) merged.xLabel = analysis?.x || '시간';
    if (!merged.yLabel) merged.yLabel = analysis?.signal || analysis?.y || '값';
    return merged;
  }

  function analysisGraphSvg(analysis, state = readState(), styleOverride = null) {
    const width = 920, height = 520, left = 86, right = 30, top = 112, bottom = 76;
    const series = analysisGraphSeries(state, analysis);
    const style = Object.assign({}, defaultAnalysisGraphStyle(analysis), styleOverride || {});
    const colors = Array.isArray(style.colors) && style.colors.length ? style.colors : defaultAnalysisGraphStyle(analysis).colors;
    const font = escapeHtml(style.fontFamily || 'Arial, sans-serif');
    const background = style.transparent ? 'none' : '#ffffff';
    const title = style.title || analysis.name || '분석 결과';
    const subtitle = style.subtitle || '';
    if (!series.length) {
      return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(title)}"><rect width="100%" height="100%" fill="${background}"/><text x="${width/2}" y="230" text-anchor="middle" font-family="${font}" font-size="22" font-weight="700" fill="#475569">실제 그래프 데이터가 없습니다.</text><text x="${width/2}" y="265" text-anchor="middle" font-family="${font}" font-size="13" fill="#64748b">CSV preview data 또는 Python 분석 결과가 연결되면 그래프를 편집할 수 있습니다.</text></svg>`;
    }
    const all = series.flatMap(item => item.points).filter(point => Number.isFinite(Number(point.minute)) && Number.isFinite(Number(point.value)));
    const xs = all.map(point => Number(point.minute));
    const ys = all.map(point => Number(point.value));
    let xMin = Math.min(...xs), xMax = Math.max(...xs), yMin = Math.min(...ys), yMax = Math.max(...ys);
    if (xMin === xMax) xMax = xMin + 1;
    if (yMin === yMax) { yMin -= 1; yMax += 1; }
    const yPad = Math.max((yMax - yMin) * .1, .01); yMin -= yPad; yMax += yPad;
    const sx = x => left + ((x - xMin) / (xMax - xMin)) * (width - left - right);
    const sy = y => top + (1 - ((y - yMin) / (yMax - yMin))) * (height - top - bottom);
    const yTicks = Array.from({ length: 5 }, (_, index) => yMin + ((yMax - yMin) * index / 4));
    const xTicks = Array.from({ length: 5 }, (_, index) => xMin + ((xMax - xMin) * index / 4));
    const grid = style.showGrid ? yTicks.map(tick => `<line x1="${left}" x2="${width-right}" y1="${sy(tick).toFixed(1)}" y2="${sy(tick).toFixed(1)}" stroke="#e2e8f0" stroke-width="1"/>`).join('') : '';
    const paths = series.map((item, index) => {
      const d = item.points.filter(point => Number.isFinite(Number(point.minute)) && Number.isFinite(Number(point.value))).map((point, pointIndex) => `${pointIndex ? 'L' : 'M'}${sx(Number(point.minute)).toFixed(1)},${sy(Number(point.value)).toFixed(1)}`).join(' ');
      return `<path d="${d}" fill="none" stroke="${escapeHtml(colors[index % colors.length])}" stroke-width="${Number(style.lineWidth || 3)}" stroke-linejoin="round" stroke-linecap="round"/>`;
    }).join('');
    const legend = style.showLegend ? series.map((item, index) => {
      const row = Math.floor(index / 3), col = index % 3;
      const x = left + col * 250, y = 78 + row * 20;
      return `<g transform="translate(${x},${y})"><line x1="0" y1="0" x2="24" y2="0" stroke="${escapeHtml(colors[index % colors.length])}" stroke-width="${Math.max(3, Number(style.lineWidth || 3))}"/><text x="32" y="4" font-family="${font}" font-size="12" fill="#334155">${escapeHtml(String(item.name).slice(0, 28))}</text></g>`;
    }).join('') : '';
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeHtml(title)}"><rect width="100%" height="100%" fill="${background}"/><text x="${left}" y="38" font-family="${font}" font-size="${Number(style.titleSize || 24)}" font-weight="700" fill="#0b1f3a">${escapeHtml(title)}</text>${subtitle ? `<text x="${left}" y="62" font-family="${font}" font-size="13" fill="#64748b">${escapeHtml(subtitle)}</text>` : ''}${legend}${grid}${yTicks.map(tick => `<text x="${left-14}" y="${(sy(tick)+4).toFixed(1)}" text-anchor="end" font-family="${font}" font-size="${Number(style.axisSize || 13)}" fill="#64748b">${Number(tick).toFixed(1)}</text>`).join('')}${xTicks.map(tick => `<text x="${sx(tick).toFixed(1)}" y="${height-42}" text-anchor="middle" font-family="${font}" font-size="${Number(style.axisSize || 13)}" fill="#64748b">${Math.round(tick)}</text>`).join('')}<line x1="${left}" x2="${left}" y1="${top}" y2="${height-bottom}" stroke="#64748b"/><line x1="${left}" x2="${width-right}" y1="${height-bottom}" y2="${height-bottom}" stroke="#64748b"/>${paths}<text x="${(left+width-right)/2}" y="${height-12}" text-anchor="middle" font-family="${font}" font-size="${Number(style.axisSize || 13)}" fill="#334155">${escapeHtml(style.xLabel || '시간')}</text><text transform="translate(24 ${(top+height-bottom)/2}) rotate(-90)" text-anchor="middle" font-family="${font}" font-size="${Number(style.axisSize || 13)}" fill="#334155">${escapeHtml(style.yLabel || '값')}</text></svg>`;
  }

  function graphStyleFromEditor(analysis) {
    const base = defaultAnalysisGraphStyle(analysis);
    const colors = $$('[data-graph-series-color]').map(input => input.value);
    return {
      title: $('#graphTitleInput')?.value || base.title,
      subtitle: $('#graphSubtitleInput')?.value || '',
      xLabel: $('#graphXLabelInput')?.value || base.xLabel,
      yLabel: $('#graphYLabelInput')?.value || base.yLabel,
      titleSize: Number($('#graphTitleSizeInput')?.value || base.titleSize),
      axisSize: Number($('#graphAxisSizeInput')?.value || base.axisSize),
      lineWidth: Number($('#graphLineWidthInput')?.value || base.lineWidth),
      fontFamily: $('#graphFontInput')?.value || base.fontFamily,
      showLegend: Boolean($('#graphLegendInput')?.checked),
      showGrid: Boolean($('#graphGridInput')?.checked),
      transparent: Boolean($('#graphTransparentInput')?.checked),
      colors: colors.length ? colors : base.colors
    };
  }

  function fillGraphEditor(analysis, state) {
    const empty = $('#graphEditorEmpty'), controls = $('#graphEditorControls');
    if (!analysis) { if (empty) empty.hidden = false; if (controls) controls.hidden = true; return; }
    if (empty) empty.hidden = true;
    if (controls) controls.hidden = false;
    const style = defaultAnalysisGraphStyle(analysis);
    if ($('#graphTitleInput')) $('#graphTitleInput').value = style.title;
    if ($('#graphSubtitleInput')) $('#graphSubtitleInput').value = style.subtitle;
    if ($('#graphXLabelInput')) $('#graphXLabelInput').value = style.xLabel;
    if ($('#graphYLabelInput')) $('#graphYLabelInput').value = style.yLabel;
    if ($('#graphTitleSizeInput')) $('#graphTitleSizeInput').value = style.titleSize;
    if ($('#graphAxisSizeInput')) $('#graphAxisSizeInput').value = style.axisSize;
    if ($('#graphLineWidthInput')) $('#graphLineWidthInput').value = style.lineWidth;
    if ($('#graphFontInput')) $('#graphFontInput').value = style.fontFamily;
    if ($('#graphLegendInput')) $('#graphLegendInput').checked = style.showLegend;
    if ($('#graphGridInput')) $('#graphGridInput').checked = style.showGrid;
    if ($('#graphTransparentInput')) $('#graphTransparentInput').checked = style.transparent;
    const series = analysisGraphSeries(state, analysis);
    const colorBox = $('#graphSeriesColorControls');
    if (colorBox) {
      const names = series.length ? series.map(item => item.name) : ['Series 1'];
      colorBox.innerHTML = names.map((name, index) => `<label class="series-color-item"><input type="color" data-graph-series-color="${index}" value="${escapeHtml(style.colors[index % style.colors.length])}"><span>${escapeHtml(String(name).slice(0,32))}</span></label>`).join('');
      $$('[data-graph-series-color]', colorBox).forEach(input => input.addEventListener('input', refreshAnalysisGraphEditor));
    }
  }

  function refreshAnalysisGraphEditor() {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === selectedAnalysisResultId);
    const graph = $('.analysis-result-graph');
    if (!analysis || !graph) return;
    graph.innerHTML = analysisGraphSvg(analysis, state, graphStyleFromEditor(analysis));
  }

  function saveCurrentGraphStyle() {
    if (!selectedAnalysisResultId) return toast('먼저 분석을 선택하세요.', 'yellow');
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === selectedAnalysisResultId);
    if (!analysis) return;
    const style = graphStyleFromEditor(analysis);
    patchState(next => { const target = (next.analyses || []).find(item => item.id === selectedAnalysisResultId); if (target) { target.graphStyle = style; target.updatedAt = nowText(); } });
    refreshAnalysisGraphEditor();
    toast('그래프 제목·축·색상 설정을 저장했습니다.');
  }

  function currentGraphExportStyle(analysis) {
    return analysis?.id === selectedAnalysisResultId && !$('#graphEditorControls')?.hidden ? graphStyleFromEditor(analysis) : defaultAnalysisGraphStyle(analysis);
  }

  function downloadAnalysisGraph(analysisId, format = 'png') {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === analysisId);
    if (!analysis) return toast('분석 결과를 찾을 수 없습니다.', 'yellow');
    if (!analysisGraphSeries(state, analysis).length) return toast('다운로드할 실제 그래프 데이터가 없습니다.', 'yellow');
    const style = currentGraphExportStyle(analysis);
    const svg = analysisGraphSvg(analysis, state, style);
    const baseName = sanitizeFilename(style.title || analysis.name);
    if (format === 'svg') return downloadText(`${baseName}.svg`, svg, 'image/svg+xml;charset=utf-8');
    const blob = new Blob([svg], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const image = new Image();
    image.onload = () => {
      const scale = 4;
      const canvas = document.createElement('canvas');
      canvas.width = 920 * scale; canvas.height = 520 * scale;
      const context = canvas.getContext('2d');
      if (!style.transparent) { context.fillStyle = '#ffffff'; context.fillRect(0, 0, canvas.width, canvas.height); }
      context.drawImage(image, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      canvas.toBlob(output => {
        if (!output) return;
        const outputUrl = URL.createObjectURL(output);
        const anchor = document.createElement('a'); anchor.href = outputUrl; anchor.download = `${baseName}_4x.png`; document.body.appendChild(anchor); anchor.click(); anchor.remove(); URL.revokeObjectURL(outputUrl);
      }, 'image/png', 1);
    };
    image.onerror = () => { URL.revokeObjectURL(url); toast('PNG 변환에 실패했습니다. SVG로 내려받아 주세요.', 'yellow'); };
    image.src = url;
  }

  function csvCell(value) {
    const text = String(value ?? '');
    return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function downloadAnalysisData(analysisId, format = 'csv') {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === analysisId);
    if (!analysis) return toast('분석 결과를 찾을 수 없습니다.', 'yellow');
    const series = analysisGraphSeries(state, analysis);
    if (!series.length) return toast('내려받을 실제 그래프 데이터가 없습니다.', 'yellow');
    const separator = format === 'txt' ? '\t' : ',';
    const rows = [['series','time','value']];
    series.forEach(item => item.points.forEach(point => rows.push([item.name, point.minute, point.value])));
    let content = rows.map(row => row.map(value => format === 'txt' ? String(value ?? '') : csvCell(value)).join(separator)).join('\n');
    const style = currentGraphExportStyle(analysis);
    const baseName = sanitizeFilename(style.title || analysis.name);
    if (format === 'txt') {
      const header = [`분석명\t${analysis.name}`,`연구\t${analysis.scopeLabel || analysis.scope}`,`지표\t${analysis.signal || analysis.y}`,`분석 질문\t${analysis.studyQuestion || ''}`,`분석 방법\t${analysis.method || ''}`,`시간 범위\t${analysis.timeRange || ''}`,'','그래프 데이터'].join('\n');
      content = `${header}\n${content}`;
      downloadText(`${baseName}.txt`, content, 'text/plain;charset=utf-8');
    } else downloadText(`${baseName}_data.csv`, `\ufeff${content}`, 'text/csv;charset=utf-8');
  }

  function renderAnalysisResultDetail(analysisId) {
    const state = readState();
    const analysis = (state.analyses || []).find(item => item.id === analysisId);
    const detail = $('#analysisResultDetail');
    const environment = $('#analysisEnvironmentRecord');
    if (!detail || !environment) return;
    if (!analysis) {
      selectedAnalysisResultId = null;
      if ($('#selectedAnalysisBadge')) $('#selectedAnalysisBadge').textContent = '선택 없음';
      detail.innerHTML = '<div class="empty-state"><strong>표시할 결과가 없습니다.</strong><span>목록에서 그래프 편집을 선택하세요.</span></div>';
      fillGraphEditor(null, state);
      return;
    }
    selectedAnalysisResultId = analysis.id;
    if ($('#selectedAnalysisBadge')) $('#selectedAnalysisBadge').textContent = analysis.name;
    detail.innerHTML = `<div class="analysis-result-graph">${analysisGraphSvg(analysis, state)}</div>${analysis.note ? `<div class="callout" style="margin-top:12px"><strong>비고</strong><br>${escapeHtml(analysis.note)}</div>` : ''}`;
    const files = analysisFiles(state, analysis);
    const modelFormula = analysis.model ? `${analysis.signal || 'outcome'} ~ ${analysis.model.fixedEffects || 'time'}${analysis.model.interactions ? ' + ' + analysis.model.interactions : ''}${analysis.model.covariates ? ' + ' + analysis.model.covariates : ''}` : '-';
    environment.innerHTML = `<dl class="kv"><dt>연구 질문</dt><dd>${escapeHtml(analysis.studyQuestion || analysis.scopeLabel || '-')}</dd><dt>분석 지표</dt><dd>${escapeHtml(analysis.signal || analysis.y || '-')}</dd><dt>연결 파일</dt><dd>${files.length}개</dd><dt>시간 범위</dt><dd>${escapeHtml(analysis.timeRange || '-')}</dd><dt>모델</dt><dd>${escapeHtml(modelFormula)}</dd><dt>생성일</dt><dd>${escapeHtml(analysis.createdAt || '-')}</dd><dt>최근 수정</dt><dd>${escapeHtml(analysis.updatedAt || '-')}</dd></dl>`;
    fillGraphEditor(analysis, state);
    refreshAnalysisGraphEditor();
  }

  function renderAnalysisResults() {
    const state = readState();
    const body = $('#analysisResultBody');
    if (!body) return;
    if (!(state.analyses || []).length) {
      setTableEmpty(body, 6, '아직 저장된 분석 결과가 없습니다.', '통계 분석 화면에서 분석 설정을 저장하세요.');
      renderAnalysisResultDetail(null);
      return;
    }
    if (!selectedAnalysisResultId || !(state.analyses || []).some(item => item.id === selectedAnalysisResultId)) selectedAnalysisResultId = state.analyses[0].id;
    body.innerHTML = state.analyses.map(analysis => {
      const files = analysisFiles(state, analysis);
      const patients = new Set(files.map(file => file.patientId).filter(Boolean)).size;
      return `<tr class="${analysis.id === selectedAnalysisResultId ? 'selected-result-row' : ''}"><td><strong>${escapeHtml(analysis.name)}</strong><div class="muted">${escapeHtml(analysis.createdAt || '')}</div></td><td>${escapeHtml(analysis.scopeLabel || analysis.scope || '-')}</td><td><strong>${escapeHtml(analysis.signal || analysis.y || '-')}</strong><div class="muted">${escapeHtml(analysis.method || '-')}</div></td><td>${patients}명 · ${files.length}개 파일</td><td>${badge(analysis.status || '분석 사양 저장됨', analysis.status === '분석 완료' ? 'green' : analysis.status === '확인 필요' ? 'yellow' : 'blue')}</td><td><div class="analysis-result-actions"><button class="btn teal compact-btn" type="button" data-analysis-detail="${escapeHtml(analysis.id)}">그래프 편집</button><button class="btn ghost compact-btn" type="button" data-analysis-edit="${escapeHtml(analysis.id)}">정보 수정</button><button class="btn ghost compact-btn danger-text" type="button" data-analysis-delete="${escapeHtml(analysis.id)}">삭제</button></div></td></tr>`;
    }).join('');
    $$('[data-analysis-detail]', body).forEach(button => button.addEventListener('click', () => { selectedAnalysisResultId = button.dataset.analysisDetail; renderAnalysisResults(); }));
    $$('[data-analysis-edit]', body).forEach(button => button.addEventListener('click', () => openAnalysisEditModal(button.dataset.analysisEdit)));
    $$('[data-analysis-delete]', body).forEach(button => button.addEventListener('click', () => deleteAnalysisResult(button.dataset.analysisDelete)));
    renderAnalysisResultDetail(selectedAnalysisResultId);
  }

  function initAnalysisResults() {
    $('#analysisResultRefreshBtn')?.addEventListener('click', renderAnalysisResults);
    $('#analysisEditCloseBtn')?.addEventListener('click', closeAnalysisEditModal);
    $('#analysisEditSaveBtn')?.addEventListener('click', saveAnalysisResultEdit);
    $('#analysisEditModal')?.addEventListener('click', event => { if (event.target.id === 'analysisEditModal') closeAnalysisEditModal(); });
    ['#graphTitleInput','#graphSubtitleInput','#graphXLabelInput','#graphYLabelInput','#graphTitleSizeInput','#graphAxisSizeInput','#graphLineWidthInput','#graphFontInput','#graphLegendInput','#graphGridInput','#graphTransparentInput'].forEach(selector => $(selector)?.addEventListener('input', refreshAnalysisGraphEditor));
    $('#graphStyleSaveBtn')?.addEventListener('click', saveCurrentGraphStyle);
    $('#graphDownloadPngBtn')?.addEventListener('click', () => selectedAnalysisResultId && downloadAnalysisGraph(selectedAnalysisResultId, 'png'));
    $('#graphDownloadSvgBtn')?.addEventListener('click', () => selectedAnalysisResultId && downloadAnalysisGraph(selectedAnalysisResultId, 'svg'));
    $('#graphDownloadCsvBtn')?.addEventListener('click', () => selectedAnalysisResultId && downloadAnalysisData(selectedAnalysisResultId, 'csv'));
    $('#graphDownloadTxtBtn')?.addEventListener('click', () => selectedAnalysisResultId && downloadAnalysisData(selectedAnalysisResultId, 'txt'));
    renderAnalysisResults();
  }





  function analysisGraphSeries(state, analysis) {
    const candidates = [analysis.signal, analysis.y, String(analysis.y || '').replace(/^var:/, ''), String(analysis.y || '').split(' ')[0]].filter(Boolean);
    const series = [];
    analysisFiles(state, analysis).slice(0, 8).forEach(file => {
      let points = [];
      for (const variable of candidates) {
        points = extractPreviewSeries(file, variable, 'all');
        if (points.length) break;
      }
      if (!points.length) return;
      const patient = (state.patients || []).find(item => item.id === file.patientId);
      const outcome = patient ? patientOutcome(state, patient) : 'unknown';
      const prefix = analysis.scope === 'ecmo-outcome' ? `${outcome === 'dead' ? '사망' : outcome === 'alive' ? '생존' : '미상'} · ` : '';
      series.push({ name: `${prefix}${patient?.initials || patient?.patientInitials || patient?.pseudoId || file.name || file.caseId || 'CSV'}`, points: points.slice(0, 360) });
    });
    return series;
  }




  function initWorkplaceHome() {
    const state = readState();
    const now = new Date();
    const dateText = new Intl.DateTimeFormat('ko-KR', { year: 'numeric', month: 'long', day: 'numeric', weekday: 'short' }).format(now);
    if ($('#workspaceToday')) $('#workspaceToday').textContent = dateText;

    const patients = state.patients || [];
    const files = state.vitalFiles || [];
    const assignments = state.assignments || [];
    const episodes = state.ecmoEpisodes || [];
    const matchedFiles = files.filter(file => file.patientId || file.matchedPatientId || file.episodeId);
    const assignmentTargets = new Set(assignments.filter(item => item.tagId).map(item => item.targetId));
    const taggedFiles = files.filter(file => (file.tagIds || []).length || assignmentTargets.has(file.id));
    const taggedPatientIds = new Set(assignments.filter(item => item.targetType === 'patient' && item.tagId).map(item => item.targetId));
    assignments.filter(item => item.targetType === 'episode' && item.tagId).forEach(item => {
      const episode = episodes.find(candidate => candidate.id === item.targetId);
      if (episode?.patientId) taggedPatientIds.add(episode.patientId);
    });
    const untaggedPatients = patients.filter(patient => !taggedPatientIds.has(patient.id));
    const unmatchedFiles = files.filter(file => !(file.patientId || file.matchedPatientId || file.episodeId));
    const untaggedFiles = files.filter(file => !((file.tagIds || []).length || assignmentTargets.has(file.id)));
    const pendingMembers = (state.signupRequests || []).filter(item => !item.status || ['pending', '대기', '승인 대기'].includes(String(item.status).toLowerCase()));

    const counts = {
      workspacePatientCount: patients.length,
      workspaceCsvCount: files.length,
      workspaceMatchedCount: matchedFiles.length,
      workspaceTagCount: (state.tags || []).length,
      workspaceAnalysisCount: (state.analyses || []).length,
      workspaceUnmatchedCsvCount: unmatchedFiles.length,
      workspaceUntaggedCsvCount: untaggedFiles.length,
      workspaceUntaggedPatientCount: untaggedPatients.length,
      workspacePendingMemberCount: pendingMembers.length
    };
    Object.entries(counts).forEach(([id, value]) => {
      const element = document.getElementById(id);
      if (element) element.textContent = String(value);
    });

    const matchRate = files.length ? Math.round(matchedFiles.length / files.length * 100) : 0;
    const tagRate = files.length ? Math.round(taggedFiles.length / files.length * 100) : 0;
    if ($('#workspaceMatchRateText')) $('#workspaceMatchRateText').textContent = `${matchRate}%`;
    if ($('#workspaceTagRateText')) $('#workspaceTagRateText').textContent = `${tagRate}%`;
    if ($('#workspaceMatchRateBar')) $('#workspaceMatchRateBar').style.width = `${matchRate}%`;
    if ($('#workspaceTagRateBar')) $('#workspaceTagRateBar').style.width = `${tagRate}%`;

    const projectList = $('#workspaceProjectList');
    if (projectList) {
      const projects = (state.projects || [])
        .filter(project => !project.type || project.type === 'vital-db')
        .slice()
        .sort((a, b) => String(b.createdAt || '').localeCompare(String(a.createdAt || '')))
        .slice(0, 4);
      if (!projects.length) {
        projectList.innerHTML = '<div class="team-empty-state"><strong>등록된 연구가 없습니다.</strong>연구 기본정보를 생성하면 팀 홈에서 함께 확인할 수 있습니다.</div>';
      } else {
        projectList.innerHTML = projects.map(project => {
          const status = project.status || '준비 중';
          const hold = /완료|중단|보류/.test(status);
          const detail = [project.topic, project.irb].filter(Boolean).join(' · ') || '연구 주제와 IRB 정보를 등록해 주세요.';
          return `<div class="team-project-item"><div><strong>${escapeHtml(project.title || '제목 없는 연구')}</strong><p>${escapeHtml(detail)}</p></div><span class="team-project-status ${hold ? 'is-hold' : ''}">${escapeHtml(status)}</span></div>`;
        }).join('');
      }
    }

    const activityList = $('#workspaceActivityList');
    if (activityList) {
      const actionLabels = {
        'research project create': '연구 생성',
        'tree entity move': '태그 트리 이동',
        'analysis export': '분석 자료 내보내기',
        'member approval': '팀원 승인',
        'member reject': '가입 요청 처리',
        'signup request': '가입 요청',
        'preset tag template': '태그 구조 생성',
        'trajectory example tag': '예시 태그 생성'
      };
      const activities = (state.audit || []).slice(0, 5);
      if (!activities.length) {
        activityList.innerHTML = '<div class="team-empty-state"><strong>최근 활동이 없습니다.</strong>팀원이 데이터를 등록하거나 수정하면 이곳에 표시됩니다.</div>';
      } else {
        activityList.innerHTML = activities.map(activity => {
          const user = activity.user || 'EXCITE';
          const initials = user === '로그인 사용자' ? 'E+' : String(user).replace(/\s+/g, '').slice(0, 2).toUpperCase();
          const action = actionLabels[activity.action] || activity.action || '데이터 변경';
          return `<div class="team-activity-item"><span class="team-activity-avatar">${escapeHtml(initials)}</span><div><strong>${escapeHtml(user)} · ${escapeHtml(action)}</strong><p>${escapeHtml(activity.description || activity.target || '-')}</p></div><time>${escapeHtml(activity.time || '-')}</time></div>`;
        }).join('');
      }
    }
  }




  /* v14: standardized temporal input, safe row merging, grouped sorting/filtering. */
  function installClinicalWorkbookV14() {
    const dateColumns = [
      [BULK_PATIENT_COLUMNS,'ecmoStartTime','datetime'],[BULK_PATIENT_COLUMNS,'ecmoFinishTime','datetime'],[BULK_PATIENT_COLUMNS,'intubationStartTime','datetime'],
      [BULK_PATIENT_COLUMNS,'admissionDate','date'],[BULK_PATIENT_COLUMNS,'birthDate','date'],
      [CLINICAL_SHEET_CONFIG.pre.columns,'preCheckDateTime','datetime'],
      [CLINICAL_SHEET_CONFIG.intra.columns,'postAbga24hDateTime','datetime'],
      [CLINICAL_SHEET_CONFIG.outcome.columns,'intubationStartTime','datetime'],[CLINICAL_SHEET_CONFIG.outcome.columns,'extubationDateTime','datetime'],
      [CLINICAL_SHEET_CONFIG.outcome.columns,'icuAdmissionDate','date'],[CLINICAL_SHEET_CONFIG.outcome.columns,'icuDischargeDateTime','datetime'],
      [CLINICAL_SHEET_CONFIG.outcome.columns,'dischargeDate','date'],[CLINICAL_SHEET_CONFIG.outcome.columns,'deathDate','date'],
      [CLINICAL_SHEET_CONFIG.micro.columns,'collectionDateTime','datetime']
    ];
    dateColumns.forEach(([columns,key,type])=>{const col=columns.find(item=>item.key===key);if(col)col.temporal=type;});

    function pad2(value){return String(value).padStart(2,'0');}
    function validDateParts(year,month,day){const d=new Date(Date.UTC(year,month-1,day));return d.getUTCFullYear()===year&&d.getUTCMonth()===month-1&&d.getUTCDate()===day;}
    function parseTemporal(value,type){
      let raw=String(value??'').trim();if(!raw)return'';
      if(/^\d{5}(?:\.\d+)?$/.test(raw)){const serial=Number(raw);if(serial>20000&&serial<80000){const millis=Date.UTC(1899,11,30)+serial*86400000;const d=new Date(millis);const date=`${d.getUTCFullYear()}-${pad2(d.getUTCMonth()+1)}-${pad2(d.getUTCDate())}`;return type==='datetime'?`${date} ${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}`:date;}}
      raw=raw.replace(/오전/gi,' AM ').replace(/오후/gi,' PM ').replace(/년|월/g,'-').replace(/일/g,' ').replace(/[.\/]/g,'-').replace(/T/g,' ').replace(/\s*-\s*/g,'-').replace(/-$/,'').replace(/\s+/g,' ').trim();
      let ampm='';const ap=raw.match(/\b(AM|PM)\b/i);if(ap){ampm=ap[1].toUpperCase();raw=raw.replace(/\b(AM|PM)\b/i,'').replace(/\s+/g,' ').trim();}
      let m=raw.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:\s+(\d{1,2})(?::(\d{1,2}))?(?::\d{1,2})?)?$/);
      if(!m){const compact=raw.replace(/\D/g,'');if(compact.length===8)m=[raw,compact.slice(0,4),compact.slice(4,6),compact.slice(6,8),undefined,undefined];else if(compact.length===12||compact.length===14)m=[raw,compact.slice(0,4),compact.slice(4,6),compact.slice(6,8),compact.slice(8,10),compact.slice(10,12)];}
      if(!m)return'';const year=Number(m[1]),month=Number(m[2]),day=Number(m[3]);if(!validDateParts(year,month,day))return'';const date=`${year}-${pad2(month)}-${pad2(day)}`;if(type==='date')return date;
      let hour=m[4]===undefined?0:Number(m[4]),minute=m[5]===undefined?0:Number(m[5]);if(ampm){if(hour<1||hour>12)return'';if(ampm==='PM'&&hour<12)hour+=12;if(ampm==='AM'&&hour===12)hour=0;}if(hour<0||hour>23||minute<0||minute>59)return'';return`${date} ${pad2(hour)}:${pad2(minute)}`;
    }
    function temporalDisplay(value,type){return parseTemporal(String(value||'').replace('T',' '),type)||String(value||'').replace('T',' ');}
    function temporalStorage(value,type){const normalized=parseTemporal(value,type);return type==='datetime'?normalized.replace(' ','T'):normalized;}
    function formatTemporalInput(input,type){if(!input||!input.value.trim()){input?.classList.remove('is-temporal-invalid');return true;}const normalized=parseTemporal(input.value,type);input.classList.toggle('is-temporal-invalid',!normalized);if(normalized)input.value=normalized;return Boolean(normalized);}
    window.EXCITE_TEMPORAL_FORMAT={date:'YYYY-MM-DD',datetime:'YYYY-MM-DD HH:mm'};
    parseEventDate=function(value){if(!value)return null;const normalized=parseTemporal(value,'datetime');if(!normalized)return null;const d=new Date(normalized.replace(' ','T'));return Number.isNaN(d.getTime())?null:d;};

    const oldBulkPatientToRow=bulkPatientToRow;
    bulkPatientToRow=function(patient,episode){const row=oldBulkPatientToRow(patient,episode);BULK_PATIENT_COLUMNS.forEach(c=>{if(c.temporal&&row[c.key])row[c.key]=temporalDisplay(row[c.key],c.temporal);});return row;};

    bulkRowHtml=function(values={}){const cells=BULK_PATIENT_COLUMNS.map((column,columnIndex)=>{const hint=column.condition?'<span class="bulk-master-condition-hint">없음 / 미상 / 있음: 메모</span>':column.temporal?`<span class="temporal-format-note">${column.temporal==='date'?'YYYY-MM-DD':'YYYY-MM-DD HH:mm'}</span>`:'';const placeholder=column.required?'필수':column.condition?'미상':column.temporal?(column.temporal==='date'?'YYYY-MM-DD':'YYYY-MM-DD HH:mm'):'';const list=column.listId?` list="${column.listId}"`:'';const fixed=['initials','registrationNo','episodeSequence'].includes(column.key)?` bulk-fixed-${column.key}`:'';const temporal=column.temporal?` temporal-format-cell" data-temporal="${column.temporal}`:'';const value=column.temporal?temporalDisplay(values[column.key]??'',column.temporal):(values[column.key]??'');return `<td class="${fixed}"><input class="bulk-master-cell${temporal}" data-field="${column.key}" data-col-index="${columnIndex}" data-condition="${column.condition?'true':'false'}" value="${bulkEscapeValue(value)}" placeholder="${placeholder}" aria-label="${bulkEscapeValue(column.label)}"${list}>${hint}</td>`;}).join('');return `<tr data-bulk-patient-row><td class="bulk-row-select"><input type="checkbox" data-bulk-row-check aria-label="행 선택"></td><td class="bulk-row-number"></td><td class="bulk-status-cell"><span class="bulk-row-state is-empty">빈 행</span></td>${cells}</tr>`;};

    sheetRowHtml=function(name,values={}){const cells=sheetConfig(name).columns.map((c,i)=>{const list=c.listId?` list="${c.listId}"`:'';const fixed=c.fixed?` clinical-fixed-col clinical-fixed-${c.key}`:'';const temporal=c.temporal?` temporal-format-cell" data-temporal="${c.temporal}`:'';const placeholder=c.required?'필수':c.temporal?(c.temporal==='date'?'YYYY-MM-DD':'YYYY-MM-DD HH:mm'):'';const value=c.temporal?temporalDisplay(values[c.key]??'',c.temporal):(values[c.key]??'');return `<td class="${fixed}"><input class="bulk-master-cell clinical-sheet-cell${temporal}" data-sheet-field="${c.key}" data-col-index="${i}" value="${sheetCellValue(value)}" placeholder="${placeholder}" aria-label="${escapeHtml(c.label)}"${list}></td>`;}).join('');return `<tr data-sheet-row="${name}"><td class="bulk-row-select"><input type="checkbox" data-sheet-row-check aria-label="행 선택"></td><td class="bulk-row-number"></td><td class="bulk-status-cell"><span class="bulk-row-state is-empty">빈 행</span></td>${cells}</tr>`;};

    const oldPasteBulk=pasteBulkPatientGrid;
    pasteBulkPatientGrid=function(event,target){oldPasteBulk(event,target);bulkRows().forEach(row=>BULK_PATIENT_COLUMNS.forEach(c=>{if(c.temporal){const input=$(`[data-field="${c.key}"]`,row);if(input&&input.value)formatTemporalInput(input,c.temporal);}}));refreshBulkPatientRowStates();};
    const oldPasteSheet=pasteSheetGrid;
    pasteSheetGrid=function(name,event,target){oldPasteSheet(name,event,target);sheetRows(name).forEach(row=>sheetConfig(name).columns.forEach(c=>{if(c.temporal){const input=$(`[data-sheet-field="${c.key}"]`,row);if(input&&input.value)formatTemporalInput(input,c.temporal);}}));refreshSheetStates(name);};

    bulkValidation=function(values,state,duplicates){if(!bulkRowHasData(values))return{type:'empty',label:'빈 행',detail:''};if(!values.initials)return{type:'error',label:'이니셜 없음',detail:'환자 이니셜은 필수입니다.'};if(!values.registrationNo)return{type:'error',label:'등록번호 없음',detail:'등록번호는 필수입니다.'};const seq=Number(values.episodeSequence);if(!Number.isInteger(seq)||seq<1)return{type:'error',label:'차수 확인',detail:'ECMO 차수는 1 이상의 정수입니다.'};if(duplicates.has(bulkEpisodeKey(values)))return{type:'error',label:'표 안 중복',detail:'같은 등록번호와 ECMO 차수가 두 번 있습니다. 선택 행 합치기를 사용할 수 있습니다.'};const badTemporal=BULK_PATIENT_COLUMNS.find(c=>c.temporal&&values[c.key]&&!parseTemporal(values[c.key],c.temporal));if(badTemporal)return{type:'error',label:'날짜·시간 확인',detail:`${badTemporal.label}: ${badTemporal.temporal==='date'?'YYYY-MM-DD':'YYYY-MM-DD HH:mm'} 형식으로 입력하세요.`};const badNumber=['heightCm','weightKg'].find(key=>values[key]&&!Number.isFinite(Number(String(values[key]).replace(/,/g,''))));if(badNumber)return{type:'error',label:'숫자 확인',detail:'Height와 Weight는 숫자로 입력하세요.'};const patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);const episode=patient?episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===seq):null;if(episode)return{type:'existing',label:'기존 차수 수정',detail:`${seq}차 ECMO`,patient,episode};if(patient)return{type:'new',label:'새 차수',detail:`기존 환자의 ${seq}차 ECMO로 바로 이어서 추가`,patient};return{type:'new',label:'신규',detail:'새 환자와 ECMO 차수 생성'};};

    sheetValidation=function(name,values,state,duplicates=new Set()){if(!sheetHasData(values))return{type:'empty',label:'빈 행'};if(!values.registrationNo)return{type:'error',label:'등록번호 없음',detail:'등록번호는 필수입니다.'};if(!values.initials)return{type:'error',label:'이니셜 없음',detail:'환자 이니셜은 필수입니다.'};const sequence=Number(values.episodeSequence);if(!Number.isInteger(sequence)||sequence<1)return{type:'error',label:'차수 확인',detail:'ECMO 차수는 1 이상의 정수입니다.'};if(duplicates.has(sheetEpisodeKey(values)))return{type:'error',label:'표 안 중복',detail:'같은 등록번호와 ECMO 차수가 두 번 있습니다. 선택 행 합치기를 사용할 수 있습니다.'};const patient=(state.patients||[]).find(p=>String(p.registrationNo||'')===values.registrationNo);if(!patient)return{type:'error',label:'환자 없음',detail:'Patient Master를 먼저 저장하세요.'};const missing=sheetConfig(name).columns.find(c=>c.required&&!String(values[c.key]||'').trim());if(missing)return{type:'error',label:`${missing.label} 없음`,detail:`${missing.label}은 필수입니다.`};const badTemporal=sheetConfig(name).columns.find(c=>c.temporal&&values[c.key]&&!parseTemporal(values[c.key],c.temporal));if(badTemporal)return{type:'error',label:'날짜·시간 확인',detail:`${badTemporal.label}: ${badTemporal.temporal==='date'?'YYYY-MM-DD':'YYYY-MM-DD HH:mm'} 형식으로 입력하세요.`};const bad=sheetConfig(name).columns.find(c=>c.numeric&&values[c.key]!==''&&!Number.isFinite(numberOrBlank(values[c.key])));if(bad)return{type:'error',label:'숫자 확인',detail:`${bad.label} 값을 확인하세요.`};const ep=episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===sequence);return ep?{type:'existing',label:'기존 차수 수정',patient,episode:ep}:{type:'new',label:'새 차수 연결',patient};};

    ensureEpisodeForSequence=function(state,patient,sequence){let episode=episodesForPatient(state,patient.id).find(e=>Number(e.sequence)===Number(sequence));if(!episode){episode={id:uid('ECMO'),patientId:patient.id,patientLabel:patientDisplayLabel(patient),sequence:Number(sequence),label:`${Number(sequence)}차 ECMO`,events:{},measurements:{},details:{},dischargeAlive:'',note:'',createdAt:nowText(),updatedAt:nowText(),createdBy:USER};const sameIndexes=(state.ecmoEpisodes||[]).map((item,index)=>item.patientId===patient.id?index:-1).filter(index=>index>=0);const insertAt=sameIndexes.length?Math.max(...sameIndexes)+1:state.ecmoEpisodes.length;state.ecmoEpisodes.splice(insertAt,0,episode);}episode.events=episode.events||{};episode.measurements=episode.measurements||{};episode.details=episode.details||{};const same=(state.ecmoEpisodes||[]).filter(item=>item.patientId===patient.id).sort((a,b)=>Number(a.sequence||0)-Number(b.sequence||0));const first=(state.ecmoEpisodes||[]).findIndex(item=>item.patientId===patient.id);state.ecmoEpisodes=(state.ecmoEpisodes||[]).filter(item=>item.patientId!==patient.id);state.ecmoEpisodes.splice(Math.max(0,first),0,...same);return episode;};

    function mergeRows(rows,columns,keyFields,label){const selected=rows.filter(row=>$('input[type="checkbox"]',row)?.checked);if(selected.length<2)return toast('합칠 행을 2개 이상 선택하세요.','gray');const values=selected.map(row=>{const out={};columns.forEach(c=>{const selector=c.master?`[data-field="${c.key}"]`:`[data-sheet-field="${c.key}"]`;out[c.key]=($(selector,row)?.value||'').trim();});return out;});const key=(item)=>keyFields.map(field=>item[field]||'').join('|');const firstKey=key(values[0]);if(!firstKey||values.some(item=>key(item)!==firstKey))return toast(`${label}은 같은 등록번호와 ECMO 차수의 행만 합칠 수 있습니다.`,'yellow');const target=selected[0];let conflicts=0;columns.forEach(c=>{const selector=c.master?`[data-field="${c.key}"]`:`[data-sheet-field="${c.key}"]`;const input=$(selector,target);if(!input)return;const nonempty=values.map(v=>v[c.key]).filter(Boolean);if(!input.value&&nonempty.length)input.value=nonempty[0];const distinct=[...new Set(nonempty)];if(distinct.length>1)conflicts+=1;});selected.slice(1).forEach(row=>row.remove());const check=$('input[type="checkbox"]',target);if(check)check.checked=false;toast(`${selected.length}개 행을 1개로 합쳤습니다.${conflicts?` 값이 다른 ${conflicts}개 열은 첫 행 값을 유지했습니다.`:''}`,conflicts?'yellow':'teal');}
    function mergeBulkRows(){mergeRows(bulkRows(),BULK_PATIENT_COLUMNS.map(c=>({...c,master:true})),['registrationNo','episodeSequence'],'Patient Master');renumberBulkPatientRows();refreshBulkPatientRowStates();}
    function mergeSheetRows(name){const keys=name==='micro'?['registrationNo','episodeSequence','collectionDateTime','organismName']:['registrationNo','episodeSequence'];mergeRows(sheetRows(name),sheetConfig(name).columns,['registrationNo',...keys.slice(1)],sheetConfig(name).title);renumberSheetRows(name);refreshSheetStates(name);}

    const oldInitBulk=initBulkPatientMasterGrid;
    initBulkPatientMasterGrid=function(){oldInitBulk();const body=$('#bulkPatientGridBody');body?.addEventListener('focusout',event=>{const input=event.target.closest('[data-temporal]');if(input){formatTemporalInput(input,input.dataset.temporal);refreshBulkPatientRowStates();}});$('#bulkMergeRowsBtn')?.addEventListener('click',mergeBulkRows);};
    const oldInitSheets=initEpisodeBulkSheets;
    initEpisodeBulkSheets=function(){oldInitSheets();Object.keys(CLINICAL_SHEET_CONFIG).forEach(name=>{const body=sheetBody(name);body?.addEventListener('focusout',event=>{const input=event.target.closest('[data-temporal]');if(input){formatTemporalInput(input,input.dataset.temporal);refreshSheetStates(name);}});document.querySelector(`[data-bulk-sheet="${name}"] [data-sheet-action="merge"]`)?.addEventListener('click',()=>mergeSheetRows(name));});};

    const oldSaveBulk=saveBulkPatientMasters;
    saveBulkPatientMasters=function(){bulkRows().forEach(row=>BULK_PATIENT_COLUMNS.forEach(c=>{if(c.temporal){const input=$(`[data-field="${c.key}"]`,row);if(input&&input.value&&formatTemporalInput(input,c.temporal))input.value=temporalStorage(input.value,c.temporal);}}));oldSaveBulk();bulkRows().forEach(row=>BULK_PATIENT_COLUMNS.forEach(c=>{if(c.temporal){const input=$(`[data-field="${c.key}"]`,row);if(input&&input.value)input.value=temporalDisplay(input.value,c.temporal);}}));refreshBulkPatientRowStates();};
    const oldSaveSheet=saveClinicalSheet;
    saveClinicalSheet=function(name){sheetRows(name).forEach(row=>sheetConfig(name).columns.forEach(c=>{if(c.temporal){const input=$(`[data-sheet-field="${c.key}"]`,row);if(input&&input.value&&formatTemporalInput(input,c.temporal))input.value=temporalStorage(input.value,c.temporal);}}));oldSaveSheet(name);sheetRows(name).forEach(row=>sheetConfig(name).columns.forEach(c=>{if(c.temporal){const input=$(`[data-sheet-field="${c.key}"]`,row);if(input&&input.value)input.value=temporalDisplay(input.value,c.temporal);}}));refreshSheetStates(name);};

    renderClinicalPatients=function(state=readState()){
      const body=$('#clinicalPatientBody');if(!body)return;const patients=state.patients||[];
      if(!patients.length){setTableEmpty(body,12,'아직 등록된 자료가 없습니다.','Patient Master 시트에 환자와 ECMO 차수를 입력하세요.');if($('#clinicalListSummary'))$('#clinicalListSummary').textContent='표시할 환자 0명';return;}
      const organismSelect=$('#clinicalOrganismFilter');const currentOrganism=organismSelect?.value||'';const organisms=[...new Set((state.microbiologyRecords||[]).map(r=>String(r.organismName||'').trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b,'ko'));
      if(organismSelect){organismSelect.innerHTML=option('','전체 균종')+organisms.map(name=>option(name,name)).join('');if(organisms.includes(currentOrganism))organismSelect.value=currentOrganism;}
      const query=String($('#clinicalPatientSearch')?.value||'').trim().toLowerCase(),filter=$('#clinicalPatientFilter')?.value||'all',organism=$('#clinicalOrganismFilter')?.value||'',sort=$('#clinicalPatientSort')?.value||'initials';
      const files=state.vitalFiles||[],micro=state.microbiologyRecords||[];
      const groups=patients.map(patient=>{const episodes=episodesForPatient(state,patient.id);const eps=episodes.length?episodes:[{id:'',sequence:1,events:{},details:{}}];const patientFiles=files.filter(f=>f.patientId===patient.id||f.matchedPatientId===patient.id||eps.some(ep=>ep.id&&f.episodeId===ep.id));const patientMicro=micro.filter(r=>r.patientId===patient.id);const dead=eps.some(ep=>ep.dischargeAlive==='dead'||ep.dischargeAlive==='0'||ep.events?.deathDate);const alive=eps.some(ep=>ep.dischargeAlive==='alive'||ep.dischargeAlive==='1');const detected=patientMicro.some(r=>r.organismName&&!/no growth|negative|없음/i.test(String(r.organismName)));const text=[patient.initials,patient.registrationNo,...eps.flatMap(ep=>[ep.details?.diagnosis,ep.details?.indication,ep.events?.ecmoStartTime,ep.events?.ecmoFinishTime]),...patientFiles.map(f=>f.name),...patientMicro.map(r=>r.organismName)].join(' ').toLowerCase();return{patient,episodes:eps,files:patientFiles,micro:patientMicro,dead,alive,detected,text,csvCount:patientFiles.length,earliestStart:eps.map(e=>e.events?.ecmoStartTime).filter(Boolean).sort()[0]||'',latestStart:eps.map(e=>e.events?.ecmoStartTime).filter(Boolean).sort().slice(-1)[0]||'',earliestFinish:eps.map(e=>e.events?.ecmoFinishTime).filter(Boolean).sort()[0]||'',latestFinish:eps.map(e=>e.events?.ecmoFinishTime).filter(Boolean).sort().slice(-1)[0]||''};});
      let visible=groups.filter(g=>!query||g.text.includes(query)).filter(g=>!organism||g.micro.some(r=>r.organismName===organism)).filter(g=>filter==='all'||(filter==='dead'&&g.dead)||(filter==='alive'&&g.alive)||(filter==='organismPositive'&&g.detected)||(filter==='hasCsv'&&g.csvCount>0)||(filter==='noCsv'&&g.csvCount===0)||(filter==='multiEpisode'&&g.episodes.length>1));
      const cmpText=(a,b,key)=>String(a[key]||'').localeCompare(String(b[key]||''),'ko-KR',{numeric:true,sensitivity:'base'});visible.sort((a,b)=>{if(sort==='registration')return cmpText(a.patient,b.patient,'registrationNo');if(sort==='ecmoStartAsc')return cmpText(a,b,'earliestStart');if(sort==='ecmoStartDesc')return cmpText(b,a,'latestStart');if(sort==='ecmoFinishAsc')return cmpText(a,b,'earliestFinish');if(sort==='ecmoFinishDesc')return cmpText(b,a,'latestFinish');if(sort==='admissionAsc')return cmpText(a.patient,b.patient,'admissionDate');if(sort==='csvDesc')return b.csvCount-a.csvCount||cmpText(a.patient,b.patient,'initials');if(sort==='updatedDesc')return String(b.patient.updatedAt||'').localeCompare(String(a.patient.updatedAt||''));return cmpText(a.patient,b.patient,'initials')||cmpText(a.patient,b.patient,'registrationNo');});
      const rows=[];visible.forEach((group,groupIndex)=>group.episodes.forEach((ep,episodeIndex)=>rows.push({group,ep,groupIndex,episodeIndex})));
      if(!rows.length){setTableEmpty(body,12,'조건에 맞는 자료가 없습니다.','정렬·필터 조건을 변경하세요.');if($('#clinicalListSummary'))$('#clinicalListSummary').textContent=`전체 ${patients.length}명 중 0명 표시`;return;}
      body.innerHTML=rows.map(({group,ep,groupIndex,episodeIndex})=>{const p=group.patient,d=ep.details||{},e=ep.events||{};const epFiles=group.files.filter(f=>f.episodeId===ep.id||(!f.episodeId&&episodeIndex===0));const names=epFiles.map(f=>f.name).filter(Boolean);const epMicro=group.micro.filter(r=>!ep.id||r.episodeId===ep.id);const organismNames=[...new Set(epMicro.map(r=>r.organismName).filter(Boolean))];const outcome=e.deathDate||ep.dischargeAlive==='dead'?'사망':ep.dischargeAlive==='alive'?'생존 퇴원':'미상';return `<tr class="${episodeIndex?'episode-followup':''}"><td>${episodeIndex?'↳':groupIndex+1}</td><td><strong>${escapeHtml(p.initials||'-')}</strong></td><td>${escapeHtml(patientMaskedRegistration(p.registrationNo))}</td><td>${badge(`${ep.sequence||1}차`,'blue')}</td><td>${escapeHtml([temporalDisplay(e.ecmoStartTime,'datetime'),temporalDisplay(e.ecmoFinishTime,'datetime')].filter(Boolean).join(' → ')||'-')}</td><td>${escapeHtml(temporalDisplay(p.admissionDate,'date')||'-')}</td><td>${escapeHtml([p.sex,temporalDisplay(p.birthDate,'date')].filter(Boolean).join(' / ')||'-')}</td><td>${escapeHtml([d.indication,d.diagnosis].filter(Boolean).join(' / ')||'-')}</td><td>${escapeHtml([d.ecmoMode,d.drainSite,d.perfusionSite||d.returnSite].filter(Boolean).join(' / ')||'-')}</td><td class="clinical-csv-cell" title="${escapeHtml(names.join('\n'))}"><strong>${epFiles.length}개</strong><small>${escapeHtml(names.slice(0,2).join(', ')||'업로드 없음')}</small></td><td class="clinical-micro-outcome"><strong>${escapeHtml(outcome)}</strong><small>${escapeHtml(organismNames.slice(0,3).join(', ')||'균종 기록 없음')}</small></td><td><div class="master-row-actions"><button class="btn secondary" type="button" data-load-master-grid="${escapeHtml(p.id)}">표에서 수정</button><button class="btn ghost" type="button" data-delete-clinical-patient="${escapeHtml(p.id)}">환자 삭제</button></div></td></tr>`;}).join('');
      if($('#clinicalListSummary'))$('#clinicalListSummary').textContent=`전체 ${patients.length}명 · 현재 ${visible.length}명 · ECMO 차수 ${rows.length}건 · CSV ${visible.reduce((sum,g)=>sum+g.csvCount,0)}개`;
      $$('[data-load-master-grid]',body).forEach(btn=>btn.addEventListener('click',()=>{activateClinicalSheet('master');loadPatientsIntoBulkGrid();$('#bulkPatientGridScroll')?.scrollIntoView({behavior:'smooth',block:'center'});}));
      $$('[data-delete-clinical-patient]',body).forEach(btn=>btn.addEventListener('click',event=>{event.stopPropagation();if(!confirm('이 환자 Master와 연결된 모든 ECMO 차수, 미생물검사, 진단검사 기록을 삭제할까요?'))return;const patientId=btn.dataset.deleteClinicalPatient;const next=patchState(s=>{s.patients=(s.patients||[]).filter(p=>p.id!==patientId);s.studyPatients=(s.studyPatients||[]).filter(sp=>sp.patientId!==patientId);s.ecmoEpisodes=(s.ecmoEpisodes||[]).filter(e=>e.patientId!==patientId);s.microbiologyRecords=(s.microbiologyRecords||[]).filter(r=>r.patientId!==patientId);s.labRecords=(s.labRecords||[]).filter(r=>r.patientId!==patientId);});if(activeEpisodeId&&!episodeById(next,activeEpisodeId))activeEpisodeId=null;renderClinicalEntry(next);toast('환자 Master와 연결 자료를 삭제했습니다.');}));
    };

    window.__initClinicalRegisteredControlsV14=function(){['clinicalPatientSort','clinicalPatientFilter','clinicalOrganismFilter','clinicalPatientSearch'].forEach(id=>$('#'+id)?.addEventListener(id==='clinicalPatientSearch'?'input':'change',()=>renderClinicalPatients(readState())));$('#clinicalFilterResetBtn')?.addEventListener('click',()=>{if($('#clinicalPatientSort'))$('#clinicalPatientSort').value='initials';if($('#clinicalPatientFilter'))$('#clinicalPatientFilter').value='all';if($('#clinicalOrganismFilter'))$('#clinicalOrganismFilter').value='';if($('#clinicalPatientSearch'))$('#clinicalPatientSearch').value='';renderClinicalPatients(readState());});renderClinicalPatients(readState());};
  }

  document.addEventListener('DOMContentLoaded', () => {
    commonInit();
    const page = currentPage();
    if (page === 'login.html') initLogin();
    if (page === 'signup.html') initSignup();
    if (page === 'dashboard.html' || page === 'index.html') refreshDashboard();
    if (page === 'workplace.html') initWorkplaceHome();
    if (page === 'vital-upload.html') initVitalUpload();
    if (page === 'vital-registry.html') initVitalRegistry();
    if (page === 'tag-manager.html') initTagTreeManager();
    if (page === 'patient-upload.html') { installClinicalWorkbookV14(); initPatientUpload(); initEpisodeEnhancements(); window.__initClinicalRegisteredControlsV14?.(); }
    if (page === 'tag-assignment.html') initConditionalTagAssignment();
    if (page === 'tag-detail.html') initTagDetail();
    if (page === 'statistical-analysis.html') initStatisticalAnalysis();
    if (page === 'analysis-preview.html') initAnalysisPreviewPage();
    if (page === 'analysis-results.html') initAnalysisResults();
    if (page === 'audit-log.html') initAuditLog();
    if (page === 'patient-matching.html') initIntegratedPatientMatching();
    if (page === 'export-center.html') initExportCenter();
    if (page === 'members.html') initMembers();
    if (page === 'research-projects.html') initResearchProjects();
    bindFallbackDisabledButtons();
  });
})();
