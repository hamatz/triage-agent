/* triage-agent local mode: view navigation and the kernel inquiry screen (ADR-022 / ADR-023).
 * Everything coming from the server or the user's file is inserted with textContent (never as HTML),
 * so a crafted CSV cannot inject markup. */
(function () {
  'use strict';

  const VIEWS = ['home', 'kernel', 'sbom'];
  const csrf = () => window.CSRF_TOKEN || (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

  // ---------- navigation ----------
  function showView(name) {
    if (!VIEWS.includes(name)) name = 'home';
    VIEWS.forEach(v => {
      const el = document.getElementById('view-' + v);
      if (el) el.classList.toggle('hidden', v !== name);
    });
    document.querySelectorAll('.app-nav-link').forEach(a => a.classList.toggle('active', a.dataset.view === name));
    window.scrollTo(0, 0);
  }
  window.addEventListener('hashchange', () => showView(location.hash.slice(1)));

  // ---------- helpers ----------
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => {
      if (k === 'class') node.className = v;
      else if (k === 'text') node.textContent = v;
      else node.setAttribute(k, v);
    });
    children.flat().forEach(c => { if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c))); });
    return node;
  }

  function download(text, filename, type) {
    const blob = new Blob([text], { type: type || 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = el('a', { href: url, download: filename });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function postJson(path, body) {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
    if (!res.ok || data.success === false) throw new Error(data.error || ('サーバーの応答が不正です（' + res.status + '）'));
    return data;
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(',', 2)[1] || '');
      reader.onerror = () => reject(new Error('ファイルを読み込めませんでした'));
      reader.readAsDataURL(file);   // bytes as-is: the server handles UTF-8 and Shift_JIS
    });
  }

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    const target = document.getElementById(btn.dataset.copyTarget);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      const old = btn.textContent;
      btn.textContent = 'コピーしました';
      setTimeout(() => { btn.textContent = old; }, 1500);
    } catch (err) {
      const range = document.createRange();
      range.selectNodeContents(target);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);   // clipboard API unavailable: leave it selected for Ctrl+C
    }
  });

  // ---------- kernel inquiry ----------
  const ki = { request: null, result: null, file: null };
  const $ = id => document.getElementById(id);
  const safeName = s => (s || '').replace(/[\\/:*?"<>|\s]+/g, '_').slice(0, 60);

  async function makeRequest() {
    const btn = $('ki-btn-request');
    btn.disabled = true;
    try {
      ki.request = await postJson('/api/kernel-inquiry/request', { target: $('ki-target').value });
      download(ki.request.csv, ki.request.filename, 'text/csv;charset=utf-8');
      $('ki-request-file').textContent = ki.request.filename;
      $('ki-request-message').textContent = ki.request.message;
      $('ki-request-result').classList.remove('hidden');
    } catch (err) {
      alert('記入表を作れませんでした: ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  function chooseFile(file) {
    ki.file = file || null;
    $('ki-file-label').textContent = file ? ('選んだファイル: ' + file.name) : 'ここに記入表（CSV）をドラッグするか、クリックして選んでください';
    $('ki-btn-answers').disabled = !file;
    $('ki-error').classList.add('hidden');
  }

  function statusCell(g) {
    if (g.status === 'unknown') return '❓ 判定できませんでした';
    if (g.status === 'clear') return '✅ なし';
    const noFix = g.remaining.filter(r => !r.fixed).length;
    return '🚨 ' + g.remaining.length + ' 件' + (noFix ? '（うち修正版なし ' + noFix + ' 件）' : '');
  }

  function renderResult(data) {
    const groups = data.groups || [];
    const count = s => groups.filter(g => g.status === s).length;
    const cards = $('ki-summary-cards');
    cards.replaceChildren(
      el('div', { class: 'result-card bad' }, el('div', { class: 'num', text: count('remaining') }), el('div', { class: 'lbl', text: '残っているカーネル' })),
      el('div', { class: 'result-card ok' }, el('div', { class: 'num', text: count('clear') }), el('div', { class: 'lbl', text: '悪用確認済みは残っていない' })),
      el('div', { class: 'result-card unknown' }, el('div', { class: 'num', text: count('unknown') }), el('div', { class: 'lbl', text: '判定できなかった' })),
    );
    $('ki-table').replaceChildren(...groups.map(g => el('tr', {},
      el('td', { text: g.label }), el('td', { text: g.os }), el('td', { class: 'mono', text: g.uname }),
      el('td', { text: g.count ? g.count + ' 台' : '不明' }), el('td', { text: statusCell(g) }),
      el('td', { class: 'mono', text: g.target ? g.target + ' 以上' : '—' }))));

    const msg = data.message || '';
    $('ki-message-block').classList.toggle('hidden', !msg);
    $('ki-result-message').textContent = msg;

    $('ki-details').replaceChildren(...groups.map(g => {
      const box = el('div', { class: 'group-detail' }, el('h3', { text: g.label + '（' + g.uname + '）' }));
      if (g.status === 'unknown') {
        box.append(el('p', { text: '❓ 判定できませんでした: ' + g.reason }),
          el('p', { text: '残っている脆弱性がない、という意味ではありません。ベンダーに、ディストリの勧告での確認をお願いしてください。' }));
        return box;
      }
      if (g.reboot_pending) {
        box.append(el('p', { text: '⚠️ 新しいカーネル' + (g.reboot_pending !== 'yes' ? '（' + g.reboot_pending + '）' : '') +
          'はインストールされていますが、再起動されておらず、古いカーネルのまま動いています。' }));
      }
      if (g.status === 'clear') {
        box.append(el('p', { text: '✅ 悪用確認済み・警戒を引き上げた脆弱性で、直っていないものはありません（確認できた範囲）。' }));
      } else {
        const rows = g.remaining.map(r => el('tr', {},
          el('td', {}, r.url ? el('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer', text: r.cve }) : r.cve),
          el('td', { text: r.name }), el('td', { text: r.reason }), el('td', { class: 'mono', text: r.fixed || '修正版なし' })));
        box.append(el('div', { class: 'table-wrap' }, el('table', { class: 'result-table' },
          el('thead', {}, el('tr', {}, el('th', { text: 'CVE' }), el('th', { text: '名前' }), el('th', { text: '理由' }), el('th', { text: '修正版' }))),
          el('tbody', {}, rows))));
      }
      if (g.others) {
        box.append(el('p', { text: 'ほかに、悪用の確認されていない未修正の脆弱性が ' + g.others + ' 件あります' +
          (g.all_fixes_target ? '（すべて解消するには ' + g.all_fixes_target + ' 以上）' : '') + '。通常の更新の枠で対応してもらうのが目安です。' }));
      }
      return box;
    }));

    const notes = [].concat(data.problems || [], data.errors || []);
    $('ki-notes').classList.toggle('hidden', notes.length === 0);
    $('ki-notes').replaceChildren(el('strong', { text: '読み込めなかったもの・照会できなかったもの' }),
      el('ul', { style: 'margin-top: 6px; padding-left: 18px; list-style: disc;' }, notes.map(n => el('li', { text: n }))));
    $('ki-result').classList.remove('hidden');
    $('ki-result').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function submitAnswers() {
    if (!ki.file) return;
    const btn = $('ki-btn-answers');
    btn.disabled = true;
    $('ki-busy').classList.remove('hidden');
    $('ki-error').classList.add('hidden');
    try {
      ki.result = await postJson('/api/kernel-inquiry/answers', {
        target: $('ki-target').value, filename: ki.file.name,
        content_b64: await fileToBase64(ki.file), offline: $('ki-offline').checked,
      });
      renderResult(ki.result);
    } catch (err) {
      $('ki-error').textContent = '突き合わせできませんでした: ' + err.message;
      $('ki-error').classList.remove('hidden');
    } finally {
      $('ki-busy').classList.add('hidden');
      btn.disabled = !ki.file;
    }
  }

  function initKernel() {
    if (!$('view-kernel')) return;
    $('ki-btn-request').addEventListener('click', makeRequest);
    $('ki-btn-request-csv').addEventListener('click', () => ki.request && download(ki.request.csv, ki.request.filename, 'text/csv;charset=utf-8'));
    $('ki-btn-request-md').addEventListener('click', () => ki.request && download(ki.request.markdown, ki.request.filename.replace(/\.csv$/, '.md'), 'text/markdown;charset=utf-8'));
    $('ki-btn-result-md').addEventListener('click', () => ki.result && download(ki.result.markdown,
      'kernel_inquiry_result_' + (safeName($('ki-target').value) || 'system') + '.md', 'text/markdown;charset=utf-8'));
    $('ki-file').addEventListener('change', e => chooseFile(e.target.files && e.target.files[0]));
    const drop = $('ki-drop');
    ['dragenter', 'dragover'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.add('dragover'); }));
    ['dragleave', 'drop'].forEach(t => drop.addEventListener(t, e => { e.preventDefault(); drop.classList.remove('dragover'); }));
    drop.addEventListener('drop', e => chooseFile(e.dataTransfer.files && e.dataTransfer.files[0]));
    $('ki-btn-answers').addEventListener('click', submitAnswers);
  }

  document.addEventListener('DOMContentLoaded', () => {
    initKernel();
    showView(location.hash.slice(1) || 'home');
  });
})();
