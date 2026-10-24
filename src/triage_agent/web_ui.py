"""Lightweight, zero-dependency Web GUI for triage-agent.

Runs a local web dashboard using Python's standard library http.server,
providing an interactive interface to run triage scans, inspect reports,
run codebase verifications, and draft audit sign-offs.
"""

import argparse
import json
import os
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict

from rich.console import Console

from triage_agent.config import get_model_name, is_llm_configured
from triage_agent.demo import generate_demo_report
from triage_agent.schemas import (
    CheckPointItem,
    ReconPlan,
    ReconTarget,
    TargetResearchResult,
    TriageNotice,
    TriageReport,
    compute_check_point_id,
    compute_notice_hash,
)
from triage_agent.verifier import (
    AuditAttestation,
    format_verification_markdown,
    verify_codebase,
)

console = Console()

HTML_PAGE = """<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>triage-agent Web Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    .badge-critical { background-color: #fee2e2; color: #991b1b; border: 1px solid #f87171; }
    .badge-high { background-color: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }
    .badge-normal { background-color: #d1fae5; color: #065f46; border: 1px solid #6ee7b7; }
    .badge-unknown { background-color: #f3f4f6; color: #374151; border: 1px solid #d1d5db; }
  </style>
</head>
<body class="bg-slate-50 text-slate-900 font-sans min-h-screen">

  <!-- Header -->
  <header class="bg-slate-900 text-white shadow-lg sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <i class="fa-solid fa-shield-halved text-cyan-400 text-2xl"></i>
        <div>
          <h1 class="text-lg font-bold tracking-tight">triage-agent <span class="text-xs font-normal bg-cyan-950 text-cyan-300 border border-cyan-700 px-2 py-0.5 rounded ml-2">Console</span></h1>
          <p class="text-xs text-slate-400">Autonomous SBOM Vulnerability Intelligence & Triage</p>
        </div>
      </div>
      <div class="flex items-center space-x-4 text-xs">
        <div id="llm-status" class="flex items-center space-x-1.5 bg-slate-800 px-3 py-1.5 rounded-full border border-slate-700">
          <span class="w-2 h-2 rounded-full bg-yellow-400 animate-pulse"></span>
          <span class="text-slate-300">Checking LLM...</span>
        </div>
        <span class="text-slate-500">|</span>
        <a href="https://github.com" target="_blank" class="text-slate-400 hover:text-white transition"><i class="fa-brands fa-github text-base"></i></a>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 py-6 grid grid-cols-1 lg:grid-cols-12 gap-6">

    <!-- Left Controls Panel (4 cols) -->
    <section class="lg:col-span-4 space-y-6">
      <div class="bg-white p-5 rounded-xl shadow-sm border border-slate-200">
        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-500 mb-4 flex items-center">
          <i class="fa-solid fa-sliders text-indigo-500 mr-2"></i> スキャン & トリアージ設定
        </h2>

        <form id="triage-form" class="space-y-4">
          <!-- Execution Mode -->
          <div>
            <label class="block text-xs font-medium text-slate-700 mb-1">実行モード</label>
            <div class="grid grid-cols-3 gap-2">
              <label class="cursor-pointer">
                <input type="radio" name="mode" value="demo" checked class="peer sr-only">
                <div class="text-center py-2 px-1 text-xs rounded border border-slate-200 peer-checked:bg-indigo-50 peer-checked:border-indigo-500 peer-checked:text-indigo-700 peer-checked:font-semibold hover:bg-slate-50 transition">
                  Demo
                </div>
              </label>
              <label class="cursor-pointer">
                <input type="radio" name="mode" value="dry-run" class="peer sr-only">
                <div class="text-center py-2 px-1 text-xs rounded border border-slate-200 peer-checked:bg-indigo-50 peer-checked:border-indigo-500 peer-checked:text-indigo-700 peer-checked:font-semibold hover:bg-slate-50 transition">
                  Dry-Run
                </div>
              </label>
              <label class="cursor-pointer">
                <input type="radio" name="mode" value="live" class="peer sr-only">
                <div class="text-center py-2 px-1 text-xs rounded border border-slate-200 peer-checked:bg-indigo-50 peer-checked:border-indigo-500 peer-checked:text-indigo-700 peer-checked:font-semibold hover:bg-slate-50 transition">
                  Live Agent
                </div>
              </label>
            </div>
            <p id="mode-desc" class="text-[11px] text-slate-500 mt-1">展示用データ（DEMO-*）で即座にUIを確認します。</p>
          </div>

          <!-- SBOM File -->
          <div>
            <label class="block text-xs font-medium text-slate-700 mb-1">SBOM ファイルパス</label>
            <input type="text" id="sbom-path" value="sample_sbom.json" class="w-full text-xs font-mono px-3 py-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 focus:outline-none">
            <span class="text-[11px] text-slate-400">Syft CycloneDX JSON または Syft native JSON</span>
          </div>

          <!-- Codebase Path (for Verifier) -->
          <div>
            <label class="block text-xs font-medium text-slate-700 mb-1">自社検証コードパス (任意)</label>
            <input type="text" id="code-dir" value="demo_app" class="w-full text-xs font-mono px-3 py-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 focus:outline-none">
            <span class="text-[11px] text-slate-400">空欄でスキップ（外注委託システム向け指示書のみ）</span>
          </div>

          <!-- Audit Sign-off File -->
          <div>
            <label class="block text-xs font-medium text-slate-700 mb-1">手動監査サインオフパス (任意)</label>
            <input type="text" id="audit-file" value="sample_audit_signoff.json" class="w-full text-xs font-mono px-3 py-2 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500 focus:outline-none">
          </div>

          <!-- Submit Button -->
          <button type="submit" id="btn-run" class="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded shadow transition flex items-center justify-center space-x-2 text-sm">
            <i class="fa-solid fa-play"></i>
            <span>トリアージ実行</span>
          </button>
        </form>
      </div>

      <!-- Quick Tips -->
      <div class="bg-indigo-50/60 p-4 rounded-xl border border-indigo-100 text-xs text-indigo-900 space-y-2">
        <div class="font-semibold flex items-center space-x-1.5 text-indigo-800">
          <i class="fa-solid fa-lightbulb text-indigo-600"></i>
          <span>トリアージ運用の3鉄則</span>
        </div>
        <ul class="list-disc list-inside space-y-1 text-slate-700 text-[11px]">
          <li><strong>分からないものを安全と言わない:</strong> コード内未検出は外部設定の要確認。</li>
          <li><strong>正本管理:</strong> AI下書きを人間が承認し固定したJSONを正本とする。</li>
          <li><strong>手動サインオフ:</strong> SRE/インフラの確認根拠を添えて安全（NO）に昇格。</li>
        </ul>
      </div>
    </section>

    <!-- Right Results Panel (8 cols) -->
    <section class="lg:col-span-8 space-y-6">

      <!-- Status Indicator / Spinner -->
      <div id="loading-spinner" class="hidden bg-white p-8 rounded-xl shadow-sm border border-slate-200 text-center space-y-3">
        <i class="fa-solid fa-circle-notch fa-spin text-indigo-600 text-3xl"></i>
        <p class="text-sm font-medium text-slate-700" id="loading-msg">エージェントが調査を実行中...</p>
      </div>

      <!-- Verification Audit Summary (If Codebase Scanned) -->
      <div id="verification-panel" class="hidden bg-white p-5 rounded-xl shadow-sm border border-slate-200 space-y-4">
        <div class="flex items-center justify-between border-b pb-3 border-slate-100">
          <div>
            <h2 class="text-sm font-bold text-slate-800 flex items-center space-x-2">
              <i class="fa-solid fa-code-compare text-emerald-600"></i>
              <span>自社コードベース検証結果サマリ</span>
            </h2>
            <p id="audit-code-dir" class="text-xs text-slate-500 font-mono mt-0.5"></p>
          </div>
          <div id="audit-overall-badge" class="px-3 py-1 rounded-full text-xs font-bold"></div>
        </div>

        <!-- Counts Grid -->
        <div class="grid grid-cols-4 gap-3 text-center">
          <div class="p-3 bg-slate-50 rounded border border-slate-200">
            <span class="block text-xs text-slate-500">総検査項目</span>
            <span id="count-total" class="text-lg font-bold text-slate-800">0</span>
          </div>
          <div class="p-3 bg-red-50 rounded border border-red-200">
            <span class="block text-xs text-red-600 font-medium">YES (要対応)</span>
            <span id="count-yes" class="text-lg font-bold text-red-700">0</span>
          </div>
          <div class="p-3 bg-amber-50 rounded border border-amber-200">
            <span class="block text-xs text-amber-600 font-medium">要確認 (外部設定)</span>
            <span id="count-unverified" class="text-lg font-bold text-amber-700">0</span>
          </div>
          <div class="p-3 bg-emerald-50 rounded border border-emerald-200">
            <span class="block text-xs text-emerald-600 font-medium">NO (確認済安全)</span>
            <span id="count-safe" class="text-lg font-bold text-emerald-700">0</span>
          </div>
        </div>
      </div>

      <!-- Unscanned / Errors Alert Banner -->
      <div id="unscanned-panel" class="hidden bg-amber-50 border-l-4 border-amber-500 p-4 rounded-r-xl shadow-sm">
        <div class="flex items-start">
          <i class="fa-solid fa-triangle-exclamation text-amber-600 text-lg mr-3 mt-0.5"></i>
          <div class="text-xs">
            <h3 class="font-bold text-amber-800">【注意】調査不能・未調査コンポーネント</h3>
            <p class="text-amber-700 mt-1">以下のコンポーネントは調査不能でした。未調査の項目を「安全」と誤認してはなりません。</p>
            <ul id="unscanned-list" class="list-disc list-inside mt-2 space-y-1 font-mono text-[11px] text-amber-900"></ul>
          </div>
        </div>
      </div>

      <!-- Notices Container -->
      <div id="notices-container" class="space-y-6">
        <!-- Empty Placeholder -->
        <div class="bg-white p-12 rounded-xl shadow-sm border border-dashed border-slate-300 text-center space-y-3">
          <i class="fa-solid fa-clipboard-list text-slate-300 text-4xl"></i>
          <h3 class="text-sm font-semibold text-slate-600">レポートがまだありません</h3>
          <p class="text-xs text-slate-400 max-w-sm mx-auto">左側のパネルから実行モードを選択し、「トリアージ実行」をクリックしてください。</p>
        </div>
      </div>

    </section>
  </main>

  <!-- Signoff Modal -->
  <div id="signoff-modal" class="hidden fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl border border-slate-200 max-w-lg w-full p-6 space-y-4">
      <div class="flex items-center justify-between border-b pb-3">
        <h3 class="text-base font-bold text-slate-800 flex items-center space-x-2">
          <i class="fa-solid fa-signature text-indigo-600"></i>
          <span>手動監査サインオフの作成</span>
        </h3>
        <button onclick="closeModal()" class="text-slate-400 hover:text-slate-600"><i class="fa-solid fa-xmark text-lg"></i></button>
      </div>

      <div class="space-y-3 text-xs">
        <div>
          <label class="block font-medium text-slate-600 mb-0.5">対象確認ポイント ID</label>
          <input type="text" id="modal-cp-id" readonly class="w-full font-mono bg-slate-100 px-3 py-1.5 border border-slate-300 rounded text-slate-600">
        </div>
        <div>
          <label class="block font-medium text-slate-600 mb-0.5">Notice Fingerprint (notice_hash)</label>
          <input type="text" id="modal-notice-hash" readonly class="w-full font-mono bg-slate-100 px-3 py-1.5 border border-slate-300 rounded text-slate-600">
        </div>
        <div>
          <label class="block font-medium text-slate-600 mb-0.5">確認ポイントの質問</label>
          <textarea id="modal-question" readonly rows="2" class="w-full bg-slate-100 px-3 py-1.5 border border-slate-300 rounded text-slate-600"></textarea>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block font-medium text-slate-700 mb-0.5">確認者 (氏名/チーム) *</label>
            <input type="text" id="modal-reviewer" placeholder="例: SRE 山田" class="w-full px-3 py-1.5 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500">
          </div>
          <div>
            <label class="block font-medium text-slate-700 mb-0.5">確認日付 *</label>
            <input type="date" id="modal-date" class="w-full px-3 py-1.5 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500">
          </div>
        </div>
        <div>
          <label class="block font-medium text-slate-700 mb-0.5">確認根拠・エビデンス *</label>
          <textarea id="modal-evidence" placeholder="例: 本番環境の server.xml を確認。該当コネクタはコメントアウトされており非該当。" rows="3" class="w-full px-3 py-1.5 border border-slate-300 rounded focus:ring-2 focus:ring-indigo-500"></textarea>
        </div>
      </div>

      <div class="flex justify-end space-x-2 pt-3 border-t">
        <button onclick="closeModal()" class="px-4 py-2 border border-slate-300 text-slate-700 rounded text-xs hover:bg-slate-50 transition">キャンセル</button>
        <button onclick="applySignoff()" class="px-4 py-2 bg-indigo-600 text-white rounded text-xs hover:bg-indigo-700 transition font-medium">サインオフを適用・保存</button>
      </div>
    </div>
  </div>

  <script>
    let currentReport = null;
    let currentAudit = null;

    // Check system status on load
    fetch('/api/status')
      .then(res => res.json())
      .then(data => {
        const el = document.getElementById('llm-status');
        if (data.is_llm_configured) {
          el.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-400"></span><span class="text-slate-300">LLM Ready (${data.model})</span>`;
        } else {
          el.innerHTML = `<span class="w-2 h-2 rounded-full bg-amber-400"></span><span class="text-slate-300">Offline / API Key Missing</span>`;
        }
      });

    // Handle Mode change description
    document.querySelectorAll('input[name="mode"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        const desc = document.getElementById('mode-desc');
        if (e.target.value === 'demo') desc.innerText = '展示用合成データ（DEMO-*）で即座にUIを確認します。';
        else if (e.target.value === 'dry-run') desc.innerText = 'LLM APIを呼ばず、OSV・GitHubの公開情報でローカルシミュレーションします。';
        else desc.innerText = 'Gemini ライブエージェントが深層調査・パッチDiff精読・即応指示書生成を実行します。';
      });
    });

    // Form Submit
    document.getElementById('triage-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const mode = document.querySelector('input[name="mode"]:checked').value;
      const sbom = document.getElementById('sbom-path').value;
      const codeDir = document.getElementById('code-dir').value;
      const auditFile = document.getElementById('audit-file').value;

      document.getElementById('loading-spinner').classList.remove('hidden');
      document.getElementById('notices-container').classList.add('hidden');
      document.getElementById('verification-panel').classList.add('hidden');
      document.getElementById('unscanned-panel').classList.add('hidden');

      try {
        const res = await fetch('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ mode, sbom, code_dir: codeDir, audit_file: auditFile })
        });
        const data = await res.json();
        currentReport = data.report;
        currentAudit = data.audit;

        renderReport(currentReport, currentAudit);
      } catch (err) {
        alert('実行エラー: ' + err);
      } finally {
        document.getElementById('loading-spinner').classList.add('hidden');
        document.getElementById('notices-container').classList.remove('hidden');
      }
    });

    function renderReport(report, audit) {
      // 1. Render Verification summary if available
      const vPanel = document.getElementById('verification-panel');
      if (audit) {
        vPanel.classList.remove('hidden');
        document.getElementById('audit-code-dir').innerText = `対象リポジトリ: ${audit.code_dir}`;
        const b = document.getElementById('audit-overall-badge');
        b.innerText = audit.overall_status;
        if (audit.overall_status.startsWith('YES')) {
          b.className = 'px-3 py-1 rounded-full text-xs font-bold badge-critical';
        } else if (audit.overall_status.includes('確認')) {
          b.className = 'px-3 py-1 rounded-full text-xs font-bold badge-high';
        } else {
          b.className = 'px-3 py-1 rounded-full text-xs font-bold badge-normal';
        }

        document.getElementById('count-total').innerText = audit.summary_counts.total_checks || 0;
        document.getElementById('count-yes').innerText = audit.summary_counts.yes_count || 0;
        document.getElementById('count-unverified').innerText = audit.summary_counts.unverified_count || 0;
        document.getElementById('count-safe').innerText = audit.summary_counts.safe_count || 0;
      } else {
        vPanel.classList.add('hidden');
      }

      // 2. Unscanned warnings
      const uPanel = document.getElementById('unscanned-panel');
      const uList = document.getElementById('unscanned-list');
      if (report.unscanned_or_failed_components && report.unscanned_or_failed_components.length > 0) {
        uPanel.classList.remove('hidden');
        uList.innerHTML = report.unscanned_or_failed_components.map(item => `<li>${escapeHtml(item)}</li>`).join('');
      } else {
        uPanel.classList.add('hidden');
      }

      // 3. Notices
      const container = document.getElementById('notices-container');
      if (!report.notices || report.notices.length === 0) {
        container.innerHTML = `
          <div class="bg-white p-8 rounded-xl shadow-sm border border-slate-200 text-center">
            <i class="fa-solid fa-circle-check text-emerald-500 text-3xl mb-2"></i>
            <h3 class="text-sm font-bold text-slate-700">該当する要対応コンポーネントはありません</h3>
            <p class="text-xs text-slate-400 mt-1">スキャンされたコンポーネントに対処必要なシグナルは検出されませんでした。</p>
          </div>
        `;
        return;
      }

      container.innerHTML = report.notices.map((n, idx) => {
        // Find matching audit notice result if any
        let auditNotice = null;
        if (audit && audit.notice_results) {
          auditNotice = audit.notice_results.find(an => an.notice.product_name === n.product_name);
        }

        let deadlineBadge = 'badge-normal';
        if (n.conclusion.includes('48時間')) deadlineBadge = 'badge-critical';
        else if (n.conclusion.includes('7日')) deadlineBadge = 'badge-high';

        return `
          <article class="bg-white rounded-xl shadow-sm border border-slate-200 overflow-hidden">
            <!-- Notice Header -->
            <div class="p-5 border-b border-slate-100 bg-slate-50/50">
              <div class="flex items-start justify-between">
                <div>
                  <div class="flex items-center space-x-2">
                    <h3 class="text-base font-bold text-slate-900">${escapeHtml(n.product_name)}</h3>
                    <span class="text-[10px] font-mono text-slate-400 bg-slate-100 px-2 py-0.5 rounded">hash: ${n.notice_hash || 'none'}</span>
                  </div>
                  <p class="text-xs text-slate-500 mt-0.5">公開日: ${escapeHtml(n.announcement_date)} | 修正版: <strong class="text-slate-700">${escapeHtml(n.fixed_versions)}</strong></p>
                </div>
                <span class="text-xs font-bold px-3 py-1 rounded-full ${deadlineBadge}">
                  ${n.severity_note || '要確認'}
                </span>
              </div>

              <!-- Conclusion Box -->
              <div class="mt-3 p-3 bg-white rounded-lg border border-slate-200 text-xs">
                <strong class="text-slate-800">【結論】</strong> ${escapeHtml(n.conclusion)}
              </div>
            </div>

            <!-- Check Points Table -->
            <div class="p-5 space-y-4">
              <div class="overflow-x-auto">
                <table class="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr class="bg-slate-100 text-slate-600 font-semibold border-b border-slate-200">
                      <th class="p-2.5 w-1/5">対象 / CVE (CVSS)</th>
                      <th class="p-2.5 w-1/4">確認ポイント (Yes/No)</th>
                      <th class="p-2.5 w-1/3">具体的確認方法</th>
                      ${audit ? '<th class="p-2.5 w-1/5">自社判定 / サインオフ</th>' : ''}
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100 text-slate-700">
                    ${n.check_points.map((cp, cpIdx) => {
                      let auditCp = null;
                      if (auditNotice && auditNotice.results) {
                        auditCp = auditNotice.results[cpIdx];
                      }

                      let auditTd = '';
                      if (audit) {
                        let stBadge = 'bg-slate-100 text-slate-700';
                        if (auditCp) {
                          if (auditCp.status.startsWith('YES')) stBadge = 'badge-critical font-bold';
                          else if (auditCp.status.startsWith('NO')) stBadge = 'badge-normal font-bold';
                          else stBadge = 'badge-high font-bold';
                        }

                        const statusText = auditCp ? auditCp.status : '未検証';
                        const isUnverified = statusText.includes('未検出') || statusText.includes('要手動確認');

                        auditTd = `
                          <td class="p-2.5">
                            <span class="inline-block px-2 py-0.5 rounded text-[11px] ${stBadge}">${statusText}</span>
                            ${auditCp && auditCp.matches && auditCp.matches.length > 0 ? 
                              `<div class="mt-1 text-[10px] font-mono text-red-600">
                                📍 ${escapeHtml(auditCp.matches[0].file_path)}:${auditCp.matches[0].line_number}
                              </div>` : ''}
                            ${isUnverified ? `
                              <button onclick="openSignoffModal('${escapeHtml(cp.check_point_id)}', '${escapeHtml(n.notice_hash)}', '${escapeHtml(cp.check_point_yes_no)}')" class="mt-1.5 text-[10px] bg-slate-100 hover:bg-indigo-50 hover:text-indigo-600 text-slate-600 px-2 py-0.5 rounded border border-slate-200 transition flex items-center space-x-1">
                                <i class="fa-solid fa-pen-to-square"></i>
                                <span>サインオフ作成</span>
                              </button>
                            ` : ''}
                          </td>
                        `;
                      }

                      return `
                        <tr class="hover:bg-slate-50/50">
                          <td class="p-2.5 font-medium">
                            <div>${escapeHtml(cp.target_or_cve)}</div>
                            <div class="text-[10px] text-slate-400 font-mono">${escapeHtml(cp.check_point_id || '')}</div>
                          </td>
                          <td class="p-2.5 font-medium text-slate-800">${escapeHtml(cp.check_point_yes_no)}</td>
                          <td class="p-2.5 text-slate-600 font-mono text-[11px]">${escapeHtml(cp.verification_method)}</td>
                          ${auditTd}
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>

              <!-- Workaround & Unconfirmed -->
              ${n.workaround ? `
                <div class="text-xs bg-emerald-50/60 p-3 rounded-lg border border-emerald-100 text-emerald-900">
                  <strong>💡 推奨回避策:</strong> ${escapeHtml(n.workaround)}
                </div>
              ` : ''}

              <!-- Sources -->
              ${n.sources && n.sources.length > 0 ? `
                <div class="text-[11px] text-slate-400 flex items-center space-x-2 pt-2 border-t border-slate-100">
                  <span class="font-semibold text-slate-500">出典:</span>
                  ${n.sources.map(s => `<a href="${s}" target="_blank" class="text-indigo-600 hover:underline truncate max-w-xs">${s}</a>`).join(', ')}
                </div>
              ` : ''}
            </div>
          </article>
        `;
      }).join('');
    }

    // Modal controls
    function openSignoffModal(cpId, noticeHash, question) {
      document.getElementById('modal-cp-id').value = cpId;
      document.getElementById('modal-notice-hash').value = noticeHash;
      document.getElementById('modal-question').value = question;
      document.getElementById('modal-reviewer').value = '';
      document.getElementById('modal-date').value = new Date().toISOString().split('T')[0];
      document.getElementById('modal-evidence').value = '';
      document.getElementById('signoff-modal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('signoff-modal').classList.add('hidden');
    }

    async function applySignoff() {
      const cpId = document.getElementById('modal-cp-id').value;
      const noticeHash = document.getElementById('modal-notice-hash').value;
      const reviewer = document.getElementById('modal-reviewer').value.trim();
      const date = document.getElementById('modal-date').value;
      const evidence = document.getElementById('modal-evidence').value.trim();
      const auditFile = document.getElementById('audit-file').value.trim() || 'sample_audit_signoff.json';

      if (!reviewer || !evidence) {
        alert('確認者と確認根拠（エビデンス）を入力してください。');
        return;
      }

      try {
        const res = await fetch('/api/create-signoff', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            audit_file: auditFile,
            attestation: {
              check_point_id: cpId,
              notice_hash: noticeHash,
              status: "NO (手動確認済み・非該当)",
              reviewer: reviewer,
              date: date,
              evidence: evidence
            }
          })
        });
        const data = await res.json();
        if (data.success) {
          closeModal();
          // Auto re-run verification
          document.getElementById('btn-run').click();
        } else {
          alert('サインオフ保存失敗: ' + data.error);
        }
      } catch (err) {
        alert('エラー: ' + err);
      }
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }
  </script>
</body>
</html>
"""


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for snappy UI responsiveness."""
    daemon_threads = True


class TriageDashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the triage-agent dashboard."""

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))
        elif self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            status = {
                "is_llm_configured": is_llm_configured(),
                "model": get_model_name(),
                "cwd": str(Path.cwd()),
            }
            self.wfile.write(json.dumps(status).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)

        try:
            req_data = json.loads(post_body.decode("utf-8"))
        except Exception:
            req_data = {}

        if self.path == "/api/run":
            mode = req_data.get("mode", "demo")
            sbom_path = req_data.get("sbom", "sample_sbom.json")
            code_dir = req_data.get("code_dir")
            audit_file = req_data.get("audit_file")

            try:
                # 1. Execute triage notice generation
                if mode == "demo":
                    triage_report = generate_demo_report()
                elif mode == "dry-run":
                    from triage_agent.agents.planner import run_recon_planner
                    from triage_agent.agents.researcher import run_researcher
                    from triage_agent.agents.triage import run_triage_agent
                    from triage_agent.tools.osv import query_osv_batch
                    from triage_agent.tools.sbom import load_sbom_summary

                    components = load_sbom_summary(sbom_path)
                    osv_hits, osv_errs = query_osv_batch(components)
                    recon_plan = run_recon_planner(sbom_path, osv_results=osv_hits, dry_run=True)
                    unscanned = [f"OSVエラー: {e}" for e in osv_errs]
                    res_list = []
                    for t in recon_plan.targets[:10]:
                        r = run_researcher(t, dry_run=True)
                        res_list.append(r)
                        if r.errors:
                            unscanned.extend([f"{t.name}: {err}" for err in r.errors])
                    triage_report = run_triage_agent(res_list, unscanned_components=unscanned, dry_run=True)
                else:  # live agent mode
                    from triage_agent.agents.planner import run_recon_planner
                    from triage_agent.agents.researcher import run_researcher
                    from triage_agent.agents.triage import run_triage_agent
                    from triage_agent.tools.osv import query_osv_batch
                    from triage_agent.tools.sbom import load_sbom_summary

                    components = load_sbom_summary(sbom_path)
                    osv_hits, osv_errs = query_osv_batch(components)
                    recon_plan = run_recon_planner(sbom_path, osv_results=osv_hits, dry_run=False)
                    unscanned = [f"OSVエラー: {e}" for e in osv_errs]
                    res_list = []
                    for t in recon_plan.targets[:10]:
                        r = run_researcher(t, dry_run=False)
                        res_list.append(r)
                        if r.errors:
                            unscanned.extend([f"{t.name}: {err}" for err in r.errors])
                    triage_report = run_triage_agent(res_list, unscanned_components=unscanned, dry_run=False)

                # 2. Run codebase verification if code_dir specified
                audit_report = None
                if code_dir and Path(code_dir).exists():
                    audit_res = verify_codebase(triage_report, code_dir, audit_file_path=audit_file)
                    audit_report = audit_res.model_dump()

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response_payload = {
                    "report": triage_report.model_dump(),
                    "audit": audit_report,
                }
                self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))

        elif self.path == "/api/create-signoff":
            audit_file_path = req_data.get("audit_file", "sample_audit_signoff.json")
            attestation_data = req_data.get("attestation", {})

            try:
                path = Path(audit_file_path)
                existing_attestations = []
                if path.exists():
                    try:
                        raw = json.loads(path.read_text(encoding="utf-8"))
                        if isinstance(raw, dict) and "attestations" in raw:
                            existing_attestations = raw["attestations"]
                        elif isinstance(raw, list):
                            existing_attestations = raw
                    except Exception:
                        existing_attestations = []

                # Replace or append attestation for the same check_point_id
                cp_id = attestation_data.get("check_point_id")
                updated = False
                for idx, item in enumerate(existing_attestations):
                    if item.get("check_point_id") == cp_id:
                        existing_attestations[idx] = attestation_data
                        updated = True
                        break
                if not updated:
                    existing_attestations.append(attestation_data)

                # Write back
                path.write_text(
                    json.dumps({"attestations": existing_attestations}, indent=2, ensure_ascii=False),
                    encoding="utf-8"
                )

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))

        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Mute excessive polling logs
        pass


def run_gui(host: str = "127.0.0.1", port: int = 8080, open_browser: bool = True):
    """Launch the Web GUI dashboard server."""
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, TriageDashboardHandler)
    url = f"http://{host}:{port}"

    console.print(
        f"[bold green]🚀 triage-agent Web Dashboard 起動中...[/bold green]\n"
        f"URL: [bold cyan]{url}[/bold cyan] (Ctrl+C で停止)\n"
    )

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]ダッシュボードサーバーを停止しました。[/yellow]")
        httpd.server_close()


def main():
    parser = argparse.ArgumentParser(description="triage-agent Web Dashboard GUI")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")

    args = parser.parse_args()
    run_gui(host=args.host, port=args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
