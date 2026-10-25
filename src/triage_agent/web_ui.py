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
  <title>triage-agent — DAWN Studio</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --bg-app: #f6f1e8;
      --bg-surface: #ffffff;
      --bg-surface-subtle: #fcfaf6;
      --text-main: #17243a;
      --text-muted: #5e6d82;
      --text-dim: #8c9ba5;
      --accent-gold: #c49b49;
      --accent-gold-dark: #9f752f;
      --accent-gold-light: #faedd7;
      --accent-gold-bg: #fff9ee;
      --border-color: #d9c9af;
      --border-subtle: #ebdcc5;
      --bd-gold: #d9c9af;
      --serif: Georgia, "Hiragino Mincho ProN", "BIZ UDPMincho", serif;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sh-panel: 0 4px 14px rgba(159, 117, 47, 0.08);
      --sh-modal: 0 24px 64px rgba(7, 19, 41, 0.28);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg-app);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      -webkit-font-smoothing: antialiased;
    }

    /* DAWN Typography & Utilities */
    .eyeb {
      font: 10px var(--mono);
      letter-spacing: 2px;
      color: var(--accent-gold-dark);
      text-transform: uppercase;
      font-weight: 700;
    }
    .serif-title {
      font-family: var(--serif);
      letter-spacing: -0.3px;
    }

    /* Surfaces & Glassmorphism */
    .surface {
      background: rgba(255, 255, 255, 0.82);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      box-shadow: var(--sh-panel);
      backdrop-filter: blur(12px);
    }
    .surface-warm {
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.95) 0%, rgba(251, 248, 242, 0.9) 100%);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      box-shadow: var(--sh-panel);
    }

    /* Form Inputs */
    .dawn-input {
      background: #ffffff;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 8px 12px;
      font-size: 12px;
      color: var(--text-main);
      font-family: var(--mono);
      width: 100%;
      transition: all 0.15s ease;
    }
    .dawn-input:focus {
      outline: none;
      border-color: var(--accent-gold-dark);
      box-shadow: 0 0 0 2px rgba(159, 117, 47, 0.18);
    }

    /* Buttons */
    .btn-dawn-primary {
      background: var(--accent-gold-dark);
      color: #ffffff;
      border: 1px solid #846124;
      border-radius: 10px;
      padding: 10px 18px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      box-shadow: 0 2px 8px rgba(159, 117, 47, 0.25);
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .btn-dawn-primary:hover {
      background: #846124;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(159, 117, 47, 0.32);
    }
    .btn-dawn-secondary {
      background: #ffffff;
      color: var(--text-main);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 6px 14px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-dawn-secondary:hover {
      background: #fbf8f2;
      border-color: var(--accent-gold);
      color: var(--accent-gold-dark);
    }

    /* Action Table Button */
    .table-action-btn {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 4px 10px;
      border: 1px solid var(--border-color);
      background: #ffffff;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      color: var(--accent-gold-dark);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .table-action-btn:hover {
      background: var(--accent-gold-light);
      border-color: var(--accent-gold);
      color: #17243a;
      transform: translateY(-1px);
    }

    /* Mode Subnav Tabs */
    .subnav-tabs {
      display: inline-flex;
      border: 1px solid var(--border-color);
      border-radius: 10px;
      overflow: hidden;
      background: #ffffff;
      box-shadow: 0 1px 4px rgba(0, 0, 0, 0.04);
      width: 100%;
    }
    .subnav-tab {
      flex: 1;
      text-align: center;
      position: relative;
    }
    .subnav-label {
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 8px 10px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.15s ease;
      user-select: none;
    }
    .subnav-tab input:checked + .subnav-label {
      background: rgba(159, 117, 47, 0.12);
      color: var(--text-main);
      font-weight: 600;
      box-shadow: inset 0 -2px 0 var(--accent-gold-dark);
    }
    .subnav-label:hover {
      color: var(--text-main);
      background: rgba(0, 0, 0, 0.02);
    }

    /* Badges & Pills */
    .badge-pill {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 2px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.2px;
    }
    .badge-critical {
      background: #fdf2f2;
      color: #991b1b;
      border: 1px solid #fecaca;
    }
    .badge-high {
      background: #fff9ed;
      color: #92400e;
      border: 1px solid #fde68a;
    }
    .badge-normal {
      background: #f0fdf4;
      color: #166534;
      border: 1px solid #bbf7d0;
    }
    .badge-neutral {
      background: #f8fafc;
      color: #475569;
      border: 1px solid #e2e8f0;
    }

    /* DAWN Spinner Ring Animation */
    .generating-spinner {
      position: relative;
      width: 52px;
      height: 52px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto;
    }
    .generating-ring {
      position: absolute;
      inset: 0;
      border: 3px solid rgba(196, 155, 73, 0.2);
      border-top-color: #c49b49;
      border-right-color: #faedd7;
      border-radius: 50%;
      animation: spinRing 1s linear infinite;
    }
    @keyframes spinRing {
      to { transform: rotate(360deg); }
    }
    .generating-icon {
      font-size: 20px;
      color: #c49b49;
      animation: pulseIcon 1.5s ease-in-out infinite;
    }
    @keyframes pulseIcon {
      0%, 100% { transform: scale(1); opacity: .9; }
      50% { transform: scale(1.15); opacity: 1; }
    }

    /* Modal Overlay */
    .modal-overlay {
      background: rgba(7, 19, 41, 0.65);
      backdrop-filter: blur(6px);
    }
    .modal-card {
      background: #ffffff;
      border: 1.5px solid var(--border-color);
      border-radius: 20px;
      box-shadow: var(--sh-modal);
      max-width: 620px;
      width: 100%;
    }

    /* Footer */
    .app-footer {
      height: 42px;
      border-top: 1px solid var(--border-color);
      padding: 0 24px;
      font: 10px var(--mono);
      color: var(--text-dim);
      background: rgba(255, 255, 255, 0.75);
      backdrop-filter: blur(10px);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
  </style>
</head>
<body class="min-h-screen flex flex-col justify-between">

  <!-- App Header -->
  <header class="h-16 px-6 border-b border-[#d9c9af] bg-white/80 backdrop-blur-md sticky top-0 z-40 flex items-center justify-between">
    <div class="flex items-center space-x-4">
      <div class="flex items-center space-x-2.5">
        <span class="text-xl text-[#c49b49] leading-none">◈</span>
        <div class="serif-title text-2xl text-[#17243a] font-normal leading-tight">
          triage-agent <small class="font-mono text-[10px] tracking-[2px] text-[#9f752f] ml-2">DAWN / 0.1</small>
        </div>
      </div>
      <div class="hidden sm:block text-[11px] text-[#5e6d82] border-l border-[#d9c9af] pl-4 py-0.5">
        Autonomous SBOM Vulnerability Intelligence &amp; Triage
      </div>
    </div>
    
    <div class="flex items-center space-x-3 text-xs">
      <div id="llm-status" class="flex items-center space-x-2 bg-white/90 px-3 py-1.5 rounded-full border border-[#d9c9af] shadow-sm font-mono text-[11px]">
        <span class="w-2 h-2 rounded-full bg-yellow-400 animate-pulse"></span>
        <span class="text-[#5e6d82]">Checking LLM...</span>
      </div>
      <a href="https://github.com" target="_blank" class="text-[#8c9ba5] hover:text-[#17243a] transition p-1.5" title="GitHub Repository">
        <i class="fa-brands fa-github text-base"></i>
      </a>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-8 grid grid-cols-1 lg:grid-cols-12 gap-8">

    <!-- Left Controls Panel (4 cols) -->
    <section class="lg:col-span-4 space-y-6">
      <div class="surface p-6">
        <div class="eyeb mb-1">SCAN &amp; TRIAGE CONFIGURATION</div>
        <h2 class="serif-title text-xl text-[#17243a] font-normal mb-5 flex items-center">
          スキャン &amp; トリアージ設定
        </h2>

        <form id="triage-form" class="space-y-5">
          <!-- Execution Mode -->
          <div>
            <div class="flex items-center justify-between mb-1.5">
              <label class="text-xs font-semibold text-[#17243a]">実行モード</label>
              <span class="text-[10px] font-mono text-[#9f752f]">PIPELINE MODE</span>
            </div>
            
            <div class="subnav-tabs">
              <label class="subnav-tab">
                <input type="radio" name="mode" value="demo" checked class="sr-only">
                <span class="subnav-label">Demo</span>
              </label>
              <label class="subnav-tab">
                <input type="radio" name="mode" value="dry-run" class="sr-only">
                <span class="subnav-label">Dry-Run</span>
              </label>
              <label class="subnav-tab">
                <input type="radio" name="mode" value="live" class="sr-only">
                <span class="subnav-label">Live Agent</span>
              </label>
            </div>
            <p id="mode-desc" class="text-[11px] text-[#5e6d82] mt-2 leading-relaxed bg-[#fcfaf6] p-2.5 rounded-lg border border-[#ebdcc5]">
              展示用合成データ（DEMO-*）で即座にUIを確認します。
            </p>
          </div>

          <!-- SBOM File -->
          <div>
            <label class="block text-xs font-semibold text-[#17243a] mb-1">SBOM ファイルパス</label>
            <input type="text" id="sbom-path" value="sample_sbom.json" class="dawn-input" spellcheck="false">
            <span class="text-[10.5px] text-[#8c9ba5] block mt-1">Syft CycloneDX JSON または Syft native JSON</span>
          </div>

          <!-- Codebase Path (for Verifier) -->
          <div>
            <label class="block text-xs font-semibold text-[#17243a] mb-1">自社検証コードパス (任意)</label>
            <input type="text" id="code-dir" value="demo_app" class="dawn-input" spellcheck="false">
            <span class="text-[10.5px] text-[#8c9ba5] block mt-1">空欄でスキップ（外注委託システム向け指示書のみ）</span>
          </div>

          <!-- Audit Sign-off File -->
          <div>
            <label class="block text-xs font-semibold text-[#17243a] mb-1">手動監査サインオフパス (任意)</label>
            <input type="text" id="audit-file" value="sample_audit_signoff.json" class="dawn-input" spellcheck="false">
            <span class="text-[10.5px] text-[#8c9ba5] block mt-1">SRE/インフラ合意済みの恒久安全判定ファイル</span>
          </div>

          <!-- Submit Button -->
          <button type="submit" id="btn-run" class="w-full btn-dawn-primary py-3">
            <span>◈</span>
            <span>トリアージ実行</span>
          </button>
        </form>
      </div>

      <!-- Quick Tips Box (DAWN Style) -->
      <div class="surface-warm p-5 border-l-[3px] border-l-[#9f752f]">
        <div class="eyeb mb-2 flex items-center space-x-1.5">
          <span>TRIAGE OPERATING PRINCIPLES</span>
        </div>
        <div class="serif-title text-sm text-[#17243a] font-bold mb-2">トリアージ運用の3鉄則</div>
        <ul class="space-y-2 text-[11.5px] text-[#5e6d82] leading-relaxed">
          <li class="flex items-start">
            <span class="text-[#9f752f] mr-1.5">•</span>
            <span><strong class="text-[#17243a]">分からないものを安全と言わない:</strong> コード内未検出は外部設定の要確認。</span>
          </li>
          <li class="flex items-start">
            <span class="text-[#9f752f] mr-1.5">•</span>
            <span><strong class="text-[#17243a]">正本管理:</strong> AI下書きを人間が承認し固定したJSONを正本とする。</span>
          </li>
          <li class="flex items-start">
            <span class="text-[#9f752f] mr-1.5">•</span>
            <span><strong class="text-[#17243a]">手動サインオフ:</strong> 監査根拠を添えて安全（NO）に昇格。</span>
          </li>
        </ul>
      </div>
    </section>

    <!-- Right Results Panel (8 cols) -->
    <section class="lg:col-span-8 space-y-6">

      <!-- Status Indicator / DAWN Gold Ring Spinner -->
      <div id="loading-spinner" class="hidden surface p-10 text-center space-y-4">
        <div class="generating-spinner">
          <div class="generating-ring"></div>
          <span class="generating-icon">◈</span>
        </div>
        <div>
          <h3 class="serif-title text-lg text-[#17243a] font-normal" id="loading-msg">エージェントが調査を実行中...</h3>
          <p class="text-xs text-[#5e6d82] mt-1">OSV.dev・GitHub Security Advisories・差分情報を精読しています</p>
        </div>
      </div>

      <!-- Error Alert Panel -->
      <div id="error-panel" class="hidden bg-[#fdf2f2] border border-[#fecaca] border-l-4 border-l-[#991b1b] p-5 rounded-xl shadow-sm">
        <div class="flex items-start space-x-3">
          <i class="fa-solid fa-circle-exclamation text-[#991b1b] text-lg mt-0.5"></i>
          <div class="text-xs flex-1">
            <div class="eyeb text-[#991b1b] mb-1">EXECUTION ERROR</div>
            <h3 class="font-bold text-[#991b1b] text-sm">実行時エラーが発生しました</h3>
            <p id="error-message" class="text-[#7f1d1d] mt-2 whitespace-pre-wrap font-mono text-[11px] bg-white/70 p-3 rounded border border-[#fecaca]"></p>
          </div>
        </div>
      </div>

      <!-- Verification Audit Summary (If Codebase Scanned) -->
      <div id="verification-panel" class="hidden surface p-6 space-y-5">
        <div class="flex items-center justify-between border-b border-[#ebdcc5] pb-4">
          <div>
            <div class="eyeb mb-1">AUDIT SUMMARY REPORT</div>
            <h2 class="serif-title text-xl text-[#17243a] font-normal flex items-center space-x-2">
              <span>自社コードベース検証結果サマリ</span>
            </h2>
            <p id="audit-code-dir" class="text-xs text-[#8c9ba5] font-mono mt-1"></p>
          </div>
          <div id="audit-overall-badge" class="badge-pill text-xs py-1 px-3"></div>
        </div>

        <!-- Metric Counts Grid -->
        <div class="grid grid-cols-2 sm:grid-cols-4 gap-3.5 text-center">
          <div class="p-3.5 bg-white/90 rounded-xl border border-[#d9c9af] shadow-xs">
            <div class="eyeb text-[9px] mb-1">TOTAL CHECKS</div>
            <div id="count-total" class="serif-title text-3xl text-[#17243a] font-normal">0</div>
            <span class="text-[10.5px] text-[#5e6d82]">総検査項目</span>
          </div>
          <div class="p-3.5 bg-[#fdf2f2] rounded-xl border border-[#fecaca]">
            <div class="eyeb text-[9px] text-[#991b1b] mb-1">AFFECTED</div>
            <div id="count-yes" class="serif-title text-3xl text-[#991b1b] font-normal">0</div>
            <span class="text-[10.5px] text-[#991b1b] font-medium">YES (要対応)</span>
          </div>
          <div class="p-3.5 bg-[#fff9ed] rounded-xl border border-[#fde68a]">
            <div class="eyeb text-[9px] text-[#92400e] mb-1">UNVERIFIED</div>
            <div id="count-unverified" class="serif-title text-3xl text-[#92400e] font-normal">0</div>
            <span class="text-[10.5px] text-[#92400e] font-medium">要確認 (外部設定)</span>
          </div>
          <div class="p-3.5 bg-[#f0fdf4] rounded-xl border border-[#bbf7d0]">
            <div class="eyeb text-[9px] text-[#166534] mb-1">ATTESTED SAFE</div>
            <div id="count-safe" class="serif-title text-3xl text-[#166534] font-normal">0</div>
            <span class="text-[10.5px] text-[#166534] font-medium">NO (確認済安全)</span>
          </div>
        </div>
      </div>

      <!-- Unscanned / Errors Alert Banner -->
      <div id="unscanned-panel" class="hidden bg-[#fff9ed] border border-[#fde68a] border-l-4 border-l-[#92400e] p-5 rounded-xl shadow-sm">
        <div class="flex items-start space-x-3">
          <i class="fa-solid fa-triangle-exclamation text-[#92400e] text-lg mt-0.5"></i>
          <div class="text-xs">
            <div class="eyeb text-[#92400e] mb-1">UNSCANNED WARNING</div>
            <h3 class="font-bold text-[#92400e] text-sm">【注意】調査不能・未調査コンポーネント</h3>
            <p class="text-[#78350f] mt-1 leading-relaxed">
              以下のコンポーネントは調査不能でした。未調査の項目を「安全」と誤認してはなりません。
            </p>
            <ul id="unscanned-list" class="list-disc list-inside mt-2.5 space-y-1 font-mono text-[11px] text-[#78350f] bg-white/70 p-3 rounded-lg border border-[#fde68a]"></ul>
          </div>
        </div>
      </div>

      <!-- Notices Container -->
      <div id="notices-container" class="space-y-6">
        <!-- Empty Placeholder -->
        <div class="surface p-12 text-center space-y-3 border-dashed border-[#d9c9af]">
          <div class="w-12 h-12 mx-auto rounded-full bg-[#faedd7]/50 flex items-center justify-center text-[#9f752f] text-xl">
            ◈
          </div>
          <h3 class="serif-title text-base text-[#17243a] font-normal">レポートがまだありません</h3>
          <p class="text-xs text-[#5e6d82] max-w-sm mx-auto leading-relaxed">
            左側のパネルから実行モードを選択し、「トリアージ実行」をクリックしてください。
          </p>
        </div>
      </div>

    </section>
  </main>

  <!-- Signoff Modal (DAWN Style) -->
  <div id="signoff-modal" class="hidden fixed inset-0 modal-overlay z-50 flex items-center justify-center p-4">
    <div class="modal-card p-6 sm:p-7 space-y-5">
      <div class="flex items-start justify-between border-b border-[#ebdcc5] pb-3.5">
        <div>
          <div class="eyeb mb-1">AUDIT ATTESTATION (DEC-021)</div>
          <h3 class="serif-title text-xl text-[#17243a] font-normal">手動監査サインオフの作成</h3>
        </div>
        <button onclick="closeModal()" class="text-[#8c9ba5] hover:text-[#17243a] transition p-1 text-lg">✕</button>
      </div>

      <div class="space-y-3.5 text-xs">
        <div>
          <label class="block font-semibold text-[#17243a] mb-1">対象確認ポイント ID</label>
          <input type="text" id="modal-cp-id" readonly class="dawn-input bg-[#fcfaf6] text-[#5e6d82]">
        </div>
        <div>
          <label class="block font-semibold text-[#17243a] mb-1">Notice Fingerprint (notice_hash)</label>
          <input type="text" id="modal-notice-hash" readonly class="dawn-input bg-[#fcfaf6] text-[#5e6d82]">
        </div>
        <div>
          <label class="block font-semibold text-[#17243a] mb-1">確認ポイントの質問</label>
          <textarea id="modal-question" readonly rows="2" class="dawn-input bg-[#fcfaf6] text-[#5e6d82]"></textarea>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
          <div>
            <label class="block font-semibold text-[#17243a] mb-1">確認者 (氏名/チーム) *</label>
            <input type="text" id="modal-reviewer" placeholder="例: SRE 山田" class="dawn-input">
          </div>
          <div>
            <label class="block font-semibold text-[#17243a] mb-1">確認日付 *</label>
            <input type="date" id="modal-date" class="dawn-input">
          </div>
        </div>
        <div>
          <label class="block font-semibold text-[#17243a] mb-1">確認根拠・エビデンス *</label>
          <textarea id="modal-evidence" placeholder="例: 本番環境の server.xml を確認。該当コネクタはコメントアウトされており非該当。" rows="3" class="dawn-input font-sans"></textarea>
        </div>
      </div>

      <div class="flex justify-end space-x-2.5 pt-3 border-t border-[#ebdcc5]">
        <button onclick="closeModal()" class="btn-dawn-secondary">キャンセル</button>
        <button onclick="applySignoff()" class="btn-dawn-primary text-xs py-2 px-4">サインオフを適用・保存</button>
      </div>
    </div>
  </div>

  <!-- App Footer -->
  <footer class="app-footer">
    <span>NSTAR DESIGN SYSTEM · DAWN · TRIAGE AGENT STUDIO v0.1</span>
    <span class="hidden sm:inline">AUTONOMOUS SECURITY INTELLIGENCE</span>
  </footer>

  <script>
    let currentReport = null;
    let currentAudit = null;

    // Check system status on load
    fetch('/api/status')
      .then(res => res.json())
      .then(data => {
        const el = document.getElementById('llm-status');
        if (data.is_llm_configured) {
          el.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500"></span><span class="text-[#17243a] font-medium">LLM Ready (${data.model})</span>`;
        } else {
          el.innerHTML = `<span class="w-2 h-2 rounded-full bg-amber-400"></span><span class="text-[#92400e]">Offline / API Key Missing</span>`;
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

    function showError(msg) {
      const errPanel = document.getElementById('error-panel');
      const errMsg = document.getElementById('error-message');
      errMsg.innerText = msg;
      errPanel.classList.remove('hidden');
    }

    // Form Submit
    document.getElementById('triage-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const mode = document.querySelector('input[name="mode"]:checked').value;
      const sbom = document.getElementById('sbom-path').value.trim();
      const codeDir = document.getElementById('code-dir').value.trim();
      const auditFile = document.getElementById('audit-file').value.trim();

      document.getElementById('error-panel').classList.add('hidden');
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

        if (!res.ok || data.error || !data.report) {
          const msg = data.error || ('HTTP ' + res.status + ': ' + res.statusText);
          showError(msg);
          return;
        }

        currentReport = data.report;
        currentAudit = data.audit;

        renderReport(currentReport, currentAudit);
      } catch (err) {
        showError('通信または実行エラー: ' + err.message);
      } finally {
        document.getElementById('loading-spinner').classList.add('hidden');
        document.getElementById('notices-container').classList.remove('hidden');
      }
    });

    function renderReport(report, audit) {
      if (!report) return;

      // 1. Render Verification summary if available
      const vPanel = document.getElementById('verification-panel');
      if (audit) {
        vPanel.classList.remove('hidden');
        document.getElementById('audit-code-dir').innerText = `対象リポジトリ: ${audit.code_dir}`;
        const b = document.getElementById('audit-overall-badge');
        b.innerText = audit.overall_status;
        if (audit.overall_status.startsWith('YES')) {
          b.className = 'badge-pill badge-critical text-xs';
        } else if (audit.overall_status.includes('確認')) {
          b.className = 'badge-pill badge-high text-xs';
        } else {
          b.className = 'badge-pill badge-normal text-xs';
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
          <div class="surface p-10 text-center space-y-3">
            <div class="text-2xl text-emerald-600 mb-2">◈</div>
            <h3 class="serif-title text-base text-[#17243a] font-normal">該当する要対応コンポーネントはありません</h3>
            <p class="text-xs text-[#5e6d82] mt-1">スキャンされたコンポーネントに対処必要なシグナルは検出されませんでした。</p>
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
          <article class="surface overflow-hidden">
            <!-- Notice Header -->
            <div class="p-6 border-b border-[#ebdcc5] bg-white/70">
              <div class="flex items-start justify-between flex-wrap gap-4">
                <div>
                  <div class="eyeb mb-1">SECURITY NOTICE 0${idx + 1}</div>
                  <div class="flex items-center space-x-3">
                    <h3 class="serif-title text-2xl text-[#17243a] font-semibold">${escapeHtml(n.product_name)}</h3>
                    <span class="text-[10px] font-mono text-[#9f752f] bg-[#faedd7] px-2 py-0.5 rounded border border-[#ebdcc5]">
                      hash: ${n.notice_hash ? n.notice_hash.substring(0, 12) + '...' : 'none'}
                    </span>
                  </div>
                  <p class="text-xs text-[#5e6d82] mt-1 font-mono">
                    公開日: ${escapeHtml(n.announcement_date)} &nbsp;|&nbsp; 修正版: <strong class="text-[#17243a]">${escapeHtml(n.fixed_versions)}</strong>
                  </p>
                </div>
                <span class="badge-pill ${deadlineBadge} text-xs py-1 px-3">
                  ${escapeHtml(n.severity_note || '要確認')}
                </span>
              </div>

              <!-- Conclusion Box -->
              <div class="mt-4 p-4 bg-[#fff9ee] rounded-xl border border-[#d9c9af] border-l-4 border-l-[#9f752f] text-xs leading-relaxed text-[#17243a]">
                <strong class="font-semibold text-[#9f752f]">【結論】</strong> ${escapeHtml(n.conclusion)}
              </div>
            </div>

            <!-- Check Points Table -->
            <div class="p-6 space-y-5">
              <div class="overflow-x-auto">
                <table class="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr class="bg-[#fcfaf6] text-[#9f752f] font-mono text-[10.5px] tracking-wider uppercase border-b border-[#d9c9af]">
                      <th class="p-3 w-1/5">対象 / CVE (CVSS)</th>
                      <th class="p-3 w-1/4">確認ポイント (Yes/No)</th>
                      <th class="p-3 w-1/3">具体的確認方法</th>
                      ${audit ? '<th class="p-3 w-1/5">自社判定 / サインオフ</th>' : ''}
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-[#eee5d8] text-[#17243a]">
                    ${n.check_points.map((cp, cpIdx) => {
                      let auditCp = null;
                      if (auditNotice && auditNotice.results) {
                        auditCp = auditNotice.results[cpIdx];
                      }

                      let auditTd = '';
                      if (audit) {
                        let stBadge = 'badge-neutral';
                        if (auditCp) {
                          if (auditCp.status.startsWith('YES')) stBadge = 'badge-critical';
                          else if (auditCp.status.startsWith('NO')) stBadge = 'badge-normal';
                          else stBadge = 'badge-high';
                        }

                        const statusText = auditCp ? auditCp.status : '未検証';
                        const isUnverified = statusText.includes('未検出') || statusText.includes('要手動確認');

                        auditTd = `
                          <td class="p-3">
                            <span class="badge-pill ${stBadge} text-[11px]">${escapeHtml(statusText)}</span>
                            ${auditCp && auditCp.matches && auditCp.matches.length > 0 ? 
                              `<div class="mt-1.5 text-[10px] font-mono text-[#991b1b]">
                                📍 ${escapeHtml(auditCp.matches[0].file_path)}:${auditCp.matches[0].line_number}
                              </div>` : ''}
                            ${isUnverified ? `
                              <button onclick="openSignoffModal('${escapeHtml(cp.check_point_id)}', '${escapeHtml(n.notice_hash)}', '${escapeHtml(cp.check_point_yes_no)}')" class="table-action-btn mt-2">
                                <i class="fa-solid fa-pen-nib"></i>
                                <span>サインオフ作成</span>
                              </button>
                            ` : ''}
                          </td>
                        `;
                      }

                      return `
                        <tr class="hover:bg-[#faedd7]/20 transition-colors">
                          <td class="p-3 font-medium">
                            <div class="text-[#17243a]">${escapeHtml(cp.target_or_cve)}</div>
                            <div class="text-[10px] text-[#8c9ba5] font-mono mt-0.5">${escapeHtml(cp.check_point_id || '')}</div>
                          </td>
                          <td class="p-3 font-medium text-[#17243a] leading-relaxed">${escapeHtml(cp.check_point_yes_no)}</td>
                          <td class="p-3 text-[#5e6d82] font-mono text-[11px] leading-relaxed bg-[#fcfaf6]/50 rounded">${escapeHtml(cp.verification_method)}</td>
                          ${auditTd}
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>

              <!-- Workaround & Unconfirmed -->
              ${n.workaround ? `
                <div class="text-xs bg-[#f0fdf4] p-3.5 rounded-xl border border-[#bbf7d0] text-[#166534] leading-relaxed">
                  <strong>💡 推奨回避策:</strong> ${escapeHtml(n.workaround)}
                </div>
              ` : ''}

              <!-- Sources -->
              ${n.sources && n.sources.length > 0 ? `
                <div class="text-[11px] text-[#8c9ba5] flex items-center space-x-2 pt-3 border-t border-[#ebdcc5] flex-wrap gap-y-1">
                  <span class="font-mono text-[#9f752f] uppercase">出典:</span>
                  ${n.sources.map(s => `<a href="${s}" target="_blank" class="text-[#9f752f] hover:underline hover:text-[#17243a] truncate max-w-xs transition font-mono">${s}</a>`).join(', ')}
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
            sbom_path = req_data.get("sbom", "sample_sbom.json").strip()
            code_dir = req_data.get("code_dir", "").strip() or None
            audit_file = req_data.get("audit_file", "").strip() or None

            try:
                # 0. Pre-flight validations
                if mode != "demo":
                    p = Path(sbom_path)
                    if not p.exists():
                        # Try common typos like .jsom -> .json
                        alt_p = p.with_suffix(".json")
                        if alt_p.exists():
                            sbom_path = str(alt_p)
                        else:
                            raise FileNotFoundError(f"SBOMファイルが見つかりません: '{sbom_path}'")

                if mode == "live" and not is_llm_configured():
                    raise ValueError(
                        "LLM API が設定されていません。\n"
                        "Live Agent モードを実行するには、.env または環境変数に GEMINI_API_KEY を設定するか、"
                        "Google Cloud Vertex AI (GOOGLE_GENAI_USE_VERTEXAI=true) を設定してください。\n"
                        "APIキーなしで挙動を試す場合は、画面左の実行モードで「Demo」または「Dry-Run」を選択してください。"
                    )

                # 1. Execute triage notice generation
                if mode == "demo":
                    triage_report = generate_demo_report()
                elif mode == "dry-run":
                    from triage_agent.agents.researcher import run_researcher
                    from triage_agent.agents.triage import run_triage_agent
                    from triage_agent.tools.osv import query_osv_batch
                    from triage_agent.tools.sbom import load_sbom_summary

                    components = load_sbom_summary(sbom_path)
                    osv_hits, osv_errs = query_osv_batch(components)
                    unscanned = [f"OSVエラー: {e}" for e in osv_errs]
                    targets = []
                    repo_map = {
                        "urllib3": "urllib3/urllib3",
                        "jsonwebtoken": "auth0/node-jsonwebtoken",
                        "axios": "axios/axios",
                        "log4j-core": "apache/logging-log4j2",
                        "fastapi": "fastapi/fastapi",
                        "express": "expressjs/express",
                    }
                    for c in components:
                        is_hit = c.name in osv_hits
                        targets.append(
                            ReconTarget(
                                name=c.name,
                                version=c.version,
                                ecosystem=c.ecosystem,
                                github_repo=repo_map.get(c.name),
                                priority="CRITICAL" if is_hit and c.name in ["log4j-core", "urllib3", "jsonwebtoken"] else "HIGH",
                                rationale=f"Known OSV hits found ({len(osv_hits.get(c.name, []))} alerts)" if is_hit else "Core web/network component",
                                search_queries=[f"{c.name} {c.version} security patch"],
                                github_search_keywords=["security", "cve", "patch"],
                            )
                        )
                    targets.sort(key=lambda t: 0 if t.priority == "CRITICAL" else 1)
                    res_list = []
                    for t in targets[:10]:
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
                    recon_plan = run_recon_planner(sbom_path, osv_results=osv_hits)
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
                import traceback
                traceback.print_exc()
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

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
