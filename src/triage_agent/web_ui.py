"""Lightweight, zero-dependency Web GUI for triage-agent.

Runs a local web dashboard using Python's standard library http.server,
providing an interactive interface to run triage scans, inspect reports,
run codebase verifications, and draft audit sign-offs.
"""

import argparse
import getpass
import json
import os
import secrets
import sys
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Dict, Optional

from rich.console import Console

from triage_agent.config import get_model_name, is_llm_configured
from triage_agent.pipeline import execute_triage_pipeline
from triage_agent.schemas import TriageReport
from triage_agent.verifier import CodebaseAuditReport

console = Console()

# Cryptographically secure random CSRF token generated on server startup
SERVER_CSRF_TOKEN = secrets.token_hex(24)


def resolve_safe_path(path_str: str, base_dir: Optional[Path] = None) -> Path:
    """Ensure a user-supplied path stays strictly within the authorized base directory.

    Prevents directory traversal (e.g. ../../) and arbitrary filesystem overwrites.
    """
    if not path_str or not path_str.strip():
        raise ValueError("パスが指定されていません。")
    if base_dir is None:
        base_dir = Path.cwd().resolve()
    resolved = (base_dir / path_str.strip()).resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        raise PermissionError(
            f"セキュリティ制限: 作業ディレクトリ外のファイルへのアクセスは拒否されました ('{path_str}')"
        )
    return resolved


HTML_PAGE = """<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>triage-agent — DAWN Studio</title>
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

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg-app);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
      -webkit-font-smoothing: antialiased;
      line-height: 1.5;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    /* Layout & Helpers (Zero CDN) */
    .hidden { display: none !important; }
    .flex { display: flex; }
    .flex-col { flex-direction: column; }
    .items-center { align-items: center; }
    .items-start { align-items: flex-start; }
    .justify-between { justify-content: space-between; }
    .justify-end { justify-content: flex-end; }
    .justify-center { justify-content: center; }
    .flex-1 { flex: 1 1 0%; }
    .flex-wrap { flex-wrap: wrap; }
    .grid { display: grid; }
    .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
    .grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .gap-2 { gap: 8px; }
    .gap-3 { gap: 12px; }
    .gap-4 { gap: 16px; }
    .gap-6 { gap: 24px; }
    .gap-8 { gap: 32px; }
    .w-full { width: 100%; }
    .max-w-7xl { max-width: 1280px; }
    .mx-auto { margin-left: auto; margin-right: auto; }
    .p-3 { padding: 12px; }
    .p-4 { padding: 16px; }
    .p-5 { padding: 20px; }
    .p-6 { padding: 24px; }
    .p-8 { padding: 32px; }
    .p-10 { padding: 40px; }
    .p-12 { padding: 48px; }
    .px-4 { padding-left: 16px; padding-right: 16px; }
    .px-6 { padding-left: 24px; padding-right: 24px; }
    .py-1 { padding-top: 4px; padding-bottom: 4px; }
    .py-2 { padding-top: 8px; padding-bottom: 8px; }
    .py-3 { padding-top: 12px; padding-bottom: 12px; }
    .py-8 { padding-top: 32px; padding-bottom: 32px; }
    .mb-1 { margin-bottom: 4px; }
    .mb-2 { margin-bottom: 8px; }
    .mb-3 { margin-bottom: 12px; }
    .mb-4 { margin-bottom: 16px; }
    .mb-5 { margin-bottom: 20px; }
    .mt-1 { margin-top: 4px; }
    .mt-2 { margin-top: 8px; }
    .mt-3 { margin-top: 12px; }
    .mt-4 { margin-top: 16px; }
    .mr-1 { margin-right: 4px; }
    .mr-2 { margin-right: 8px; }
    .space-y-2 > * + * { margin-top: 8px; }
    .space-y-3 > * + * { margin-top: 12px; }
    .space-y-4 > * + * { margin-top: 16px; }
    .space-y-5 > * + * { margin-top: 20px; }
    .space-y-6 > * + * { margin-top: 24px; }
    .space-x-2 > * + * { margin-left: 8px; }
    .space-x-3 > * + * { margin-left: 12px; }
    .space-x-4 > * + * { margin-left: 16px; }

    /* Typography */
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
    .font-mono { font-family: var(--mono); }
    .text-xs { font-size: 12px; line-height: 16px; }
    .text-sm { font-size: 14px; line-height: 20px; }
    .text-base { font-size: 16px; line-height: 24px; }
    .text-lg { font-size: 18px; line-height: 28px; }
    .text-xl { font-size: 20px; line-height: 28px; }
    .text-2xl { font-size: 24px; line-height: 32px; }
    .text-3xl { font-size: 30px; line-height: 36px; }
    .font-semibold { font-weight: 600; }
    .font-bold { font-weight: 700; }
    .text-center { text-align: center; }

    /* Responsive Grid */
    @media (min-width: 1024px) {
      .main-grid {
        display: grid;
        grid-template-columns: 360px minmax(0, 1fr);
        gap: 32px;
      }
    }
    @media (max-width: 1023px) {
      .main-grid {
        display: flex;
        flex-direction: column;
        gap: 24px;
      }
    }

    /* Surfaces & Glassmorphism */
    .surface {
      background: rgba(255, 255, 255, 0.85);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      box-shadow: var(--sh-panel);
      backdrop-filter: blur(12px);
    }
    .surface-warm {
      background: linear-gradient(135deg, rgba(255, 255, 255, 0.95) 0%, rgba(251, 248, 242, 0.92) 100%);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      box-shadow: var(--sh-panel);
    }

    /* Form Inputs */
    .dawn-input {
      background: #ffffff;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 9px 12px;
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

    /* Phase Pills for Progress Bar */
    .phase-pill-active {
      border-color: var(--accent-gold-dark) !important;
      background: var(--accent-gold-bg) !important;
      box-shadow: 0 2px 8px rgba(159, 117, 47, 0.12);
    }
    .phase-pill-active .eyeb {
      color: var(--accent-gold-dark) !important;
      font-weight: 700;
    }
    .phase-pill-completed {
      border-color: #a7f3d0 !important;
      background: #f0fdf4 !important;
    }
    .phase-pill-completed .eyeb {
      color: #059669 !important;
    }

    /* Table Styles */
    table { width: 100%; border-collapse: collapse; text-align: left; }
    table thead tr { background: #fcfaf6; border-bottom: 1.5px solid var(--border-color); }
    table thead th {
      font: 10.5px var(--mono);
      color: #9f752f;
      letter-spacing: 1px;
      text-transform: uppercase;
      padding: 10px 12px;
    }
    table tbody td {
      padding: 12px;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 12px;
    }
    table tbody tr:hover { background: rgba(250, 237, 215, 0.25); }

    /* Modal Overlay */
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(7, 19, 41, 0.65);
      backdrop-filter: blur(6px);
      z-index: 50;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
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
<body>

  <!-- App Header -->
  <header style="height: 64px; padding: 0 24px; border-bottom: 1px solid var(--border-color); background: rgba(255, 255, 255, 0.85); backdrop-filter: blur(16px); position: sticky; top: 0; z-index: 40;" class="flex items-center justify-between">
    <div class="flex items-center space-x-4">
      <div class="flex items-center space-x-2">
        <span style="font-size: 22px; color: var(--accent-gold);">◈</span>
        <div class="serif-title" style="font-size: 22px; color: var(--text-main);">
          triage-agent <small class="eyeb" style="margin-left: 8px;">DAWN / 0.1</small>
        </div>
      </div>
      <div style="font-size: 11px; color: var(--text-muted); border-left: 1px solid var(--border-color); padding-left: 16px;">
        Autonomous SBOM Vulnerability Intelligence &amp; Triage
      </div>
    </div>
    
    <div class="flex items-center space-x-3 text-xs">
      <div id="llm-status" class="flex items-center space-x-2 bg-white px-3 py-1 rounded-full border border-[#d9c9af] shadow-xs font-mono text-xs">
        <span style="width: 8px; height: 8px; border-radius: 50%; background: #eab308; display: inline-block;"></span>
        <span style="color: var(--text-muted);">Checking Status...</span>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="w-full max-w-7xl mx-auto px-6 py-8 flex-1">
    <div class="main-grid">

      <!-- Left Controls Panel -->
      <section class="space-y-6">
        <div class="surface p-6">
          <div class="eyeb mb-1">SCAN &amp; TRIAGE CONFIGURATION</div>
          <h2 class="serif-title text-xl font-normal mb-5">
            スキャン &amp; トリアージ設定
          </h2>

          <form id="triage-form" class="space-y-5">
            <!-- Execution Mode -->
            <div>
              <div class="flex items-center justify-between mb-1">
                <label class="text-xs font-semibold">実行モード</label>
                <span class="eyeb" style="font-size: 9px;">PIPELINE MODE</span>
              </div>
              
              <div class="subnav-tabs">
                <label class="subnav-tab">
                  <input type="radio" name="mode" value="demo" checked style="position: absolute; opacity: 0;">
                  <span class="subnav-label">Demo</span>
                </label>
                <label class="subnav-tab">
                  <input type="radio" name="mode" value="dry-run" style="position: absolute; opacity: 0;">
                  <span class="subnav-label">Dry-Run</span>
                </label>
                <label class="subnav-tab">
                  <input type="radio" name="mode" value="live" style="position: absolute; opacity: 0;">
                  <span class="subnav-label">Live Agent</span>
                </label>
              </div>
              <p id="mode-desc" class="text-xs mt-2" style="color: var(--text-muted); background: var(--bg-surface-subtle); padding: 10px; border-radius: 8px; border: 1px solid var(--border-subtle); line-height: 1.6;">
                展示用合成データ（DEMO-*）で即座にUIを確認します。
              </p>
            </div>

            <!-- SBOM File -->
            <div>
              <label class="block text-xs font-semibold mb-1">SBOM ファイルパス</label>
              <input type="text" id="sbom-path" value="sample_sbom.json" class="dawn-input" spellcheck="false">
              <span class="text-xs block mt-1" style="color: var(--text-dim); font-size: 11px;">Syft CycloneDX JSON または Syft native JSON</span>
            </div>

            <!-- Codebase Path (for Verifier) -->
            <div>
              <label class="block text-xs font-semibold mb-1">自社検証コードパス (外注時は空欄)</label>
              <input type="text" id="code-dir" value="demo_app" class="dawn-input" spellcheck="false">
              <span class="text-xs block mt-1" style="color: var(--text-dim); font-size: 11px;">空欄の場合はベンダー委託システムとして手動・ベンダー回答を記録</span>
            </div>

            <!-- Audit Sign-off File -->
            <div>
              <label class="block text-xs font-semibold mb-1">手動/ベンダー監査サインオフパス</label>
              <input type="text" id="audit-file" value="sample_audit_signoff.json" class="dawn-input" spellcheck="false">
              <span class="text-xs block mt-1" style="color: var(--text-dim); font-size: 11px;">SRE・ベンダー合意済みの恒久安全判定ファイル</span>
            </div>

            <!-- Submit Button -->
            <button type="submit" id="btn-run" class="w-full btn-dawn-primary py-3">
              <span>◈</span>
              <span>トリアージ実行</span>
            </button>
          </form>
        </div>

        <!-- Operating Principles Box -->
        <div class="surface-warm p-5" style="border-left: 3px solid var(--accent-gold-dark);">
          <div class="eyeb mb-1">TRIAGE OPERATING PRINCIPLES</div>
          <div class="serif-title font-bold text-sm mb-2">トリアージ運用の3鉄則</div>
          <ul class="space-y-2 text-xs" style="color: var(--text-muted); line-height: 1.6; list-style: none;">
            <li class="flex items-start">
              <span style="color: var(--accent-gold-dark); margin-right: 6px;">•</span>
              <span><strong>分からないものを安全と言わない:</strong> コード内未検出や外注システムは外部設定・ベンダーの要確認。</span>
            </li>
            <li class="flex items-start">
              <span style="color: var(--accent-gold-dark); margin-right: 6px;">•</span>
              <span><strong>正本管理:</strong> AI下書きを人間が承認・固定したJSONを正本とする。</span>
            </li>
            <li class="flex items-start">
              <span style="color: var(--accent-gold-dark); margin-right: 6px;">•</span>
              <span><strong>監査サインオフ:</strong> ベンダー回答・根拠を添えて安全（NO）に昇格。</span>
            </li>
          </ul>
        </div>
      </section>

      <!-- Right Results Panel -->
      <section class="space-y-6 flex-1">

        <!-- Status Indicator / DAWN Gold Ring Spinner & Realtime Progress Bar -->
        <div id="loading-spinner" class="hidden surface p-8 space-y-6">
          <div class="flex items-center justify-between" style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px;">
            <div class="flex items-center space-x-3">
              <div class="generating-spinner" style="width: 36px; height: 36px;">
                <div class="generating-ring"></div>
                <span class="generating-icon" style="font-size: 16px;">◈</span>
              </div>
              <div>
                <div class="eyeb" id="loading-eyebrow" style="font-size: 9px; margin-bottom: 2px;">AUTONOMOUS INVESTIGATION IN PROGRESS</div>
                <h3 class="serif-title text-base font-normal" id="loading-msg">エージェントが調査を実行中...</h3>
              </div>
            </div>
            <div class="text-right">
              <div id="progress-percent" class="serif-title text-3xl font-normal" style="color: var(--accent-gold-dark); line-height: 1;">0%</div>
              <span id="progress-step-text" class="text-xs" style="color: var(--text-dim); font-size: 10px;">Phase 1 / 3</span>
            </div>
          </div>

          <!-- Progress Bar Fill -->
          <div class="space-y-2">
            <div style="width: 100%; height: 10px; background: var(--border-subtle); border-radius: 999px; overflow: hidden; position: relative;">
              <div id="progress-bar-fill" style="width: 0%; height: 100%; background: linear-gradient(90deg, var(--accent-gold) 0%, var(--accent-gold-dark) 100%); border-radius: 999px; transition: width 0.35s ease-out;"></div>
            </div>
            <div class="flex items-center justify-between text-xs" style="color: var(--text-muted); font-size: 11px;">
              <span id="progress-detail" class="font-mono">準備中...</span>
              <span id="progress-target" class="font-mono" style="color: var(--accent-gold-dark); font-weight: 600;"></span>
            </div>
          </div>

          <!-- Phase Indicator Pills -->
          <div class="grid grid-cols-3 gap-3 text-center text-xs pt-1">
            <div id="phase-pill-1" class="p-3 rounded-lg border border-subtle bg-surface-subtle" style="transition: all 0.3s;">
              <div class="eyeb" style="font-size: 9px; margin-bottom: 2px;">PHASE 1</div>
              <div class="font-semibold text-xs" style="color: var(--text-main);">Recon Planner</div>
              <div class="text-xs mt-1" style="font-size: 10px; color: var(--text-dim);">SBOM解析 & 戦略</div>
            </div>
            <div id="phase-pill-2" class="p-3 rounded-lg border border-subtle bg-surface-subtle" style="transition: all 0.3s;">
              <div class="eyeb" style="font-size: 9px; margin-bottom: 2px;">PHASE 2</div>
              <div class="font-semibold text-xs" style="color: var(--text-main);">Researcher</div>
              <div class="text-xs mt-1" style="font-size: 10px; color: var(--text-dim);">OSV & Web動的調査</div>
            </div>
            <div id="phase-pill-3" class="p-3 rounded-lg border border-subtle bg-surface-subtle" style="transition: all 0.3s;">
              <div class="eyeb" style="font-size: 9px; margin-bottom: 2px;">PHASE 3</div>
              <div class="font-semibold text-xs" style="color: var(--text-main);">Triage Agent</div>
              <div class="text-xs mt-1" style="font-size: 10px; color: var(--text-dim);">発火条件 & 指示書</div>
            </div>
          </div>
        </div>

        <!-- Error Alert Panel -->
        <div id="error-panel" class="hidden p-5" style="background: #fdf2f2; border: 1px solid #fecaca; border-left: 4px solid #991b1b; border-radius: 12px;">
          <div class="flex items-start space-x-3">
            <span style="font-size: 20px; line-height: 1; color: #991b1b;">🚨</span>
            <div class="text-xs flex-1">
              <div class="eyeb" style="color: #991b1b; margin-bottom: 4px;">EXECUTION ERROR</div>
              <h3 class="font-bold text-sm" style="color: #991b1b;">実行時エラーが発生しました</h3>
              <p id="error-message" class="font-mono mt-2 p-3 text-xs" style="white-space: pre-wrap; background: rgba(255, 255, 255, 0.8); border: 1px solid #fecaca; border-radius: 6px; color: #7f1d1d;"></p>
            </div>
          </div>
        </div>

        <!-- Verification Audit Summary -->
        <div id="verification-panel" class="hidden surface p-6 space-y-5">
          <div class="flex items-center justify-between" style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 16px;">
            <div>
              <div class="eyeb mb-1" id="audit-eyebrow">AUDIT SUMMARY REPORT</div>
              <h2 class="serif-title text-xl font-normal" id="audit-title">自社コードベース検証結果サマリ</h2>
              <p id="audit-code-dir" class="text-xs font-mono mt-1" style="color: var(--text-dim);"></p>
            </div>
            <div id="audit-overall-badge" class="badge-pill text-xs py-1 px-3"></div>
          </div>

          <!-- Metric Counts Grid -->
          <div class="grid grid-cols-2 gap-3" style="grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));">
            <div class="p-3 text-center" style="background: #ffffff; border: 1px solid var(--border-color); border-radius: 12px;">
              <div class="eyeb" style="font-size: 9px; margin-bottom: 4px;">TOTAL CHECKS</div>
              <div id="count-total" class="serif-title text-3xl font-normal">0</div>
              <span class="text-xs" style="color: var(--text-muted); font-size: 11px;">総検査項目</span>
            </div>
            <div class="p-3 text-center" style="background: #fdf2f2; border: 1px solid #fecaca; border-radius: 12px;">
              <div class="eyeb" style="font-size: 9px; color: #991b1b; margin-bottom: 4px;">AFFECTED / NEED CHECK</div>
              <div id="count-yes" class="serif-title text-3xl font-normal" style="color: #991b1b;">0</div>
              <span class="text-xs font-medium" style="color: #991b1b; font-size: 11px;">YES (要実地確認)</span>
            </div>
            <div class="p-3 text-center" style="background: #fff9ed; border: 1px solid #fde68a; border-radius: 12px;">
              <div class="eyeb" style="font-size: 9px; color: #92400e; margin-bottom: 4px;">UNVERIFIED</div>
              <div id="count-unverified" class="serif-title text-3xl font-normal" style="color: #92400e;">0</div>
              <span class="text-xs font-medium" style="color: #92400e; font-size: 11px;">要確認 (外部/照会)</span>
            </div>
            <div class="p-3 text-center" style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 12px;">
              <div class="eyeb" style="font-size: 9px; color: #166534; margin-bottom: 4px;">ATTESTED SAFE</div>
              <div id="count-safe" class="serif-title text-3xl font-normal" style="color: #166534;">0</div>
              <span class="text-xs font-medium" style="color: #166534; font-size: 11px;">NO (確認済安全)</span>
            </div>
          </div>
        </div>

        <!-- Unscanned / Warnings Alert Banner -->
        <div id="unscanned-panel" class="hidden p-5" style="background: #fff9ed; border: 1px solid #fde68a; border-left: 4px solid #92400e; border-radius: 12px;">
          <div class="flex items-start space-x-3">
            <span style="font-size: 20px; line-height: 1; color: #92400e;">⚠</span>
            <div class="text-xs flex-1">
              <div class="eyeb" style="color: #92400e; margin-bottom: 4px;">UNSCANNED WARNING</div>
              <h3 class="font-bold text-sm" style="color: #92400e;">【注意】調査不能・未調査コンポーネント</h3>
              <p style="color: #78350f; margin-top: 4px; line-height: 1.6;">
                以下のコンポーネントは調査不能または未調査です。未調査の項目を「安全」と誤認してはなりません。
              </p>
              <ul id="unscanned-list" class="font-mono text-xs mt-2 p-3 space-y-1" style="background: rgba(255, 255, 255, 0.7); border: 1px solid #fde68a; border-radius: 8px; color: #78350f; list-style-position: inside;"></ul>
            </div>
          </div>
        </div>

        <!-- Notices Container -->
        <div id="notices-container" class="space-y-6">
          <!-- Empty Placeholder -->
          <div class="surface p-12 text-center space-y-3" style="border-style: dashed;">
            <div style="width: 48px; height: 48px; margin: 0 auto; border-radius: 50%; background: rgba(250, 237, 215, 0.5); display: flex; align-items: center; justify-content: center; color: var(--accent-gold-dark); font-size: 22px;">
              ◈
            </div>
            <h3 class="serif-title text-base font-normal">レポートがまだありません</h3>
            <p class="text-xs" style="color: var(--text-muted); max-width: 360px; margin: 0 auto; line-height: 1.6;">
              左側のパネルから実行モードを選択し、「トリアージ実行」をクリックしてください。
            </p>
          </div>
        </div>

      </section>
    </div>
  </main>

  <!-- Signoff Modal (DAWN Style, XSS-proof, Vendor-friendly) -->
  <div id="signoff-modal" class="hidden modal-overlay">
    <div class="modal-card p-6 space-y-5">
      <div class="flex items-start justify-between" style="border-bottom: 1px solid var(--border-subtle); padding-bottom: 14px;">
        <div>
          <div class="eyeb mb-1">AUDIT ATTESTATION (DEC-021)</div>
          <h3 class="serif-title text-xl font-normal">手動/ベンダー監査サインオフの作成</h3>
        </div>
        <button type="button" id="btn-close-modal" class="text-lg" style="background: none; border: none; cursor: pointer; color: var(--text-dim); padding: 4px;">✕</button>
      </div>

      <div class="space-y-4 text-xs">
        <div>
          <label class="block font-semibold mb-1">対象確認ポイント ID</label>
          <input type="text" id="modal-cp-id" readonly class="dawn-input" style="background: var(--bg-surface-subtle); color: var(--text-muted);">
        </div>
        <div>
          <label class="block font-semibold mb-1">Notice Fingerprint (notice_hash)</label>
          <input type="text" id="modal-notice-hash" readonly class="dawn-input" style="background: var(--bg-surface-subtle); color: var(--text-muted);">
          <input type="hidden" id="modal-matches-hash">
        </div>
        <div>
          <label class="block font-semibold mb-1">確認ポイントの質問</label>
          <textarea id="modal-question" readonly rows="2" class="dawn-input" style="background: var(--bg-surface-subtle); color: var(--text-muted); resize: none;"></textarea>
        </div>
        <div id="modal-drift-note" class="hidden p-3" style="background: #fff9ed; border: 1px solid #fde68a; border-left: 4px solid #d97706; border-radius: 8px; color: #92400e; font-size: 11px; line-height: 1.5;">
          <strong>🛡️ コードドリフト保護（自動照合）:</strong> 現在検出されているコード箇所のフィンガープリント（ハッシュ）を同時に記録します。今後コードが変更された場合は、安全のため自動的に再確認対象に戻ります。
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block font-semibold mb-1">判定ステータス *</label>
            <select id="modal-status" class="dawn-input">
              <option value="NO (ベンダー確認済み・非該当)">NO (ベンダー確認済み・非該当)</option>
              <option value="NO (手動確認済み・非該当)">NO (手動確認済み・非該当)</option>
              <option value="YES (ベンダー回答・該当あり)">YES (ベンダー回答・該当あり)</option>
              <option value="YES (該当あり・要対応)">YES (該当あり・要対応)</option>
              <option value="要確認 (ベンダー回答待ち・調査中)">要確認 (ベンダー回答待ち・調査中)</option>
            </select>
          </div>
          <div>
            <label class="block font-semibold mb-1">確認日付 *</label>
            <input type="date" id="modal-date" class="dawn-input">
          </div>
        </div>
        <div>
          <label class="block font-semibold mb-1">確認者 (氏名・所属) *</label>
          <input type="text" id="modal-reviewer" placeholder="例: 山田 (システム担当)" class="dawn-input">
          <span style="font-size: 10px; color: var(--text-dim); display: block; margin-top: 2px;">※ 本番運用時は社内ID/LDAP認証ログと照合されます</span>
        </div>
        <div>
          <label class="block font-semibold mb-1">確認根拠・エビデンス *</label>
          <textarea id="modal-evidence" placeholder="例: ベンダー窓口（2026/10/25回答）にて、本番アプライアンスはHTTP/2無効化設定済みと確認。" rows="3" class="dawn-input" style="font-family: inherit; resize: vertical;"></textarea>
        </div>
      </div>

      <div class="flex justify-end space-x-2 pt-3" style="border-top: 1px solid var(--border-subtle);">
        <button type="button" id="btn-cancel-modal" class="btn-dawn-secondary">キャンセル</button>
        <button type="button" id="btn-save-signoff" class="btn-dawn-primary" style="font-size: 12px; padding: 8px 16px;">サインオフを適用・保存</button>
      </div>
    </div>
  </div>

  <!-- App Footer -->
  <footer class="app-footer">
    <span>NSTAR DESIGN SYSTEM · DAWN · TRIAGE AGENT STUDIO v0.1</span>
    <span class="eyeb" style="font-size: 9px;">ZERO CDN · OFFLINE ENTERPRISE READY</span>
  </footer>

  <script>
    // Embedded CSRF Token from Server
    window.CSRF_TOKEN = "__CSRF_TOKEN__";
    window.DEFAULT_REVIEWER = "__DEFAULT_REVIEWER__";

    let currentReport = null;
    let currentAudit = null;

    // Check system status on load
    fetch('/api/status')
      .then(res => res.json())
      .then(data => {
        const el = document.getElementById('llm-status');
        if (data.is_llm_configured) {
          el.innerHTML = '<span style="width: 8px; height: 8px; border-radius: 50%; background: #10b981; display: inline-block;"></span><span style="color: #17243a; font-weight: 500;">LLM Ready (' + escapeHtml(data.model) + ')</span>';
        } else {
          el.innerHTML = '<span style="width: 8px; height: 8px; border-radius: 50%; background: #eab308; display: inline-block;"></span><span style="color: #92400e;">Offline / API Key Missing</span>';
        }
        if (data.default_reviewer && !document.getElementById('modal-reviewer').value) {
          document.getElementById('modal-reviewer').value = data.default_reviewer;
        }
      })
      .catch(() => {});

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

    function updateProgress(data) {
      if (!data) return;
      const pct = Math.min(100, Math.max(0, data.percent !== undefined ? data.percent : 0));
      document.getElementById('progress-bar-fill').style.width = pct + '%';
      document.getElementById('progress-percent').innerText = pct + '%';

      if (data.message) {
        document.getElementById('progress-detail').innerText = data.message;
      }
      if (data.current_target) {
        document.getElementById('progress-target').innerText = '▸ ' + data.current_target;
      } else {
        document.getElementById('progress-target').innerText = '';
      }

      // Update Phase pills
      const phase = (data.phase || '').toLowerCase();
      const p1 = document.getElementById('phase-pill-1');
      const p2 = document.getElementById('phase-pill-2');
      const p3 = document.getElementById('phase-pill-3');
      const stepText = document.getElementById('progress-step-text');
      const loadingMsg = document.getElementById('loading-msg');

      if (phase.includes('recon') || pct <= 15) {
        p1.className = 'p-3 rounded-lg border phase-pill-active';
        p2.className = 'p-3 rounded-lg border border-subtle bg-surface-subtle';
        p3.className = 'p-3 rounded-lg border border-subtle bg-surface-subtle';
        stepText.innerText = 'Phase 1 / 3: Recon Planner';
        loadingMsg.innerText = 'SBOM解析 & 巡回戦略を立案中...';
      } else if (phase.includes('researcher') || (pct > 15 && pct <= 75)) {
        p1.className = 'p-3 rounded-lg border phase-pill-completed';
        p2.className = 'p-3 rounded-lg border phase-pill-active';
        p3.className = 'p-3 rounded-lg border border-subtle bg-surface-subtle';
        stepText.innerText = 'Phase 2 / 3: Dynamic Researcher';
        loadingMsg.innerText = '各コンポーネントの脆弱性・パッチ差分を動的調査中...';
      } else {
        p1.className = 'p-3 rounded-lg border phase-pill-completed';
        p2.className = 'p-3 rounded-lg border phase-pill-completed';
        p3.className = 'p-3 rounded-lg border phase-pill-active';
        stepText.innerText = 'Phase 3 / 3: Triage Agent';
        loadingMsg.innerText = '発火条件特定・現場即応指示書を生成中...';
      }
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

      // Initialize progress bar
      updateProgress({ percent: 2, phase: 'Recon Planner', message: 'パイプライン初期化中...' });

      try {
        const res = await fetch('/api/run-stream', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({ mode, sbom, code_dir: codeDir, audit_file: auditFile })
        });

        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.error || ('HTTP ' + res.status + ': ' + res.statusText));
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder('utf-8');
        let buffer = '';
        let completed = false;

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          const events = buffer.split('\n\n');
          buffer = events.pop(); // keep remainder

          for (const ev of events) {
            const trimmed = ev.trim();
            if (!trimmed.startsWith('data: ')) continue;
            const jsonStr = trimmed.slice(6);
            try {
              const payload = JSON.parse(jsonStr);
              if (payload.type === 'progress') {
                updateProgress(payload);
              } else if (payload.type === 'complete') {
                completed = true;
                updateProgress({ percent: 100, phase: 'Complete', message: '調査完了！レポートを表示します。' });
                currentReport = payload.report;
                currentAudit = payload.audit;
                // Brief pause for visual smoothness before switching view
                await new Promise(r => setTimeout(r, 200));
                renderReport(currentReport, currentAudit);
              } else if (payload.type === 'error') {
                throw new Error(payload.error || '不明なエラー');
              }
            } catch (pErr) {
              if (pErr.message && !pErr.message.includes('JSON')) throw pErr;
            }
          }
        }

        if (!completed && !currentReport) {
          throw new Error('サーバーからの応答が完了前に終了しました。');
        }
      } catch (err) {
        showError('実行時エラー: ' + err.message);
      } finally {
        document.getElementById('loading-spinner').classList.add('hidden');
        document.getElementById('notices-container').classList.remove('hidden');
      }
    });

    function renderReport(report, audit) {
      if (!report) return;

      // 1. Render Verification / Attestation summary
      const vPanel = document.getElementById('verification-panel');
      if (audit) {
        vPanel.classList.remove('hidden');
        const isVendorMode = audit.code_dir && audit.code_dir.includes('外注');
        document.getElementById('audit-eyebrow').innerText = isVendorMode ? 'VENDOR ATTESTATION REPORT' : 'AUDIT SUMMARY REPORT';
        document.getElementById('audit-title').innerText = isVendorMode ? '外注・ベンダー委託システム 検証・回答サマリ' : '自社コードベース検証結果サマリ';
        document.getElementById('audit-code-dir').innerText = `対象: ${audit.code_dir}`;

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
            <div style="font-size: 24px; color: #166534; margin-bottom: 8px;">◈</div>
            <h3 class="serif-title text-base font-normal">該当する要対応コンポーネントはありません</h3>
            <p class="text-xs" style="color: var(--text-muted); margin-top: 4px;">スキャンされたコンポーネントに対処必要なシグナルは検出されませんでした。</p>
          </div>
        `;
        return;
      }

      container.innerHTML = report.notices.map((n, idx) => {
        let auditNotice = null;
        if (audit && audit.notice_results) {
          auditNotice = audit.notice_results.find(an => an.notice.product_name === n.product_name);
        }

        let deadlineBadge = 'badge-normal';
        if (n.conclusion.includes('48時間')) deadlineBadge = 'badge-critical';
        else if (n.conclusion.includes('7日')) deadlineBadge = 'badge-high';

        return `
          <article class="surface" style="overflow: hidden;">
            <!-- Notice Header -->
            <div class="p-6" style="border-bottom: 1px solid var(--border-subtle); background: rgba(255, 255, 255, 0.7);">
              <div class="flex items-start justify-between flex-wrap gap-4">
                <div>
                  <div class="eyeb mb-1">SECURITY NOTICE 0${idx + 1}</div>
                  <div class="flex items-center space-x-3">
                    <h3 class="serif-title text-2xl font-semibold">${escapeHtml(n.product_name)}</h3>
                    <span class="font-mono text-xs" style="color: var(--accent-gold-dark); background: var(--accent-gold-light); padding: 2px 8px; border-radius: 4px; border: 1px solid var(--border-subtle);">
                      hash: ${n.notice_hash ? n.notice_hash.substring(0, 12) + '...' : 'none'}
                    </span>
                  </div>
                  <p class="text-xs font-mono mt-1" style="color: var(--text-muted);">
                    公開日: ${escapeHtml(n.announcement_date)} &nbsp;|&nbsp; 修正版: <strong>${escapeHtml(n.fixed_versions)}</strong>
                  </p>
                </div>
                <span class="badge-pill ${deadlineBadge} text-xs py-1 px-3">
                  ${escapeHtml(n.severity_note || '要確認')}
                </span>
              </div>

              <!-- Conclusion Box -->
              <div class="mt-4 p-4 text-xs" style="background: #fff9ee; border: 1px solid var(--border-color); border-left: 4px solid var(--accent-gold-dark); border-radius: 8px; line-height: 1.6;">
                <strong style="color: var(--accent-gold-dark); font-weight: 600;">【結論】</strong> ${escapeHtml(n.conclusion)}
              </div>
            </div>

            <!-- Check Points Table -->
            <div class="p-6 space-y-4">
              <div style="overflow-x: auto;">
                <table>
                  <thead>
                    <tr>
                      <th style="width: 22%;">対象 / CVE (CVSS)</th>
                      <th style="width: 26%;">確認ポイント (Yes/No)</th>
                      <th style="width: 30%;">具体的確認方法</th>
                      <th style="width: 22%;">判定 / 監査サインオフ</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${n.check_points.map((cp, cpIdx) => {
                      let auditCp = null;
                      if (auditNotice && auditNotice.results) {
                        auditCp = auditNotice.results[cpIdx];
                      }

                      let stBadge = 'badge-neutral';
                      if (auditCp) {
                        if (auditCp.status.startsWith('YES')) {
                          stBadge = 'badge-critical';
                        } else if (auditCp.status.startsWith('NO')) {
                          stBadge = 'badge-normal';
                        } else {
                          stBadge = 'badge-high';
                        }
                      }

                      const statusText = auditCp ? auditCp.status : '未検証';

                      const auditTd = `
                        <td>
                          <span class="badge-pill ${stBadge}">${escapeHtml(statusText)}</span>
                          ${auditCp && auditCp.matches && auditCp.matches.length > 0 ? 
                            `<div class="mt-1 font-mono text-xs" style="color: ${auditCp.status.startsWith('NO') ? '#166534' : '#991b1b'}; font-size: 10px;">
                              ${auditCp.status.startsWith('NO') ? '✔ 確認済' : '📍 検出'} ${escapeHtml(auditCp.matches[0].file_path)}:${auditCp.matches[0].line_number} (${auditCp.matches.length}件)
                            </div>` : ''}
                          <button type="button" class="table-action-btn mt-2 btn-open-signoff"
                                  data-cp-id="${escapeHtml(cp.check_point_id || '')}"
                                  data-notice-hash="${escapeHtml(n.notice_hash || '')}"
                                  data-matches-hash="${escapeHtml(auditCp && auditCp.matches_hash ? auditCp.matches_hash : '')}"
                                  data-question="${escapeHtml(cp.check_point_yes_no || '')}"
                                  data-current-status="${escapeHtml(statusText)}">
                            <span>✎</span>
                            <span>${auditCp && auditCp.attestation ? 'サインオフ更新' : 'サインオフ / 回答記録'}</span>
                          </button>
                        </td>
                      `;

                      return `
                        <tr>
                          <td class="font-medium">
                            <div>${escapeHtml(cp.target_or_cve)}</div>
                            <div class="font-mono mt-1" style="font-size: 10px; color: var(--text-dim);">${escapeHtml(cp.check_point_id || '')}</div>
                          </td>
                          <td class="font-medium" style="line-height: 1.6;">${escapeHtml(cp.check_point_yes_no)}</td>
                          <td class="font-mono text-xs" style="color: var(--text-muted); line-height: 1.6; background: rgba(252, 250, 246, 0.6); border-radius: 6px;">${escapeHtml(cp.verification_method)}</td>
                          ${auditTd}
                        </tr>
                      `;
                    }).join('')}
                  </tbody>
                </table>
              </div>

              <!-- Workaround -->
              ${n.workaround ? `
                <div class="text-xs p-3" style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; color: #166534; line-height: 1.6;">
                  <strong>💡 推奨回避策:</strong> ${escapeHtml(n.workaround)}
                </div>
              ` : ''}

              <!-- Sources -->
              ${n.sources && n.sources.length > 0 ? `
                <div class="text-xs flex items-center space-x-2 pt-3" style="border-top: 1px solid var(--border-subtle); color: var(--text-dim); font-size: 11px;">
                  <span class="font-mono" style="color: var(--accent-gold-dark);">出典:</span>
                  ${n.sources.map(formatSourceLink).join(', ')}
                </div>
              ` : ''}
            </div>
          </article>
        `;
      }).join('');
    }

    // Modal event delegation (Prevents XSS completely)
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.btn-open-signoff');
      if (!btn) return;
      const cpId = btn.getAttribute('data-cp-id') || '';
      const noticeHash = btn.getAttribute('data-notice-hash') || '';
      const matchesHash = btn.getAttribute('data-matches-hash') || '';
      const question = btn.getAttribute('data-question') || '';
      const currentStatus = btn.getAttribute('data-current-status') || '';
      openSignoffModal(cpId, noticeHash, question, currentStatus, matchesHash);
    });

    document.getElementById('btn-close-modal').addEventListener('click', closeModal);
    document.getElementById('btn-cancel-modal').addEventListener('click', closeModal);
    document.getElementById('btn-save-signoff').addEventListener('click', applySignoff);

    function openSignoffModal(cpId, noticeHash, question, currentStatus, matchesHash) {
      document.getElementById('modal-cp-id').value = cpId;
      document.getElementById('modal-notice-hash').value = noticeHash;
      document.getElementById('modal-matches-hash').value = matchesHash || '';
      document.getElementById('modal-question').value = question;
      if (!document.getElementById('modal-reviewer').value && window.DEFAULT_REVIEWER) {
        document.getElementById('modal-reviewer').value = window.DEFAULT_REVIEWER;
      }
      document.getElementById('modal-date').value = new Date().toISOString().split('T')[0];
      document.getElementById('modal-evidence').value = '';

      // Drift protection note
      const driftNote = document.getElementById('modal-drift-note');
      if (matchesHash) {
        driftNote.classList.remove('hidden');
      } else {
        driftNote.classList.add('hidden');
      }

      // Pre-select appropriate status based on currentStatus
      const statusSelect = document.getElementById('modal-status');
      let matched = false;
      for (let i = 0; i < statusSelect.options.length; i++) {
        if (statusSelect.options[i].value === currentStatus) {
          statusSelect.selectedIndex = i;
          matched = true;
          break;
        }
      }
      if (!matched) {
        if (currentStatus && currentStatus.startsWith('YES')) {
          statusSelect.value = "YES (ベンダー回答・該当あり)";
        } else if (currentStatus && currentStatus.startsWith('NO')) {
          statusSelect.value = "NO (ベンダー確認済み・非該当)";
        } else {
          statusSelect.value = "要確認 (ベンダー回答待ち・調査中)";
        }
      }

      document.getElementById('signoff-modal').classList.remove('hidden');
    }

    function closeModal() {
      document.getElementById('signoff-modal').classList.add('hidden');
    }

    async function applySignoff() {
      const cpId = document.getElementById('modal-cp-id').value;
      const noticeHash = document.getElementById('modal-notice-hash').value;
      const matchesHash = document.getElementById('modal-matches-hash').value;
      const status = document.getElementById('modal-status').value;
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
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({
            audit_file: auditFile,
            attestation: {
              check_point_id: cpId,
              notice_hash: noticeHash,
              matches_hash: matchesHash || null,
              status: status,
              reviewer: reviewer,
              date: date,
              evidence: evidence
            }
          })
        });
        const data = await res.json();
        if (data.success) {
          closeModal();
          // Auto re-run verification with updated audit file
          document.getElementById('btn-run').click();
        } else {
          alert('サインオフ保存失敗: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('エラー: ' + err.message);
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

    function formatSourceLink(rawUrl) {
      if (!rawUrl) return '';
      const str = String(rawUrl).trim();
      const escaped = escapeHtml(str);
      // Strictly allow only http:// and https:// URLs for clickable <a> links
      if (/^https?:\\/\\//i.test(str)) {
        return `<a href="${escaped}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-gold-dark); text-decoration: underline; font-family: var(--mono);">${escaped}</a>`;
      }
      // Otherwise render as safe plain text (blocks javascript:, data:, etc.)
      return `<span style="font-family: var(--mono);">${escaped}</span>`;
    }
  </script>
</body>
</html>
"""


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in separate threads for snappy UI responsiveness."""
    daemon_threads = True


class TriageDashboardHandler(BaseHTTPRequestHandler):
    """Secure HTTP request handler for the triage-agent dashboard."""

    def _is_host_allowed(self) -> bool:
        """Validate Host header against allowed local addresses to prevent DNS rebinding."""
        server_port = getattr(self.server, "server_port", 8080)
        allowed_hosts = {
            f"127.0.0.1:{server_port}",
            f"localhost:{server_port}",
            "127.0.0.1",
            "localhost",
        }
        host_header = self.headers.get("Host", "").strip()
        return bool(host_header and host_header in allowed_hosts)

    def do_GET(self):
        # 1. Host verification to prevent DNS rebinding attacks
        if not self._is_host_allowed():
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"error": f"アクセス拒否: 不正な Host ヘッダーです ({self.headers.get('Host', '')})"},
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return

        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            default_reviewer = f"{getpass.getuser()} (システム担当)"
            html_content = HTML_PAGE.replace("__CSRF_TOKEN__", SERVER_CSRF_TOKEN).replace(
                "__DEFAULT_REVIEWER__", default_reviewer
            )
            self.wfile.write(html_content.encode("utf-8"))
        elif self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            status = {
                "is_llm_configured": is_llm_configured(),
                "model": get_model_name(),
                "cwd": str(Path.cwd()),
                "default_reviewer": f"{getpass.getuser()} (システム担当)",
            }
            self.wfile.write(json.dumps(status, ensure_ascii=False).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        # 1. Enforce Content-Type check (application/json only to force CORS preflight)
        content_type = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
        if content_type != "application/json":
            self.send_response(415)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "Content-Type must be application/json"}, ensure_ascii=False).encode("utf-8")
            )
            return

        # 2. Origin & Host verification (Strict localhost/127.0.0.1 validation)
        if not self._is_host_allowed():
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {"error": f"アクセス拒否: 不正な Host ヘッダーです ({self.headers.get('Host', '')})"},
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            return

        server_port = getattr(self.server, "server_port", 8080)
        origin_header = self.headers.get("Origin", "").strip()
        if origin_header:
            allowed_origins = {
                f"http://127.0.0.1:{server_port}",
                f"http://localhost:{server_port}",
            }
            if origin_header not in allowed_origins:
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    json.dumps(
                        {"error": f"アクセス拒否: 外部サイトからのクロスオリジンリクエストです ({origin_header})"},
                        ensure_ascii=False,
                    ).encode("utf-8")
                )
                return

        # 3. Read body safely
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length)
        try:
            req_data = json.loads(post_body.decode("utf-8"))
        except Exception:
            req_data = {}

        # 4. Enforce CSRF token verification
        client_token = self.headers.get("X-CSRF-Token") or req_data.get("csrf_token")
        if not client_token or client_token != SERVER_CSRF_TOKEN:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "アクセス拒否: CSRFトークンが無効または欠落しています。"}, ensure_ascii=False).encode(
                    "utf-8"
                )
            )
            return

        if self.path in ("/api/run", "/api/run-stream"):
            is_stream = (self.path == "/api/run-stream")
            mode = req_data.get("mode", "demo")
            sbom_path = req_data.get("sbom", "sample_sbom.json").strip()
            code_dir = req_data.get("code_dir", "").strip() or None
            audit_file = req_data.get("audit_file", "sample_audit_signoff.json").strip() or None

            try:
                # Restrict paths strictly within authorized workspace
                safe_sbom = str(resolve_safe_path(sbom_path)) if mode != "demo" else sbom_path
                safe_code = str(resolve_safe_path(code_dir)) if code_dir else None
                safe_audit = str(resolve_safe_path(audit_file)) if audit_file else None

                if is_stream:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("X-Accel-Buffering", "no")
                    self.end_headers()

                    def send_progress(msg: str, percent: int = 0, phase: str = "Init", **kwargs):
                        evt = {
                            "type": "progress",
                            "message": msg,
                            "percent": percent,
                            "phase": phase,
                            **kwargs,
                        }
                        try:
                            self.wfile.write(f"data: {json.dumps(evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            pass

                    triage_report, audit_report = execute_triage_pipeline(
                        sbom_path=safe_sbom,
                        mode=mode,
                        code_dir=safe_code,
                        audit_file_path=safe_audit,
                        progress_callback=send_progress,
                    )

                    complete_evt = {
                        "type": "complete",
                        "report": triage_report.model_dump(),
                        "audit": audit_report.model_dump() if audit_report else None,
                    }
                    self.wfile.write(f"data: {json.dumps(complete_evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                    self.wfile.flush()

                else:
                    triage_report, audit_report = execute_triage_pipeline(
                        sbom_path=safe_sbom,
                        mode=mode,
                        code_dir=safe_code,
                        audit_file_path=safe_audit,
                    )

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    response_payload = {
                        "report": triage_report.model_dump(),
                        "audit": audit_report.model_dump() if audit_report else None,
                    }
                    self.wfile.write(json.dumps(response_payload, ensure_ascii=False).encode("utf-8"))

            except Exception as e:
                if is_stream:
                    err_evt = {"type": "error", "error": str(e)}
                    try:
                        self.wfile.write(f"data: {json.dumps(err_evt, ensure_ascii=False)}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                else:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))

        elif self.path == "/api/create-signoff":
            audit_file_path = req_data.get("audit_file", "sample_audit_signoff.json").strip()
            attestation_data = req_data.get("attestation", {})

            try:
                safe_audit_path = resolve_safe_path(audit_file_path)
                existing_attestations = []
                if safe_audit_path.exists():
                    try:
                        raw = json.loads(safe_audit_path.read_text(encoding="utf-8"))
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

                # Write back safely to the authorized audit file
                safe_audit_path.write_text(
                    json.dumps({"attestations": existing_attestations}, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )

                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}, ensure_ascii=False).encode("utf-8"))

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
