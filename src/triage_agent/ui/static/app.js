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

      // 0. Show report action bar and toggle audit download button
      const actionBar = document.getElementById('report-action-bar');
      if (actionBar) {
        actionBar.classList.remove('hidden');
        const dlAuditBtn = document.getElementById('btn-dl-audit');
        if (dlAuditBtn) {
          if (audit) dlAuditBtn.classList.remove('hidden');
          else dlAuditBtn.classList.add('hidden');
        }
      }

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
      if (/^https?:\/\//i.test(str)) {
        return `<a href="${escaped}" target="_blank" rel="noopener noreferrer" style="color: var(--accent-gold-dark); text-decoration: underline; font-family: var(--mono);">${escaped}</a>`;
      }
      // Otherwise render as safe plain text (blocks javascript:, data:, etc.)
      return `<span style="font-family: var(--mono);">${escaped}</span>`;
    }

    // Client-side Blob download helper
    function downloadBlob(content, filename, mimeType) {
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    // Load Previous Report Handlers
    const loadModal = document.getElementById('load-modal');
    document.getElementById('btn-open-load-modal').addEventListener('click', () => {
      loadModal.classList.remove('hidden');
    });
    document.getElementById('btn-close-load-modal').addEventListener('click', () => {
      loadModal.classList.add('hidden');
    });
    document.getElementById('btn-cancel-load-modal').addEventListener('click', () => {
      loadModal.classList.add('hidden');
    });

    document.getElementById('btn-submit-load').addEventListener('click', async () => {
      const reportPath = document.getElementById('load-report-path').value.trim() || 'triage_report.json';
      const codeDir = document.getElementById('code-dir').value.trim() || null;
      const auditFile = document.getElementById('audit-file').value.trim() || null;

      try {
        const res = await fetch('/api/load-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({
            report_path: reportPath,
            code_dir: codeDir,
            audit_file: auditFile
          })
        });
        const data = await res.json();
        if (data.success && data.report) {
          currentReport = data.report;
          currentAudit = data.audit;
          renderReport(currentReport, currentAudit);
          loadModal.classList.add('hidden');
          // Update progress status
          updateProgress({ percent: 100, phase: 'Restored', message: `レポート '${escapeHtml(data.loaded_from)}' を復元しました。継続編集可能です。` });
          document.getElementById('loading-spinner').classList.add('hidden');
          document.getElementById('notices-container').classList.remove('hidden');
        } else {
          alert('読込失敗: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('読込エラー: ' + err.message);
      }
    });

    // Save Report to Workspace Handlers
    const saveModal = document.getElementById('save-modal');
    document.getElementById('btn-open-save-modal').addEventListener('click', () => {
      if (!currentReport) {
        alert('保存するレポートデータがありません。');
        return;
      }
      saveModal.classList.remove('hidden');
    });
    document.getElementById('btn-close-save-modal').addEventListener('click', () => {
      saveModal.classList.add('hidden');
    });
    document.getElementById('btn-cancel-save-modal').addEventListener('click', () => {
      saveModal.classList.add('hidden');
    });

    document.getElementById('btn-submit-save').addEventListener('click', async () => {
      if (!currentReport) return;
      const outputMd = document.getElementById('save-md-path').value.trim() || null;
      const outputJson = document.getElementById('save-json-path').value.trim() || null;
      const verifyOutput = document.getElementById('save-audit-path').value.trim() || null;

      try {
        const res = await fetch('/api/save-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({
            report: currentReport,
            audit: currentAudit,
            output_md: outputMd,
            output_json: outputJson,
            verify_output: verifyOutput
          })
        });
        const data = await res.json();
        if (data.success) {
          saveModal.classList.add('hidden');
          alert('ファイルを正常に保存しました:\n• ' + data.saved_files.join('\n• '));
        } else {
          alert('保存失敗: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('保存エラー: ' + err.message);
      }
    });

    // Client-side Direct Download Handlers
    document.getElementById('btn-dl-json').addEventListener('click', () => {
      if (!currentReport) return;
      const jsonStr = JSON.stringify(currentReport, null, 2);
      downloadBlob(jsonStr, 'triage_report.json', 'application/json');
    });

    document.getElementById('btn-dl-md').addEventListener('click', async () => {
      if (!currentReport) return;
      try {
        const res = await fetch('/api/save-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({
            report: currentReport,
            audit: currentAudit,
            output_md: null,
            output_json: null,
            verify_output: null
          })
        });
        const data = await res.json();
        if (data.success && data.md_content) {
          downloadBlob(data.md_content, 'triage_report.md', 'text/markdown; charset=utf-8');
        } else {
          alert('Markdown生成失敗: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('ダウンロードエラー: ' + err.message);
      }
    });

    document.getElementById('btn-dl-audit').addEventListener('click', async () => {
      if (!currentReport || !currentAudit) return;
      try {
        const res = await fetch('/api/save-report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': window.CSRF_TOKEN
          },
          body: JSON.stringify({
            report: currentReport,
            audit: currentAudit,
            output_md: null,
            output_json: null,
            verify_output: null
          })
        });
        const data = await res.json();
        if (data.success && data.audit_content) {
          downloadBlob(data.audit_content, 'verification_audit_report.md', 'text/markdown; charset=utf-8');
        } else {
          alert('検証Markdown生成失敗: ' + (data.error || '不明なエラー'));
        }
      } catch (err) {
        alert('ダウンロードエラー: ' + err.message);
      }
    });
