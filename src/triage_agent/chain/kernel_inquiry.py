"""Kernel vulnerability inquiry for the development vendor (ADR-022, v0.5.1).

A system owner who is not a specialist usually wants to know one thing: "an attacker took over a
server through a kernel flaw elsewhere; are there other flaws like that left on our servers?"

Asking the vendor about every CVE one by one is slow and hard to answer. Asking which kernel each
server runs is easy, and the rest can be worked out here. So the inquiry is two steps:

1. ``--kernel-inquiry`` writes a short request: a CSV form where the vendor pastes one line of output
   per kernel version (a read-only one-liner) and the number of servers, plus a Markdown note for the
   system owner with a ready-to-send request.
2. ``--kernel-inquiry-answers <returned CSV>`` reads the lines back and looks the versions up with the
   same distribution advisories as ``--kernel-auto`` (no telemetry collection or environment file is
   needed). The result lists, per kernel version, the exploited (CISA KEV) and promoted kernel CVEs that
   are still unfixed, and the version to update to. After the update the vendor returns the same form
   again, and the next run shows whether they are gone.

The form asks for nothing that identifies a server (no host names, no addresses).
"""

import csv
import io
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from triage_agent.chain.models import EnvironmentDefinition, NodePoolDefinition, NodeTelemetry
from triage_agent.chain.version_parser import compare_kernel_versions

OS_LABELS = {"amzn": "Amazon Linux", "rhel": "RHEL", "ubuntu": "Ubuntu", "debian": "Debian",
             "almalinux": "AlmaLinux", "rocky": "Rocky Linux"}

REQUEST_HEADERS = [
    "DistributionID", "No", "サーバー群（呼び名・任意）", "コマンドの出力（1 行をそのまま貼り付け）", "台数",
    "確認者 (会社名・氏名)", "確認日 (YYYY-MM-DD)", "備考",
]
EXAMPLE_NO = "記入例"
BLANK_ROWS = 8

# Read-only. Prints one line: OS, running kernel, the package that owns it (with epoch), the newest
# installed build of that package (to spot a pending reboot) and installed livepatches.
COLLECT_COMMAND = (
    "sh -c '. /etc/os-release; U=$(uname -r); "
    "if command -v rpm >/dev/null 2>&1; then F=/boot/vmlinuz-$U; [ -e \"$F\" ] || F=/lib/modules/$U/vmlinuz; "
    "P=$(rpm -q --qf \"%{NAME}\" -f \"$F\" 2>/dev/null); E=$(rpm -q --qf \"%{EPOCHNUM}:%{VERSION}-%{RELEASE}\" -f \"$F\" 2>/dev/null); "
    "S=$(rpm -q --qf \"%{SOURCERPM}\" -f \"$F\" 2>/dev/null); "
    "L=$(rpm -q --qf \"%{INSTALLTIME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n\" \"$P\" 2>/dev/null | sort -n | tail -1 | cut -d\" \" -f2); "
    "LP=$(rpm -qa --qf \"%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE},\" \"kernel-livepatch-*\" 2>/dev/null); "
    "else P=linux-image-$U; E=$(dpkg-query -W -f=\"\\${Version}\" \"$P\" 2>/dev/null); S=$(dpkg-query -W -f=\"\\${source:Package}\" \"$P\" 2>/dev/null); "
    "L=; [ -e /var/run/reboot-required ] && L=reboot-required; LP=; fi; "
    "echo \"kernel-line ID=$ID VERSION_ID=$VERSION_ID UNAME=$U PKG=$P EVR=$E SRC=$S LATEST=$L LP=$LP\"'"
)
LINE_RE = re.compile(r"kernel-line\s+(.*)$")
FIELD_RE = re.compile(r"([A-Z_]+)=(\S*)")


def os_label(distro: str, release: str) -> str:
    return f"{OS_LABELS.get(distro, distro)} {release}".strip()


# -- step 1: the request ---------------------------------------------------------------------------
def write_request(target: str, csv_path: Path) -> Tuple[Path, Path, str]:
    from triage_agent.tools.vendor_workflow import generate_distribution_id, record_workflow_event, sanitize_csv_cell as s

    distribution_id = generate_distribution_id(target or "kernel")
    rows = [{
        "DistributionID": distribution_id, "No": EXAMPLE_NO, "サーバー群（呼び名・任意）": "Web サーバー",
        "コマンドの出力（1 行をそのまま貼り付け）": s("kernel-line ID=amzn VERSION_ID=2023 UNAME=6.1.189-236.399.amzn2023.x86_64 "
                                          "PKG=kernel EVR=1:6.1.189-236.399.amzn2023 SRC=kernel-6.1.189-236.399.amzn2023.src.rpm "
                                          "LATEST=1:6.1.189-236.399.amzn2023 LP="),
        "台数": "4", "確認者 (会社名・氏名)": "", "確認日 (YYYY-MM-DD)": "",
        "備考": s("この行は記入例です（読み込みでは無視されます）。各サーバーで次のコマンドを実行し、出力の 1 行を貼り付けてください。"
                 "同じ出力のサーバーは 1 行にまとめ、台数を書いてください。ホスト名は書かないでください。コマンド: " + COLLECT_COMMAND),
    }]
    for i in range(1, BLANK_ROWS + 1):
        rows.append({h: "" for h in REQUEST_HEADERS} | {"DistributionID": distribution_id, "No": str(i)})
    buf = io.StringIO()
    buf.write("\ufeff")
    w = csv.DictWriter(buf, fieldnames=REQUEST_HEADERS)
    w.writeheader()
    w.writerows(rows)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.write_text(buf.getvalue(), encoding="utf-8")
    md_path = csv_path.with_suffix(".md")
    md_path.write_text(render_request_markdown(target, csv_path, distribution_id), encoding="utf-8")
    record_workflow_event("vendor_checklist_exported", {
        "distribution_id": distribution_id, "file_path": str(csv_path), "target_product": target or None,
        "check_points_count": 0, "report_title": "kernel_inquiry", "announced_at": None,
    })
    return csv_path, md_path, distribution_id


def render_request_markdown(target: str, csv_path: Path, distribution_id: str) -> str:
    name = target or "本番環境"
    return "\n".join([
        f"# カーネル脆弱性の問い合わせ（{name}）",
        "",
        f"配布 ID: `{distribution_id}` ／ ベンダーに送る記入表: `{csv_path.name}`",
        "",
        "## なぜ問い合わせるのか",
        "",
        "Web アプリなどの穴から侵入した攻撃者は、次にサーバーの **カーネル（OS の中核）** の脆弱性を使って管理者の権限を奪い、"
        "サーバー全体と、同じサーバーで動く他のシステムを乗っ取ろうとします。「ローカルからしか使えない」と後回しにされやすい種類の脆弱性ですが、"
        "侵入の足場と組み合わさると致命的になります。",
        "",
        "どの脆弱性が残っているかは、**各サーバーで動いているカーネルの版** が分かれば、このツールが各ディストリの勧告と突き合わせて割り出せます。"
        "そこでベンダーには、脆弱性を 1 件ずつ確かめてもらうのではなく、カーネルの版だけを教えてもらいます。",
        "",
        "## ベンダーへの依頼文（そのまま送れます）",
        "",
        "> 本番環境のサーバーで動いているカーネルの版を確認させてください。",
        "> 各サーバーで次のコマンドを実行し、出力された 1 行を、添付の記入表に貼り付けてご返送ください。"
        "同じ出力のサーバーは 1 行にまとめ、台数をご記入ください。",
        "> コマンドは読み取りのみで、設定は変更しません。ホスト名や IP アドレスは不要です。",
        "",
        "```sh",
        COLLECT_COMMAND,
        "```",
        "",
        "## 返ってきたら",
        "",
        f"```sh\npython -m triage_agent.cli --kernel-inquiry-answers <返送された記入表.csv> --kernel-inquiry-target \"{name}\"\n```",
        "",
        "カーネルの版ごとに、**悪用が確認されている脆弱性**（米国 CISA の KEV カタログに掲載）と、悪用の兆候が強まって"
        "**このツールが警戒を引き上げたもの** のうち、まだ直っていないものと、「この版まで上げれば解消する」版が出ます。"
        "ベンダーへの更新の依頼文も一緒に出ます。更新のあとで同じ記入表をもう一度返してもらえば、解消したかをこのツールで確かめられます。",
        "",
        "## 注意",
        "",
        "- 照会には、カーネルのパッケージ名と版を、各ディストリの勧告の提供元（OSV.dev など）に送ります。ホスト名や台数、システム名は送りません"
        "（[データの取り扱い](https://github.com/hamatz/triage-agent/blob/main/docs/data-handling.md)）。",
        "- 修正版を自動で調べられるのは、Amazon Linux、RHEL、Ubuntu、Debian、AlmaLinux、Rocky Linux です。ほかの OS は「照会元なし」と表示します。",
        "",
    ])


# -- step 2: the answers ---------------------------------------------------------------------------
@dataclass
class KernelLine:
    group_id: str
    label: str
    distro: str
    release: str
    uname: str
    package: str
    version: str                    # version-release without epoch
    epoch: Optional[str]
    flavor: str
    latest: str = ""                # newest installed build of the package, or 'reboot-required'
    livepatch: List[str] = field(default_factory=list)
    count: Optional[int] = None
    rows: List[str] = field(default_factory=list)

    @property
    def evr(self) -> str:
        return f"{self.epoch}:{self.version}" if self.epoch else self.version

    def reboot_pending(self) -> Optional[str]:
        """The newer installed build waiting for a reboot, 'yes' (Debian/Ubuntu flag), or None."""
        if self.latest == "reboot-required":
            return "yes"
        if self.latest and self.latest != self.evr:
            cmp = compare_kernel_versions(self.distro, self.latest, self.evr)
            if cmp is not None and cmp > 0:
                return self.latest
        return None


def parse_line(text: str) -> Tuple[Optional[dict], str]:
    m = LINE_RE.search(text or "")
    if not m:
        return None, "コマンドの出力（kernel-line で始まる 1 行）が見つかりません"
    fields = dict(FIELD_RE.findall(m.group(1)))
    missing = [k for k in ("ID", "VERSION_ID", "UNAME", "PKG", "EVR") if not fields.get(k)]
    if missing:
        return None, f"出力に {'・'.join(missing)} がありません（コマンドが途中で失敗した可能性）"
    return fields, ""


def read_answers(csv_path: Path) -> Tuple[List[KernelLine], List[str], Optional[str]]:
    """Kernel lines from a returned form (identical kernels merged), problems, and the distribution ID."""
    content = Path(csv_path).read_text(encoding="utf-8-sig")
    groups: Dict[Tuple[str, str, str, str], KernelLine] = {}
    problems: List[str] = []
    dist_ids = set()
    for row in csv.DictReader(io.StringIO(content)):
        no = (row.get("No") or "").strip()
        if no == EXAMPLE_NO:
            continue
        if (row.get("DistributionID") or "").strip():
            dist_ids.add(row["DistributionID"].strip())
        raw = (row.get("コマンドの出力（1 行をそのまま貼り付け）") or "").strip().lstrip("'")
        if not raw:
            continue
        f, problem = parse_line(raw)
        if f is None:
            problems.append(f"No {no}: {problem}")
            continue
        count = None
        count_raw = (row.get("台数") or "").strip()
        if count_raw:
            try:
                count = int(count_raw)
            except ValueError:
                problems.append(f"No {no}: 台数「{count_raw}」を数として読めません（台数不明として扱います）")
        distro, release = f["ID"].lower(), f["VERSION_ID"]
        epoch, version = (f["EVR"].split(":", 1) if ":" in f["EVR"] else (None, f["EVR"]))
        is_rpm = f.get("SRC", "").endswith(".src.rpm")
        flavor = re.sub(r"-\d.*$", "", f.get("SRC", "")) if is_rpm else (f.get("SRC") or f["PKG"])
        key = (distro, release, f["PKG"], f["EVR"])
        line = groups.get(key)
        if line is None:
            line = KernelLine(
                group_id=f"G{len(groups) + 1}", label=(row.get("サーバー群（呼び名・任意）") or "").strip(),
                distro=distro, release=release, uname=f["UNAME"],
                package=f["PKG"] if is_rpm else "", version=version, epoch=epoch if is_rpm else None,
                flavor=flavor, latest=f.get("LATEST", ""),
                livepatch=[p for p in f.get("LP", "").split(",") if p], count=count,
            )
            groups[key] = line
        else:
            # A row without a count makes the total unknown rather than silently too small.
            line.count = None if (count is None or line.count is None) else line.count + count
            extra = (row.get("サーバー群（呼び名・任意）") or "").strip()
            if extra and extra not in line.label.split("、"):
                line.label = f"{line.label}、{extra}" if line.label else extra
        line.rows.append(no)
    if len(dist_ids) > 1:
        problems.append(f"記入表に複数の配布 ID が混ざっています: {', '.join(sorted(dist_ids))}")
    return list(groups.values()), problems, (sorted(dist_ids)[0] if dist_ids else None)


def to_environment(lines: List[KernelLine]) -> Tuple[EnvironmentDefinition, Dict[str, NodeTelemetry]]:
    """One node pool per kernel line, so the --kernel-auto lookup can be reused unchanged."""
    pools, tels = [], {}
    for ln in lines:
        pools.append(NodePoolDefinition(pool_id=ln.group_id, os_distribution=ln.distro, os_release=ln.release,
                                        kernel_package_name=ln.package or ln.flavor, kernel_flavor=ln.flavor))
        tels[ln.group_id] = NodeTelemetry(
            pool_id=ln.group_id, os_distribution=ln.distro, os_release=ln.release,
            kernel_package_name=ln.package or f"linux-image-{ln.uname}", kernel_flavor=ln.flavor,
            kernel_package_version=ln.version, kernel_release=ln.uname,
            kernel_package_epoch=ln.epoch, kernel_binary_package=ln.package or None,
            livepatch_packages=ln.livepatch, observed_nodes_count=ln.count or 1,
        )
    return EnvironmentDefinition(environment_name="kernel-inquiry", node_pools=pools), tels


def _show(ln: "KernelLine", version: Optional[str]) -> Optional[str]:
    """Drop the epoch when it equals the server's (``rpm -q`` shows versions without it)."""
    if version and ln.epoch is not None and ":" in version:
        e, rest = version.split(":", 1)
        if e.isdigit() and ln.epoch.isdigit() and int(e) == int(ln.epoch):
            return rest
    return version


def _tier1_target(distro: str, exposed) -> Optional[str]:
    best = None
    for x in exposed:
        if x.tier != 1 or not x.fixed_evr:
            continue
        if best is None or (compare_kernel_versions(distro, x.fixed_evr, best) or 0) > 0:
            best = x.fixed_evr
    return best


def _reason(x, kev: Dict[str, dict]) -> str:
    item = kev.get(x.cve_id)
    if item:
        r = f"悪用確認済み（CISA KEV・{item.get('dateAdded', '')} 掲載）"
        if str(item.get("knownRansomwareCampaignUse", "")).lower() == "known":
            r += "・ランサムウェアでの悪用あり"
        return r
    if x.promotion is not None:
        return f"警戒を引き上げたもの（{x.promotion.label}: {x.promotion.detail}）"
    return ""


def render_result(target: str, lines: List[KernelLine], auto, kev: Dict[str, dict], problems: List[str],
                  distribution_id: Optional[str], answers_path: Path) -> str:
    name = target or "本番環境"
    out = [
        f"# カーネル脆弱性の照会結果（{name}）",
        "",
        f"記入表: `{answers_path.name}`" + (f" ／ 配布 ID: `{distribution_id}`" if distribution_id else ""),
        "",
        "ベンダーから返ってきたカーネルの版を、各ディストリの勧告と突き合わせました。対象は、**悪用が確認されている脆弱性**（CISA KEV）と、"
        "**このツールが警戒を引き上げたもの** です。",
        "",
        "## まとめ",
        "",
        "| サーバー群 | OS | 動いているカーネル | 台数 | 残っている脆弱性（悪用確認済み・警戒引き上げ） | 更新してほしい版 |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]
    requests: List[str] = []
    details: List[str] = []
    for ln in lines:
        s = auto.pools.get(ln.group_id)
        label = ln.label or ln.group_id
        count = f"{ln.count} 台" if ln.count else "不明"
        if s is None or s.status != "ok":
            reason = s.reason if s else "照会できませんでした"
            out.append(f"| {label} | {os_label(ln.distro, ln.release)} | `{ln.uname}` | {count} | ❓ 判定できませんでした | — |")
            details += [f"### {label}（`{ln.uname}`、{count}）", "", f"❓ **判定できませんでした**: {reason}", "",
                        "この版は、残っている脆弱性がないという意味ではありません。ベンダーに、ディストリの勧告での確認をお願いしてください。", ""]
            requests.append(f"- {label}（{os_label(ln.distro, ln.release)}、現在 `{ln.uname}`、{count}）: こちらでは判定できませんでした。"
                            "CISA KEV に載っている Linux カーネルの脆弱性が残っていないか、ディストリの勧告でご確認ください。")
            continue
        t1 = [x for x in s.exposed if x.tier == 1]
        target_v = _show(ln, _tier1_target(ln.distro, s.exposed))
        no_fix = [x for x in t1 if not x.fixed_evr]
        reboot = ln.reboot_pending()
        fixes_reboot = False
        if not t1:
            out.append(f"| {label} | {os_label(ln.distro, ln.release)} | `{ln.uname}` | {count} | ✅ なし | — |")
        else:
            out.append(f"| {label} | {os_label(ln.distro, ln.release)} | `{ln.uname}` | {count} | 🚨 {len(t1)} 件"
                       + (f"（うち修正版なし {len(no_fix)} 件）" if no_fix else "") + f" | {target_v + ' 以上' if target_v else '—'} |")
        details += [f"### {label}（`{ln.uname}`、{count}）", ""]
        if reboot:
            newer = "新しいカーネル" + (f"（{_show(ln, reboot)}）" if reboot != "yes" else "")
            raw_target = _tier1_target(ln.distro, s.exposed)
            cmp = compare_kernel_versions(ln.distro, reboot, raw_target) if reboot != "yes" and raw_target else None
            fixes_all = fixes_reboot = cmp is not None and cmp >= 0
            details += [f"⚠️ {newer}はインストールされていますが、**再起動されておらず、古いカーネルのまま動いています**。"
                        + ("再起動すれば、下の脆弱性のうち修正版のあるものは解消します。" if fixes_all else "再起動してから、もう一度確かめてください。"), ""]
        if not t1:
            details += ["✅ 悪用確認済み・警戒を引き上げた脆弱性で、直っていないものはありません（確認できた範囲）。", ""]
        else:
            details += ["| CVE | 名前 | 理由 | 修正版 |", "| :--- | :--- | :--- | :--- |"]
            for x in t1:
                cve_name = (kev.get(x.cve_id) or {}).get("vulnerabilityName") or ""
                details.append(f"| [{x.cve_id}]({x.source_url}) | {cve_name} | {_reason(x, kev)} | {_show(ln, x.fixed_evr) or '修正版なし'} |")
            details.append("")
        others = s.tier_counts.get(2, 0) + s.tier_counts.get(3, 0)
        if others:
            details += [f"ほかに、悪用の確認されていない未修正の脆弱性が {others} 件あります（悪用の可能性が高めのもの {s.tier_counts.get(2, 0)} 件）。"
                        + (f"すべて解消するには {_show(ln, s.all_fixes_target)} 以上です。" if s.all_fixes_target else "")
                        + "通常の更新の枠で対応してもらうのが目安です。", ""]
        if s.livepatched:
            details += [f"livepatch で解消済みのものが {s.livepatched} 件あります（数に含めていません）。", ""]
        if s.indeterminate:
            details += [f"版の比べ方が確定できず、残っているものとして数えたものが {s.indeterminate} 件あります。", ""]
        if t1:
            req = f"- {label}（{os_label(ln.distro, ln.release)}、現在 `{ln.uname}`、{count}）: "
            if target_v and fixes_reboot:
                req += f"インストール済みの新しいカーネル（{_show(ln, reboot)}）で再起動してください（{target_v} 以上であれば解消します）。"
            elif target_v:
                req += f"カーネルを **{target_v} 以上** に更新し、再起動してください。"
            if no_fix:
                req += f" 修正版のまだない {', '.join(x.cve_id for x in no_fix)} は、緩和策の適用状況を教えてください。"
            requests.append(req)
    out += [""]
    if requests:
        out += [
            "## ベンダーへの依頼文（そのまま送れます）",
            "",
            "> ご回答いただいたカーネルの版を確認したところ、悪用が確認されているカーネルの脆弱性が残っているサーバーがありました。",
            "> 以下の対応をお願いします。対応後、前回と同じコマンドの出力を、記入表でもう一度ご返送ください。こちらで解消を確認します。",
            ">",
        ] + [f"> {r}" for r in requests] + [""]
    out += ["## サーバー群ごとの詳細", ""] + details
    notes = list(problems) + list(auto.errors)
    if notes:
        out += ["## 読み込めなかったもの・照会できなかったもの（調べられなかったものを隠さない）", ""] + [f"- {n}" for n in notes] + [""]
    out += [
        "## 注意",
        "",
        "- これは「悪用が確認されたもの」と「警戒を引き上げたもの」に絞った結果です。✅ は、ほかの脆弱性がないという意味ではありません。",
        "- 判定は、返ってきた版と各ディストリの勧告の突き合わせです。記入表に載っていないサーバーについては何も言えません。",
        "- 延長サポート（RHEL の EUS など）の系列は本流と比べるため、直っているのに残っていると出ることがあります（安全側）。",
        "",
    ]
    return "\n".join(out)


def record_answers_imported(distribution_id: Optional[str], answers_path: Path, lines: List[KernelLine]) -> None:
    from triage_agent.tools.vendor_workflow import record_workflow_event

    record_workflow_event("vendor_checklist_imported", {
        "distribution_id": distribution_id, "file_path": str(answers_path), "imported_count": len(lines),
        "no_held_count": 0, "conflict_count": 0, "warnings": [], "total_attestations": 0, "kind": "kernel_inquiry",
    })
