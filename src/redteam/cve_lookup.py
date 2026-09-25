"""CVE 直查模組(cve lookup)— 「不信任指紋版本」的產品級 CVE 查詢。

來源:用戶需求(2026-09-19)— 偵測到套件/框架時不該直接相信目標自報版本,
而要從「該套件/框架本身」查全部已發布 CVE,再動態嘗試。

三個資料源(全部公開 API、GET only):
- GHSA (api.github.com/advisories): ecosystem 內套件最全,附 first_patched。
  支援 ?cve_id= 直查與 ?affects=<pkg>&ecosystem= 產品級查詢(不按版本過濾)。
- OSV  (api.osv.dev/v1/query): 多生態系(npm/pip/composer/maven/go/cargo/
  rubygems/nuget/hex/pub...),回傳該 package 全部漏洞(可帶 version 過濾)。
- NVD  (services.nvd.nist.gov/api/2.0): 唯一廣泛涵蓋伺服器軟體(nginx/
  apache/wordpress 等非套件生態)的源;匿名限 5 req/30s,設 NVD_API_KEY
  提升額度。無 key 時降頻使用並在結果中如實標註。

鐵律:全 GET、零靶點流量(僅控制平面公開 API)、無法解析的資料保守跳過,
查無 ≠ 無漏洞(latest_advisory_date 新鮮度必須如實帶回)。
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

GHSA_API = "https://api.github.com/advisories"
OSV_API = "https://api.osv.dev/v1/query"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: GHSA ecosystem 正名(與 version_watch 對齊)
ECOSYSTEM_ALIAS = {"pypi": "pip", "pypi.org": "pip", "packagist": "composer",
                   "crates.io": "cargo", "golang": "go"}

#: 常見框架 → (GHSA/OSV ecosystem, 套件名)。偵測到框架後直查該包全部 CVE。
FRAMEWORK_PACKAGES: dict[str, tuple[str, str]] = {
    "wordpress": ("composer", "wordpress/wordpress"),
    "drupal": ("composer", "drupal/core"),
    "laravel": ("composer", "laravel/framework"),
    "django": ("pip", "django"),
    "flask": ("pip", "flask"),
    "rails": ("rubygems", "rails"),
    "spring": ("maven", "org.springframework.boot:spring-boot"),
    "express": ("npm", "express"),
    "next": ("npm", "next"),
    "react": ("npm", "react"),
    "nuxt": ("npm", "nuxt"),
    "vue": ("npm", "vue"),
    "jquery": ("npm", "jquery"),
    "tomcat": ("maven", "org.apache.tomcat:tomcat-catalina"),
    "jenkins": ("maven", "org.jenkins-ci.main:jenkins-core"),
    "n8n": ("npm", "n8n"),
    "strapi": ("npm", "@strapi/strapi"),
    "grafana": ("go", "github.com/grafana/grafana"),
    "nginx": ("", ""),          # 非套件生態 → 僅 NVD
    "apache": ("", ""),
    "iis": ("", ""),
    "php": ("", ""),
    "openssl": ("", ""),
}


@dataclass
class CveAdvisory:
    cve: str
    source: str            # ghsa | osv | nvd
    severity: str          # critical | high | medium | low | unknown
    summary: str
    product: str = ""
    ecosystem: str = ""
    vulnerable_range: str = ""
    first_patched: str | None = None
    published: str = ""
    urls: list[str] = field(default_factory=list)
    # EPSS/KEV 攻擊 likelihood 情報(enrich() 填入;None = 該源無資料,如實呈現)
    epss: float | None = None
    epss_percentile: float | None = None
    kev: bool = False


@dataclass
class LookupResult:
    """統一查詢結果。ok=False 時 error 必須如實呈現(不隱瞞)。"""
    query: str
    advisories: list[CveAdvisory] = field(default_factory=list)
    error: str = ""
    sources: list[str] = field(default_factory=list)   # 成功回應的源
    latest_advisory_date: str = ""                     # 資料源新鮮度

    @property
    def ok(self) -> bool:
        return not self.error


def _get_json(url: str, *, headers: dict[str, str] | None = None, timeout: int = 25):
    # Accept 依 host 分流(實錄 2026-09-25 www.tph run):無腦對所有源發
    # vendor 型別 application/vnd.github+json,NVD 會回 406 Not Acceptable;
    # 只有 api.github.com 需要它,其餘源一律標準 application/json。
    base_headers = {
        "Accept": ("application/vnd.github+json" if "api.github.com" in url
                   else "application/json"),
        "User-Agent": "tanli-cve-lookup",
    }
    base_headers.update(headers or {})
    req = urllib.request.Request(url, headers=base_headers)
    tok = os.environ.get("GITHUB_TOKEN", "")
    if "api.github.com" in url and tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))



def _ref_urls(references) -> list[str]:
    """GHSA/NVD references 形狀不穩(list[dict] 或 list[str]),兩者都吃。"""
    out = []
    for h in references or []:
        u = h.get("url", "") if isinstance(h, dict) else (h if isinstance(h, str) else "")
        if u:
            out.append(u)
    return out[:4]


def _sev_norm(s: str | None) -> str:
    s = (s or "unknown").lower()
    return {"moderate": "medium", "important": "high", "none": "unknown"}.get(s, s)


def _latest_date(advs: list[CveAdvisory]) -> str:
    ds = [a.published for a in advs if a.published]
    return max(ds) if ds else ""


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

def ghsa_by_cve(cve_id: str) -> LookupResult:
    """CVE ID 直查(GHSA ?cve_id=)。適合 'CVE-2025-55182' 這種精確查證。"""
    res = LookupResult(query=f"cve_id={cve_id}")
    if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_id.upper()):
        res.error = f"不是合法 CVE ID 格式: {cve_id!r}"
        return res
    try:
        data = _get_json(f"{GHSA_API}?cve_id={cve_id.upper()}")
    except Exception as e:  # noqa: BLE001
        res.error = f"GHSA 查詢失敗({e.__class__.__name__}): {e}"
        return res
    res.sources.append("ghsa")
    for a in data or []:
        sev = _sev_norm(a.get("severity"))
        if sev == "unknown":
            sev = _sev_norm((a.get("cvss") or {}).get("severity"))
        urls = _ref_urls(a.get("references"))
        vulns = a.get("vulnerabilities") or [{}]
        for v in vulns:
            pkg = v.get("package") or {}
            res.advisories.append(CveAdvisory(
                cve=a.get("cve_id") or cve_id.upper(),
                source="ghsa",
                severity=sev,
                summary=(a.get("summary") or "")[:300],
                product=pkg.get("name", ""),
                ecosystem=pkg.get("ecosystem", ""),
                vulnerable_range=v.get("vulnerable_version_range") or "",
                first_patched=v.get("first_patched_version"),
                published=(a.get("published_at") or "")[:10],
                urls=urls,
            ))
    res.latest_advisory_date = _latest_date(res.advisories)
    return res


def ghsa_product(product: str, ecosystem: str) -> LookupResult:
    """產品級查詢:該套件的全部已發布 advisory(不按版本過濾)。"""
    eco = ECOSYSTEM_ALIAS.get((ecosystem or "").lower(), (ecosystem or "").lower())
    res = LookupResult(query=f"affects={product}&ecosystem={eco}")
    try:
        data = _get_json(
            f"{GHSA_API}?affects={urllib.parse.quote(product, safe='')}"
            f"&ecosystem={eco}&per_page=50")
    except Exception as e:  # noqa: BLE001
        res.error = f"GHSA 產品查詢失敗({e.__class__.__name__}): {e}"
        return res
    res.sources.append("ghsa")
    for a in data or []:
        cve = a.get("cve_id") or ""
        vulns = a.get("vulnerabilities") or [{}]
        for v in vulns:
            pkg = v.get("package") or {}
            if pkg.get("name") and pkg.get("name").lower() != product.lower():
                continue
            res.advisories.append(CveAdvisory(
                cve=cve or a.get("ghsa_id", "?"),
                source="ghsa",
                severity=_sev_norm(a.get("severity")),
                summary=(a.get("summary") or "")[:300],
                product=pkg.get("name", product),
                ecosystem=eco,
                vulnerable_range=v.get("vulnerable_version_range") or "",
                first_patched=v.get("first_patched_version"),
                published=(a.get("published_at") or "")[:10],
                urls=_ref_urls(a.get("references")),
            ))
    res.latest_advisory_date = _latest_date(res.advisories)
    return res


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

def osv_query(package: str, ecosystem: str, version: str | None = None) -> LookupResult:
    """OSV 查詢:不帶 version = 該套件全部漏洞;帶 version = 精確命中。"""
    eco = ECOSYSTEM_ALIAS.get(ecosystem.lower(), ecosystem.lower())
    body: dict = {"package": {"name": package, "ecosystem": ecosystem_cap(eco)}}
    if version:
        body["version"] = version
    payload = json.dumps(body).encode()
    req = urllib.request.Request(OSV_API, data=payload, headers={
        "Content-Type": "application/json", "User-Agent": "tanli-cve-lookup"})
    res = LookupResult(query=f"osv {package}@{version or '*'} ({eco})")
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        res.error = f"OSV 查詢失敗({e.__class__.__name__}): {e}"
        return res
    res.sources.append("osv")
    for v in data.get("vulns", [])[:50]:
        aliases = v.get("aliases") or []
        cve = next((x for x in aliases if x.startswith("CVE-")), v.get("id", "?"))
        severities = [s.get("severity", "") for s in v.get("severity", []) if isinstance(s, dict)]
        sev = _sev_norm(severities[0] if severities else
                        (v.get("database_specific") or {}).get("severity"))
        rng = ""
        patched = None
        for aff in v.get("affected", []):
            for r_ in aff.get("ranges", []):
                for ev in r_.get("events", []):
                    if "introduced" in ev:
                        rng = f">= {ev['introduced']}"
                    if "fixed" in ev:
                        patched = ev["fixed"]
        res.advisories.append(CveAdvisory(
            cve=cve, source="osv", severity=sev,
            summary=(v.get("summary") or "")[:300],
            product=package, ecosystem=eco,
            vulnerable_range=rng, first_patched=patched,
            published=(v.get("published") or "")[:10],
            urls=_ref_urls(v.get("references")),
        ))
    res.latest_advisory_date = _latest_date(res.advisories)
    return res


def ecosystem_cap(eco: str) -> str:
    """OSV 生態系正名(首字母大寫慣例):pip→PyPI, npm→npm, composer→Packagist..."""
    caps = {"npm": "npm", "pip": "PyPI", "composer": "Packagist", "maven": "Maven",
            "go": "Go", "cargo": "crates.io", "rubygems": "RubyGems",
            "nuget": "NuGet", "hex": "Hex", "pub": "Pub"}
    return caps.get(eco, eco)


# ---------------------------------------------------------------------------
# NVD(涵蓋非套件生態:nginx/apache/wordpress/php/iis/openssl...)
# ---------------------------------------------------------------------------

def nvd_search(*, keyword: str | None = None, cve_id: str | None = None) -> LookupResult:
    """NVD 關鍵字/CVE ID 查詢。匿名額度極低(5 req/30s)——只給框架級直查用,
    結果如實標註資料源與時間;建議設 NVD_API_KEY。"""
    params: dict[str, str] = {}
    if cve_id:
        params["cveId"] = cve_id.upper()
    elif keyword:
        params["keywordSearch"] = keyword
        params["resultsPerPage"] = "30"
    else:
        res = LookupResult(query="nvd")
        res.error = "nvd_search 需要 keyword 或 cve_id"
        return res
    url = f"{NVD_API}?{urllib.parse.urlencode(params)}"
    headers = {}
    if key := os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = key
    res = LookupResult(query=f"nvd {'cveId=' + cve_id if cve_id else 'kw=' + (keyword or '')}")
    try:
        data = _get_json(url, headers=headers, timeout=30)
    except Exception as e:  # noqa: BLE001
        res.error = f"NVD 查詢失敗({e.__class__.__name__}): {e}"
        return res
    res.sources.append("nvd")
    for item in data.get("vulnerabilities", [])[:30]:
        c = item.get("cve", {})
        metrics = c.get("metrics", {})
        score_vec = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                     or metrics.get("cvssMetricV2") or [{}])[0]
        cvss = score_vec.get("cvssData", {}) if score_vec else {}
        sev = cvss.get("baseSeverity") or "unknown"
        desc = next((d.get("value", "") for d in c.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        res.advisories.append(CveAdvisory(
            cve=c.get("id", "?"), source="nvd", severity=_sev_norm(sev),
            summary=desc[:300],
            vulnerable_range="",  # NVD CPE 匹配不在本模組範圍,如實留空
            published=(c.get("published") or "")[:10],
            urls=_ref_urls(c.get("references")),
        ))
    res.latest_advisory_date = _latest_date(res.advisories)
    return res


# ---------------------------------------------------------------------------
# 統一入口
# ---------------------------------------------------------------------------

def lookup(*, cve_id: str | None = None, product: str | None = None,
           ecosystem: str | None = None, version: str | None = None) -> LookupResult:
    """Agent 工具 `cve_lookup` 的後端:
    - cve_id → 精確直查(GHSA + NVD 雙源交叉)
    - product(+ecosystem/version)→ 產品級全部 CVE(GHSA+OSV),
      無生態系的伺服器軟體(nginx 等)改走 NVD keyword。
    """
    if cve_id:
        g = ghsa_by_cve(cve_id)
        n = nvd_search(cve_id=cve_id)
        merged = LookupResult(query=g.query)
        merged.advisories = g.advisories + [a for a in (n.advisories if n.ok else [])]
        merged.sources = g.sources + (n.sources if n.ok else [])
        errs = [e for e in (g.error, n.error) if e]
        merged.error = "; ".join(errs) if not merged.sources else ""
        merged.latest_advisory_date = _latest_date(merged.advisories)
        return merged

    if not product:
        r = LookupResult(query="(empty)")
        r.error = "需要 cve_id 或 product"
        return r

    product = product.strip()
    if not ecosystem:
        eco_guess = _guess_ecosystem(product)
        ecosystem = eco_guess or ""

    if ecosystem:
        g = ghsa_product(product, ecosystem)
        o = osv_query(product, ecosystem, version)
        merged = LookupResult(query=g.query)
        seen: set[str] = set()
        for a in g.advisories + o.advisories:
            if a.cve in seen:
                continue
            seen.add(a.cve)
            merged.advisories.append(a)
        merged.sources = [s for s, r_ in (("ghsa", g), ("osv", o)) if r_.ok]
        errs = [e for e in (g.error, o.error) if e]
        merged.error = "; ".join(errs) if not merged.sources else ""
        merged.latest_advisory_date = _latest_date(merged.advisories)
        return merged

    # 無生態系 → NVD keyword 是唯一覆蓋面
    n = nvd_search(keyword=product)
    n.query = f"nvd-kw {product}"
    return n


def _guess_ecosystem(product: str) -> str | None:
    """依 FRAMEWORK_PACKAGES 或名稱形態猜生態系(不猜伺服器軟體)。"""
    key = product.lower()
    if key in FRAMEWORK_PACKAGES:
        eco = FRAMEWORK_PACKAGES[key][0]
        return eco or None
    if "/" in product:
        return "composer" if not re.match(r"^[a-z0-9._-]+\.[a-z0-9._-]+/", product) else "npm"
    return None


# ---------------------------------------------------------------------------
# 攻擊 likelihood 情報:EPSS + CISA KEV(借鑑 RedAmon vulnx 四源精神)
# ---------------------------------------------------------------------------
#
# EPSS (api.first.org): 未來 14 天被利用的機率(0~1)。區分「有 CVE」與
#   「真的會被拿起來打」— triage 排序的關鍵因子。
# CISA KEV (known_exploited_vulnerabilities.json): 已在真實世界被利用的
#   權威清單;命中 = 強制升級處置優先級。
# 兩者都是控制平面公開 GET(零靶點流量),失敗如實回報,不阻斷主查詢。

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


def epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """批次 EPSS 分數。回傳 {CVE: {score, percentile}};查不到/失敗不入典
    (呼叫端據缺漏如實標註,絕不臆測分數)。"""
    out: dict[str, dict] = {}
    ids = [c.upper() for c in cve_ids if re.match(r"^CVE-\d{4}-\d{4,7}$", c.upper())]
    if not ids:
        return out
    for i in range(0, len(ids), 25):  # API 批次上限保守切
        chunk = ids[i:i + 25]
        url = EPSS_API + "?cve=" + ",".join(chunk)
        try:
            data = _get_json(url, timeout=20)
        except Exception:  # noqa: BLE001 — EPSS 缺援不阻斷 CVE 查詢
            continue
        for row in data.get("data", []):
            cve = (row.get("cve") or "").upper()
            try:
                out[cve] = {"score": float(row.get("epss", 0.0)),
                            "percentile": float(row.get("percentile", 0.0))}
            except (TypeError, ValueError):
                continue
    return out


def kev_set(cache_path: str | Path | None = None,
            max_age_hours: int = 24) -> tuple[set[str], str]:
    """CISA KEV CVE 集合(帶 24h 本地快取,避免重複抓 1.3MB)。
    回傳 (set, status);status ∈ cached|fresh|stale-cache|unavailable。"""
    import time as _t
    cp = Path(cache_path) if cache_path else Path("state/kev_cache.json")
    if cp.exists():
        try:
            cached = json.loads(cp.read_text(encoding="utf-8"))
            if _t.time() - cached.get("_ts", 0) < max_age_hours * 3600:
                return set(cached.get("cves", [])), "cached"
        except (json.JSONDecodeError, OSError):
            pass
    try:
        data = _get_json(KEV_URL, timeout=30)
        cves = sorted({v.get("cveID", "").upper() for v in data.get("vulnerabilities", [])
                       if v.get("cveID")})
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text(json.dumps({"_ts": _t.time(), "cves": cves}), encoding="utf-8")
        return set(cves), "fresh"
    except Exception:  # noqa: BLE001
        if cp.exists():  # 網路掛但快取舊 → 如實標 stale 並沿用
            try:
                return set(json.loads(cp.read_text(encoding="utf-8")).get("cves", [])), \
                    "stale-cache"
            except (json.JSONDecodeError, OSError):
                pass
        return set(), "unavailable"


def enrich(advs: list[CveAdvisory]) -> dict:
    """對一批 advisories 補 EPSS/KEV 情報(就地寫入 a.summary 尾註記 +
    回傳摘要 dict 給 tool 層)。失敗如實標 status,不編造分數。"""
    cves = [a.cve for a in advs if re.match(r"^CVE-\d{4}-\d{4,7}$", a.cve or "", re.I)]
    kev, kev_status = kev_set()
    epss = epss_scores(sorted(set(cves)))
    hit_kev = 0
    for a in advs:
        c = (a.cve or "").upper()
        if c in kev:
            a.kev = True
            hit_kev += 1
        e = epss.get(c)
        if e:
            a.epss = e["score"]
            a.epss_percentile = e["percentile"]
    return {"epss_covered": len(epss), "epss_requested": len(set(cves)),
            "kev_status": kev_status, "kev_hits": hit_kev}
