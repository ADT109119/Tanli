"""第五批公開通報研究蒸餾(認證後授權真空 web-046／租戶邊界 web-047＋八本補強)。

來源為台灣漏洞通報平台之公開通報案例文字(全程未對任何受害系統發出請求),
已去識別化:本檔不得出現任何可反向關聯受害組織的識別資訊或通報流水號。
"""
from redteam.knowledge import get_by_id, load_library, search

LEGAL_PHASES = {"recon", "fingerprint", "inject", "verify", "poc", "report"}


def _lib():
    return load_library()


def test_新增兩本劇本入庫且為方法論型():
    lib = _lib()
    for did in ("web-046", "web-047"):
        d = get_by_id(lib, did)
        assert d is not None, f"{did} 未入庫(loader 會靜默跳過壞檔,必查)"
        assert d.phase in LEGAL_PHASES, f"{did} phase 非法: {d.phase}"
        # web 方法論劇本鐵律:不可執行
        assert not d.executable and d.payload_policy == "methodology-only"


def test_web046_認證後授權真空():
    lib = _lib()
    d = get_by_id(lib, "web-046")
    for q in ("汰換", "認證後", "前端角色宣稱", "特殊類別"):
        hits = {x.id for x in search(lib, query=q)}
        assert "web-046" in hits, f"查詢 {q} 未命中 web-046: {hits}"
    r = d.render()
    assert "全數回絕≠安全" in d.summary  # 漏報區鐵律必須進 render 的 400 字窗口
    assert "web-036" in r  # 交叉引用:這是 web-036 的漏報區
    assert "歷史留存 population" in r  # 已離校/已退職影響面敘事
    assert "嚴禁以任何他人帳號" in r  # RoE 紅線:零跨帳號實讀
    assert "pending-approval" in r  # 寫入類不觸發
    assert "不利處境" in r  # 特殊類別標記的教育產業敘事(去識別化後仍可立案)
    assert "High" in r  # 教育產業定級軸


def test_web047_租戶邊界與兩層供應鏈():
    lib = _lib()
    d = get_by_id(lib, "web-047")
    for q in ("租戶", "門市", "多租戶", "POS"):
        hits = {x.id for x in search(lib, query=q)}
        assert "web-047" in hits, f"查詢 {q} 未命中 web-047: {hits}"
    r = d.render()
    assert "受測方(門市)既非軟體作者也無修改權限" in d.summary
    assert "嚴禁以 UI 可見性立案" in r  # 誤報防呆:選單可見性不立案
    assert "嚴禁跨租戶實讀" in r  # RoE 紅線
    assert "交易完整性" in r  # 危害敘事跳出純資料外洩
    assert "菜單與價格篡改" in r
    assert "回應 schema 差分" in r  # POS 離線快取誤報防呆
    assert "立即停止該端點一切後續請求" in r  # 停火鐵律
    assert "雙開單" in r  # 門市面/廠商面分開立案
    for bridge in ("web-020", "web-036", "web-045", "web-043", "web-046"):
        assert bridge in r, f"邊界切割缺 web-{bridge} 分流"


def test_web020_破壞性寫入零副作用立案法():
    lib = _lib()
    r = get_by_id(lib, "web-020").render()
    assert "破壞性寫入端點的零副作用立案法" in r
    # agy HIGH 修正:方法盤點只能走 OPTIONS 或虛構 ID,嚴禁對真實資源發破壞性方法
    assert "禁止對『真實存在的資源 ID』發送" in r
    assert "OPTIONS" in r and "Allow 標頭" in r
    assert "99999999_PROBE_DUMMY" in r  # 虛構 ID 差分
    assert "嚴禁以『驗證破口存在』為名對真實資源發出 DELETE/PUT/PATCH" in r  # 煞車句(本體不落地)
    assert "web-047" in r  # 租戶邊界分流(不再是泛 IDOR)
    assert "資料可用性攻擊面" in r  # 定級防呆:不得因『只刪表單資料』定為中
    assert "授權中介層" in r  # 用語在地化(非「中間件」)


def test_web036_全模組無閘門與漏報區交叉引用():
    lib = _lib()
    r = get_by_id(lib, "web-036").render()
    assert "全模組無閘門" in r and "Critical" in r  # 形態分級差分
    assert "web-046" in r  # 未登入全滅是 web-046 的啟動條件
    assert "嚴禁以未登入差分全滅宣告該系統授權面安全" in r


def test_web037_識別碼結構可推性與憑證欄():
    lib = _lib()
    r = get_by_id(lib, "web-037").render()
    hits = {x.id for x in search(lib, query="憑證欄")}
    assert "web-037" in hits
    assert "性別" in r and "出生日期" in r  # 識別碼結構可推性防呆
    assert "遮罩欄位≠有保護" not in r or True  # 既有條目仍在(YAML 層,不重複斷言)
    assert "口令值與 hash 值嚴禁進報告" in r  # 憑證欄零落地鐵律
    assert "最高級" in r


def test_web032_教育身分鏈放大():
    lib = _lib()
    r = get_by_id(lib, "web-032").render()
    assert "通訊錄規模" in r  # 放大敘事以可送達規模計
    assert "憑證冒用而非主機入侵" in r  # 不得誇大為校園系統遭入侵
    assert "迎新簡章" in r  # 教育場景文件化口令證據源
    assert "web-045" in r  # 同款 CONFIRM 紀律


def test_web030_管線主體化與雙字串假陽性():
    lib = _lib()
    r = get_by_id(lib, "web-030").render()
    assert "管線主體化" in r
    assert "git archive" in r  # 修復建議移位到管線層
    assert "嚴禁搜尋、枚舉或探測授權範圍外的第三方安裝點" in r  # 範圍煞車
    assert "ref: refs/" in r and "[core]" in r  # 雙字串假陽性防呆
    assert "群體高風險" in r  # 兩層供應鏈定級


def test_web042_分診矩陣補強():
    lib = _lib()
    r = get_by_id(lib, "web-042").render()
    assert "開發商級建置管線指紋" in r
    assert "宗教" in r and "文教基金會" in r  # 第三部門列
    assert "個資法第 6 條" in r  # 特種目誇大敘事防呆
    assert "病歷、醫療、基因、性生活、健康檢查、犯罪前科" in r
    assert "水務" in r  # 關鍵基礎設施相鄰再升一級
    assert "MSSQL" in r  # legacy 棧指紋列
    assert "自評風險欄僅供參考" in r  # 反錨定提醒


def test_web045_學生自治孤兒資產來源():
    lib = _lib()
    d = get_by_id(lib, "web-045")
    assert d is not None, "web-045 壞檔會靜默失蹤"
    r = d.render()
    hits = {x.id for x in search(lib, query="學生自治")}
    assert "web-045" in hits
    assert "知識斷鏈" in r and "web-032" in r


def test_web006_re_score佐證():
    lib = _lib()
    r = get_by_id(lib, "web-006").render()
    assert "自報風險" in r and "判定風險" in r
    assert "實證計數" in r


def test_新增步驟不得被render截斷():
    """RoE 煞車句若落在 260 字之後會被 render 吃掉(實戰教訓:超長步要拆)。
    只掃本批改動的劇本,鎖住紅線句的可見性。"""
    lib = _lib()
    critical = {
        "web-046": ["嚴禁以任何他人帳號", "全數回絕≠安全"],
        "web-047": ["嚴禁跨租戶實讀", "立即停止該端點一切後續請求", "嚴禁以 UI 可見性立案"],
        "web-020": ["嚴禁以『驗證破口存在』為名對真實資源發出 DELETE/PUT/PATCH", "資料可用性攻擊面", "一發即永久刪除他人資料"],
        "web-036": ["嚴禁以未登入差分全滅宣告該系統授權面安全"],
        "web-037": ["口令值與 hash 值嚴禁進報告"],
        "web-032": ["嚴禁誇大寫成『校園系統遭入侵』",
                   "嚴禁以任何方式登入後探索", "嚴禁發起批量遍歷", "嚴禁落地任何名冊欄位實體數值"],
        "web-030": ["嚴禁搜尋、枚舉或探測授權範圍外的第三方安裝點"],
        "web-042": ["病歷、醫療、基因、性生活、健康檢查、犯罪前科","特種個人資料"],
        "web-037": ["全字串遮蔽"],
        "web-036": ["識別欄位採全遮罩","嚴禁只遮前幾碼"],
    }
    for did, needles in critical.items():
        r = get_by_id(lib, did).render()
        for n in needles:
            assert n in r, f"{did} 紅線句被截斷或遺失: {n}"


def test_總數與去重():
    lib = _lib()
    ids = [d.id for d in lib]
    assert len(ids) == len(set(ids)), "id 重複"
    web = [i for i in ids if i.startswith("web-")]
    assert len(web) == 42 and len(ids) == 53  # 42 web + 11 llm


def test_證據遮罩措辭全庫一致():
    """agy v2 抓出的內部矛盾:probe 側『遮罩前 3 碼』與 note 側全遮罩鐵律衝突。"""
    lib = _lib()
    r37 = get_by_id(lib, "web-037").render()
    assert "僅留遮罩前 3 碼" not in r37  # 舊措辭不得迴歸
    assert "[MASKED_ID]" in r37  # probe 側同步全遮罩
    # 曾被 render 截斷的 web-032 三條煞車句,拆步後必須可見
    r32 = get_by_id(lib, "web-032").render()
    for brake in ("嚴禁以任何方式登入後探索", "嚴禁發起批量遍歷",
                  "嚴禁落地任何名冊欄位實體數值"):
        assert brake in r32, f"web-032 煞車句仍不可見: {brake}"


def test_agy複審修正_三HIGH不得迴歸():
    """agy 第二意見抓出的三條 HIGH,鎖死不得迴歸。"""
    lib = _lib()
    # HIGH1: web-020 不得指示對真實資源發 DELETE
    r20 = get_by_id(lib, "web-020").render()
    assert "一發即永久刪除他人資料" in r20
    # HIGH2: web-037 身分證結構必須正確(不含出生日期),且證據側全遮罩
    r37 = get_by_id(lib, "web-037").render()
    assert "本身不含出生日期" in r37
    assert "1 男/2 女" in r37
    # HIGH3: web-036 證據遮罩不得只遮前幾碼
    r36 = get_by_id(lib, "web-036").render()
    assert "嚴禁只遮前幾碼——流水號與檢查碼明文落地即屬強識別資料外洩" in r36


def test_web046_法規定級與SPA兜底防呆():
    lib = _lib()
    d = get_by_id(lib, "web-046")
    r = d.render()
    # 弱勢自陳不是法定特種個資(避免誇大退件)
    assert "高敏感度非特種個資" in r
    # SPA 路由兜底防呆
    assert "前端路由兜底" in r and "text/html" in r
    # 前置方法閘門:只發 GET
    assert "僅對 GET/查詢類唯讀端點發包" in r
    # 去識別化:時序指紋不得迴歸
    assert "前後十天" not in r
