# 上游回報：GLEIF-IT/vlei-verifier

| 項目 | 內容 |
|---|---|
| 目前狀態 | **未送出**（本輪不在 GitHub 做任何寫入）。內文已定稿、`<!-- -->` 註解全數清除，可直接貼上送出 |
| live 重現 | **已確認**（2026-09-24）。`1.0.0` 與 `0.1.5` 兩個 tag 依 issue-final.md「Steps to reproduce」逐步照跑，都在「No witness URL provided」分支崩潰、容器 `exited (exit 1)`。log 尾段已貼入 issue-final.md「Actual behaviour」 |
| 重現環境 | Docker Engine 28.0.4（Docker Desktop，Compose v2.34.0-desktop.1）、Windows 11。image digest：`gleif/vlei-verifier:1.0.0` = `sha256:a0cd3fb09a47c1d6def11c054aabb2be2436c6a89b7f597cdbd7415c059f85e5`；`gleif/vlei-verifier:0.1.5` = `sha256:9dbccc7d3601906931f625bb960af9a991aca88e4b81c07aed60fa8148ce0e4e` |
| 送出日期 | （送出後填入） |
| Issue 連結 | （送出後填入，格式 `https://github.com/GLEIF-IT/vlei-verifier/issues/<n>`） |
| 上游回應 | （送出後追蹤：維護者回覆、label、修正 PR、修正版 tag） |

## 檔案

- [`issue-final.md`](issue-final.md)：要送出的版本。第 1 行是標題，其餘是內文。內文裡的 `<!-- 需 live 重現確認 -->` 註解，確認完要刪掉。
- [`issue.md`](issue.md)：原始草稿，保留作對照。內容有錯，**不要送這份**（錯處見下方核對表）。
- [`patch-notes.md`](patch-notes.md)：修補構想。第 1 案只擋 `process_revocations_from_event_log`，不夠用：`_mark_as_revocation_check_failed` 也會拿 `None` 當 key，而且真正讓程序結束的是它。改用 issue-final.md「Suggested fix」的三案。

## 查重（2026-09-24，只做讀取）

- 用 `gh issue list --state all` 列出全部 issue（#2–#134），加上全部 PR（#1–#146）。
- 在 repo 內用 `gh search issues --include-prs` 查這些關鍵字：`NoneType`、`TypeError`、`process_revocations_from_event_log`、`revocation`、`revocationCheck`、`crash`、`koming`、`_tokey`、`unknown AID`、`observer`、`CRED_CRYPT_INVALID`、`_mark_as_revocation_check_failed`、`restart`、`sequence item 0`。另外在全 GitHub 與 GLEIF-IT 組織內也搜過。
- **結果：沒有人回報過同一個問題**，所以開新 issue，不是去舊 issue 下補充。
- 看起來相近、但其實不同的 issue：
  - [#66](https://github.com/GLEIF-IT/vlei-verifier/issues/66)（closed，2024-10）vlei-verifier service crash after successful singlesig-single-user workflow run during clear authorization on valid presentation：`Authorizer` 裡的 `JSONDecodeError`，已修。
  - [#134](https://github.com/GLEIF-IT/vlei-verifier/issues/134)（open）Environment mapsize limit reached：LMDB `MapFullError`。
  - [#132](https://github.com/GLEIF-IT/vlei-verifier/issues/132)（open）Implement Watcher Functionality for Revocations and Issuer Chain Validation：功能需求。
  - [#80](https://github.com/GLEIF-IT/vlei-verifier/issues/80)（open）There is a problem when calling the presentation interface：使用問題。
  - GLEIF-IT/sally#45：不同專案。

## 上游 main 修了嗎：**沒有**

- main HEAD 是 `5850051`（2026-08-20，PR #146），之後沒有新的 push。
- main 上的 `utils.py`、`observing.py`、`verifying.py`、`start.py`，和 1.0.0 image 內的檔案逐一比對，完全相同。
- 沒有 open PR，也沒有比 main 更新的分支。
- `tests/` 裡沒有任何測試涵蓋 observer。

## 核對結果

核對方法：從 Docker Hub registry 用唯讀 HTTP 下載 1.0.0、0.1.5 兩個 image 的 layer 並解出原始碼，沒有啟動任何容器。image 內 `.git/HEAD` 顯示，1.0.0 是 `e9d175b` 建的，0.1.5 是 `e16c64d` 建的。另外用 `gh api` 讀了 tag 1.0.0、0.1.5、0.1.3、0.1.4 與 main 的原始碼。

| 草稿內容 | 結果 |
|---|---|
| image 1.0.0 推送日 2026-06-29、0.1.5 推送日 2026-08-20 | 已確認 |
| Python 3.12、keripy 裝在 `/keripy/venv` | 已確認（3.12.3、keri 1.2.12、hio 0.6.14） |
| 函式名 `process_revocations_from_event_log`、路徑 `/usr/local/var/vlei-verifier/src/verifier/core/utils.py` | 已確認（editable install，所以路徑正確） |
| 「1.0.0 和 0.1.5 都在 `utils.py:133-143`」、traceback 寫 `line 143` | **不符（已修正）**：0.1.5 是 143；**1.0.0 和 main 是 241**（函式在 219–245）。1.0.0 的 133–143 行是另一個函式 `process_revocations`。草稿的 traceback 行號對的是 0.1.5，請回想當時跑的是哪個 tag |
| `koming.py` line 110 in `_tokey`、`TypeError: sequence item 0: expected str instance, NoneType found` | 已確認（1.0.0 與 0.1.5 內的 koming.py 都等於 keri 1.2.12） |
| 「例外沒被捕捉，所以程序結束」 | **不符（已修正）**：第一個 TypeError 其實被 `observing.py` 的 `except Exception` 接住了，但 handler 呼叫的 `_mark_as_revocation_check_failed` 又拿 `None` 當 key（1.0.0 在 L55、0.1.5 在 L45），第二個 TypeError 才讓程序結束。真正的 traceback 是兩段串接的 |
| 重現步驟：成功出示有效憑證 → 撤銷 → 等待 | **不符（已修正）**：成功出示時 SAID 底下會存 aid，走不到 None 分支。觸發條件是「該 SAID 底下存的是 `CRED_CRYPT_INVALID`（aid=None）狀態」。最終版改成一行 `PUT` 空 body 的最小重現 |
| observer「預設每 60 秒」 | **不符（已修正）**：建構時沒傳 `interval`，預設是 **5 秒**（docstring 寫 60，但程式碼是 5.0） |
| 設定檔路徑 `scripts/keri/cf/verifier-config-public.json` | **不符（已修正）**：這是上游 repo 與容器內的路徑，本 repo 裡實際在 `scripts/verifier-config/`。最終版改成把設定 JSON 直接貼進 issue，再用 `docker run -v` 掛載，不需要 clone mcp-vlei |
| `revocationCheck` 只能從設定檔開、沒有環境變數、出廠是關的 | 已確認（`start.py:179`；image 內所有設定檔都是 false 或沒有這個 key） |
| 設定檔必須可寫入掛載 | 已確認（Configer 用 `r+b` 開檔，失敗時 hio 會改用另一個路徑） |
| `CRED_CRYPT_INVALID` 狀態沒有 aid，而且是唯一來源 | 已確認（`verifying.py:466-479`；另一處 `AUTH_PENDING` 建構完還沒 pin 就被覆蓋，不算） |
| 重啟後 DB 清空，回 `unknown AID` | 程式碼路徑已確認：hby、reger、vdb 都是 `temp=True`；`GET /authorizations/{aid}` 回 401 `unknown AID: …`。實際行為需 live 重現確認 |
| 「Docker Desktop 28.0.4」 | **不符（已修正）**：Docker Desktop 版本是 4.40.0，28.0.4 是 Engine 版本 |
| `POST /root_of_trust` 回 202、`POST /oobi` 回 202、`PUT /presentations` 成功回 202 | 已確認（程式碼） |
| 替代做法 `GET {witness}/query?typ=tel&vcid={said}` | 已確認（本機 server.log 有這筆請求） |

## live 重現結果（2026-09-24）

在乾淨環境照 issue-final.md「Steps to reproduce」實跑。用自己的容器名與不衝突的 host 埠（`upstream-repro-verifier-100` → `-p 17676:7676`；`upstream-repro-verifier-015` → `-p 18080:7676`），沒有動到現有的 `mcp-vlei-*`、`mcp-vlei-regulator-*`、`agentpassport-*`、`ragflow-*` 等容器。掛載的設定檔就是 issue 內嵌那份最小 config（`iurls/durls` 皆空），放在暫存區，不是本 repo 的 `scripts/verifier-config/`（那份有 OOBI）。跑完兩個容器都已 `docker rm`，未建立自訂網路，`mcp-vlei-verifier` 仍在 7676 正常運作。

**兩個 tag 都重現，行為一致：**

1. [x] `PUT` 空 body → **400**（`did not cryptographically verify`）。
2. [x] observer 下一次 tick（實測約 0.6 秒後就觸發，非等滿 5 秒）走「No witness URL provided」分支 → `_mark_as_revocation_check_failed` → `iss.get(keys=(None,))` → koming `_tokey` `TypeError: sequence item 0: expected str instance, NoneType found`，容器 `exited (exit 1)`。
3. [x] log 尾段（去掉 3.12 caret 行）已貼進 issue-final.md「Actual behaviour」。
   - `1.0.0`：`observing.py:44 → :110 → :55 → koming.py:329 → koming.py:110`。
   - `0.1.5`：同樣路徑，只有 `observing.py` 行號不同（`recur` 34、`_check_revocations` 88、`_mark_as_revocation_check_failed` 45）。issue 內文已如實區分兩個 tag 的行號。
4. [x] issue-final.md 內所有 `<!-- … -->` 註解已清除；第 1 行是 Title、其餘是內文。

5. [x] （選做，已加做）加上 `?witness_url=http://127.0.0.1:9`（無人聆聽）再跑 1.0.0：`requests.get` 在 `observing.py:81` 拋 `ConnectionError` → 被 `observing.py:101` 分支接住 → 呼叫 `_mark_as_revocation_check_failed`（`observing.py:55`）→ 同樣的 `koming.py:329/110` `TypeError`。這是一段 **"During handling of the above exception, another exception occurred"** 的串接 traceback，容器一樣 `exit 1`。issue-final.md line 「Adding `?witness_url=…`… ends in the same place」的敘述已由 live log 佐證。

**上面 1–4 是「最小重現」路徑（空 body → No witness URL 分支），只有單段 traceback**，直接由 `_mark_as_revocation_check_failed` 拋出、逸出 `recur()`。issue 另外描述的**完整「撤銷路徑」**（witness 回 `rev` 事件 → `process_revocations_from_event_log` 在 `utils.py:241` 先炸、被 `except` 接住、handler 再炸出第二段）本輪**未實跑**，因為需要完整 witness＋憑證環境並在 witness 的 TEL 上放 `rev` 事件；那段仍是靜態分析，issue 內文措辭維持「we first ran into this」的回述語氣。不過第 5 點的 witness_url 實測，已 live 證實「第一段例外被接住 → handler 再炸第二段 TypeError → process 結束」這個雙段串接機制本身成立。

未做（皆需完整環境，非送出必要條件）：

- 完整環境重跑「撤銷」路徑、確認第一段是 `utils.py:241` 的 `Komer.pin` TypeError（而非 requests 的 ConnectionError）：未實跑。機制已由 witness_url 版佐證。
- 「clients saw only connection errors」「restart 後回 unknown AID」兩句：屬你們當時的現場回述，本輪未重建該情境（需先授權一個 holder）。最小重現已證實「process 崩潰結束」這個根因；`temp=True` → 重啟 DB 清空 → `unknown AID` 仍為靜態確認。
- 送出後回來填上方表格的「送出日期」「Issue 連結」，並把狀態改成「已送出」。

**建議：可以送出。** 兩個 tag 的 live traceback 與內文所述完全一致，最小重現只需公開 image、一行 `PUT`，不需 clone 本 repo，上游可直接照跑。（是否先私下聯絡 GLEIF 走漏洞揭露流程，見下方「資安考量」。）

## 資安考量（送出前請決定）

依靜態分析，`CRED_CRYPT_INVALID` 狀態是在 signed-header 檢查**之前**寫入的（`verifying.py:466-479` 在 `:489` 之前），所以 production 模式也擋不住。換句話說，只要部署有開 `revocationCheck`，任何人不需要任何憑證，發一個未認證的請求就能讓 verifier 當機（DoS）。

上游 repo 沒有 SECURITY.md，GitHub 的 private vulnerability reporting 也沒開（`enabled: false`）。好在出廠預設 `revocationCheck: false`，受影響的範圍有限。要公開送出，還是先私下聯繫 GLEIF 維護者，由你決定；最終版內文沒有特別強調 production 模式這一點。

## 本 repo 其他地方的同類錯誤（本次沒改，只記錄）

- `scripts/bootstrap-credentials.sh` 的 Check 6 註解與錯誤訊息寫「60-second interval」，實際是 5 秒。
- `scripts/docker-compose.yml` 第 75–78 行的敘述大致正確，但沒提到 `_mark_as_revocation_check_failed` 這個第二現場。
