# AGENTS.md

このリポジトリは、C++17 で実装された DNS フォワーダ `BEHIND` です。UDP/TCP の DNS 問い合わせを受け、静的 hosts、ローカルキャッシュ、ドメインフィルタ、上流 DNS 転送を組み合わせて応答します。

## 作業方針

- 既存の構成と実装スタイルを尊重し、不要な大規模リファクタリングは避ける。
- P0/P1 相当の安全性・正確性・フェイルセーフ修正を優先する。
- P2 以下の挙動変更や機能追加は、明示的に依頼されない限り行わない。
- `std::regex` は維持する。正規表現エンジンの置き換えは行わず、コンパイル時・実行時の `std::regex_error` を安全に扱う。
- DNSSEC 検証は不要。EDNS の DO bit や DNSSEC 検証機能を追加しない。
- ユーザー由来の未コミット変更を巻き戻さない。特に `scripts/` 配下にはユーザー変更が含まれている可能性がある。

## これまでの主な変更

- 設定解析を fail-closed 化した。
  - 未知の section/key、壊れた quote、余分な trailing text、制御文字/NUL、欠落 include、循環 include を拒否する。
  - エラーは file:line 付きで報告する。
  - include は通常ファイルのみ受け付け、FIFO や device による起動・reload のブロックを避ける。
- `--check-config` を追加し、設定、hosts、forwarder 解決を検証して終了できるようにした。
- startup と SIGHUP reload を厳格化した。
  - 起動時の検証失敗は非ゼロ終了にする。
  - SIGHUP は候補設定を非同期に検証し、成功した場合だけ旧 runtime を止めて切り替える。
  - reload 失敗時は直前の有効な設定、hosts snapshot、resolved forwarder を維持する。
- hosts 読み込みを厳格化した。
  - full-line comment と inline comment に対応した。
  - 不正な非空行は拒否する。
  - suffix 付き hosts 名や絶対名の正規化を修正した。
- forwarder hostname 解決を改善した。
  - `AF_UNSPEC` に対応し、検証済み endpoint snapshot を `Option` に保持する。
- client ACL と rate limit を追加した。
  - `allow-client` 未指定時は `127.0.0.0/8` と `::1/128` のみ許可する。
  - `allow-client` は repeatable。
  - per-client/global token bucket による rate limit を行う。
- resource limit を強化した。
  - `max-tasks`、FD 上限、cache bytes、cache entry size、task 数を検証する。
  - `max-tasks` の hard upper bound は `50000`。
  - 通常の `rlim_cur = 1024` 環境では、FD 安全計算により実効上限はおおむね `504`。
- UDP/TCP の正確性を改善した。
  - nonblocking TCP state machine、partial read/write、deadline、SIGPIPE 対策を入れた。
  - malformed/timeout/overload では適切な DNS エラーを返す。
  - UDP 上流応答は transaction id、QR/opcode、case-randomized question、qtype/qclass を検証する。
  - 不正または不一致の UDP 応答で、同じ問い合わせの正常な sibling 応答を潰さない。
  - 同一 UDP query の coalescing は 200 waiters に制限する。
- DNS codec と cache を堅牢化した。
  - unaligned type-punning load を避けた。
  - compression pointer の offset、backward pointer、jump 数、RDATA bounds を検証する。
  - 安全に再シリアライズできない compressed RDATA は cache しない。
  - response truncation は record boundary で行い、count を更新する。
  - cache は global LRU、entry size、total bytes を制限する。
  - TTL 0 は cache しない。
  - negative caching は SOA がある場合だけ行い、SOA TTL と SOA minimum の小さい方を使う。
- EDNS 処理を修正した。
  - 非 EDNS client には 512 byte UDP limit を使う。
  - EDNS client は advertised payload size と `edns0-buffer-size` の小さい方を使う。
  - unsupported EDNS version には BADVERS を返す。
  - 上流が EDNS に FORMERR/NOTIMP を返した場合、EDNS なしで retry する。

## 設定値の目安

- 家庭用途の `max-tasks` は `256` から `500` 程度が妥当。
- `rlim_cur = 1024` の一般的な環境では `max-tasks = 500` がほぼ上限に近い。
- README の設定例は、一般的な `rlim_cur = 1024` でも収まる `max-tasks = 500` としている。
- 外部 LAN に公開する場合は、必ず必要な CIDR を `allow-client` で明示する。

## 検証

変更後は、影響範囲に応じて以下を実行する。

```sh
make -j2
git diff --check
```

安全性や DNS 処理に触れた場合は、追加で以下の観点を確認する。

- `--check-config` の正常・異常系。
- invalid regex、unknown option、missing include、cyclic include、malformed quote。
- hosts file の comment、invalid entry、suffix、絶対名。
- UDP/TCP forwarding、timeout、ID mismatch、EDNS fallback、cache hit、TTL 0。
- ASan/UBSan build。sandbox により LeakSanitizer が使えない場合は、その制約を明記する。

## 触るときの注意

- `scripts/Makefile`、`scripts/behind.conf`、`scripts/nxdomain.conf`、`scripts/nxdomain.pl`、`scripts/hosts.lan`、`scripts/nxdomain.in` にはユーザー変更が存在する可能性がある。依頼がない限り変更しない。
- DNSSEC、forward-zone の longest-match など、P2 以下として残した領域は勝手に修正しない。
- `std::regex` の catastrophic backtracking そのものはライブラリ維持の制約上、根本対策していない。入力長、rule 数、例外処理で防御している。
- reload、shutdown、FD ownership、detached TCP client の扱いは壊れやすい。変更時は SIGHUP 中の失敗、paused listener、active task cleanup を確認する。
