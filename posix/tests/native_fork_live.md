# マルチスレッド fork / exec のネイティブ試験

`native_fork_live.c` は mochiOS 向けに最新の newlib runtime とリンクして
実行します。ホストでの実行では COW、Handle 継承、ネイティブスレッドの
待機状態を検証できません。SDK の再生成は必要ありません。

引数なしでは次の全条件を実行します。各オプションを指定すると、その条件だけを
実行します。サービス起動時の logger 引数は条件指定として扱いません。

| オプション | 別スレッドの待機処理 |
| --- | --- |
| `--pipe` | pipe の read |
| `--socket` | socketpair の recv |
| `--socket-read` | socketpair の read |
| `--readv` | pipe の readv |
| `--socket-readv` | socketpair の readv |
| `--poll` | pipe の poll |
| `--select` | pipe の select |
| `--socket-poll` | socketpair の poll |
| `--socket-select` | socketpair の select |

各条件で実際のネイティブスレッド待機状態を確認してから、3 回 fork します。
子は継承した pipe に書き込み、自分のイメージを exec して正常終了します。
実行パスには初期スタックの `AT_EXECFN` を使います。`argv[0]` は表示名でも
よいため、実行パスとして扱いません。

別スレッドの newlib キャッシュには意図的に無効なポインタを置き、子がその
キャッシュを解放したり、親の TLS デストラクタを実行したりしないことを確認します。
親では待機を解除して join し、cleanup と TLS デストラクタが各 1 回実行される
ことを確認します。成功時は各条件の `PASS` と最後の
`fork-live: PASS all nine I/O wait modes` が出ます。

KVM 検証では、既存の Compositor 用サービス枠を一時的に使用できます。
マニフェストの権限は変更せず、試験後は元のサービスを復元します。
起動待ちを長くした検証用 manager を使った場合、その結果を通常起動や
デスクトップ表示の成功として扱ってはいけません。

この試験だけでは、任意の libc 操作中の fork、ファイル offset の共有、
exec 後の FD 維持・CLOEXEC、完全な POSIX 適合性は証明できません。
