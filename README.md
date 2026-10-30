# iptables-tui

用 Go 编写的 iptables 终端界面，**只依赖标准库**（无任何第三方模块，静态链接的单个二进制）。

## 功能

- 浏览 filter / nat / mangle / raw / security 各表的链和规则，显示包/字节计数、策略、引用关系
- IPv4（`iptables`）与 IPv6（`ip6tables`）：
  - `-6` 以 IPv6 启动；运行中按 `6` 或点击表标签行左侧的 IPv4/IPv6 切换，两边的光标位置各自保留；
  - 支持 legacy / nft 后端：`-iptables iptables-legacy` 时 IPv6 自动使用 `ip6tables-legacy`，不会混用；
  - 模板会自动使用对应协议族的地址和 ICMP 类型；IPv6 另有"放行 ICMPv6"（邻居发现依赖它）和"DHCPv6 客户端"模板；
  - 在 IPv6 规则里填了 IPv4 地址（或反过来），表单会立即提示，而不是等 ip6tables 报 "host/network not found"。
- watch 模式：定时自动刷新，`+pkts` 列显示两次刷新之间新增的包数并高亮
- 添加规则：
  - **简单模式**：模板（放行端口、放行 established、TCPMSS clamp-to-PMTU、端口转发 DNAT、MASQUERADE、限速、日志……按表过滤，有链限制的模板会提示可用的链）+ 表单字段，实时预览生成的命令
  - **高级模式**：直接写 iptables 参数（F2 切换，简单模式的结果会带过去）；可直接粘贴 `iptables-save` 行（`-A CHAIN ...`）
  - 可选择以 **disabled** 状态添加（默认 enabled）
  - iptables 报错时对话框会带着错误信息重新打开，内容不丢
- 复制粘贴：
  - `y` 复制当前规则，`Y` 复制当前链中显示的所有规则（配合 `/` 过滤可只复制匹配的部分）；
  - `p` 粘贴到光标下方，在链面板时追加到链尾；可在 IPv4/IPv6 各自内部粘贴，也可以跨协议族粘贴；
  - 跨协议族时自动转换 ICMP（`-p icmp`↔`ipv6-icmp`、`--icmp-type 8`↔`--icmpv6-type 128` 等常见类型）、REJECT 的 `--reject-with`、TTL↔HL，并逐条列出改动；
  - 地址（`-s`/`-d`/NAT 目标）、`-f`、`-m frag` 等仅单一协议族有的选项，以及跳转到目标表中不存在的链，都会明确列出，需要手工修正；
  - 粘贴单条规则时打开预填好的添加对话框，可修改后再提交；多条规则在确认框中逐条列出，并通过一次 `iptables-restore` 事务原子插入；
  - 已禁用的规则粘贴后仍是禁用状态（生成新的存储项）。剪贴板只在内存中，不持久化。
- NFLOG：
  - 各表的 target 可选 NFLOG，"Log via NFLOG" 模板默认使用 group 100（`-nflog-group` 可改），规则列表显示为 `NFLOG:100`；
  - `n` 打开数据包监视器：程序自己通过 netlink 接收该 group 的数据包（只用标准库），解析 IPv4/IPv6（含扩展头）和 TCP/UDP/ICMP，显示时间、接口、协议、地址端口、标志、前缀；
  - group 已被 ulogd 等占用时给出明确提示；内核缓冲区溢出时计数显示丢包；
  - 可暂停、过滤、查看详情（含十六进制），`W` 导出为 pcap 文件，可用 Wireshark/tcpdump 打开。
- TRACE：
  - raw 表可选 TRACE，"Trace packets" 模板；
  - `T` 打开追踪监视器，显示每个被追踪的包依次经过哪些表/链、每一步的结果和匹配的规则，以及最终结果；
  - nft 后端通过 `xtables-monitor --trace` 获取，legacy 后端读取内核日志 `/dev/kmsg`；
  - TRACE 开销较大，匹配条件尽量窄，用完记得删除。
- 监视器在后台持续运行，返回规则界面后标签行会显示计数；退出程序时自动停止（包括结束 xtables-monitor 进程）。
- 编辑、删除、上下移动、移动到指定位置（移动通过 `iptables-restore --noflush` 原子完成，保留计数器）
- **临时禁用 / 启用规则**（见下文）
- 过滤（`/`，当前面板实时过滤，多个词须同时匹配）和全局搜索（`s`，跨所有表和链，含已禁用规则的原始内容，回车跳转）
- 链操作：新建、重命名、删除、清空、设置策略、清零计数
- 回车跟随跳转到目标链，Backspace 返回
- 命令日志（`L`）；`W` 将规则集（iptables-save 格式）写入文件：
  - 路径由用户输入，默认为当前目录下的 `rules.v4` / `rules.v6`；
  - 目标文件已存在时，会红字警告并显示其大小和修改时间，确认后才覆盖。
- 修改前二次确认：添加、编辑、删除规则（以及删链、清空、改策略、覆盖文件等）都会弹出确认框，内容包括：
  - 将要发生的变化（编辑时显示新旧规则对比、状态变化、计数器是否重置）；
  - 将要执行的完整命令；
  - 只有按 `y` 或点击 Yes 才会执行；添加/编辑时选否会回到表单，已填内容保留。
- 鼠标支持：
  - 点击切换表/链/规则，双击打开链、跳转或查看详情，滚轮滚动；
  - 底部按键提示、对话框按钮、标题栏的 WATCH/IPv4 都可点击；
  - `M` 开关鼠标，或用 `-no-mouse` 启动时关闭。开启时选择终端文字需按住 Shift。

## 构建与运行

```sh
make                           # 构建并显示版本号
sudo ./iptables-tui            # 需要 root（CAP_NET_ADMIN）
sudo ./iptables-tui -6 -t nat -w -i 1s
```

版本号来自 git：
- `make` 用 `git describe --tags --always --dirty` 写入版本，例如：
  - 打了 tag 的提交：`v0.0.1`
  - tag 之后的提交：`v0.0.1-3-gabc1234`
  - 有未提交修改：带 `-dirty` 后缀
- 直接 `go build` 时，使用 Go 自动记录的 tag 或 commit。
- 程序标题栏、帮助页和 `-version` 都会显示版本号。

| 参数 | 说明 |
|---|---|
| `-6` | 以 IPv6 模式启动 |
| `-t TABLE` | 初始表（默认 filter） |
| `-w` / `-i 1s` | 启动即进入 watch 模式 / 刷新间隔（默认 1 秒） |
| `-iptables NAME` / `-ip6tables NAME` | 使用的命令，`-save`/`-restore` 由此派生，如 `iptables-legacy`；`-ip6tables` 默认由 `-iptables` 推导 |
| `-state PATH` | 禁用规则存储文件（默认 `/var/lib/iptables-tui/disabled.json`） |
| `-no-mouse` | 不启用鼠标（运行中可按 `M` 切换） |
| `-nflog-group N` | NFLOG 模板和监视器默认使用的 group（默认 100） |
| `-version` | 显示版本号 |

## 按键

界面内按 `?` 查看完整帮助。

| 按键 | 作用 |
|---|---|
| `↑↓ j k` `PgUp PgDn` `g G` | 移动光标 |
| `Tab` `←→ h l` | 切换链 / 规则面板 |
| `1`-`5` `[` `]` | 切换表 |
| `6` | 切换 IPv4（iptables）/ IPv6（ip6tables） |
| `Enter` / `Backspace` | 打开链、跳转到目标链或查看规则详情 / 返回 |
| `/` `s` | 过滤当前面板 / 全局搜索 |
| `w` `+` `-` `r` `x` | watch 开关、刷新间隔、立即刷新、精确计数 |
| `a` `i` `o` | 追加 / 在光标上方插入 / 在光标下方插入规则 |
| `e` `d` `Space` | 编辑、删除、禁用/启用规则 |
| `K` `J`（`Shift+↑↓`）`m` | 上移 / 下移 / 移动到指定位置 |
| `y` `Y` `p` | 复制规则 / 复制链中显示的所有规则 / 粘贴 |
| `N` `R` `X` `F` `P` `Z` | 新建、重命名、删除、清空链，设置策略，清零计数 |
| `D` `L` `W` | 已禁用规则列表、命令日志、保存规则集到文件 |
| `M` | 开关鼠标 |
| `n` / `T` | NFLOG 数据包监视器 / TRACE 追踪监视器（监视器内：Space 暂停、Enter 详情、`/` 过滤、`c` 清空、`x` 停止、`W` 导出 pcap、Tab 切换、Esc 返回） |
| `q` | 退出 |

## 禁用规则的实现

iptables 本身没有"禁用"开关，本程序这样实现：

1. 生成一个随机 ID，把原规则（参数 + 计数器）写入状态文件 `disabled.json`（flock 加锁 + 原子替换）；
2. 用 `iptables -R` 把原位置的规则替换为占位规则
   `-m comment --comment iptui-disabled-<id>`。它没有 target，对数据包没有任何影响，只负责占住位置；
3. 启用时按 ID 取回原规则、连同当时的计数器原位替换回去，并删除存储项。

因此 comment 里只有一个 ID。其他说明：
- 以 disabled 状态添加或编辑规则时，会先用 `iptables -C` 校验语法（退出码 2 表示参数错误）；
- 链被清空或删除时，相关的存储项会一并清理；
- `D` 列表会显示"孤儿"存储项，即占位规则已经不在链里的那些（例如被别的工具删除，或重启后没有恢复）。孤儿项可以重新追加（`a`）或丢弃（`x`）；
- 如果占位规则对应的存储项丢失，规则会以红色显示，只能删除。

**注意**：用 `W`/`iptables-save` 持久化的规则集中包含占位规则，需要同时保留状态文件，否则无法恢复。

## 安全措施

- 每次修改前都会重新读取该表，确认光标所指位置上仍是同一条规则；否则拒绝执行并刷新。这样可以避免 docker、fail2ban 等工具同时修改规则时删错或改错；
- 添加、编辑、删除规则以及删链、清空、改策略、覆盖文件前，都会弹窗显示具体变化和将执行的命令，确认后才执行。点击对话框外部不会被当作确认；
- 没有任何匹配条件的 ACCEPT/DROP/REJECT 规则，确认框里会额外显示红色警告，防止误操作把自己锁在外面；
- 不经过 shell，参数直接以 argv 传给 iptables；
- 所有修改**立即生效但不持久化**。需要时用 `W` 导出；若要开机自动加载，可写到 `/etc/iptables/rules.v4` 等由开机服务读取的路径。禁用/启用（Space）和移动（K/J）不弹确认框，通过 ssh 操作 INPUT 链时请留意。

## 无 root 测试

可以在非特权的 user+net namespace 中测试，不会影响本机规则：

```sh
unshare -rn sh -c 'PATH=/usr/sbin:$PATH; iptables -A INPUT -p tcp --dport 22 -j ACCEPT; ./iptables-tui -state /tmp/state.json'
```

（legacy 后端在这种环境下无法读取 `/proc/net/ip_tables_names`，需要真实 root。）

## 代码结构

| 文件 | 内容 |
|---|---|
| `term_linux.go` `keys.go` | termios 原始模式、窗口大小、按键/鼠标转义序列解析 |
| `screen.go` `lineedit.go` | 双缓冲单元格渲染（按行 diff、CJK 宽字符）、单行编辑器 |
| `iptables.go` | 调用 iptables、解析 `iptables-save -c`、参数切分与引号 |
| `store.go` `ops.go` | 禁用规则存储、带校验的各项修改操作 |
| `form.go` | 添加/编辑对话框（模板、简单/高级模式） |
| `clipboard.go` | 复制粘贴、IPv4/IPv6 规则转换 |
| `nflog.go` | NFLOG netlink 接收、IPv4/IPv6/TCP/UDP/ICMP 解析 |
| `trace.go` | TRACE 输出解析（xtables-monitor / 内核日志）、pcap 导出 |
| `monitor.go` | NFLOG/TRACE 监视器界面 |
| `app.go` `view.go` | 事件循环、后台 worker、按键处理与界面绘制 |

## License

[MIT](LICENSE)
