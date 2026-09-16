从0.7.1到0.8.0的一些变化

二、真正的退步

1.  外部 fd 用不了了。 0.7.1 的 read_fid_events、FdReader::read、write_response 都是 public 且收 &OwnedFd，从父进程继承
    /SCM_RIGHTS 拿来的 group fd 可以自己驱动。0.8.0 把 read/write 收进 Fanotify（fd::read_*、response::write_response  
    都是 pub(crate)），而 Fanotify 只能 init/new 创建，没有 from_fd/From<OwnedFd>。最实在的一条能力损失。
2.  HandleCache 每次 get 多一次分配。 HashMap<Vec<u8>,_> 的 0.7.1 能用 &[u8] 直接查（Borrow），命中零分配；0.8.0 的键是
    元组，get 里 &(fsid, handle.to_vec()) 每次拷一份 handle 字节。cache 命中正是 resolver 的热路径，与"零分配"主张冲突  
    。（改成 HashMap<Fsid, HashMap<Vec<u8>, PathBuf>> 即可恢复借用查找。）
3.  unknown/malformed 记录的 payload 边界错了。 FidEvent::preserve 取 record_at+4 .. event_end，而 accessor 文档写的是"
    记录头之后的 record body"。我用 [未知类型 200][合法 FID 记录] 实测：unknown payload 是 34 字节（14 自己的 + 后面  
    FID 记录整 20 字节），0.7.1 的 preserve_unparsed 精确切 14 字节；循环还会继续把后面那条也解析成 typed 字段，同一段  
    字节出现两次。今天内核只定义 1–7/10/12，命中的只有"未来新类型"和畸形 buffer，不致命，但 crate 的卖点恰是"未来类型也
    保留"。附带注释 "verbatim, header included" 与代码（排除 4 字节 header）不符。
4.  fd 格式失去栈缓冲/零堆路径：0.7.1 默认 200 events 的 4800 字节 SmallVec 在栈上；0.8.0 统一走堆 Vec<u8>（稳态复用，  
    首次分配）。
5.  callback 读取被删（read_fd_events_do/read_do）——虽然原本就不是真流式。
6.  便利项：mark_mount、read_fid_events 自由函数没了（前者可用 flags 表达，后者被 Fanotify 取代）。

三、值得商榷 / 值得取舍

1.  borrowed 模型的代价：事件不能跨 read、跨线程存活，要保留就得 into_owned 复制。对"读一批 → 丢线程池"的架构，零拷贝收
    益归零，这时 0.7.1 的 owned 反而顺手。这是本次最大的取舍点。
2.  PathResolver<HandleCache> 默认无界：crate 说"不能替调用者猜上限"，但长期 daemon 默认就是无限增长  
    ；NoCache/forget/with_store 给了，默认值仍是内存泄漏形状。
3.  零 fsid 文件系统让 fsid 过滤失效：man page 明确 FUSE 等报 fsid=0；fsid_of_statfs 原样返回  
    (0,0)，wanted_filesystem((0,0),(0,0)) 判为匹配，于是两个 FUSE 文件系统之间 0.7.1 的"盲试开错文件"风险原样存在，整套
    fsid 正确性论证没提这个例外。
4.  name 为 "." 时路径带 /.：man page 说目录自身的 DFID_NAME name 是 "."；PathBuf::push(".") 得到  
    /srv/data/.，resolve_event 又按 self handle 存进 store，注释却称与单独解析该 handle "byte-identical"。Path 相等按  
    component（所以逻辑没坏），但 display() 会带 /.。name == "." 时直接返回目录路径即可。
5.  读路径没有 _into：parse_fid_events_into 能复用事件 Vec，但 Fanotify::read_events* 每次新建外层 Vec（每 read 一次  
    malloc）。
6.  resolve_handle 每次 miss 都 mounts.candidates().collect() 一个 Vec；resolve_events 返回值把 AlreadyResolved 也算进  
    去，看不出新解析了几个、几趟；EventStop/EventResolution/Pidfd 的 #[non_exhaustive] 对不在乎兼容性的人是纯 match 噪  
    音（但对内核表面类型是正确的）。
