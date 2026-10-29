import Foundation

// MARK: - Which archive formats does the Calendar unzip path actually register?
//
// The open question behind CVE-2026-112619. On 27.0 CalendarFoundation ships `_UnzipArchive`
// with no containment at all, and the harness can already prove two neighbouring facts: that
// libarchive itself accepts a `../` entry name, and that it accepts an ISO9660/Joliet image
// with the 1024-byte pathname chain (arc.iso). What is missing is the join — whether the
// attachment bytes reach libarchive through `archive_read_support_format_all` (format is
// sniffed from the bytes, so an attacker can make the attachment an ISO and reach
// build_pathname_utf16be) or through a ZIP-only registration (the Joliet site is unreachable
// on that delivery path whatever the attachment is called).
//
// A sandboxed app cannot call `_UnzipArchive`, but it can read the framework binary and report
// which libarchive entry points that binary references. This module does exactly that, twice
// over: once through LC_SYMTAB's undefined symbols (precise, but empty when the table is a
// dyld-cache stub) and once by a raw scan for the symbol names (coarse, but survives a
// stripped symtab). A negative answer from one pass is never reported as a negative finding
// while the other pass still has data.

/// Bounds-checked Mach-O readers. Every accessor returns a value rather than trapping: a
/// malformed or unexpected file has to produce a report line, never a crash in the harness.
private enum MO {
    static func le32(_ d: Data, _ o: Int) -> UInt32 {
        guard o >= 0, o + 4 <= d.count else { return 0 }
        return UInt32(d[o]) | (UInt32(d[o + 1]) << 8) | (UInt32(d[o + 2]) << 16) | (UInt32(d[o + 3]) << 24)
    }

    static func be32(_ d: Data, _ o: Int) -> UInt32 {
        guard o >= 0, o + 4 <= d.count else { return 0 }
        return (UInt32(d[o]) << 24) | (UInt32(d[o + 1]) << 16) | (UInt32(d[o + 2]) << 8) | UInt32(d[o + 3])
    }

    static func cstring(_ d: Data, _ start: Int, _ limit: Int) -> String {
        guard start >= 0, start < d.count else { return "" }
        let end = min(limit, d.count)
        var bytes: [UInt8] = []
        var i = start
        while i < end, d[i] != 0 {
            bytes.append(d[i])
            i += 1
        }
        return String(decoding: bytes, as: UTF8.self)
    }
}

enum MachOImportScan {
    struct Result {
        var path: String
        var exists = false
        var bytes = 0
        var kind = "—"
        var note = ""
        var archives: [String] = []
        var hits: [String] = []
    }

    /// The entry points that decide the question, plus the ones that only describe the
    /// plumbing around it.
    static let needles = [
        "archive_read_support_format_all",
        "archive_read_support_format_zip",
        "archive_read_support_format_iso9660",
        "archive_read_support_filter_all",
        "archive_read_open_memory",
        "archive_read_open_filename",
        "archive_read_extract",
    ]

    static func scan(path: String) -> Result {
        var r = Result(path: path)
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return r }
        r.exists = true
        r.bytes = data.count
        guard data.count >= 32 else {
            r.note = "文件过短"
            return r
        }

        let fat = MO.be32(data, 0)
        if fat == 0xCAFE_BABE || fat == 0xCAFE_BABF {
            r.kind = "fat"
            r.note = "胖二进制：未解出具体架构，只做名字扫描"
        } else if MO.le32(data, 0) == 0xFEED_FACF {
            r.kind = "Mach-O 64"
            let parsed = undefinedSymbols(data)
            r.archives = parsed.0.filter { $0.contains("archive_") }
            if !parsed.1.isEmpty { r.note = parsed.1 }
        } else {
            r.kind = "非 Mach-O"
        }

        for needle in needles where data.range(of: Data(needle.utf8)) != nil {
            r.hits.append(needle)
        }
        return r
    }

    /// Undefined (imported) symbols from LC_SYMTAB. The second element explains why the table
    /// could not be used, or is empty on success.
    static func undefinedSymbols(_ data: Data) -> ([String], String) {
        guard data.count >= 32 else { return ([], "文件过短") }
        let ncmds = MO.le32(data, 16)
        var off = 32
        var symoff = 0, nsyms = 0, stroff = 0, strsize = 0
        var found = false

        for _ in 0..<min(Int(ncmds), 8192) {
            guard off + 8 <= data.count else { break }
            let cmd = MO.le32(data, off)
            let size = MO.le32(data, off + 4)
            guard size >= 8, off + Int(size) <= data.count else { break }
            if cmd == 0x2, off + 24 <= data.count {   // LC_SYMTAB
                symoff = Int(MO.le32(data, off + 8))
                nsyms = Int(MO.le32(data, off + 12))
                stroff = Int(MO.le32(data, off + 16))
                strsize = Int(MO.le32(data, off + 20))
                found = true
            }
            off += Int(size)
        }

        guard found else { return ([], "无 LC_SYMTAB") }
        guard nsyms > 0, strsize > 0 else { return ([], "符号表为空（已剥离）") }
        guard symoff > 0, symoff + nsyms * 16 <= data.count, stroff + strsize <= data.count else {
            return ([], "符号表不在文件内（dyld 共享缓存 stub）")
        }

        var out: [String] = []
        let strEnd = stroff + strsize
        for i in 0..<nsyms {
            let base = symoff + i * 16
            let strx = Int(MO.le32(data, base))
            let ntype = data[base + 4]
            // N_UNDF (0x0) with N_EXT (0x1) is an import; defined symbols live in a section.
            guard (ntype & 0x0e) == 0, (ntype & 0x01) != 0, strx > 0 else { continue }
            let name = MO.cstring(data, stroff + strx, strEnd)
            if !name.isEmpty { out.append(name) }
        }
        return (out, "")
    }
}

extension Catalog {

    static let formatProbes: [ExploitModule] = [

        ExploitModule(
            id: "cal.format",
            titleZh: "日历解压的归档格式面（libarchive 导入表）",
            cve: "—",
            component: "CalendarFoundation · libarchive 导入表",
            primitive: .probe,
            reach: .systemProcess,
            tier: 3,
            summaryZh: "CVE-2026-112619 的遏制层缺了什么已经清楚，仍未测绘的是投递面的格式宽度。若日历附件解压经 archive_read_support_format_all 注册，归档格式由字节嗅探决定 —— 攻击者可以把附件做成 ISO9660/Joliet 镜像，把 112522 的 1024 字节链路越界写挪进这条投递路径；若只注册了 format_zip，则 Joliet 站点在该路径上不可达。沙盒应用无法调用 _UnzipArchive，但可以读框架二进制并报告它引用了哪些 libarchive 入口点。本模块用两条独立通道做这件事：LC_SYMTAB 的未定义符号（精确，但 dyld 共享缓存 stub 上为空）与符号名原始扫描（粗糙，但剥离符号表后仍有效）。一条通道为空时，绝不把结论写成否定。",
            notesZh: "两条通道的结果必须分开记录。若只剩名字扫描命中 format_all，结论是「引用存在」而不是「嗅探已启用」—— 引用存在是必要不充分条件；判定要等投递路径的实测。候选集同时包含固定路径与 /System/Library/PrivateFrameworks 下所有名字含 Calendar 的框架，避免漏掉解压真正所在的二进制。",
            run: { ctx in
                ctx.arm("cal.format", "import scan")
                var lines: [String] = []
                var report = "cinder27 · cal.format — libarchive import scan\n"

                var candidates: [String] = [
                    "/System/Library/PrivateFrameworks/CalendarFoundation.framework/CalendarFoundation",
                    "/System/Library/PrivateFrameworks/CalendarDaemon.framework/CalendarDaemon",
                    "/System/Library/PrivateFrameworks/CalendarUIKit.framework/CalendarUIKit",
                    "/System/Library/PrivateFrameworks/DataAccess.framework/DataAccess",
                    "/System/Library/PrivateFrameworks/EventKit.framework/EventKit",
                    "/System/Library/Frameworks/EventKit.framework/EventKit",
                ]
                if let names = try? FileManager.default.contentsOfDirectory(atPath: "/System/Library/PrivateFrameworks") {
                    for name in names.sorted() where name.hasSuffix(".framework") && name.contains("Calendar") {
                        let base = (name as NSString).deletingPathExtension
                        let path = "/System/Library/PrivateFrameworks/\(name)/\(base)"
                        if !candidates.contains(path) { candidates.append(path) }
                    }
                }

                var sawAll = false, sawZip = false, sawAny = false, present = 0, stubs = 0

                for path in candidates {
                    let r = MachOImportScan.scan(path: path)
                    let short = r.path.components(separatedBy: "/").suffix(2).joined(separator: "/")
                    guard r.exists else {
                        lines.append("· \(short) — " + tl("不存在"))
                        continue
                    }
                    present += 1
                    lines.append("· \(short)  \(r.bytes) B  \(r.kind)")
                    report += "\n\(r.path)\n  bytes=\(r.bytes) kind=\(r.kind) note=\(r.note)\n"
                    if !r.note.isEmpty {
                        lines.append("    " + r.note)
                        report += "  note=\(r.note)\n"
                    }
                    if r.archives.isEmpty {
                        lines.append("    " + tl("无 archive_* 导入符号"))
                    } else {
                        for symbol in r.archives { lines.append("    \(symbol)") }
                        report += "  symtab=\(r.archives.joined(separator: ","))\n"
                    }
                    if !r.hits.isEmpty {
                        lines.append("    " + tl("名字命中: ") + r.hits.joined(separator: ", "))
                        report += "  hits=\(r.hits.joined(separator: ","))\n"
                    }
                    if r.hits.contains("archive_read_support_format_all") { sawAll = true }
                    if r.hits.contains("archive_read_support_format_zip") { sawZip = true }
                    if !r.hits.isEmpty || !r.archives.isEmpty { sawAny = true }
                    if r.note.contains("stub") { stubs += 1 }
                }

                lines.append("")
                lines.append(tl("— 判定 —"))
                if sawAll {
                    lines.append(tl("format_all 被引用：格式由字节嗅探决定，ISO/Joliet 站点在该投递路径上具备可达性前提。"))
                } else if sawZip {
                    lines.append(tl("只引用 format_zip：该投递路径上 ISO/Joliet 站点不可达。"))
                } else if sawAny {
                    lines.append(tl("只引用了解包入口，未见格式注册 —— 需要确认调用点在哪个二进制里。"))
                } else if present == 0 {
                    lines.append(tl("候选二进制均不在磁盘上 —— 系统框架在 dyld 共享缓存里，需要换用内存内镜像解析。"))
                } else if stubs > 0 {
                    lines.append("\(stubs) " + tl("个候选是 dyld 共享缓存 stub，磁盘读取路径无法定论 —— 下一步改用内存内镜像解析，不能就此写成否定。"))
                } else {
                    lines.append(tl("候选二进制均未引用 archive_* —— 解压发生在本进程看不到的其它二进制里。"))
                }
                lines.append(tl("注意：名字命中只证明「引用存在」，不证明「嗅探已启用」；后者要在投递路径上实测。"))

                let url = ctx.write("cal_format_report.txt", Data(report.utf8))
                ctx.disarm("cal.format", "scanned=\(present)")
                return ModuleOutcome(headline: tl("格式面已测绘，命中二进制 ") + "\(present)",
                                     detail: lines.joined(separator: "\n"),
                                     evidence: [
                                        tl("两条独立通道：LC_SYMTAB 未定义符号 + 原始名字扫描"),
                                        tl("候选集含 /System/Library/PrivateFrameworks 下全部 Calendar 框架"),
                                        tl("引用存在 ≠ 嗅探启用，结论分级记录"),
                                     ],
                                     artifacts: [url])
            }),
    ]
}
