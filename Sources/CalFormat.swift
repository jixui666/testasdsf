import Foundation
import Darwin

// MARK: - Which archive formats does the Calendar unzip path actually register?
//
// The open question behind CVE-2026-112619. On 27.0 CalendarFoundation ships `_UnzipArchive`
// with no containment at all, and the harness can already prove two neighbouring facts: that
// libarchive itself accepts a `../` entry name when the caller does not arm SECURE_NODOTDOT,
// and that it accepts an ISO9660/Joliet image with the 1024-byte pathname chain (arc.iso).
// What is missing is the join — whether the attachment bytes reach libarchive through
// archive_read_support_format_all (the format is sniffed from the bytes, so an attacker can
// make the attachment an ISO and reach build_pathname_utf16be) or through a ZIP-only
// registration (the Joliet site is unreachable on that delivery path whatever the attachment
// is called).
//
// A sandboxed app cannot call `_UnzipArchive`, but it can read which libarchive entry points
// the owning binary references. On 27.0.1 the system frameworks are **not on disk** — the
// first device run found none of the eighteen Calendar binaries in /System — so the disk scan
// alone reports "cannot decide". This module therefore tries both routes:
//
//   1. disk    — LC_SYMTAB undefined symbols plus a raw name scan (exact, but empty for a
//                 dyld-cache-only framework)
//   2. memory  — dlopen the framework so dyld resolves it out of the shared cache, then walk
//                 the *mapped* __LINKEDIT of that image. Every read is bounds-checked against
//                 the segment's file range before it happens, so a malformed or unexpected
//                 image produces a report line instead of a crash.

/// Bounds-checked readers for `Data`. Every accessor returns a value rather than trapping.
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

// MARK: - Raw readers over a mapped image

private func u32at(_ b: UnsafePointer<UInt8>, _ o: Int) -> UInt32 {
    UInt32(b[o]) | (UInt32(b[o + 1]) << 8) | (UInt32(b[o + 2]) << 16) | (UInt32(b[o + 3]) << 24)
}

private func u64at(_ b: UnsafePointer<UInt8>, _ o: Int) -> UInt64 {
    var v: UInt64 = 0
    var k = 0
    while k < 8 {
        v |= UInt64(b[o + k]) << UInt64(8 * k)
        k += 1
    }
    return v
}

private func segName(_ b: UnsafePointer<UInt8>, _ o: Int) -> String {
    var bytes: [UInt8] = []
    var i = 0
    while i < 16, b[o + i] != 0 {
        bytes.append(b[o + i])
        i += 1
    }
    return String(decoding: bytes, as: UTF8.self)
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

// MARK: - Loaded images (dyld shared cache)

enum LoadedImageScan {
    struct Image {
        let name: String
        let header: UnsafeRawPointer
    }

    static func images() -> [Image] {
        var out: [Image] = []
        let total = _dyld_image_count()
        var i: UInt32 = 0
        while i < total {
            if let namePointer = _dyld_get_image_name(i), let header = _dyld_get_image_header(i) {
                out.append(Image(name: String(cString: namePointer),
                                 header: UnsafeRawPointer(header)))
            }
            i += 1
        }
        return out
    }

    /// Imported symbols of a mapped image. The addresses come from LC_SEGMENT_64 metadata, and
    /// every range is checked against __LINKEDIT's file range before it is read, so this
    /// cannot walk off the mapping.
    static func imports(of image: Image) -> ([String], String) {
        let b = image.header.assumingMemoryBound(to: UInt8.self)
        guard u32at(b, 0) == 0xFEED_FACF else { return ([], "非 64 位 Mach-O") }

        let ncmds = Int(u32at(b, 16))
        let sizeofcmds = Int(u32at(b, 20))
        guard ncmds > 0, ncmds <= 4096, sizeofcmds > 32, sizeofcmds < (1 << 20) else {
            return ([], "加载命令尺寸异常")
        }

        var off = 32
        var textVM: UInt64 = 0
        var linkVM: UInt64 = 0, linkFile: UInt64 = 0, linkSize: UInt64 = 0
        var symoff: UInt64 = 0, nsyms: UInt64 = 0, stroff: UInt64 = 0, strsize: UInt64 = 0
        var hasText = false, hasLink = false, hasSym = false

        for _ in 0..<ncmds {
            guard off + 8 <= sizeofcmds else { break }
            let cmd = u32at(b, off)
            let size = Int(u32at(b, off + 4))
            guard size >= 8, off + size <= sizeofcmds else { break }

            if cmd == 0x19, size >= 72 {                 // LC_SEGMENT_64
                let name = segName(b, off + 8)
                let vmaddr = u64at(b, off + 24)
                let fileoff = u64at(b, off + 40)
                let filesize = u64at(b, off + 48)
                if name == "__TEXT" {
                    textVM = vmaddr
                    hasText = true
                } else if name == "__LINKEDIT" {
                    linkVM = vmaddr
                    linkFile = fileoff
                    linkSize = filesize
                    hasLink = true
                }
            } else if cmd == 0x2, size >= 24 {           // LC_SYMTAB
                symoff = UInt64(u32at(b, off + 8))
                nsyms = UInt64(u32at(b, off + 12))
                stroff = UInt64(u32at(b, off + 16))
                strsize = UInt64(u32at(b, off + 20))
                hasSym = true
            }
            off += size
        }

        guard hasText, hasLink, hasSym else { return ([], "缺少 __TEXT / __LINKEDIT / LC_SYMTAB") }
        guard nsyms > 0, nsyms < (1 << 22), strsize > 0, strsize < (1 << 24) else {
            return ([], "符号表为空")
        }
        guard linkSize > 0, linkSize < (1 << 28) else { return ([], "__LINKEDIT 尺寸异常") }

        let linkEnd = linkFile + linkSize
        guard linkVM >= textVM, linkVM - textVM < (1 << 30),
              symoff >= linkFile, symoff + nsyms * 16 <= linkEnd,
              stroff >= linkFile, stroff + strsize <= linkEnd else {
            return ([], "符号表不在 __LINKEDIT 内")
        }

        let delta = Int(linkVM - textVM)
        let symBase = b + delta + Int(symoff - linkFile)
        let strBase = b + delta + Int(stroff - linkFile)
        let strCount = Int(strsize)

        var out: [String] = []
        var i: UInt64 = 0
        while i < nsyms {
            let entry = symBase + Int(i * 16)
            let strx = Int(u32at(entry, 0))
            let ntype = entry[4]
            i += 1
            guard (ntype & 0x0e) == 0, (ntype & 0x01) != 0, strx > 0, strx < strCount else { continue }
            var bytes: [UInt8] = []
            var j = strx
            while j < strCount, strBase[j] != 0 {
                bytes.append(strBase[j])
                j += 1
            }
            if !bytes.isEmpty { out.append(String(decoding: bytes, as: UTF8.self)) }
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
            summaryZh: "CVE-2026-112619 的遏制层缺了什么已经清楚，仍未测绘的是投递面的格式宽度。若日历附件解压经 archive_read_support_format_all 注册，归档格式由字节嗅探决定 —— 攻击者可以把附件做成 ISO9660/Joliet 镜像，把 112522 的 1024 字节链路越界写挪进这条投递路径；若只注册了 format_zip，则 Joliet 站点在该路径上不可达。沙盒应用无法调用 _UnzipArchive，但可以读框架二进制并报告它引用了哪些 libarchive 入口点。27.0.1 上系统框架不在磁盘（首轮真机实测：18 个候选全部不存在），因此本模块走两条通道：磁盘上的 LC_SYMTAB 与名字扫描；以及 dlopen 之后从 dyld 共享缓存取出已映射镜像、解析其 __LINKEDIT。所有读取都先按段范围校验，越界即报错而不是崩溃。",
            notesZh: "两条通道的结果分开记录。名字命中或导入符号都只证明「引用存在」，不证明「嗅探已启用」—— 引用存在是必要不充分条件。若磁盘通道为空而内存通道有符号，结论以内存通道为准；若两条都无，如实写「无法定论」，绝不写成否定。",
            run: { ctx in
                ctx.arm("cal.format", "import scan")
                var lines: [String] = []
                var report = "cinder27 · cal.format — libarchive import scan\n"

                var candidates: [String] = [
                    "/System/Library/PrivateFrameworks/CalendarFoundation.framework/CalendarFoundation",
                    "/System/Library/PrivateFrameworks/CalendarDaemon.framework/CalendarDaemon",
                    "/System/Library/PrivateFrameworks/CalendarUIKit.framework/CalendarUIKit",
                    "/System/Library/PrivateFrameworks/CalendarDatabase.framework/CalendarDatabase",
                    "/System/Library/PrivateFrameworks/DataAccess.framework/DataAccess",
                    "/System/Library/PrivateFrameworks/EventKit.framework/EventKit",
                    "/System/Library/Frameworks/EventKit.framework/EventKit",
                    "/System/Library/PrivateFrameworks/iCalendar.framework/iCalendar",
                ]
                if let names = try? FileManager.default.contentsOfDirectory(atPath: "/System/Library/PrivateFrameworks") {
                    for name in names.sorted() where name.hasSuffix(".framework") && name.contains("Calendar") {
                        let base = (name as NSString).deletingPathExtension
                        let path = "/System/Library/PrivateFrameworks/\(name)/\(base)"
                        if !candidates.contains(path) { candidates.append(path) }
                    }
                }

                var sawAll = false, sawZip = false, sawAny = false
                var onDisk = 0, inMemory = 0, unreachable = 0

                for path in candidates {
                    let short = path.components(separatedBy: "/").suffix(2).joined(separator: "/")
                    let base = (path as NSString).lastPathComponent
                    var archives: [String] = []
                    var hits: [String] = []
                    var origin = ""

                    let disk = MachOImportScan.scan(path: path)
                    if disk.exists {
                        onDisk += 1
                        origin = tl("磁盘 ") + "\(disk.bytes)" + " B " + disk.kind
                        archives = disk.archives
                        hits = disk.hits
                        if !disk.note.isEmpty { origin = origin + " · " + disk.note }
                    } else if dlopen(path, RTLD_NOW) != nil {
                        let images = LoadedImageScan.images()
                        var match: LoadedImageScan.Image?
                        for image in images where image.name.hasSuffix(base) {
                            match = image
                            break
                        }
                        if match == nil {
                            for image in images where image.name.contains(base) {
                                match = image
                                break
                            }
                        }
                        if let image = match {
                            let parsed = LoadedImageScan.imports(of: image)
                            inMemory += 1
                            origin = tl("内存镜像 ") + image.name
                            archives = parsed.0.filter { $0.contains("archive_") }
                            if !parsed.1.isEmpty { origin = origin + " · " + parsed.1 }
                        } else {
                            unreachable += 1
                            origin = tl("dlopen 成功但未找到镜像")
                        }
                    } else {
                        unreachable += 1
                        let err = dlerror()
                        let text = err == nil ? "nil" : String(cString: err!)
                        origin = tl("不在磁盘，dlopen 失败: ") + text
                    }

                    if !archives.isEmpty || !hits.isEmpty {
                        lines.append("· \(short)")
                        lines.append("    " + origin)
                        for symbol in archives { lines.append("    " + symbol) }
                        if !hits.isEmpty {
                            lines.append("    " + tl("名字命中: ") + hits.joined(separator: ", "))
                        }
                    }
                    report = report + "\n" + path + "\n  origin=" + origin + "\n"
                    if !archives.isEmpty {
                        report = report + "  symtab=" + archives.joined(separator: ",") + "\n"
                    }
                    if !hits.isEmpty {
                        report = report + "  hits=" + hits.joined(separator: ",") + "\n"
                    }

                    if archives.contains("archive_read_support_format_all") { sawAll = true }
                    if archives.contains("archive_read_support_format_zip") { sawZip = true }
                    if hits.contains("archive_read_support_format_all") { sawAll = true }
                    if hits.contains("archive_read_support_format_zip") { sawZip = true }
                    if !hits.isEmpty || !archives.isEmpty { sawAny = true }
                }

                lines.append("")
                lines.append(tl("— 判定 —"))
                lines.append(tl("磁盘 ") + "\(onDisk)" + tl(" · 内存镜像 ") + "\(inMemory)" + tl(" · 不可达 ") + "\(unreachable)")
                if sawAll {
                    lines.append(tl("format_all 被引用：格式由字节嗅探决定，ISO/Joliet 站点在该投递路径上具备可达性前提。"))
                } else if sawZip {
                    lines.append(tl("只引用 format_zip：该投递路径上 ISO/Joliet 站点不可达。"))
                } else if sawAny {
                    lines.append(tl("只引用了解包入口，未见格式注册 —— 需要确认调用点在哪个二进制里。"))
                } else {
                    lines.append(tl("两条通道都没有拿到符号：无法定论（不是否定）。需要换用未 strip 的 dyld 缓存镜像。"))
                }
                lines.append(tl("注意：引用存在只证明「引用存在」，不证明「嗅探已启用」；后者要在投递路径上实测。"))

                report = report + "\nsummary: onDisk=\(onDisk) inMemory=\(inMemory) unreachable=\(unreachable) format_all=\(sawAll) format_zip=\(sawZip)\n"
                let url = ctx.write("cal_format_report.txt", Data(report.utf8))
                ctx.disarm("cal.format", "disk=\(onDisk) mem=\(inMemory) all=\(sawAll)")
                let _outHeadline = tl("格式面: 磁盘 ") + "\(onDisk)" + tl(" · 内存 ") + "\(inMemory)" + tl(" · 不可达 ") + "\(unreachable)"
                let _outDetail = lines.joined(separator: "\n")
                let _outEvidence = [
                    tl("通道一：磁盘 LC_SYMTAB 未定义符号 + 名字扫描"),
                    tl("通道二：dlopen 后解析已映射镜像的 __LINKEDIT（所有读取按段范围校验）"),
                    tl("引用存在 ≠ 嗅探启用，结论分级记录"),
                ]
                let _outArtifacts = [url]
                return ModuleOutcome(headline: _outHeadline, detail: _outDetail,
                                     evidence: _outEvidence, artifacts: _outArtifacts)
            }),
    ]
}
