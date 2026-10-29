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

    // `_dyld_image_count` and friends live in <mach-o/dyld.h>, which the Darwin overlay does
    // not re-export to Swift, so they are resolved with dlsym instead of being imported.
    private typealias CountFn = @convention(c) () -> UInt32
    private typealias HeaderFn = @convention(c) (UInt32) -> UnsafeMutableRawPointer?
    private typealias NameFn = @convention(c) (UInt32) -> UnsafePointer<CChar>?

    private static let bindings: (count: CountFn, header: HeaderFn, name: NameFn)? = {
        guard let count = DyLib.shared.symbol("_dyld_image_count"),
              let header = DyLib.shared.symbol("_dyld_get_image_header"),
              let name = DyLib.shared.symbol("_dyld_get_image_name") else { return nil }
        return (unsafeBitCast(count, to: CountFn.self),
                unsafeBitCast(header, to: HeaderFn.self),
                unsafeBitCast(name, to: NameFn.self))
    }()

    static var available: Bool { bindings != nil }

    static func images() -> [Image] {
        guard let b = bindings else { return [] }
        var out: [Image] = []
        let total = b.count()
        var i: UInt32 = 0
        while i < total {
            if let namePointer = b.name(i), let header = b.header(i) {
                out.append(Image(name: String(cString: namePointer),
                                 header: UnsafeRawPointer(header)))
            }
            i += 1
        }
        return out
    }

    struct Layout {
        var textVM: UInt64 = 0
        var linkVM: UInt64 = 0
        var linkFile: UInt64 = 0
        var linkSize: UInt64 = 0
        var symoff: UInt64 = 0
        var nsyms: UInt64 = 0
        var stroff: UInt64 = 0
        var strsize: UInt64 = 0
        var hasText = false
        var hasLink = false
        var hasSym = false
        var note = ""
    }

    /// One pass over the load commands, shared by the symbol-table and name-scan routes.
    static func layout(of image: Image) -> Layout {
        var l = Layout()
        let b = image.header.assumingMemoryBound(to: UInt8.self)
        guard u32at(b, 0) == 0xFEED_FACF else {
            l.note = "非 64 位 Mach-O"
            return l
        }
        let ncmds = Int(u32at(b, 16))
        let sizeofcmds = Int(u32at(b, 20))
        guard ncmds > 0, ncmds <= 4096, sizeofcmds > 32, sizeofcmds < (1 << 20) else {
            l.note = "加载命令尺寸异常"
            return l
        }

        var off = 32
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
                    l.textVM = vmaddr
                    l.hasText = true
                } else if name == "__LINKEDIT" {
                    l.linkVM = vmaddr
                    l.linkFile = fileoff
                    l.linkSize = filesize
                    l.hasLink = true
                }
            } else if cmd == 0x2, size >= 24 {           // LC_SYMTAB
                l.symoff = UInt64(u32at(b, off + 8))
                l.nsyms = UInt64(u32at(b, off + 12))
                l.stroff = UInt64(u32at(b, off + 16))
                l.strsize = UInt64(u32at(b, off + 20))
                l.hasSym = true
            }
            off += size
        }
        return l
    }

    /// Name scan over the mapped __LINKEDIT.
    ///
    /// The dyld shared cache strips the nlist entries, so on 27.0.1 every Calendar image
    /// reports an empty LC_SYMTAB — the imports are still named, but in the chained-fixup
    /// string pool inside __LINKEDIT. Scanning that range for the symbol names recovers the
    /// same signal the on-disk route would have produced. The range is the segment's own
    /// filesize, so a corrupt header produces a note instead of a read past the mapping.
    static func needleHits(in image: Image, needles: [String]) -> (hits: [String], note: String) {
        let l = layout(of: image)
        if !l.note.isEmpty { return ([], l.note) }
        guard l.hasText, l.hasLink, l.linkVM >= l.textVM, l.linkVM - l.textVM < (1 << 30) else {
            return ([], "缺少 __TEXT / __LINKEDIT")
        }
        let cap: UInt64 = 64 << 20
        let size = min(l.linkSize, cap)
        guard size > 0 else { return ([], "__LINKEDIT 尺寸异常") }

        let b = image.header.assumingMemoryBound(to: UInt8.self)
        let start = b + Int(l.linkVM - l.textVM)
        let count = Int(size)
        var hits: [String] = []
        for needle in needles {
            if patternIn(start, count: count, pattern: Array(needle.utf8)) {
                hits.append(needle)
            }
        }
        let note = l.linkSize > cap ? "扫描已截断到 64 MB" : ""
        return (hits, note)
    }

    private static func patternIn(_ base: UnsafePointer<UInt8>, count: Int, pattern: [UInt8]) -> Bool {
        guard !pattern.isEmpty, count >= pattern.count else { return false }
        let n = pattern.count
        let last = count - n
        var i = 0
        while i <= last {
            if base[i] == pattern[0] {
                var k = 1
                while k < n, base[i + k] == pattern[k] {
                    k += 1
                }
                if k == n { return true }
            }
            i += 1
        }
        return false
    }

    /// Imported symbols of a mapped image. The addresses come from LC_SEGMENT_64 metadata, and
    /// every range is checked against __LINKEDIT's file range before it is read, so this
    /// cannot walk off the mapping.
    static func imports(of image: Image) -> ([String], String) {
        let l = layout(of: image)
        if !l.note.isEmpty { return ([], l.note) }
        let b = image.header.assumingMemoryBound(to: UInt8.self)
        let textVM = l.textVM, linkVM = l.linkVM, linkFile = l.linkFile, linkSize = l.linkSize
        let symoff = l.symoff, nsyms = l.nsyms, stroff = l.stroff, strsize = l.strsize
        let hasText = l.hasText, hasLink = l.hasLink, hasSym = l.hasSym

        guard hasText, hasLink, hasSym else { return ([], "缺少 __TEXT / __LINKEDIT / LC_SYMTAB") }
        guard nsyms > 0, nsyms < (1 << 22), strsize > 0, strsize < (1 << 24) else {
            return ([], "缓存镜像已剥离符号表")
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
                            // The shared cache strips the nlist entries, so the symbol table
                            // comes back empty. The import names are still in __LINKEDIT — scan
                            // the mapped range for them instead.
                            if archives.isEmpty {
                                let scan = LoadedImageScan.needleHits(in: image,
                                                                     needles: MachOImportScan.needles)
                                hits = scan.hits
                                if !hits.isEmpty {
                                    origin = origin + " · " + tl("名字扫描命中 ") + "\(hits.count)"
                                } else if !scan.note.isEmpty {
                                    origin = origin + " · " + scan.note
                                }
                            }
                        } else {
                            unreachable += 1
                            origin = tl("dlopen 成功但未找到镜像（dyld 符号可用=") + "\(LoadedImageScan.available)" + "）"
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
                    lines.append(tl("三条通道（磁盘符号表 / 内存符号表 / __LINKEDIT 名字扫描）都没有命中：无法定论（不是否定）。"))
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
