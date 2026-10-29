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
        var fixupsOff: UInt64 = 0
        var fixupsSize: UInt64 = 0
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
            } else if cmd == 0x8000_0034, size >= 16 {   // LC_DYLD_CHAINED_FIXUPS
                l.fixupsOff = UInt64(u32at(b, off + 8))
                l.fixupsSize = UInt64(u32at(b, off + 12))
            }
            off += size
        }
        return l
    }

    /// Per-image imports, read from LC_DYLD_CHAINED_FIXUPS.
    ///
    /// Everything simpler than this failed, and the failures are worth recording:
    ///
    ///   * the on-disk route finds no binary at all (frameworks are dyld-cache-only on 27.0.1);
    ///   * LC_SYMTAB in a cache image has been stripped, so `imports(of:)` returns nothing;
    ///   * a raw **name scan over __LINKEDIT is invalid**. In the cache an image's __LINKEDIT
    ///     range covers the cache-wide linkedit region, which also holds libarchive's own
    ///     symbol strings. The first run of that route reported the identical six
    ///     `archive_*` names for twelve unrelated frameworks — including CalendarWidget and
    ///     SiriCalendarUI — because the scan was reading one shared pool, not twelve import
    ///     tables. It looked like a positive answer and was not one.
    ///
    /// The chained-fixups header is per image: `imports_count` entries, each carrying a name
    /// offset into that image's symbol pool. Offsets are relative to the __LINKEDIT start, and
    /// the cache maps __LINKEDIT gigabytes away from __TEXT, so the distance is used as-is
    /// (up to 16 GB) instead of being capped.
    static func chainedImports(of image: Image) -> (symbols: [String], note: String) {
        let l = layout(of: image)
        if !l.note.isEmpty { return ([], l.note) }
        guard l.hasText, l.hasLink, l.linkVM >= l.textVM else { return ([], "段信息缺失") }
        let delta = l.linkVM - l.textVM
        guard delta < (16 << 30) else { return ([], "段间距异常 " + "\(delta)") }
        guard l.linkSize > 0, l.linkSize < (1 << 31) else {
            return ([], "__LINKEDIT 尺寸异常 " + "\(l.linkSize)")
        }

        let b = image.header.assumingMemoryBound(to: UInt8.self)
        let linkBase = b + Int(delta)
        let linkSize = Int(l.linkSize)

        // LC_DYLD_CHAINED_FIXUPS: linkedit_data_command { cmd, cmdsize, dataoff, datasize }
        guard l.fixupsOff > 0, l.fixupsSize > 0 else { return ([], "无 chained fixups") }

        // dataoff is a file offset on disk but linkedit-relative in a cache image; try the
        // file-offset reading first and validate it before trusting it. Both candidates are
        // range-checked against __LINKEDIT before anything is read, because a pointer before
        // the segment would fault instead of returning a note.
        var header: UnsafePointer<UInt8>?
        if l.fixupsOff >= l.linkFile, l.fixupsOff - l.linkFile + 24 <= l.linkSize {
            let candidate = linkBase + Int(l.fixupsOff - l.linkFile)
            if plausibleFixupsHeader(candidate, linkSize: linkSize) { header = candidate }
        }
        if header == nil, l.fixupsOff + 24 <= l.linkSize {
            let candidate = linkBase + Int(l.fixupsOff)
            if plausibleFixupsHeader(candidate, linkSize: linkSize) { header = candidate }
        }
        guard let fixed = header else { return ([], "fixups 头部不可读") }
        let headerPointer: UnsafePointer<UInt8> = fixed

        let importsOffset = Int(u32at(headerPointer, 8))
        let symbolsOffset = Int(u32at(headerPointer, 12))
        let importsCount = Int(u32at(headerPointer, 16))
        let importsFormat = Int(u32at(headerPointer, 20))
        guard importsCount > 0, importsCount < 200000,
              importsOffset > 0, importsOffset + importsCount * 8 <= linkSize,
              symbolsOffset > 0, symbolsOffset < linkSize else {
            return ([], "imports 表越界")
        }
        let stride = importsFormat == 3 ? 8 : 4
        let importsBase = linkBase + importsOffset
        let symbolsBase = linkBase + symbolsOffset

        var out: [String] = []
        var i = 0
        while i < importsCount {
            let entry = importsBase + i * stride
            let raw = u32at(entry, 0)
            let nameOffset = Int(raw & 0x7FFFFF)
            i += 1
            guard nameOffset > 0, symbolsOffset + nameOffset < linkSize else { continue }
            guard let name = cstringAt(symbolsBase + nameOffset, limit: linkSize - symbolsOffset - nameOffset) else { continue }
            out.append(name)
        }
        return (out, "imports=" + "\(importsCount)")
    }

    private static func plausibleFixupsHeader(_ p: UnsafePointer<UInt8>, linkSize: Int) -> Bool {
        // fixups_version is 0 on every shipping image; imports_count and the two offsets have
        // to land inside __LINKEDIT.
        guard u32at(p, 0) == 0 else { return false }
        let importsOffset = Int(u32at(p, 8))
        let symbolsOffset = Int(u32at(p, 12))
        let importsCount = Int(u32at(p, 16))
        guard importsCount < 200000 else { return false }
        guard importsOffset < linkSize, symbolsOffset < linkSize else { return false }
        return true
    }

    private static func cstringAt(_ p: UnsafePointer<UInt8>, limit: Int) -> String? {
        guard limit > 0 else { return nil }
        var bytes: [UInt8] = []
        var i = 0
        while i < limit, i < 1024, p[i] != 0 {
            bytes.append(p[i])
            i += 1
        }
        if bytes.isEmpty { return nil }
        return String(decoding: bytes, as: UTF8.self)
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
            summaryZh: "CVE-2026-112619 的遏制层缺了什么已经清楚，仍未测绘的是投递面的格式宽度。若日历附件解压经 archive_read_support_format_all 注册，归档格式由字节嗅探决定 —— 攻击者可以把附件做成 ISO9660/Joliet 镜像，把 112522 的 1024 字节链路越界写挪进这条投递路径；若只注册了 format_zip，则 Joliet 站点在该路径上不可达。本模块尝试了四条静态路线，全部失败：①磁盘上 18 个候选二进制一个都不存在（系统框架只在 dyld 共享缓存里）；②映射镜像的 LC_SYMTAB 被缓存构建剥离，nsyms=0；③对 __LINKEDIT 做原始名字扫描会误报 —— 镜像的 __LINKEDIT 范围覆盖缓存级 linkedit 区，里面同时装着 libarchive 自己的符号串，12 个互不相关的框架因此报出完全相同的 6 个 archive_* 名字；④缓存镜像里没有 LC_DYLD_CHAINED_FIXUPS（导入在构建缓存时就已解析）。调用侧同样走不通：_UnzipArchive 既不是选择器也不是导出 C 符号。结论是这台机器上无法静态测量，必须由投递侧行为实验给出。",
            notesZh: "本模块的价值现在是一条**否定性结果**：这条测量路径在 27.0.1 上被系统结构封死了，而不是实现不到位。③那次误报尤其值得记住 —— 它看起来完全像肯定答案（format_all 命中），实际读的是共享字符串池；判定规则是「同一个符号集在互不相关的镜像里重复出现即为共享池」。三条通道都为空时写「无法定论」，绝不写成否定。",
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
                            // comes back empty. Read the image's own chained-fixups import
                            // list instead — a name scan over __LINKEDIT is not evidence, it
                            // reads the cache-wide pool that also holds libarchive's strings.
                            if archives.isEmpty {
                                let ci = LoadedImageScan.chainedImports(of: image)
                                archives = ci.symbols.filter { $0.contains("archive_") }
                                if !ci.note.isEmpty { origin = origin + " · " + ci.note }
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
                    lines.append(tl("四条通道全部不可用（磁盘无文件 / 符号表被剥 / 名字扫描会误报 / 缓存镜像无 chained fixups）：本机无法静态测量，结论必须由投递侧行为实验给出。"))
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
