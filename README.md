# Cinder27

[中文](README.zh-CN.md)

An iOS 17.0–27.1 vulnerability-verification and device-modification lab, **51 modules**. Primary target: **iOS 27.0.1 / iPhone 18 Pro Max** (iPhone19,7 · 24A446).

Component coverage: ImageIO, CoreGraphics, CoreMedia, FontParser, ArchiveUtility, VideoToolbox, AudioToolbox, Calendar, Dolby Vision RPU, XNU kernel IPC, sandbox & filesystem, GPT / kexts, HID / peripherals / radio, entitlement probing.

## Repository layout

| Block | Contents |
|---|---|
| `CVE-2026-XXXX/` (31) | One folder per CVE with the POC proper inside: a `.py` seed builder (standalone runnable) and/or a `.swift` seed construction + trigger closures (standalone typecheckable) |
| `<module-id>/` (11) | Modules without a CVE number — tools, probes, baselines, sandbox primitives — named by module id, same folder-per-file shape |
| `Sources/` `scripts/` `Resources/` `Info.plist` | The Cinder27 app itself (the verification harness; build below) |

42 Swift POC files (all pass standalone typecheck) + 5 Python seed builders (byte-identical output to the app's built-in seeds).

## POC index — 31 CVE folders

Composite ids (e.g. `CVE-2026-112627 / 112561`) collapse into the primary id's folder; where one CVE is hit by several modules, the trigger closures sit side by side in the same file.

| CVE | Modules | Component | Primitive | Reach | Title | Files |
|---|---|---|---|---|---|---|
| [CVE-2026-112415](CVE-2026-112415/) | `vid.hevc` | AVD.videodecoder plugin | OOB read | system process | MVHEVC layer id out of range | `CVE-2026-112415.swift` |
| [CVE-2026-112416](CVE-2026-112416/) | `vid.avc` | AVD.videodecoder plugin (not a kext) | OOB write | system process | AVC slice count cap missing | `CVE-2026-112416.swift` |
| [CVE-2026-112485](CVE-2026-112485/) | `mdl.usda` | Model I/O · libusd_ms | OOB read | in-process | USDA declaration nesting depth | `CVE-2026-112485.py` · `CVE-2026-112485.swift` |
| [CVE-2026-112488](CVE-2026-112488/) | `iio.tiff.direntry` | ImageIO · TIFFReadDirEntry*Array | OOB write | in-process | TIFF directory entry allocation 32-bit truncation | `CVE-2026-112488.swift` |
| [CVE-2026-112507 / 112476](CVE-2026-112507/) | `kern.ipc` | XNU · ipc_port.c request-table consumers | use-after-free | kernel | ipc_port request table index race | `CVE-2026-112507.swift` |
| [CVE-2026-112515](CVE-2026-112515/) | `probe.hid` | IOHIDFamily · caps table lookup | OOB read | peripheral | IOHIDFamily preparsed data table index | `CVE-2026-112515.swift` |
| [CVE-2026-112522](CVE-2026-112522/) | `arc.iso`, `arc.iso.stress`, `arc.cab` | libarchive · build_pathname_utf16be | OOB write | in-process | ISO9660 Joliet pathname heap overflow | `CVE-2026-112522.py` · `CVE-2026-112522.swift` |
| [CVE-2026-112546](CVE-2026-112546/) | `aud.hoa` | AudioCodecs · APACHOADecoder::Initialize | OOB read | system process | HOA spatial audio coefficient out-of-bounds read | `CVE-2026-112546.swift` |
| [CVE-2026-112554](CVE-2026-112554/) | `kext.gpt` | IOStorageFamily | OOB read | kernel | GPT partition name scan 72-byte kernel heap out-of-bounds read | `CVE-2026-112554.swift` |
| [CVE-2026-112571](CVE-2026-112571/) | `iio.jpeg.comment` | ImageIO · ReadUserComment | info leak | in-process | EXIF UserComment short read → metadata disclosure | `CVE-2026-112571.swift` |
| [CVE-2026-112610](CVE-2026-112610/) | `cg.cmap` | CoreGraphics · _cmap_convert | OOB write | in-process | CMap /UseCMap recursion out-of-bounds write (negative-result probe) | `CVE-2026-112610.swift` |
| [CVE-2026-112611](CVE-2026-112611/) | `cg.shading`, `cg.shading.sweep` | CoreGraphics · _cg_shading_type5_draw | OOB write | in-process | Type-5 shading stack overflow (value-controlled OOB write) | `CVE-2026-112611.swift` |
| [CVE-2026-112619](CVE-2026-112619/) | `cal.unzip` | CalendarFoundation · _UnzipArchiveWithLimits | OOB write | system process | Calendar attachment extraction containment | `CVE-2026-112619.swift` |
| [CVE-2026-112625](CVE-2026-112625/) | `iio.ktx2`, `iio.pvr` | ImageIO · KTX2ReadPlugin | integer overflow | in-process | KTX2 dimension and level size arithmetic | `CVE-2026-112625.py` · `CVE-2026-112625.swift` |
| [CVE-2026-112627](CVE-2026-112627/) | `iio.dds.bc7`, `iio.appx` | ImageIO · BCReadPlugin::initialize | OOB read | in-process | BC7 texture mip truncation | `CVE-2026-112627.swift` |
| [CVE-2026-112629](CVE-2026-112629/) | `iio.jpeg.gps` | ImageIO · GPSCopy::processData | OOB read | in-process | GPS IFD value offset out of bounds | `CVE-2026-112629.swift` |
| [CVE-2026-112630](CVE-2026-112630/) | `iio.apng.fctl` | ImageIO · IIO_Reader_PNG::getImageCount | info leak | in-process | APNG fcTL truncation → uninitialised frame geometry on the stack | `CVE-2026-112630.swift` |
| [CVE-2026-112632](CVE-2026-112632/) | `iio.tiff.trunc` | ImageIO · decodeStripChunky | info leak | in-process | TIFF truncated strip → uninitialised heap into pixels | `CVE-2026-112632.swift` |
| [CVE-2026-112633 / 112614](CVE-2026-112633/) | `iio.tiff.planar`, `iio.pdf.raster` | ImageIO · decodeStripPlanar | OOB write | in-process | TIFF planar scatter out-of-bounds write | `CVE-2026-112633.swift` |
| [CVE-2026-112634](CVE-2026-112634/) | `iio.jpeg.marker` | ImageIO · _JPEGFile::processData | OOB read | in-process | JPEG marker length out of bounds | `CVE-2026-112634.swift` |
| [CVE-2026-112638](CVE-2026-112638/) | `aud.lc3` | AudioCodecs · ACLC3Decoder::AppendInputData | OOB write | entitlement-gated | LC3 decoder input buffer overflow | `CVE-2026-112638.swift` |
| [CVE-2026-112646](CVE-2026-112646/) | `sb.stash` | SpringBoard · SBHomeScreenService | OOB write | system process | SpringBoard stashed layout name validation | `CVE-2026-112646.swift` |
| [CVE-2026-112656](CVE-2026-112656/) | `font.gdef` | CoreText · GetLigatureCaretPositionsForGlyph | OOB read | in-process | GDEFLigatureCaret offset-chain out-of-bounds read | `CVE-2026-112656.swift` |
| [CVE-2026-112683](CVE-2026-112683/) | `font.cff` | FontParser · charstring interpreter | OOB write | in-process | CFF Type2 charstring operand stack overflow | `CVE-2026-112683.py` · `CVE-2026-112683.swift` |
| [CVE-2026-112688](CVE-2026-112688/) | `cm.rpu`, `cm.rpu.sweep` | CoreMedia · hevcbridgeParseVdrDmDataPayloadExMetadataBlocks | OOB write | system process | Dolby Vision RPU extension metadata block array overrun | `CVE-2026-112688.swift` |
| [CVE-2026-112696 / 84494](CVE-2026-112696/) | `probe.ane` | AppleH16ANEInterface | OOB write | kernel | ANE kernel interface reachability | `CVE-2026-112696.swift` |
| [CVE-2026-112706](CVE-2026-112706/) | `cm.fdleak`, `cm.fdleak.boundary` | CoreMedia · mediaplaybackd.bytestream.xpc | info leak | system process | CoreMedia bytestream XPC cross-sandbox file descriptor acquisition | `CVE-2026-112706.swift` |
| [CVE-2026-113907](CVE-2026-113907/) | `aud.haptic`, `aud.immersive` | AudioToolbox · AVHapticServerInstance | OOB write | system process | AVHaptic custom audio event format validation | `CVE-2026-113907.swift` |
| [CVE-2026-113910](CVE-2026-113910/) | `kern.decmpfs` | XNU · AppleFSCompressionTypeZlib | info leak | kernel | decmpfs chunked decompression under-produce → kernel heap disclosure | `CVE-2026-113910.swift` |
| [CVE-2026-113912 / 86972](CVE-2026-113912/) | `aud.drc` | AudioCodecs · mpddrc::UniDrcSelection | OOB read | system process | MPEG-D DRC downmix matrix coefficient validation | `CVE-2026-113912.swift` |
| [CVE-2026-65385](CVE-2026-65385/) | `kext.iohid` | IOKit.framework · IOHIDEventAppendEvent | OOB write | kernel | IOKit event short-heap fixed-offset write | `CVE-2026-65385.swift` |

## Modules without a CVE — 11

| Module | Component | Title | Files |
|---|---|---|---|
| [kern.baseline](kern.baseline/) | XNU · mach_port | Mach namespace baseline | `kern.baseline.swift` |
| [probe.privset](probe.privset/) | sandbox / signing / entitlements | This process's privilege surface | `probe.privset.swift` |
| [arc.rr](arc.rr/) | libarchive · RockRidge CL/PL | RockRidge relocation cycle (unfixed sibling) | `arc.rr.py` · `arc.rr.swift` |
| [sbx.toctou](sbx.toctou/) | libsystem_sandbox · sandbox_extension_issue_file | sandbox_extension symlink TOCTOU out-of-bounds read | `sbx.toctou.swift` |
| [tool.ipa](tool.ipa/) | IPASurgeon · MachO · ZipWriter | IPA surgery self-test (rename / inject / prepare for re-sign) | `tool.ipa.swift` |
| [tool.zip](tool.zip/) | ZipWriter + libarchive | ZIP writer round-trip self-test | `tool.zip.swift` |
| [tool.macho](tool.macho/) | MachO · MachOInspector | Mach-O parser self-test | `tool.macho.swift` |
| [tool.hex](tool.hex/) | HexTool | Hex search and replace self-test | `tool.hex.swift` |
| [tool.container](tool.container/) | Container · ensureAll / probe / repair / normalize | Container read/write normalisation (data container self-test and repair) | `tool.container.swift` |
| [tool.backup](tool.backup/) | BackupPane · ZipWriter · libarchive | Backup and restore round-trip self-test | `tool.backup.swift` |
| [tool.paths](tool.paths/) | Probe · FileManager | Filesystem permission matrix sweep | `tool.paths.swift` |

## Anatomy of a POC file (.swift)

Five sections, everything except comments extracted verbatim from the Cinder27 sources:

1. **Bilingual header** — module id, component, CVE, primitive / reach / tier, zh+en summary
2. **Oracle** — the observable signal of this vulnerability on-device (crash site, return-code distribution, repeated-decode fingerprinting, timing windows…)
3. **`enum B`** — byte helpers (from `Sources/Kit.swift`)
4. **Seed construction** — payload builders and their dependency closure (from `Sources/Payloads.swift` / `Payloads2.swift`; `Entry` / `BitWriter` / `PDFBuilder` structs pulled in by reference)
5. **Trigger** — the module's `run` closure, verbatim (comment block; references `RunContext` / `Runners` / `tl()`, executes inside the app harness)

The `.py` in seed folders is the same builder in its original Python (from `scripts/gen_seeds.py`) with a `__main__` writer — runnable as-is.

## Running

```bash
# Python seed builders — standalone
python3 CVE-2026-112522/CVE-2026-112522.py out.iso        # → byte-identical joliet_path_oob.iso
python3 CVE-2026-112485/CVE-2026-112485.py deep_nest.usda
python3 CVE-2026-112625/CVE-2026-112625.py bad_dims.ktx2
python3 CVE-2026-112683/CVE-2026-112683.py stack_bomb.cff
python3 arc.rr/arc.rr.py out.iso

# Swift POC — standalone typecheck (no app dependency)
xcrun swiftc -parse-as-library -swift-version 5 -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
  -target arm64-apple-macos14 -typecheck CVE-2026-112611/CVE-2026-112611.swift

# Full triggers (decode, races, crash oracles) run inside the app harness
bash scripts/build-sim.sh        # → build/sim/Cinder27.app, installed to the booted simulator
```

## Building the harness app

Dependencies: macOS + Xcode command line tools (`xcode-select --install`); no third-party package manager.

```bash
bash scripts/build-device.sh     # → dist/Cinder27-unsigned.ipa (arm64, iOS 17.0+, unsigned)
bash scripts/build-sim.sh        # → build/sim/Cinder27.app (arm64 simulator)
python3 scripts/gen_seeds.py     # → seeds/ (the app's built-in seeds, byte-identical to the .py POCs)
```

Device install: bundle id `com.jbjf.cinder27` (v1.0 build 2), unsigned — sign with your own certificate + a matching (or wildcard) provisioning profile, then sideload.

## Verification status

Full 51-module regression (simulator build): **47 done + 4 armed**.

Armed is not a timeout — it is the **death oracle firing**: the payload crashes the process, the journal stays armed, the process vanishes. The cm.rpu / cm.rpu.sweep crash stacks land inside `CMGetDMVersionLevelFromRPU` with SIGSEGV — CVE-2026-112688's struct out-of-bounds write genuinely lands on the simulator build. cg.shading / cg.shading.sweep are R=136 long-overflow ladder sweeps, by design advancing within one process to the fatal rung.

## Module semantics

- **tier 1** — direct primitive hit (OOB write / UAF / type confusion); the crash is the evidence
- **tier 2** — observable signal (info-leak fingerprints, return-code distributions, timing windows); needs a baseline comparison
- **probe / baseline / tool** — environment probes, kernel baseline sampling, device-modification tools (hex editing, xattr / decmpfs surgery, MachO analysis, container / backup / IPA signing / paths / zip)

The app switches zh/en at runtime (`RuntimeText`, 633 fully mapped keys, no hardcoded CJK residue).
