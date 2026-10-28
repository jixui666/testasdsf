// arc.rr · libarchive · RockRidge CL/PL · —
// 原语: 探测 · 进程内 · tier 3
// Primitive: probe · in-process · tier 3
//
// [zh] RockRidge 重定位环（未修复孪生）
// 上游已于 2026 年 9 月修复 RockRidge 重定位环导致的无限循环（d14de384fcc6），Apple 未取该提交。该缺陷在 27.0 与 27.2 上均存在，是本工程中唯一一条对当前系统同样成立的候选。
//
// [en] RockRidge relocation cycle (unfixed sibling)
// Upstream fixed the infinite loop caused by a RockRidge relocation cycle in September 2026 (d14de384fcc6)
// and Apple did not take the commit. The defect is present on both 27.0 and 27.2, making it the only
// candidate in this project that also holds on current systems.
// ── 判别 / oracle ──
// 以 Joliet 种子的同级结构构造 CL 指向自身的目录项。该路径一旦成立即会挂起，故测量耗时并设阈值判断。
//
// 种子构建器（python，可直接运行）: arc.rr/arc.rr.py
// runnable python seed builder: arc.rr/arc.rr.py

import Foundation

// ── byte helpers — verbatim from Cinder27 Sources/Kit.swift ──
enum B {
    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
    static func le16(_ v: UInt16) -> [UInt8] { [UInt8(v & 0xff), UInt8(v >> 8 & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]
    }
    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xff), UInt8(v >> 8 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 24 & 0xff)]
    }
    static func be64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (56 - UInt64($0) * 8)) & 0xff) }
    }
    static func le64(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8((v >> (UInt64($0) * 8)) & 0xff) }
    }
    static func both16(_ v: UInt16) -> [UInt8] { le16(v) + be16(v) }
    static func both32(_ v: UInt32) -> [UInt8] { le32(v) + be32(v) }
    static func ascii(_ s: String) -> [UInt8] { Array(s.utf8) }
}



