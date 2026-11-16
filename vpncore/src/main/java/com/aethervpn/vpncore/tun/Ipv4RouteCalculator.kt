package com.aethervpn.vpncore.tun

import java.net.Inet4Address
import java.net.InetAddress

/**
 * Canonical IPv4 CIDR block backed by a masked 32-bit network integer.
 */
data class Ipv4Cidr(
    val network: Int,
    val prefixLen: Int
) {
    init {
        require(prefixLen in 0..32) { "Invalid IPv4 prefix length: $prefixLen" }
    }

    val networkLong: Long
        get() = network.toLong() and maskLong(prefixLen)

    val hostAddress: String
        get() {
            val v = networkLong
            return "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"
        }

    fun toInetAddress(): InetAddress {
        val v = networkLong
        return InetAddress.getByAddress(
            byteArrayOf(
                ((v ushr 24) and 0xFF).toByte(),
                ((v ushr 16) and 0xFF).toByte(),
                ((v ushr 8) and 0xFF).toByte(),
                (v and 0xFF).toByte()
            )
        )
    }

    fun contains(ipLong: Long): Boolean {
        val mask = maskLong(prefixLen)
        return (ipLong and mask) == networkLong
    }

    fun contains(addr: InetAddress): Boolean {
        if (addr !is Inet4Address) return false
        return contains(bytesToLong(addr.address))
    }

    companion object {
        fun maskLong(prefixLen: Int): Long =
            if (prefixLen == 0) 0L else ((-1L shl (32 - prefixLen)) and 0xFFFFFFFFL)

        fun bytesToLong(bytes: ByteArray, offset: Int = 0): Long {
            return ((bytes[offset].toLong() and 0xFF) shl 24) or
                ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
                ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
                (bytes[offset + 3].toLong() and 0xFF)
        }

        fun parse(raw: String): Ipv4Cidr? {
            val trimmed = raw.trim().substringBefore('#').trim()
            if (trimmed.isEmpty()) return null
            val slash = trimmed.indexOf('/')
            val ipPart = if (slash >= 0) trimmed.substring(0, slash).trim() else trimmed
            val prefix = if (slash >= 0) {
                trimmed.substring(slash + 1).trim().toIntOrNull() ?: return null
            } else {
                32
            }
            if (prefix !in 0..32) return null

            val octets = ipPart.split('.')
            if (octets.size != 4) return null
            var ipLong = 0L
            for (o in octets) {
                val part = o.toIntOrNull() ?: return null
                if (part !in 0..255) return null
                ipLong = (ipLong shl 8) or part.toLong()
            }
            val masked = ipLong and maskLong(prefix)
            return Ipv4Cidr(masked.toInt(), prefix)
        }
    }
}

/**
 * IPv4 CIDR aggregation, binary-search lookup, and exact trie complement computation
 * for split-tunneling excluded CIDR blocks across all Android API levels (API 24+).
 */
object Ipv4RouteCalculator {

    val LAN_AND_MULTICAST_EXCLUDES: List<Ipv4Cidr> = listOfNotNull(
        Ipv4Cidr.parse("169.254.0.0/16"),
        Ipv4Cidr.parse("172.16.0.0/12"),
        Ipv4Cidr.parse("192.168.0.0/16"),
        Ipv4Cidr.parse("224.0.0.0/4"),
        Ipv4Cidr.parse("255.255.255.255/32")
    )

    private class TrieNode {
        var excluded: Boolean = false
        var left: TrieNode? = null
        var right: TrieNode? = null
    }

    /**
     * Sorts, removes overlapping sub-prefixes, and merges adjacent sibling CIDRs recursively.
     */
    fun coalesce(cidrs: Collection<Ipv4Cidr>): List<Ipv4Cidr> {
        if (cidrs.isEmpty()) return emptyList()
        val sorted = cidrs
            .map { Ipv4Cidr(it.networkLong.toInt(), it.prefixLen) }
            .sortedWith(compareBy<Ipv4Cidr> { it.networkLong }.thenBy { it.prefixLen })

        val stack = ArrayList<Ipv4Cidr>(sorted.size)
        for (current in sorted) {
            val prev = stack.lastOrNull()
            if (prev != null && prev.contains(current.networkLong)) {
                // Current prefix is identical to or strictly inside prev
                continue
            }
            stack.add(current)

            // Merge sibling blocks right back down the stack cleanly
            while (stack.size >= 2) {
                val b = stack[stack.size - 1]
                val a = stack[stack.size - 2]
                if (a.prefixLen != b.prefixLen || a.prefixLen == 0) break

                val bitPos = 32 - a.prefixLen
                val siblingMask = 1L shl bitPos
                val parentMask = Ipv4Cidr.maskLong(a.prefixLen - 1)
                val aParent = a.networkLong and parentMask
                val bParent = b.networkLong and parentMask
                if (aParent == bParent && (a.networkLong xor b.networkLong) == siblingMask) {
                    stack.removeAt(stack.size - 1)
                    stack.removeAt(stack.size - 1)
                    stack.add(Ipv4Cidr(aParent.toInt(), a.prefixLen - 1))
                } else {
                    break
                }
            }
        }
        return stack
    }

    /**
     * Computes the exact minimal set of IPv4 CIDRs covering `0.0.0.0/0 \ excludedCidrs`,
     * used on pre-API 33 Android devices where `VpnService.Builder.excludeRoute` is unavailable.
     */
    fun computeAllowedRoutes(excludedCidrs: Collection<Ipv4Cidr>): List<Ipv4Cidr> {
        val cleanExcluded = coalesce(excludedCidrs)
        if (cleanExcluded.isEmpty()) {
            return listOf(Ipv4Cidr(0, 0))
        }
        if (cleanExcluded.any { it.prefixLen == 0 }) {
            return emptyList()
        }

        val root = TrieNode()
        for (cidr in cleanExcluded) {
            var node = root
            val net = cidr.networkLong
            for (bit in 0 until cidr.prefixLen) {
                if (node.excluded) break
                val goRight = ((net ushr (31 - bit)) and 1L) == 1L
                val next = if (goRight) {
                    node.right ?: TrieNode().also { node.right = it }
                } else {
                    node.left ?: TrieNode().also { node.left = it }
                }
                node = next
            }
            node.excluded = true
            node.left = null
            node.right = null
        }

        val allowed = ArrayList<Ipv4Cidr>()
        collectAllowed(root, 0L, 0, allowed)
        return allowed
    }

    private fun collectAllowed(
        node: TrieNode?,
        prefix: Long,
        depth: Int,
        out: MutableList<Ipv4Cidr>
    ) {
        if (node == null) {
            out.add(Ipv4Cidr(prefix.toInt(), depth))
            return
        }
        if (node.excluded || depth == 32) return

        val shift = 31 - depth
        collectAllowed(node.left, prefix, depth + 1, out)
        collectAllowed(node.right, prefix or (1L shl shift), depth + 1, out)
    }

    /**
     * Checks whether [addr] falls inside a sorted, non-overlapping [sortedCidrs] list via binary search.
     */
    fun containsIp(sortedCidrs: List<Ipv4Cidr>, addr: InetAddress): Boolean {
        if (addr !is Inet4Address || sortedCidrs.isEmpty()) return false
        val target = Ipv4Cidr.bytesToLong(addr.address)
        var lo = 0
        var hi = sortedCidrs.size - 1
        while (lo <= hi) {
            val mid = (lo + hi) ushr 1
            val c = sortedCidrs[mid]
            if (c.contains(target)) return true
            if (c.networkLong < target) {
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }
        return false
    }
}

