package com.zhiwei.security.core

/**
 * 极简 DNS / IPv4-UDP 报文处理（域名级拦截的底层）
 *
 * 只做三件事：
 * 1. 从 tun 读到的 IPv4 包里判断是不是去 53 端口的 UDP DNS 查询，并取出域名
 * 2. 造一个 NXDOMAIN 应答包（把查询包的头/问题段原样搬回，翻转地址与端口）
 * 3. 造一个正常应答包（把上游 DNS 的响应体塞进 UDP 回给客户端）
 *
 * 不做 IPv6、不做 TCP DNS、不做 IP 分片重组 —— 域名拦截场景下够用，
 * 且能保证绝不误伤普通流量（普通流量根本不进 tun，见 NetGuardService 路由配置）。
 */
object DnsPacket {

    private const val PROTO_UDP = 17
    private const val DNS_PORT = 53

    /** 判断是否 IPv4 且为 UDP */
    private fun udpOffset(p: ByteArray, len: Int): Int {
        if (len < 28) return -1
        val vihl = p[0].toInt() and 0xFF
        if ((vihl shr 4) != 4) return -1          // 非 IPv4（IPv6 首字节高 4 位是 6）
        val ihl = (vihl and 0x0F) * 4
        if (ihl < 20 || len < ihl + 8) return -1
        if ((p[9].toInt() and 0xFF) != PROTO_UDP) return -1
        return ihl
    }

    /** UDP 目的端口；非 UDP 返回 -1 */
    fun udpDstPort(p: ByteArray, len: Int): Int {
        val ihl = udpOffset(p, len)
        if (ihl < 0) return -1
        return ((p[ihl + 2].toInt() and 0xFF) shl 8) or (p[ihl + 3].toInt() and 0xFF)
    }

    /** 目的 IP（点分十进制）；非法返回 null */
    fun dstIp(p: ByteArray, len: Int): String? {
        if (udpOffset(p, len) < 0) return null
        return "${p[16].toInt() and 0xFF}.${p[17].toInt() and 0xFF}.${p[18].toInt() and 0xFF}.${p[19].toInt() and 0xFF}"
    }

    /** 从 DNS 查询报文里取出被查询域名（小写、不带末尾点）；失败返回 null */
    fun questionName(dns: ByteArray, dnsLen: Int): String? {
        if (dnsLen < 13) return null
        // 只处理标准查询（QR=0）
        if ((dns[2].toInt() and 0x80) != 0) return null
        var pos = 12
        val sb = StringBuilder()
        var guard = 0
        while (pos < dnsLen) {
            if (guard++ > 128) return null
            val l = dns[pos].toInt() and 0xFF
            if (l == 0) break
            // 压缩指针不应出现在问题段；出现即放弃
            if ((l and 0xC0) != 0) return null
            pos++
            if (pos + l > dnsLen) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until l) sb.append((dns[pos + i].toInt() and 0xFF).toChar())
            pos += l
        }
        val name = sb.toString().lowercase()
        return if (name.isEmpty() || name.length > 253) null else name
    }

    /** 查询的 QTYPE（1=A, 28=AAAA, 65=HTTPS…）；失败返回 -1 */
    fun questionType(dns: ByteArray, dnsLen: Int): Int {
        if (dnsLen < 13) return -1
        var pos = 12
        var guard = 0
        while (pos < dnsLen) {
            if (guard++ > 128) return -1
            val l = dns[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if ((l and 0xC0) != 0) return -1
            pos += l + 1
        }
        if (pos + 4 > dnsLen) return -1
        return ((dns[pos].toInt() and 0xFF) shl 8) or (dns[pos + 1].toInt() and 0xFF)
    }

    /** 问题段结束位置（用于构造应答时原样拷贝） */
    private fun questionEnd(dns: ByteArray, dnsLen: Int): Int {
        var pos = 12
        var guard = 0
        while (pos < dnsLen) {
            if (guard++ > 128) return -1
            val l = dns[pos].toInt() and 0xFF
            if (l == 0) { pos++; break }
            if ((l and 0xC0) != 0) return -1
            pos += l + 1
        }
        return if (pos + 4 <= dnsLen) pos + 4 else -1
    }

    /**
     * 生成 NXDOMAIN 应答体（纯 DNS，不含 IP/UDP 头）
     * flags: QR=1, RD=1, RA=1, RCODE=3(NXDOMAIN) → 0x8183
     */
    fun buildNxDomain(query: ByteArray, queryLen: Int): ByteArray? {
        val qEnd = questionEnd(query, queryLen)
        if (qEnd < 0) return null
        val out = ByteArray(qEnd)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = 0x81.toByte()   // QR=1, Opcode=0, AA=0, TC=0, RD=1
        out[3] = 0x83.toByte()   // RA=1, Z=0, RCODE=3
        out[4] = 0; out[5] = 1   // QDCOUNT=1
        out[6] = 0; out[7] = 0   // ANCOUNT=0
        out[8] = 0; out[9] = 0   // NSCOUNT=0
        out[10] = 0; out[11] = 0 // ARCOUNT=0（丢掉 EDNS，避免大包）
        return out
    }

    /**
     * 用响应体构造回给客户端的完整 IPv4/UDP 包。
     * 做法：拷贝查询包的 IP 头 → 源/目的 IP 互换 → 重算 IP 头校验和 →
     * UDP 头源/目的端口互换、校验和置 0（IPv4 允许 UDP 校验和为 0）。
     */
    fun buildUdpResponse(query: ByteArray, queryLen: Int, payload: ByteArray, payloadLen: Int): ByteArray? {
        val ihl = udpOffset(query, queryLen)
        if (ihl < 0) return null
        val total = ihl + 8 + payloadLen
        val out = ByteArray(total)

        // IP 头（含选项，原样拷贝后改字段）
        System.arraycopy(query, 0, out, 0, ihl)
        out[2] = ((total shr 8) and 0xFF).toByte()
        out[3] = (total and 0xFF).toByte()
        out[10] = 0; out[11] = 0   // 清 fragmentation 字段
        // 地址互换
        for (i in 0 until 4) {
            out[12 + i] = query[16 + i]
            out[16 + i] = query[12 + i]
        }
        // IP 头校验和
        out[10] = 0; out[11] = 0
        var sum = 0
        var i = 0
        while (i < ihl) {
            sum += ((out[i].toInt() and 0xFF) shl 8) or (out[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val ck = sum.inv() and 0xFFFF
        out[10] = ((ck shr 8) and 0xFF).toByte()
        out[11] = (ck and 0xFF).toByte()

        // UDP 头：源端口 = 原目的端口(53)，目的端口 = 原源端口
        out[ihl] = query[ihl + 2]
        out[ihl + 1] = query[ihl + 3]
        out[ihl + 2] = query[ihl]
        out[ihl + 3] = query[ihl + 1]
        val udpLen = 8 + payloadLen
        out[ihl + 4] = ((udpLen shr 8) and 0xFF).toByte()
        out[ihl + 5] = (udpLen and 0xFF).toByte()
        out[ihl + 6] = 0
        out[ihl + 7] = 0

        System.arraycopy(payload, 0, out, ihl + 8, payloadLen)
        return out
    }

    /** UDP 载荷（DNS 报文）在包内的起始偏移；失败返回 -1 */
    fun payloadOffset(p: ByteArray, len: Int): Int {
        val ihl = udpOffset(p, len)
        if (ihl < 0) return -1
        val udpLen = ((p[ihl + 4].toInt() and 0xFF) shl 8) or (p[ihl + 5].toInt() and 0xFF)
        if (udpLen < 8) return -1
        val end = minOf(len, ihl + udpLen)
        if (end <= ihl + 8) return -1
        return ihl + 8
    }

    /**
     * 从 DNS 查询包构造黑洞应答：直接 A 记录 0.0.0.0
     * 部分客户端不认 NXDOMAIN（会换 DoH 重试），A=0.0.0.0 兼容性更好。
     * 仅对 QTYPE=A 生效，其余仍走 NXDOMAIN。
     */
    fun buildZeroAnswer(query: ByteArray, queryLen: Int): ByteArray? {
        if (questionType(query, queryLen) != 1) return buildNxDomain(query, queryLen)
        val qEnd = questionEnd(query, queryLen)
        if (qEnd < 0) return null
        val out = ByteArray(qEnd + 16)
        System.arraycopy(query, 0, out, 0, qEnd)
        out[2] = 0x81.toByte()
        out[3] = 0x80.toByte()   // NOERROR
        out[4] = 0; out[5] = 1
        out[6] = 0; out[7] = 1   // ANCOUNT=1
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0
        var p = qEnd
        // 指向问题段的压缩指针
        out[p++] = 0xC0.toByte(); out[p++] = 0x0C
        out[p++] = 0; out[p++] = 1               // TYPE=A
        out[p++] = 0; out[p++] = 1               // CLASS=IN
        out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 60  // TTL=60s
        out[p++] = 0; out[p++] = 4               // RDLENGTH=4
        out[p++] = 0; out[p++] = 0; out[p++] = 0; out[p++] = 0   // 0.0.0.0
        return out
    }

    const val DNS_PORT_NUM = DNS_PORT
}
