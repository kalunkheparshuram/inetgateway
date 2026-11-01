# SPDX-License-Identifier: GPL-3.0-or-later
import json, os, queue, sys, random, socket, struct, tempfile, unittest
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import inetgateway as lg

ME, GW = b"\x02\x00\x00\x00\x00\x01", b"\x02\x00\x00\x00\x00\xfe"


def _w(path, blob):
    with open(path, "wb") as fh:
        fh.write(blob)


def eth4(ip):
    return lg.build_ethernet(GW, ME, 0x0800, ip)


class DecodeTests(unittest.TestCase):
    def test_tcp_syn_ack(self):
        pkt = eth4(lg.build_ipv4("10.0.0.2", "93.184.216.34", 6, lg.build_tcp(51000, 443, 7, 9, 0x12)))
        d = lg.decode(pkt, lg.LINK_ETHERNET, detail=True)
        self.assertEqual((d.proto, d.l4, d.src, d.dst, d.sport, d.dport), ("TCP", "tcp", "10.0.0.2", "93.184.216.34", 51000, 443))
        self.assertIn("[SYN,ACK]", d.info)
        self.assertEqual(d.ipver, 4)
        self.assertTrue(any(t == "Transmission Control Protocol" for t, _ in d.layers))

    def test_tcp_payload_length_from_ip_header_not_capture(self):
        full = lg.build_ipv4("10.0.0.2", "10.0.0.3", 6, lg.build_tcp(1, 2, 0, 0, 0x10, b"z" * 500))
        d = lg.decode(full[:60], lg.LINK_RAW)  # snaplen-truncated
        self.assertIn("Len=500", d.info)

    def test_udp_dns_query(self):
        ip = lg.build_ipv4("10.0.0.2", "10.0.0.1", 17, lg.build_udp(5000, 53, lg.build_dns_query("Example.Test", 28)))
        d = lg.decode(eth4(ip), lg.LINK_ETHERNET)
        self.assertEqual(d.proto, "DNS")
        self.assertEqual(d.l4, "udp")
        self.assertIn("AAAA", d.info)
        self.assertIn("Example.Test", d.info)

    def test_ipv6_udp(self):
        ip6 = lg.build_ipv6("fe80::1", "ff02::fb", 17, lg.build_udp(5353, 5353, lg.build_dns_query("printer.local")))
        d = lg.decode(lg.build_ethernet(GW, ME, 0x86DD, ip6), lg.LINK_ETHERNET)
        self.assertEqual((d.ipver, d.src, d.dst, d.proto), (6, "fe80::1", "ff02::fb", "MDNS"))

    def test_ipv6_extension_header_skipped(self):
        hop = bytes([17, 0]) + b"\x00" * 6  # next=UDP, len=0 -> 8 bytes
        ip6 = lg.build_ipv6("2001:db8::1", "2001:db8::2", 0, hop + lg.build_udp(1000, 2000, b"hi"))
        d = lg.decode(ip6, lg.LINK_RAW)
        self.assertEqual((d.proto, d.sport, d.dport), ("UDP", 1000, 2000))

    def test_ipv4_mapped_and_arp(self):
        arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, ME, socket.inet_aton("10.0.0.2"), b"\0" * 6, socket.inet_aton("10.0.0.1"))
        d = lg.decode(lg.build_ethernet(b"\xff" * 6, ME, 0x0806, arp), lg.LINK_ETHERNET)
        self.assertEqual(d.proto, "ARP")
        self.assertEqual(d.info, "Who has 10.0.0.1? Tell 10.0.0.2")

    def test_icmp(self):
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 1, b"\x08\x00\x00\x00\x00\x01\x00\x01"), lg.LINK_RAW)
        self.assertEqual(d.proto, "ICMP")
        self.assertIn("Echo request", d.info)

    def test_fragment_not_parsed_as_l4(self):
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0x00B9, 64, 6, 0, socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"))
        d = lg.decode(hdr + b"\0" * 20, lg.LINK_RAW)
        self.assertIsNone(d.l4)
        self.assertIn("Fragmented", d.info)

    def test_offload_total_length_zero(self):
        ip = bytearray(lg.build_ipv4("1.1.1.1", "2.2.2.2", 6, lg.build_tcp(1, 2, 0, 0, 0x10, b"abc")))
        ip[2:4] = b"\0\0"
        d = lg.decode(bytes(ip), lg.LINK_RAW)
        self.assertEqual(d.proto, "TCP")
        self.assertIn("Len=3", d.info)

    def test_truncated_inputs_do_not_raise(self):
        pkt = eth4(lg.build_ipv4("10.0.0.2", "10.0.0.3", 6, lg.build_tcp(1, 2, 0, 0, 2)))
        for n in range(len(pkt) + 1):
            for lt in (0, 1, 101, 999):
                lg.decode(pkt[:n], lt, detail=True)

    def test_fuzz_random_bytes_never_raise(self):
        rnd = random.Random(7)
        for _ in range(5000):
            b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 120)))
            for lt in (0, 1, 101):
                lg.decode(b, lt, detail=True)

    def test_fuzz_mutated_valid_packets(self):
        rnd = random.Random(9)
        base = eth4(lg.build_ipv4("10.0.0.2", "10.0.0.1", 17, lg.build_udp(5000, 53, lg.build_dns_query("a.b.c"))))
        for _ in range(5000):
            b = bytearray(base)
            for _ in range(rnd.randrange(1, 6)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            lg.decode(bytes(b), lg.LINK_ETHERNET, detail=True)

    def test_dns_pointer_loop_rejected(self):
        hdr = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
        loop = hdr + b"\xc0\x0c" + struct.pack("!HH", 1, 1)  # pointer to itself
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(1, 53, loop)), lg.LINK_RAW)
        self.assertEqual(d.proto, "UDP")  # not DNS, summary kept

    def test_dns_compression_pointer_is_relative_to_dns_message(self):
        hdr = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        qname = b"\x03www\x07example\x04test\x00"
        msg = hdr + qname + struct.pack("!HH", 1, 1) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x01\x02\x03\x04"
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(53, 4000, msg)), lg.LINK_RAW)
        self.assertEqual(d.proto, "DNS")
        self.assertIn("www.example.test", d.info)
        # a pointer in the QUESTION name must resolve inside the DNS message, not the IP header
        q2 = hdr + b"\x03abc\xc0\x16" + struct.pack("!HH", 1, 1) + b"\x03xyz\x00"
        d2 = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(4000, 53, q2)), lg.LINK_RAW)
        self.assertIn("abc.xyz", d2.info)

    def test_untrusted_strings_sanitised(self):
        q = lg.build_dns_query("a\x1b[31mb.test")
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(1, 53, q)), lg.LINK_RAW)
        self.assertNotIn("\x1b", d.info)

    def test_null_link_loopback(self):
        ip = lg.build_ipv4("127.0.0.1", "127.0.0.1", 6, lg.build_tcp(1, 2, 0, 0, 2))
        d = lg.decode(struct.pack("<I", 2) + ip, lg.LINK_NULL)
        self.assertEqual((d.proto, d.src), ("TCP", "127.0.0.1"))

    def test_hexdump(self):
        out = lg.hexdump(bytes(range(32, 50)))
        self.assertTrue(out.startswith("0000  20 21 22"))
        self.assertEqual(len(out.splitlines()), 2)


class FilterTests(unittest.TestCase):
    def setUp(self):
        def mk(ip):
            d = lg.decode(ip, lg.LINK_RAW)
            return lg.Packet(1.0, ip, len(ip), d, "chrome.exe (42)" if d.dport == 443 else "")
        self.tcp = mk(lg.build_ipv4("10.0.0.2", "93.184.216.34", 6, lg.build_tcp(51000, 443, 0, 0, 2)))
        self.dns = mk(lg.build_ipv4("10.0.0.2", "10.0.0.1", 17, lg.build_udp(5000, 53, lg.build_dns_query("x.test"))))
        self.v6 = mk(lg.build_ipv6("2001:db8::1", "2001:db8::2", 17, lg.build_udp(1, 2, b"")))

    def f(self, text, p):
        return lg.compile_filter(text)(p)

    def test_protocols(self):
        self.assertTrue(self.f("tcp", self.tcp))
        self.assertFalse(self.f("tcp", self.dns))
        self.assertTrue(self.f("udp", self.dns) and self.f("dns", self.dns))
        self.assertTrue(self.f("ipv6", self.v6) and not self.f("ipv6", self.tcp))

    def test_fields(self):
        self.assertTrue(self.f("ip==93.184.216.34", self.tcp))
        self.assertTrue(self.f("port==443", self.tcp) and not self.f("port==80", self.tcp))
        self.assertTrue(self.f("proc==CHROME", self.tcp))
        self.assertTrue(self.f("ip==2001:0db8:0:0:0:0:0:2", self.v6))
        self.assertTrue(self.f("len>20", self.tcp) and not self.f("len>2000", self.tcp))

    def test_and_and_negation(self):
        self.assertTrue(self.f("tcp port==443", self.tcp))
        self.assertFalse(self.f("tcp port==53", self.tcp))
        self.assertTrue(self.f("!udp", self.tcp) and not self.f("!udp", self.dns))
        self.assertTrue(self.f("x.test", self.dns))

    def test_empty_matches_all(self):
        self.assertTrue(self.f("   ", self.tcp))

    def test_invalid_filters_raise(self):
        for bad in ("ip==999.1.1.1", "port==99999", "port==abc", "foo==1", "!", "proc==", "ip=="):
            with self.assertRaises(ValueError, msg=bad):
                lg.compile_filter(bad)


class StoreAndPipelineTests(unittest.TestCase):
    def test_store_bounded_and_contiguous(self):
        s = lg.PacketStore(5)
        d = lg.Decoded()
        for _ in range(12):
            s.add(lg.Packet(1.0, b"", 0, d))
        self.assertEqual((len(s), s.total), (5, 12))
        self.assertIsNone(s.get(7))
        self.assertEqual(s.get(8).no, 8)
        self.assertEqual(s.get(12).no, 12)

    def test_queue_bound_counts_drops(self):
        q = queue.Queue(10)
        p = lg.Pipeline(lg.LINK_RAW, 128, q)
        pkt = lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(1, 2, b"x"))
        for _ in range(25):
            p.feed(1.0, pkt, len(pkt))
        self.assertEqual((q.qsize(), p.dropped), (10, 15))

    def test_snaplen_truncates_storage_not_wirelen(self):
        q = queue.Queue(10)
        p = lg.Pipeline(lg.LINK_RAW, 64, q)
        pkt = lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(1, 2, b"x" * 1000))
        p.feed(1.0, pkt, len(pkt))
        got = q.get_nowait()
        self.assertEqual((len(got.raw), got.wirelen), (64, len(pkt)))


class AttributionTests(unittest.TestCase):
    def mk(self):
        a = lg.Attributor(lg.ProcessNames(lambda pid: {42: r"C:\Program Files\App\app.exe"}.get(pid)))
        return a

    def test_parse_tcp4_and_attribute_both_directions(self):
        def port(p):
            return ((p & 0xFF) << 8) | (p >> 8)
        row = struct.pack("<I4sI4sII", 5, socket.inet_aton("10.0.0.2"), port(51000), socket.inet_aton("93.184.216.34"), port(443), 42)
        tcp = lg.parse_tcp_table(struct.pack("<I", 1) + row, False)
        self.assertEqual(tcp, {("10.0.0.2", 51000, "93.184.216.34", 443): 42})
        a = self.mk()
        a.update(tcp, {})
        out = lg.decode(lg.build_ipv4("10.0.0.2", "93.184.216.34", 6, lg.build_tcp(51000, 443, 0, 0, 2)), lg.LINK_RAW)
        inc = lg.decode(lg.build_ipv4("93.184.216.34", "10.0.0.2", 6, lg.build_tcp(443, 51000, 0, 0, 0x12)), lg.LINK_RAW)
        self.assertEqual(a.lookup(out)[0], "app.exe (42)")
        self.assertEqual(a.lookup(inc)[0], "app.exe (42)")

    def test_unknown_stays_blank_no_guessing(self):
        a = self.mk()
        a.update({("10.0.0.2", 51000, "93.184.216.34", 443): 42}, {})
        other = lg.decode(lg.build_ipv4("10.0.0.2", "93.184.216.34", 6, lg.build_tcp(51001, 443, 0, 0, 2)), lg.LINK_RAW)
        self.assertEqual(a.lookup(other), ("", ""))

    def test_udp_local_port_and_ambiguity(self):
        def port(p):
            return ((p & 0xFF) << 8) | (p >> 8)
        buf = struct.pack("<I", 1) + struct.pack("<4sII", b"\0\0\0\0", port(5000), 42)
        udp = lg.parse_udp_table(buf, False)
        a = self.mk()
        a.update({}, udp)
        d = lg.decode(lg.build_ipv4("10.0.0.2", "10.0.0.1", 17, lg.build_udp(5000, 9999, b"")), lg.LINK_RAW)
        label, why = a.lookup(d)
        self.assertEqual(label, "app.exe (42)")
        self.assertIn("lower confidence", why)
        a.update({}, {5000: [("0.0.0.0", 42), ("0.0.0.0", 43)]})
        self.assertEqual(a.lookup(d), ("", ""))

    def test_parse_v6_tables(self):
        la, ra = ipaddress_bytes("2001:db8::1"), ipaddress_bytes("2001:db8::2")
        row = struct.pack("<16sII16sIIII", la, 0, 0x5000, ra, 0, 0xBB01, 5, 99)
        t = lg.parse_tcp_table(struct.pack("<I", 1) + row, True)
        self.assertEqual(list(t.values()), [99])
        urow = struct.pack("<16sIII", la, 0, 0x3500, 77)
        u = lg.parse_udp_table(struct.pack("<I", 1) + urow, True)
        self.assertEqual(u[53], [("2001:db8::1", 77)])

    def test_table_parsers_tolerate_garbage(self):
        rnd = random.Random(3)
        for _ in range(500):
            b = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
            for v6 in (False, True):
                lg.parse_tcp_table(b, v6)
                lg.parse_udp_table(b, v6)

    def test_special_pids(self):
        n = lg.ProcessNames(lambda pid: None)
        self.assertEqual(n.get(4)[0], "System")
        a = lg.Attributor(n)
        a.update({("1.1.1.1", 1, "2.2.2.2", 2): 1234}, {})
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 6, lg.build_tcp(1, 2, 0, 0, 2)), lg.LINK_RAW)
        self.assertEqual(a.lookup(d)[0], "PID 1234")


def ipaddress_bytes(s):
    import ipaddress
    return ipaddress.IPv6Address(s).packed


class FileTests(unittest.TestCase):
    def test_csv_injection_escaped_and_rows(self):
        d = lg.Decoded()
        d.src, d.dst, d.proto, d.info = "=cmd|calc", "@x", "TCP", "-1+1"
        p = lg.Packet(10.5, b"", 60, d, "+proc")
        p.no = 1
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "o.csv")
            lg.export_csv(path, [p], 10.0)
            with open(path, encoding="utf-8-sig") as fh:
                rows = fh.read().splitlines()
        self.assertEqual(len(rows), 2)
        self.assertIn("'=cmd|calc", rows[1])
        self.assertIn("'@x", rows[1])
        self.assertIn("'+proc", rows[1])
        self.assertIn("'-1+1", rows[1])
        self.assertIn("0.500000", rows[1])

    def test_pcap_round_trip(self):
        pkts = []
        for i in range(3):
            raw = lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(i, 2, b"p" * (i + 1)))
            p = lg.Packet(1700000000.25 + i, raw, len(raw) + 5, lg.decode(raw, lg.LINK_RAW))
            pkts.append(p)
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "o.pcap")
            lg.write_pcap(path, pkts, lg.LINK_RAW, 65535)
            lt, snap, got = lg.read_pcap(path)
            self.assertFalse(os.path.exists(path + ".tmp"))
        self.assertEqual((lt, snap, len(got)), (lg.LINK_RAW, 65535, 3))
        for p, (ts, data, wl) in zip(pkts, got):
            self.assertEqual((data, wl), (p.raw, p.wirelen))
            self.assertAlmostEqual(ts, p.ts, places=5)

    def test_pcap_rejects_bad_files(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "bad.pcap")
            for blob in (b"", b"x" * 10, b"\x0a\x0d\x0d\x0a" + b"\0" * 40):  # last one is pcapng magic
                _w(path, blob)
                with self.assertRaises(ValueError):
                    lg.read_pcap(path)
            hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
            _w(path, hdr + struct.pack("<IIII", 0, 0, 10**9, 10**9))
            with self.assertRaises(ValueError):
                lg.read_pcap(path)
            _w(path, hdr + struct.pack("<IIII", 0, 0, 100, 100) + b"short")
            self.assertEqual(lg.read_pcap(path)[2], [])  # truncated final record is dropped, no crash


class ConfigTests(unittest.TestCase):
    def test_defaults_when_missing(self):
        with tempfile.TemporaryDirectory() as t:
            cfg, warn = lg.load_config(os.path.join(t, "c.json"))
        self.assertEqual(cfg, lg.DEFAULT_CONFIG)
        self.assertIsNone(warn)

    def test_round_trip_and_theme_persist(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "sub", "c.json")
            cfg = dict(lg.DEFAULT_CONFIG, theme="dark", snaplen=256)
            self.assertTrue(lg.save_config(cfg, path))
            got, warn = lg.load_config(path)
            self.assertEqual((got["theme"], got["snaplen"], warn), ("dark", 256, None))
            self.assertEqual([f for f in os.listdir(os.path.dirname(path)) if f.endswith(".tmp")], [])


    def test_config_dir_override_for_tests(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("INETGATEWAY_CONFIG_DIR")
            os.environ["INETGATEWAY_CONFIG_DIR"] = d
            try:
                self.assertEqual(lg.config_dir(), d)
                self.assertTrue(lg.KeyStore().path.startswith(d))
                self.assertTrue(lg.IntelCache().path.startswith(d))
            finally:
                if old is None:
                    os.environ.pop("INETGATEWAY_CONFIG_DIR", None)
                else:
                    os.environ["INETGATEWAY_CONFIG_DIR"] = old
        self.assertIn("InetGateway", lg.config_dir())

    def test_corrupt_file_set_aside(self):
        with tempfile.TemporaryDirectory() as t:
            path = os.path.join(t, "c.json")
            _w(path, b"{not json")
            cfg, warn = lg.load_config(path)
            self.assertEqual(cfg, lg.DEFAULT_CONFIG)
            self.assertIn("config.json.bad", warn)
            self.assertTrue(os.path.exists(path + ".bad"))

    def test_validation_rejects_bad_values(self):
        cfg = lg.validate_config({"theme": "neon", "snaplen": 5, "max_packets": "lots", "promiscuous": "yes",
                                  "interface": "x" * 999, "extra": 1})
        self.assertEqual(cfg, lg.DEFAULT_CONFIG)
        self.assertEqual(lg.validate_config([1, 2]), lg.DEFAULT_CONFIG)
        self.assertEqual(lg.validate_config({"snaplen": True})["snaplen"], lg.DEFAULT_CONFIG["snaplen"])


L = "10.0.0.2"


def mkpkt(src, dst, proto, payload, proc="", ts=1000.0, wire=None):
    ip = lg.build_ipv4(src, dst, proto, payload) if ":" not in src else lg.build_ipv6(src, dst, proto, payload)
    d = lg.decode(ip, lg.LINK_RAW)
    return lg.Packet(ts, ip, wire or len(ip), d, proc)


class DashboardStatsTests(unittest.TestCase):
    def setUp(self):
        self.st = lg.Stats({L, "fe80::2"})

    def test_app_name_grouping(self):
        self.assertEqual(lg.app_name("chrome.exe (123)"), "chrome.exe")
        self.assertEqual(lg.app_name("svchost.exe [Dnscache, NlaSvc] (9)"), "svchost.exe [Dnscache, NlaSvc]")
        self.assertEqual(lg.app_name("PID 77"), "PID 77")
        self.assertEqual(lg.app_name(""), lg.UNATTRIBUTED)

    def test_direction_counts_and_bytes(self):
        out = mkpkt(L, "93.184.216.34", 6, lg.build_tcp(50000, 443, 1, 1, 0x10, b"a" * 100), "a.exe (1)", wire=200)
        inn = mkpkt("93.184.216.34", L, 6, lg.build_tcp(443, 50000, 1, 1, 0x10, b"b" * 300), "a.exe (1)", wire=400)
        for p in (out, inn):
            self.st.add(p)
        a = self.st.apps["a.exe"]
        self.assertEqual((a.sent_pkts, a.sent_bytes, a.recv_pkts, a.recv_bytes), (1, 200, 1, 400))
        self.assertEqual((self.st.sent_bytes, self.st.recv_bytes, self.st.other_pkts), (200, 400, 0))

    def test_flow_merges_both_directions_and_ephemeral_ports(self):
        for lp in (50000, 50001):
            self.st.add(mkpkt(L, "1.2.3.4", 6, lg.build_tcp(lp, 443, 1, 1, 0x10), "a.exe (1)", wire=100))
            self.st.add(mkpkt("1.2.3.4", L, 6, lg.build_tcp(443, lp, 1, 1, 0x10), "a.exe (1)", wire=300))
        self.assertEqual(len(self.st.flows), 1)
        f = next(iter(self.st.flows.values()))
        self.assertEqual((f.from_ip, f.to_ip, f.rport, f.fwd_pkts, f.fwd_bytes, f.rev_pkts, f.rev_bytes),
                         (L, "1.2.3.4", 443, 2, 200, 2, 600))

    def test_connection_opened_counts_only_outbound_syn(self):
        self.st.add(mkpkt(L, "1.2.3.4", 6, lg.build_tcp(50000, 443, 1, 0, 0x02), "a.exe (1)"))
        self.st.add(mkpkt("1.2.3.4", L, 6, lg.build_tcp(443, 50000, 1, 2, 0x12), "a.exe (1)"))  # SYN-ACK
        self.st.add(mkpkt("1.2.3.4", L, 6, lg.build_tcp(443, 51000, 1, 0, 0x02), "a.exe (1)"))  # inbound SYN
        self.assertEqual(self.st.apps["a.exe"].conns, 1)

    def test_unknown_local_addresses_never_guess_direction(self):
        st = lg.Stats(())
        st.add(mkpkt(L, "1.2.3.4", 17, lg.build_udp(1, 2, b"x")))
        self.assertEqual((st.sent_pkts, st.recv_pkts, st.other_pkts), (0, 0, 1))
        st2 = lg.Stats({L})
        st2.add(mkpkt("8.8.8.8", "9.9.9.9", 17, lg.build_udp(1, 2, b"x")))  # neither side is this PC
        self.assertEqual(st2.other_pkts, 1)

    def test_incoming_broadcast_and_multicast_count_as_received(self):
        self.st.add(mkpkt("10.0.0.9", "10.0.0.255", 17, lg.build_udp(137, 137, b"x")))
        self.st.add(mkpkt("10.0.0.9", "224.0.0.251", 17, lg.build_udp(5353, 5353, b"x")))
        self.assertEqual(self.st.recv_pkts, 2)

    def test_ipv6_direction(self):
        self.st.add(mkpkt("fe80::2", "ff02::fb", 17, lg.build_udp(5353, 5353, b"x")))
        self.assertEqual(self.st.sent_pkts, 1)

    def test_dns_query_response_counts_and_answers_learned(self):
        q = mkpkt(L, "10.0.0.1", 17, lg.build_udp(5000, 53, lg.build_dns_query("example.test")), "svchost.exe [Dnscache] (5)")
        r = mkpkt("10.0.0.1", L, 17, lg.build_udp(53, 5000, lg.build_dns_response("example.test", "93.184.216.34")),
                  "svchost.exe [Dnscache] (5)")
        self.assertEqual(r.answers, [("example.test", "93.184.216.34")])
        self.assertIn("-> 93.184.216.34", r.info)
        for p in (q, r):
            self.st.add(p)
        a = self.st.apps["svchost.exe [Dnscache]"]
        self.assertEqual((a.dns_q, a.dns_r), (1, 1))
        self.assertEqual(lg.endpoint_label("93.184.216.34", self.st.local, {"93.184.216.34": "example.test"}),
                         "example.test (93.184.216.34)")
        self.assertEqual(lg.endpoint_label(L, self.st.local, {}), "This PC (10.0.0.2)")
        self.assertEqual(lg.endpoint_label("1.1.1.1", self.st.local, {}), "1.1.1.1")

    def test_dns_answer_parsing_survives_truncation_and_garbage(self):
        full = lg.build_dns_response("example.test", "1.2.3.4")
        for n in range(len(full) + 1):
            d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(53, 4000, full[:n])), lg.LINK_RAW, detail=True)
            self.assertIsInstance(d.dns_answers, list)
        rnd = random.Random(5)
        for _ in range(3000):
            b = bytearray(full)
            for _ in range(rnd.randrange(1, 5)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(53, 4000, bytes(b))), lg.LINK_RAW, detail=True)

    def test_error_responses_do_not_teach_names(self):
        msg = bytearray(lg.build_dns_response("example.test", "1.2.3.4"))
        msg[3] = (msg[3] & 0xF0) | 3  # rcode NXDOMAIN
        d = lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 17, lg.build_udp(53, 4000, bytes(msg))), lg.LINK_RAW)
        self.assertEqual(d.dns_answers, [])

    def test_series_window_and_bounded_growth(self):
        self.st.add(mkpkt(L, "1.2.3.4", 17, lg.build_udp(1, 2, b""), ts=1000.2, wire=100))
        self.st.add(mkpkt("1.2.3.4", L, 17, lg.build_udp(2, 1, b""), ts=1002.7, wire=50))
        sent, recv = self.st.series_window(1002, 4)
        self.assertEqual((sent, recv), ([0, 100, 0, 0], [0, 0, 0, 50]))
        for i in range(3000):
            self.st.add(mkpkt(L, "1.2.3.4", 17, lg.build_udp(1, 2, b""), ts=2000.0 + i))
        self.assertLess(len(self.st.series), lg.SERIES_KEEP * 2 + 5)

    def test_flow_and_app_tables_are_bounded(self):
        st = lg.Stats({L})
        for i in range(lg.MAX_FLOWS + 300):
            ip = "10.%d.%d.%d" % ((i >> 16) & 255, (i >> 8) & 255, i & 255)
            st.add(mkpkt(L, ip, 17, lg.build_udp(1, 2, b""), ts=1000.0 + i))
        self.assertLessEqual(len(st.flows), lg.MAX_FLOWS)
        for i in range(lg.MAX_APPS + 100):
            st.add(mkpkt(L, "1.2.3.4", 17, lg.build_udp(1, 2, b""), "app%d.exe (1)" % i, ts=5000.0 + i))
        self.assertLessEqual(len(st.apps), lg.MAX_APPS)

    def test_sorting_and_reset(self):
        self.st.add(mkpkt(L, "1.1.1.1", 17, lg.build_udp(1, 2, b""), "small.exe (1)", wire=10))
        self.st.add(mkpkt(L, "1.1.1.1", 17, lg.build_udp(1, 2, b""), "big.exe (2)", wire=9000))
        self.assertEqual([a.name for a in self.st.apps_sorted()], ["big.exe", "small.exe"])
        self.assertEqual(len(self.st.flows_sorted("big.exe")), 1)
        self.st.reset()
        self.assertEqual((len(self.st.apps), len(self.st.flows), self.st.sent_bytes), (0, 0, 0))

    def test_helpers(self):
        self.assertEqual(lg.fmt_bytes(0), "0 B")
        self.assertEqual(lg.fmt_bytes(1536), "1.5 KB")
        self.assertEqual(lg.fmt_rate(2 * 1024 * 1024), "2.0 MB/s")
        self.assertEqual([lg.nice_ceiling(v) for v in (0, 0.5, 1, 3, 7, 120, 5001)], [1, 0.5, 1, 5, 10, 200, 10000])
        self.assertEqual(lg.top_n_slices([("a", 5), ("b", 3), ("c", 2), ("d", 1), ("z", 0)], 2),
                         [("a", 5), ("b", 3), ("Other", 3)])
        self.assertEqual(lg.top_n_slices([], 3), [])

    def test_tasklist_service_parsing(self):
        out = ('"svchost.exe","1234","Dnscache,NlaSvc"\r\n"notepad.exe","55","N/A"\r\n'
               '"spoolsv.exe","900","Spooler"\r\nbroken line\r\n"x","abc","y"\r\n')
        m = lg.parse_tasklist_svc(out)
        self.assertEqual(m, {1234: "Dnscache, NlaSvc", 900: "Spooler"})
        long = '"svchost.exe","7","%s"' % ",".join("Service%d" % i for i in range(40))
        self.assertLessEqual(len(lg.parse_tasklist_svc(long)[7]), 60)

    def test_attributor_service_label_and_local_addrs(self):
        n = lg.ProcessNames(lambda pid: r"C:\Windows\System32\svchost.exe")
        n.services = {7: "Dnscache"}
        a = lg.Attributor(n)
        a.update({(L, 50000, "1.2.3.4", 443): 7}, {5353: [("0.0.0.0", 7), ("fe80::2", 7)]})
        self.assertEqual(a.local_addrs, {L, "fe80::2"})
        d = lg.decode(lg.build_ipv4(L, "1.2.3.4", 6, lg.build_tcp(50000, 443, 0, 0, 2)), lg.LINK_RAW)
        label = a.lookup(d)[0]
        self.assertEqual(label, "svchost.exe [Dnscache] (7)")
        self.assertEqual(lg.app_name(label), "svchost.exe [Dnscache]")

    def test_demo_traffic_produces_named_software(self):
        import threading
        q = queue.Queue(5000)
        pipe = lg.Pipeline(lg.LINK_ETHERNET, 128, q, lg.make_demo_attributor())
        stop = threading.Event()
        be = lg.DemoBackend()
        th = threading.Thread(target=be.run, args=(pipe.feed, stop))
        th.start()
        import time
        time.sleep(1.5)
        stop.set()
        th.join(3)
        st = lg.Stats({lg.DemoBackend.LOCAL})
        while not q.empty():
            st.add(q.get())
        names = set(st.apps)
        self.assertIn("browser.exe", names)
        self.assertGreater(st.sent_pkts, 0)
        self.assertGreater(st.recv_pkts, 0)


def vt_body(mal=0, sus=0, har=50, und=10, **extra):
    attrs = {"last_analysis_stats": {"malicious": mal, "suspicious": sus, "harmless": har, "undetected": und}}
    attrs.update(extra)
    return json.dumps({"data": {"attributes": attrs}}).encode()


class FakeClock:
    def __init__(self):
        self.t = 1_700_000_000.0
        self.waits = []

    def __call__(self):
        return self.t

    def wait(self, secs):
        self.waits.append(secs)
        self.t += secs
        return False


def forbid_real_network(*a, **k):
    raise AssertionError("the real network must not be used in tests")


class IntelParsingTests(unittest.TestCase):
    def test_classify_indicator(self):
        self.assertEqual(lg.classify_indicator(" 8.8.8.8 "), ("ip", "8.8.8.8"))
        self.assertEqual(lg.classify_indicator("2001:4860:4860::8888"), ("ip", "2001:4860:4860::8888"))
        self.assertEqual(lg.classify_indicator("Example.COM."), ("domain", "example.com"))
        self.assertEqual(lg.classify_indicator("44D88612FEA8A8F36DE82E1278ABB02F"), ("file", "44d88612fea8a8f36de82e1278abb02f"))
        h = "a" * 64
        self.assertEqual(lg.classify_indicator(h), ("file", h))
        for bad in ("", "   ", "10.0.0.1", "192.168.1.5", "127.0.0.1", "::1", "printer.local", "nas.home.arpa",
                    "not a domain", "http://example.com/x", "a" * 300, "evil.com/../../x", "x;rm -rf", "1.2.3", "ab12"):
            with self.assertRaises(ValueError, msg=bad):
                lg.classify_indicator(bad)
        self.assertEqual(lg.classify_indicator("192.0.2.5", allow_private=True)[0], "ip")  # demo mode only

    def test_only_truly_public_addresses_qualify(self):
        for ip in ("8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"):
            self.assertTrue(lg.is_public_ip(ip), ip)
        for ip in ("10.0.0.1", "172.16.5.5", "192.168.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.251",
                   "ff02::fb", "239.255.255.250", "255.255.255.255", "0.0.0.0", "::", "100.64.0.1", "192.0.2.1",
                   "198.51.100.9", "203.0.113.5", "240.0.0.1", "not an ip", ""):
            self.assertFalse(lg.is_public_ip(ip), ip)
            if ip and ip != "not an ip":
                with self.assertRaises(ValueError, msg=ip):
                    lg.classify_indicator(ip)

    def test_urls_are_built_only_from_validated_values(self):
        self.assertEqual(lg.vt_url("ip", "8.8.8.8"), "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
        self.assertEqual(lg.vt_url("domain", "example.com"), "https://www.virustotal.com/api/v3/domains/example.com")
        self.assertTrue(lg.vt_url("file", "a" * 64).endswith("/files/" + "a" * 64))
        self.assertNotIn("/", lg.vt_url("domain", "a/b").split("/domains/")[1])  # path separators are percent-encoded
        self.assertEqual(lg.gui_link("ip", "8.8.8.8"), "https://www.virustotal.com/gui/ip-address/8.8.8.8")

    def test_parse_ok_and_fields(self):
        r = lg.parse_vt_response("ip", "8.8.8.8", 200, vt_body(3, 1, 60, 20, reputation=-5, as_owner="ACME-AS", country="US"), 5.0)
        self.assertEqual((r["status"], r["mal"], r["sus"], r["har"], r["und"], r["rep"], r["owner"], r["country"]),
                         ("ok", 3, 1, 60, 20, -5, "ACME-AS", "US"))
        self.assertEqual(lg.engines(r), 84)
        self.assertEqual(lg.verdict_text(r), "3 malicious, 1 suspicious of 84 engines")

    def test_parse_hostile_or_odd_responses(self):
        for body in (b"not json", b"[]", b"{}", b'{"data":{}}', b'{"data":{"attributes":[]}}',
                     b'{"data":{"attributes":{"last_analysis_stats":[1,2]}}}'):
            r = lg.parse_vt_response("ip", "8.8.8.8", 200, body, 1.0)
            self.assertEqual(r["status"], "error", body)
        r = lg.parse_vt_response("ip", "8.8.8.8", 200, vt_body(10 ** 9, -4, True, "x"), 1.0)
        self.assertEqual((r["mal"], r["sus"], r["har"], r["und"]), (0, 0, 0, 0))  # out-of-range values are ignored
        r = lg.parse_vt_response("ip", "8.8.8.8", 200, vt_body(as_owner="\x1b[31mevil\nowner"), 1.0)
        self.assertNotIn("\x1b", r["owner"])
        self.assertNotIn("\n", r["owner"])

    def test_parse_status_codes(self):
        for code, want in ((404, "notfound"), (401, "badkey"), (403, "badkey"), (429, "ratelimited"), (500, "error"), (0, "error")):
            self.assertEqual(lg.parse_vt_response("file", "a" * 64, code, b"boom", 1.0)["status"], want)

    def test_severity_levels_and_wording(self):
        def sev(m, s):
            return lg.severity(lg.parse_vt_response("ip", "1.1.1.1", 200, vt_body(m, s), 1.0))
        self.assertEqual([sev(0, 0), sev(0, 2), sev(1, 0), sev(2, 5), sev(3, 0), sev(40, 0)],
                         ["None", "Review", "Low", "Low", "High", "High"])
        nf = lg.parse_vt_response("file", "a" * 64, 404, b"", 1.0)
        self.assertEqual(lg.severity(nf), "Unknown")
        self.assertIn("no verdict", lg.verdict_text(nf))
        self.assertIn("not proof", lg.CAUTION)
        self.assertIn("does not mean safe", lg.CAUTION)

    def test_demo_fetch_is_canned_and_parseable(self):
        st, body = lg.demo_fetch(lg.vt_url("ip", "198.51.100.9"), "DEMO")
        r = lg.parse_vt_response("ip", "198.51.100.9", st, body, 1.0)
        self.assertEqual(lg.severity(r), "High")

    def test_redirects_are_never_followed_and_only_vt_urls_are_fetched(self):
        self.assertIsNone(lg._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example/"))
        st, body = lg.default_fetch("https://evil.example/api/v3/ip_addresses/1.1.1.1", "k" * 64)
        self.assertEqual(st, 0)
        self.assertIn(b"refused", body)


class IntelStorageTests(unittest.TestCase):
    def mkres(self, kind="ip", q="8.8.8.8", t=1000.0, mal=0):
        return lg.parse_vt_response(kind, q, 200, vt_body(mal), t)

    def test_cache_ttl_and_peek(self):
        clk = FakeClock()
        c = lg.IntelCache(persist=False, clock=clk)
        c.put(self.mkres(t=clk()))
        self.assertIsNotNone(c.get("ip", "8.8.8.8"))
        clk.t += 86400 + 1
        self.assertIsNone(c.get("ip", "8.8.8.8"))          # expired for decisions
        self.assertIsNotNone(c.peek("ip", "8.8.8.8"))      # still shown for display
        f = self.mkres("file", "a" * 64, t=clk())
        c.put(f)
        clk.t += 6 * 86400
        self.assertIsNotNone(c.get("file", "a" * 64))      # files live 7 days

    def test_only_ok_and_notfound_are_cached(self):
        c = lg.IntelCache(persist=False)
        for code in (429, 500, 0, 401):
            c.put(lg.parse_vt_response("ip", "8.8.8.8", code, b"", 1.0))
        self.assertEqual(len(c.entries), 0)
        c.put(lg.parse_vt_response("ip", "8.8.8.8", 404, b"", 1.0))
        self.assertEqual(len(c.entries), 1)

    def test_persistence_round_trip_and_atomic_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sub", "intel_cache.json")
            clk = FakeClock()
            c = lg.IntelCache(path=path, clock=clk)
            c.put(self.mkres(t=clk(), mal=4))
            c.bump()
            c.bump()
            self.assertTrue(c.save())
            self.assertEqual([f for f in os.listdir(os.path.dirname(path)) if f.endswith(".tmp")], [])
            c2 = lg.IntelCache(path=path, clock=clk)
            c2.load()
            self.assertEqual(c2.get("ip", "8.8.8.8")["mal"], 4)
            self.assertEqual(c2.used_today(), 2)
            with open(path) as fh:
                self.assertNotIn("x-apikey", fh.read().lower())

    def test_corrupt_and_hostile_cache_files(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.json")
            _w(path, b"{broken")
            c = lg.IntelCache(path=path)
            c.load()
            self.assertEqual(len(c.entries), 0)
            self.assertTrue(os.path.exists(path + ".bad"))
            self.assertIn("set aside", c.warning)
            good = self.mkres(t=5.0)
            bad_entries = {"ip:8.8.8.8": good,
                           "ip:1.1.1.1": dict(good, mal="lots"),
                           "ip:9.9.9.9": dict(good, kind="exe"),
                           "mismatch:key": good,
                           "ip:2.2.2.2": dict(good, q="2.2.2.2", status="ratelimited")}
            _w(path, json.dumps({"version": 1, "usage": {"date": "x" * 99, "count": -5}, "entries": bad_entries}).encode())
            c = lg.IntelCache(path=path)
            c.load()
            self.assertEqual(list(c.entries), ["ip:8.8.8.8"])

    def test_daily_counter_rolls_over_and_cache_is_bounded(self):
        clk = FakeClock()
        c = lg.IntelCache(persist=False, clock=clk)
        c.bump()
        c.bump()
        self.assertEqual(c.used_today(), 2)
        clk.t += 86400 * 2
        self.assertEqual(c.used_today(), 0)
        for i in range(lg.IntelCache.MAX + 50):
            c.put(self.mkres(q="10.%d.%d.1" % (i // 250, i % 250), t=float(i)))
        self.assertLessEqual(len(c.entries), lg.IntelCache.MAX)

    def test_key_store_round_trip_and_validation(self):
        key = "a1B2" * 16
        with tempfile.TemporaryDirectory() as d:
            ks = lg.KeyStore(os.path.join(d, "k", "vt_key.json"))
            self.assertFalse(ks.exists())
            self.assertIsNone(ks.load())
            ks.save(key)
            self.assertTrue(ks.exists())
            if os.name != "nt":
                self.assertEqual(ks.scheme, "plain")
                self.assertEqual(os.stat(ks.path).st_mode & 0o077, 0)  # owner-only
            self.assertEqual(ks.load(), key)
            ks.clear()
            self.assertFalse(ks.exists())
            ks.clear()  # clearing twice is fine
            for bad in ("", "short", "has space " + "a" * 40, "newline\n" + "a" * 40, "a" * 200, "key;" + "a" * 40, "\u00e9" * 40):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    ks.save(bad)
            _w(ks.path, b"garbage")
            self.assertIsNone(ks.load())
            _w(ks.path, json.dumps({"v": 1, "scheme": "plain", "data": "!!!notbase64"}).encode())
            self.assertIsNone(ks.load())

    def test_key_never_written_to_config(self):
        key = "z9Y8" * 16
        with tempfile.TemporaryDirectory() as d:
            cfgp = os.path.join(d, "config.json")
            lg.save_config(dict(lg.DEFAULT_CONFIG, vt_enabled=True), cfgp)
            lg.KeyStore(os.path.join(d, "vt_key.json")).save(key)
            with open(cfgp) as fh:
                raw = fh.read()
            self.assertNotIn(key, raw)
            self.assertNotIn("key", " ".join(json.loads(raw).keys()))

    def test_config_defaults_are_off_and_validated(self):
        d = lg.DEFAULT_CONFIG
        self.assertEqual((d["vt_enabled"], d["vt_auto_ip"], d["vt_auto_domain"], d["vt_auto_hash"]), (False,) * 4)
        cfg = lg.validate_config({"vt_enabled": "yes", "vt_rpm": 0, "vt_daily": 10 ** 9, "vt_auto_ip": 1})
        self.assertEqual((cfg["vt_enabled"], cfg["vt_rpm"], cfg["vt_daily"], cfg["vt_auto_ip"]), (False, 4, 500, False))
        cfg = lg.validate_config({"vt_enabled": True, "vt_rpm": 10, "vt_daily": 100})
        self.assertEqual((cfg["vt_enabled"], cfg["vt_rpm"], cfg["vt_daily"]), (True, 10, 100))


class IntelServiceTests(unittest.TestCase):
    def setUp(self):
        self.clk = FakeClock()
        self.cache = lg.IntelCache(persist=False, clock=self.clk)
        self.results = queue.Queue()
        self.calls = []
        self.responder = lambda url: (200, vt_body(0, 0))
        self._orig = lg.default_fetch
        lg.default_fetch = forbid_real_network

        def fetch(url, key):
            self.calls.append((url, key))
            return self.responder(url)
        self.svc = lg.IntelService(self.cache, self.results, clock=self.clk, wait=self.clk.wait, fetch=fetch)
        self.svc.configure("k" * 64, 4, 500)

    def tearDown(self):
        lg.default_fetch = self._orig

    def run_all(self):
        while not self.svc.jobs.empty():
            self.svc.process(self.svc.jobs.get_nowait())

    def drain(self):
        out = []
        while not self.results.empty():
            out.append(self.results.get_nowait())
        return out

    def test_lookup_uses_vt_url_and_key_and_caches(self):
        self.assertEqual(self.svc.submit("ip", "8.8.8.8", "chrome.exe"), "queued")
        self.run_all()
        self.assertEqual(self.calls, [("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", "k" * 64)])
        res = self.drain()
        self.assertEqual((res[0]["status"], res[0]["ctx"]), ("ok", "chrome.exe"))
        self.assertEqual(self.svc.submit("ip", "8.8.8.8", "again"), "cached")   # no second request
        self.run_all()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.cache.used_today(), 1)

    def test_rate_limit_spaces_requests(self):
        for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
            self.svc.submit("ip", ip)
        self.run_all()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(len(self.clk.waits), 2)
        self.assertTrue(all(abs(w - 15.0) < 0.01 for w in self.clk.waits))   # 4 per minute -> one every 15 s

    def test_daily_limit_blocks_requests(self):
        self.svc.configure("k" * 64, 60, 2)
        for ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1"):
            self.svc.submit("ip", ip)
        self.run_all()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([r["status"] for r in self.drain()], ["ok", "ok", "dailylimit"])
        self.assertIn("Daily limit", self.svc.status)

    def test_rate_limited_response_backs_off_and_retries_then_gives_up(self):
        self.responder = lambda url: (429, b"")
        self.svc.submit("ip", "8.8.8.8")
        self.run_all()
        self.assertEqual(len(self.calls), 3)                      # first try plus two retries
        self.assertGreaterEqual(sum(self.clk.waits), 120)         # at least 60 s back-off between tries
        self.assertEqual([r["status"] for r in self.drain()], ["ratelimited"])
        self.assertEqual(len(self.cache.entries), 0)

    def test_bad_key_stops_further_requests_until_key_changes(self):
        self.responder = lambda url: (401, b"")
        self.svc.submit("ip", "8.8.8.8")
        self.svc.submit("ip", "8.8.4.4")
        self.run_all()
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(self.svc.key_rejected)
        self.assertIn("rejected", self.svc.status)
        self.svc.configure("n" * 64, 4, 500)
        self.assertFalse(self.svc.key_rejected)

    def test_not_found_is_cached_and_reported_without_verdict(self):
        self.responder = lambda url: (404, b"")
        self.svc.submit("file", "a" * 64, "tool.exe")
        self.run_all()
        r = self.drain()[0]
        self.assertEqual((r["status"], lg.severity(r)), ("notfound", "Unknown"))
        self.assertEqual(self.svc.submit("file", "a" * 64), "cached")

    def test_duplicates_and_queue_bound_and_manual_priority(self):
        self.assertEqual(self.svc.submit("ip", "8.8.8.8"), "queued")
        self.assertEqual(self.svc.submit("ip", "8.8.8.8"), "duplicate")
        for i in range(lg.IntelService.MAX_QUEUE + 20):
            self.svc.submit("ip", "20.%d.%d.1" % (i // 250, i % 250))
        self.assertEqual(self.svc.submit("ip", "30.30.30.30"), "full")
        self.assertEqual(self.svc.submit("ip", "9.9.9.9", manual=True), "queued")   # manual jobs bypass the bound
        first = self.svc.jobs.get_nowait()
        self.assertEqual(first[3], "9.9.9.9")                                          # and go first

    def test_path_jobs_hash_files_and_send_only_the_hash(self):
        with tempfile.TemporaryDirectory() as d:
            exe = os.path.join(d, "tool.exe")
            _w(exe, b"MZ fake program bytes")
            import hashlib
            want = hashlib.sha256(b"MZ fake program bytes").hexdigest()
            self.svc.hash_fn = lg.sha256_file
            self.svc.submit("path", exe, "tool.exe")
            self.run_all()
            self.assertEqual(self.calls[0][0], lg.VT_API + "files/" + want)
            self.assertNotIn(d, self.calls[0][0])           # the path never leaves the machine
            self.assertEqual(self.drain()[0]["ctx"], "tool.exe")
            self.svc.submit("path", os.path.join(d, "missing.exe"))
            self.run_all()
            self.assertEqual(len(self.calls), 1)            # unreadable file: skipped, no request
            self.assertIn("Skipped", self.svc.status)

    def test_no_key_means_no_requests(self):
        self.svc.configure(None, 4, 500)
        self.svc.submit("ip", "8.8.8.8")
        self.run_all()
        self.assertEqual(self.calls, [])
        self.assertIn("No valid API key", self.svc.status)

    def test_worker_thread_survives_a_failing_fetch(self):
        def boom(url, key):
            raise RuntimeError("boom")
        svc = lg.IntelService(self.cache, self.results, fetch=boom)
        svc.configure("k" * 64, 60, 500)
        svc.interval_override = 0.0
        svc.start()
        svc.submit("ip", "8.8.8.8")
        import time as _t
        for _ in range(50):
            if svc.status.startswith("Error"):
                break
            _t.sleep(0.05)
        self.assertTrue(svc.status.startswith("Error"))
        self.assertTrue(svc.thread.is_alive())
        svc.stop()
        svc.thread.join(3)

    def test_stop_during_wait_abandons_the_job(self):
        svc = lg.IntelService(self.cache, self.results, clock=self.clk, wait=lambda s: True,
                              fetch=lambda u, k: self.calls.append(u) or (200, vt_body()))
        svc.configure("k" * 64, 4, 500)
        svc.last_call = self.clk()
        svc.submit("ip", "8.8.8.8")
        svc.process(svc.jobs.get_nowait())
        self.assertEqual(self.calls, [])



PROC_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 11111 1 0000 100 0 0 10 0\n"
    "   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000 20 4 30 10 -1\n"
    "   2: 0100007F:C351 0100007F:1F90 06 00000000:00000000 03:000001A4 00000000     0        0 0 3 0000 0\n"
    "garbage line\n"
    "   3: ZZZZ:0035 00000000:0000 0A 0 0 0 0 0 99 1\n")
PROC_TCP6 = (
    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 00000000000000000000000001000000:0050 00000000000000000000000001000000:D431 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000 20 4 30 10 -1\n")
PROC_UDP = (
    "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
    "  100: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 44444 2 0000 0\n"
    "  101: 0F00A8C0:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 55555 2 0000 0\n")


class LinuxAttributionTests(unittest.TestCase):
    def test_hex_addresses(self):
        self.assertEqual(lg._linux_addr("0100007F"), "127.0.0.1")
        self.assertEqual(lg._linux_addr("0F00A8C0"), "192.168.0.15")
        self.assertEqual(lg._linux_addr("00000000000000000000000001000000"), "::1")
        self.assertEqual(lg._linux_addr("B80D01200000000000000000" "01000000"), "2001:db8::1")

    def test_parse_tcp_tables(self):
        t = lg.parse_proc_net(PROC_TCP, False)
        self.assertEqual(t, {("127.0.0.1", 53, "0.0.0.0", 0): 11111, ("127.0.0.1", 50000, "127.0.0.1", 8080): 22222})
        t6 = lg.parse_proc_net(PROC_TCP6, False)
        self.assertEqual(t6, {("::1", 80, "::1", 54321): 33333})

    def test_parse_udp_tables_and_garbage(self):
        u = lg.parse_proc_net(PROC_UDP, True)
        self.assertEqual(u, {68: [("0.0.0.0", 44444)], 5353: [("192.168.0.15", 55555)]})
        for text in ("", "header only\n", "x\n" * 50, "\x00\xff" * 100):
            self.assertEqual(lg.parse_proc_net(text, False), {})
        rnd = random.Random(2)
        for _ in range(300):
            blob = "\n".join(" ".join("%x:%x" % (rnd.randrange(10 ** 6), rnd.randrange(70000)) for _ in range(rnd.randrange(12)))
                             for _ in range(5))
            lg.parse_proc_net(blob, bool(rnd.randrange(2)))

    def test_cgroup_service_names(self):
        self.assertEqual(lg.parse_cgroup_service("0::/system.slice/ssh.service\n"), "ssh")
        self.assertEqual(lg.parse_cgroup_service("0::/user.slice/user-1000.slice/user@1000.service/app.slice/pipewire.service\n"), "pipewire")
        self.assertEqual(lg.parse_cgroup_service("12:cpu:/x\n1:name=systemd:/system.slice/cron.service\n"), "cron")
        self.assertIsNone(lg.parse_cgroup_service("0::/user.slice/user-1000.slice/session-3.scope\n"))
        self.assertIsNone(lg.parse_cgroup_service("0::/.service\n"))
        self.assertIsNone(lg.parse_cgroup_service(""))
        self.assertNotIn("\x1b", lg.parse_cgroup_service("0::/system.slice/a\x1bb.service\n"))

    def test_unattributed_sockets_still_teach_local_addresses(self):
        a = lg.Attributor(lg.ProcessNames(lambda pid: None))
        a.update({("10.1.1.5", 40000, "93.184.216.34", 443): -1}, {5353: [("fe80::2", -1)]})
        self.assertEqual(a.local_addrs, {"10.1.1.5", "fe80::2"})
        d = lg.decode(lg.build_ipv4("10.1.1.5", "93.184.216.34", 6, lg.build_tcp(40000, 443, 0, 0, 2)), lg.LINK_RAW)
        self.assertEqual(a.lookup(d), ("", ""))                       # no owner known: stays blank, never guessed
        d = lg.decode(lg.build_ipv4("fe80::2", "ff02::fb", 17, lg.build_udp(5353, 5353, b"")) if False else
                      lg.build_ipv6("fe80::2", "ff02::fb", 17, lg.build_udp(5353, 5353, b"")), lg.LINK_RAW)
        self.assertEqual(a.lookup(d), ("", ""))

    def test_interface_listing_on_this_platform(self):
        ifs = lg.discover_interfaces(False)
        if sys.platform.startswith("linux"):
            self.assertTrue(all(i["kind"] in ("linux", "npcap") for i in ifs))
            self.assertIn("lo", [i["name"] for i in ifs])
            lo = [i["name"] for i in ifs].index("lo")
            self.assertEqual(lo, len(ifs) - 1)                       # loopback is listed last
        with self.assertRaises(OSError):
            lg.LinuxPacketBackend("bad name;rm").open()               # interface names are validated


def _can_open_packet_socket():
    if not sys.platform.startswith("linux"):
        return False
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.close()
        return True
    except OSError:
        return False


@unittest.skipUnless(_can_open_packet_socket(), "needs Linux with root or CAP_NET_RAW (run: sudo python3 -m unittest ...)")
class LinuxCaptureIntegrationTests(unittest.TestCase):
    def capture(self, send):
        import threading
        import time as _t
        got = []
        be = lg.LinuxPacketBackend("lo")
        be.open()
        stop = threading.Event()
        th = threading.Thread(target=be.run, args=(lambda ts, d, w: got.append((d, w)), stop))
        th.start()
        try:
            send()
            _t.sleep(0.4)
        finally:
            stop.set()
            th.join(3)
            be.close()
        return [(lg.decode(d, be.linktype), w) for d, w in got]

    def test_loopback_udp_counts_and_bytes_are_exact(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        cli = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        def send():
            for _ in range(25):
                cli.sendto(b"x" * 1000, ("127.0.0.1", port))
        try:
            pk = self.capture(send)
        finally:
            srv.close()
            cli.close()
        mine = [(d, w) for d, w in pk if d.proto == "UDP" and d.dport == port]
        self.assertEqual(len(mine), 25)                               # every datagram once: no loss, no loopback duplicates
        self.assertEqual({w for _, w in mine}, {14 + 20 + 8 + 1000})
        self.assertTrue(all(d.src == d.dst == "127.0.0.1" for d, _ in mine))

    def test_loopback_ipv6_is_captured(self):
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            srv.bind(("::1", 0))
        except OSError:
            self.skipTest("no IPv6 loopback here")
        port = srv.getsockname()[1]
        cli = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            pk = self.capture(lambda: [cli.sendto(b"y" * 300, ("::1", port)) for _ in range(5)])
        finally:
            srv.close()
            cli.close()
        mine = [d for d, _ in pk if d.proto == "UDP" and d.dport == port]
        self.assertEqual((len(mine), mine[0].ipver, mine[0].src), (5, 6, "::1"))

    def test_tcp_traffic_is_attributed_to_this_process_end_to_end(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        sport = srv.getsockname()[1]
        cli = socket.create_connection(("127.0.0.1", sport))
        conn, _ = srv.accept()
        tcp, udp = lg._linux_read_connection_tables()
        key = ("127.0.0.1", cli.getsockname()[1], "127.0.0.1", sport)
        self.assertEqual(tcp.get(key), os.getpid())                   # real /proc: this very process owns the socket
        attr = lg.Attributor(lg.ProcessNames(lg._linux_query_image_name))
        attr.update(tcp, udp)
        self.assertIn("127.0.0.1", attr.local_addrs)

        def send():
            cli.sendall(b"z" * 5000)
            conn.recv(10000)
        try:
            pk = self.capture(send)
        finally:
            for s in (cli, conn, srv):
                s.close()
        data_pkts = [(d, w) for d, w in pk if d.l4 == "tcp" and d.dport == sport and "Len=0" not in d.info]
        total = sum(int(d.info.rsplit("Len=", 1)[1]) for d, _ in data_pkts)
        self.assertEqual(total, 5000)                                 # payload bytes seen == bytes sent
        d0 = data_pkts[0][0]
        label, why = attr.lookup(d0)
        want = os.path.basename(os.path.realpath(sys.executable))
        self.assertEqual(label, "%s (%d)" % (want, os.getpid()))
        self.assertIn("exact 4-tuple", why)
        st = lg.Stats({"127.0.0.1"})
        st.set_local(attr.local_addrs)
        for d, w in pk:
            p = lg.Packet(1.0, b"", w, d, attr.lookup(d)[0])
            st.add(p)
        self.assertIn(want, st.apps)
        self.assertGreaterEqual(st.apps[want].sent_bytes, 5000)



class OfflineTests(unittest.TestCase):
    def test_importing_and_decoding_makes_no_network_calls(self):
        calls = []
        orig = socket.socket.connect
        socket.socket.connect = lambda self, *a, **k: calls.append(a)
        try:
            lg.decode(lg.build_ipv4("1.1.1.1", "2.2.2.2", 6, lg.build_tcp(1, 2, 0, 0, 2)), lg.LINK_RAW)
            lg.compile_filter("tcp ip==1.1.1.1")
        finally:
            socket.socket.connect = orig
        self.assertEqual(calls, [])

    def test_no_url_strings_in_source(self):
        with open(lg.__file__, encoding="utf-8") as fh:
            src = fh.read()
        self.assertNotIn("http://", src)
        # the only web address allowed in the program is the optional VirusTotal feature's
        for line in src.splitlines():
            if "https://" in line:
                self.assertIn("virustotal.com", line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
