# SPDX-License-Identifier: GPL-3.0-or-later
"""GUI smoke test. Needs a display (on Linux: xvfb-run -a python -m unittest test_gui_smoke). Uses demo data only."""
import os, tempfile, time, unittest
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import inetgateway as lg

HAVE_TK = lg.tk is not None


@unittest.skipUnless(HAVE_TK, "tkinter not available")
class GuiSmoke(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        old_env = os.environ.get("INETGATEWAY_CONFIG_DIR")
        os.environ["INETGATEWAY_CONFIG_DIR"] = tmp.name
        self.addCleanup(lambda: os.environ.__setitem__("INETGATEWAY_CONFIG_DIR", old_env) if old_env is not None
                        else os.environ.pop("INETGATEWAY_CONFIG_DIR", None))
        try:
            self.root = lg.tk.Tk()
        except Exception as e:  # no display
            self.skipTest("no display: %s" % e)
        self.root.withdraw()
        cfg = dict(lg.DEFAULT_CONFIG)
        self.app = lg.App(self.root, cfg, demo=True)

    def tearDown(self):
        if getattr(self, "app", None):
            self.app.shutdown()
        try:
            self.root.destroy()
        except Exception:
            pass

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            self.root.update()
            time.sleep(0.01)

    def capture_some(self):
        self.app.start()
        self.pump(2.5)
        self.app.stop()
        self.pump(1.0)
        self.assertFalse(self.app.running)

    def test_capture_select_detail_hex(self):
        self.capture_some()
        self.assertGreater(len(self.app.store), 10)
        first = self.app.tree.get_children()[0]
        self.app.tree.selection_set(first)
        self.app.on_select()
        self.root.update()
        self.assertGreater(len(self.app.detail.get_children()), 1)
        self.assertIn("0000", self.app.hex.get("1.0", "end"))

    def test_filter_valid_invalid(self):
        self.capture_some()
        total = len(self.app.rows)
        self.app.filter_var.set("dns")
        self.app.apply_filter()
        self.assertTrue(0 < len(self.app.rows) < total)
        for iid in self.app.tree.get_children():
            self.assertEqual(self.app.tree.set(iid, "proto"), "DNS")
        self.app.filter_var.set("ip==")
        self.app.apply_filter()
        self.assertEqual(str(self.app.filter_entry.cget("style")), "Bad.TEntry")
        self.assertEqual(self.app.filter_fn, self.app.filter_fn)  # previous filter retained
        self.app.filter_var.set("")
        self.app.apply_filter()
        self.assertEqual(len(self.app.rows), total)

    def test_theme_toggle_persists_to_config(self):
        self.app.dark.set(True)
        self.app.on_theme()
        cfg, warn = lg.load_config()
        self.assertEqual(cfg["theme"], "dark")
        self.app.dark.set(False)
        self.app.on_theme()
        self.assertEqual(lg.load_config()[0]["theme"], "light")

    def test_row_cap_and_clear(self):
        self.capture_some()
        self.app.clear()
        self.assertEqual((len(self.app.store), len(self.app.rows), len(self.app.tree.get_children())), (0, 0, 0))

    def test_pcap_and_csv_round_trip_through_gui_objects(self):
        self.capture_some()
        n = len(self.app.store)
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "x.pcap")
            lg.write_pcap(p, self.app.store, self.app.linktype, 65535)
            lt, _, pk = lg.read_pcap(p)
            self.assertEqual((lt, len(pk)), (lg.LINK_ETHERNET, n))
            c = os.path.join(t, "x.csv")
            lg.export_csv(c, self.app.store, self.app.t0)
            with open(c, encoding="utf-8-sig") as fh:
                self.assertEqual(len(fh.read().splitlines()), n + 1)

    def test_dashboard_tab_populates_and_filters(self):
        self.app.start()
        self.pump(4.0)
        self.app.nb.select(self.app.tab_dash)
        self.pump(0.5)
        dash = self.app.dash
        dash.refresh(force=True)
        names = [dash.tree_sw.set(i, "name") for i in dash.tree_sw.get_children()]
        self.assertIn("browser.exe", names)
        self.assertTrue(any(n.startswith("svchost.exe [Dnscache]") for n in names))
        self.assertGreater(len(dash.tree_fl.get_children()), 1)
        # DNS names learned from answers appear next to IPs
        tos = [dash.tree_fl.set(i, "to") for i in dash.tree_fl.get_children()]
        frs = [dash.tree_fl.set(i, "frm") for i in dash.tree_fl.get_children()]
        self.assertTrue(any("example.test (198.51.100.7)" in x for x in tos + frs))
        self.assertTrue(any(x.startswith("This PC (192.0.2.10)") for x in tos + frs))
        # charts actually drew something
        for cv in (dash.cv_line, dash.cv_pie, dash.cv_bar):
            self.assertGreater(len(cv.find_all()), 5)
        # click a software row -> activity list is filtered to it
        iid = next(i for i in dash.tree_sw.get_children() if dash.tree_sw.set(i, "name") == "browser.exe")
        dash.tree_sw.selection_set(iid)
        self.root.update()
        self.assertEqual({dash.tree_fl.set(i, "app") for i in dash.tree_fl.get_children()}, {"browser.exe"})
        dash.show_all()
        self.assertGreater(len({dash.tree_fl.set(i, "app") for i in dash.tree_fl.get_children()}), 1)
        for m in dash.METRICS:  # every pie selector option renders
            dash.metric.set(m)
            dash.refresh(force=True)
            self.assertGreater(len(dash.cv_pie.find_all()), 2)
        self.app.stop()
        self.pump(1.0)
        self.app.clear()
        self.assertEqual(len(dash.tree_sw.get_children()), 0)

    def show(self):
        self.root.deiconify()
        self.root.geometry("1100x720+0+0")
        self.pump(0.6)

    def test_true_black_theme_and_rounded_widgets(self):
        self.show()
        self.app.dark.set(True)
        self.app.on_theme()
        self.root.update()
        self.assertEqual(self.root.cget("bg"), "#000000")
        card = next(w for w in self.root._themed if isinstance(w, lg.Card))
        self.assertEqual(card.cget("bg"), "#000000")
        self.assertIsNotNone(card._shape)                  # the rounded outline was drawn
        self.assertGreater(len(card._cv.find_all()), 0)
        self.assertEqual(self.app.btn_start.colors["accent"], lg.THEMES["dark"]["accent"])

    def test_buttons_tabs_and_keyboard(self):
        self.show()
        calls = []
        b = lg.RButton(self.root, "Go", command=lambda: calls.append(1))
        b.pack()
        self.root.update()
        b.invoke()
        b.state(["disabled"])
        b.invoke()
        self.assertEqual(calls, [1])                        # disabled buttons do nothing
        b.state(["!disabled"])
        b.focus_force()
        self.root.update()
        b.event_generate("<space>")
        self.root.update()
        self.assertEqual(calls, [1, 1])                     # keyboard activation works
        self.assertEqual(self.app.nb.index(), 0)
        self.app.nb.select(self.app.tab_intel)
        self.assertEqual(self.app.nb.index(), 2)
        self.app.nb._step(1)
        self.assertEqual(self.app.nb.index(), 0)
        self.root.event_generate("<Control-Key-2>")
        self.root.update()
        self.assertEqual(self.app.nb.index(), 1)
        self.assertEqual([x.kind for x in self.app.nb.buttons], ["tab", "tabsel", "tab"])

    def test_threat_intel_tab_demo_end_to_end(self):
        self.app.start()
        self.pump(9.0)
        self.app.nb.select(self.app.tab_intel)
        self.pump(0.5)
        adm = self.app.intel_view
        res = adm.results
        key = "r:ip:198.51.100.9"
        self.assertIn(key, res)
        self.assertEqual(lg.severity(res[key]), "High")
        self.assertEqual(res[key]["ctx"], "browser.exe")                          # which software talked to it
        self.assertTrue(any(r["kind"] == "file" and r["ctx"] == "updater.exe" for r in res.values()))
        self.assertTrue(any(r["kind"] == "domain" for r in res.values()))
        self.assertEqual(adm.tree.set(key, "sev"), "High")
        self.assertIn("malicious", adm.tree.set(key, "verdict"))
        adm.tree.selection_set(key)
        adm._on_select()
        text = adm.detail.get("1.0", "end")
        self.assertIn("not proof", text)
        self.assertIn("Seen as: browser.exe", text)
        adm.only_hits.set(True)
        adm._render()
        sevs = {adm.tree.set(i, "sev") for i in adm.tree.get_children()}
        self.assertTrue(sevs and sevs <= {"High", "Low", "Review"})
        adm.only_hits.set(False)
        adm._render()
        # dashboard shows the verdict next to the remote address
        self.app.nb.select(self.app.tab_dash)
        self.app.dash.refresh(force=True)
        intel = [self.app.dash.tree_fl.set(i, "intel") for i in self.app.dash.tree_fl.get_children()]
        self.assertTrue(any(x.startswith("VT 9/") for x in intel))
        self.assertIn("with detections", self.app.status.cget("text"))
        # manual checks: valid, cached, invalid
        self.assertIn("cache", self.app.intel_check("198.51.100.9"))
        with self.assertRaises(ValueError):
            self.app.intel_check("not an indicator")
        with self.assertRaises(ValueError):
            self.app.intel_save_key("a" * 64)               # demo never uses a real key
        # nothing demo-related was written to the user's real settings
        self.assertFalse(self.app.keystore.exists())

    def test_threat_intel_clear_results(self):
        self.app.start()
        self.pump(6.0)
        self.assertGreater(len(self.app.intel_view.results), 0)
        self.app.intel_view._clear()
        self.assertEqual((len(self.app.intel_view.results), len(self.app.intel_view.tree.get_children())), (0, 0))
        self.assertEqual(len(self.app.intel_cache.entries), 0)


@unittest.skipUnless(HAVE_TK, "tkinter not available")
class GuiOfflineByDefault(unittest.TestCase):
    def setUp(self):
        # every change is undone through addCleanup, which also runs when setUp skips the test (no display)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        old_env = os.environ.get("INETGATEWAY_CONFIG_DIR")
        os.environ["INETGATEWAY_CONFIG_DIR"] = tmp.name
        self.addCleanup(lambda: os.environ.__setitem__("INETGATEWAY_CONFIG_DIR", old_env) if old_env is not None
                        else os.environ.pop("INETGATEWAY_CONFIG_DIR", None))
        orig_fetch = lg.default_fetch
        lg.default_fetch = lambda *a, **k: (_ for _ in ()).throw(AssertionError("network must not be used"))
        self.addCleanup(lambda: setattr(lg, "default_fetch", orig_fetch))
        try:
            self.root = lg.tk.Tk()
        except Exception as e:
            self.skipTest("no display: %s" % e)
        self.addCleanup(self._destroy)
        self.root.withdraw()
        self.app = lg.App(self.root, dict(lg.DEFAULT_CONFIG), demo=False)

    def _destroy(self):
        try:
            self.app.shutdown()
            self.root.destroy()
        except Exception:
            pass

    def test_threat_intel_is_off_until_key_saved_and_enabled(self):
        a = self.app
        self.assertFalse(a.vt_on())
        self.assertIsNone(a.intel.thread)                   # no worker thread, so no way to make a request
        with self.assertRaises(ValueError):
            a.intel_check("8.8.8.8")
        with self.assertRaises(ValueError):
            a.intel_apply(True, 4, 500, True, True, True)    # cannot enable without a key
        self.assertFalse(a.cfg["vt_enabled"])
        a.intel_save_key("k" * 64)
        self.assertTrue(a.keystore.exists())
        self.assertFalse(a.vt_on())                          # a saved key alone does not turn anything on
        a.intel_apply(True, 7, 100, True, False, False)
        self.assertTrue(a.vt_on())
        self.assertTrue(a.intel.thread.is_alive())
        self.assertEqual((a.intel.rpm, a.intel.daily), (7, 100))
        cfg, _ = lg.load_config()                            # persisted, without the key
        self.assertEqual((cfg["vt_enabled"], cfg["vt_rpm"], cfg["vt_auto_hash"]), (True, 7, False))
        with open(os.path.join(lg.config_dir(), "config.json")) as fh:
            self.assertNotIn("k" * 64, fh.read())
        a.intel_remove_key()
        self.assertFalse(a.keystore.exists())
        self.assertFalse(a.vt_on())
        self.assertFalse(lg.load_config()[0]["vt_enabled"])

    def test_private_and_local_addresses_are_never_auto_submitted(self):
        a = self.app
        a.intel_save_key("k" * 64)
        a.intel_apply(True, 60, 500, True, True, False)
        calls = []
        a.intel.submit = lambda kind, value, ctx="", manual=False: calls.append((kind, value)) or "queued"
        for dst in ("8.8.8.8", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.251", "10.1.1.1"):
            p = lg.Packet(1.0, b"", 60, lg.decode(lg.build_ipv4("10.0.0.2", dst, 6, lg.build_tcp(50000, 443, 1, 0, 0x02)), lg.LINK_RAW), "x.exe (1)")
            a.stats.local = {"10.0.0.2"}
            a.stats.add(p)
        a.dns_map.update({"1.2.3.4": "printer.local", "5.6.7.8": "example.com"})
        a._intel_feed()
        self.assertEqual(sorted(calls), [("domain", "example.com"), ("ip", "8.8.8.8")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
