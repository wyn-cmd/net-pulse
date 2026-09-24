# Unit tests for the helper functions in net_pulse.py.
# Run them with: python3 -m unittest test_net_pulse -v

import json
import os
import tempfile
import unittest

from net_pulse import format_bytes, load_config, log_event


class FormatBytesTests(unittest.TestCase):

    def test_bytes_below_one_kilobyte(self):
        # Small values keep byte units and two decimal places.
        self.assertEqual(format_bytes(512), "512.00 B")

    def test_kilobyte_and_megabyte_scaling(self):
        self.assertEqual(format_bytes(2048), "2.00 KB")
        self.assertEqual(format_bytes(5 * 1024 * 1024), "5.00 MB")

    def test_values_beyond_the_unit_list_use_petabytes(self):
        # The loop exhausts B through TB before the fallback branch runs.
        self.assertEqual(format_bytes(float(1024 ** 5)), "1.00 PB")


class TempConfigTestCase(unittest.TestCase):
    # Shared helper for tests that need to write a config or log file to disk.

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write_file(self, name: str, contents: str) -> str:
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "w") as handle:
            handle.write(contents)
        return path


class LoadConfigTests(TempConfigTestCase):

    def test_missing_file_returns_defaults(self):
        missing = os.path.join(self.tmpdir.name, "does_not_exist.json")
        config = load_config(missing)
        self.assertEqual(config["check_interval_seconds"], 5)
        self.assertEqual(config["log_file"], "net_events.json")
        self.assertIn(443, config["monitored_ports"])

    def test_partial_config_is_merged_over_defaults(self):
        path = self.write_file("config.json", '{"check_interval_seconds": 30}')
        config = load_config(path)
        self.assertEqual(config["check_interval_seconds"], 30)
        # Keys the user left out still come from the defaults.
        self.assertTrue(config["alert_on_unknown_ports"])

    def test_malformed_json_falls_back_to_defaults(self):
        path = self.write_file("config.json", "{not valid json")
        config = load_config(path)
        self.assertEqual(config["check_interval_seconds"], 5)
        self.assertEqual(config["monitored_ports"], [80, 443, 22, 53])


class LogEventTests(TempConfigTestCase):

    def test_events_are_appended_as_jsonl(self):
        path = os.path.join(self.tmpdir.name, "net_events.json")
        event = {"status": "LISTEN", "local_addr": "127.0.0.1:22", "pid": 1}
        log_event(path, event)
        log_event(path, event)

        with open(path) as handle:
            lines = [json.loads(line) for line in handle if line.strip()]

        # Two calls produce two separate JSON objects, one per line.
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["local_addr"], "127.0.0.1:22")

    def test_unwritable_path_does_not_raise(self):
        # A failed write is reported through the logger, not an exception.
        missing_dir = os.path.join(self.tmpdir.name, "nested", "net_events.json")
        log_event(missing_dir, {"status": "LISTEN"})
        self.assertFalse(os.path.exists(missing_dir))


if __name__ == "__main__":
    unittest.main()
