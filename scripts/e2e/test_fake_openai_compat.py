#!/usr/bin/env python3
"""Exercise the streaming fixture over HTTP, without a real model or daemon."""

import concurrent.futures
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest


spec = importlib.util.spec_from_file_location(
    "fake_openai", Path(__file__).with_name("fake-openai-compat.py")
)
fake = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fake)


class StreamingFixtureTests(unittest.TestCase):
    def test_hold_applies_only_to_current_user_prompt(self):
        marker = "ASTRID_E2E_INFLIGHT_CRASH_reload"
        cases = [
            ([], False),
            ([{"role": "user", "content": marker}], True),
            ([{"role": "user", "content": marker},
              {"role": "assistant", "content": "still "}], True),
            ([{"role": "user", "content": marker},
              {"role": "user", "content": "after reload"}], False),
            ([{"role": "system", "content": marker},
              {"role": "user", "content": "normal prompt"}], False),
        ]
        for messages, expected in cases:
            with self.subTest(messages=messages):
                self.assertEqual(fake.holds_current_request({"messages": messages}),
                                 expected)

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.server = fake.ThreadingHTTPServer(("127.0.0.1", 0), fake.Handler)
        cls.server.state = fake.State(Path(cls.temp.name) / "requests.jsonl")
        cls.thread = threading.Thread(target=cls.server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def request(self, model, stream=True, messages=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=10
        )
        started = time.monotonic()
        try:
            connection.request(
                "POST", "/v1/chat/completions",
                json.dumps({"model": model, "stream": stream,
                            "messages": messages or []}),
                {"Content-Type": "application/json", "Authorization": "secret"},
            )
            response = connection.getresponse()
            return response.status, response.read(), time.monotonic() - started
        finally:
            connection.close()

    def assert_complete_stream(self, model):
        status, payload, elapsed = self.request(model)
        self.assertEqual(status, 200)
        frames = payload.decode().split("\n\n")
        self.assertEqual(frames[-2:], ["data: [DONE]", ""])
        events = [json.loads(frame.removeprefix("data: ")) for frame in frames[:-2]]
        self.assertEqual(len(events), fake.FAST_STREAM_UNITS + 1)
        choices = [event["choices"][0] for event in events]
        self.assertEqual(
            [choice["delta"]["content"] for choice in choices[:-1]],
            fake.fast_stream_units(),
        )
        self.assertTrue(all(choice["finish_reason"] is None for choice in choices[:-1]))
        self.assertEqual(choices[-1]["finish_reason"], "stop")
        self.assertEqual(choices[-1]["delta"]["content"], "")
        self.assertTrue(all(event["model"] == model for event in events))
        return elapsed

    def test_burst_has_all_ordered_units_and_terminal(self):
        self.assert_complete_stream("fake-burst")

    def test_paced_stream_uses_elapsed_deadlines(self):
        elapsed = self.assert_complete_stream("fake-fast")
        # Lower bound proves pacing; no upper-bound performance claim in CI.
        self.assertGreaterEqual(elapsed, fake.FAST_STREAM_UNITS / 5000)

    def test_concurrent_streams_do_not_share_progress(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(self.assert_complete_stream, model)
                       for model in ("fake-fast", "fake-burst")]
            for result in results:
                result.result(timeout=10)

    def test_upstream_error_does_not_prevent_next_stream(self):
        status, payload, _ = self.request("fake-error")
        self.assertEqual(status, 502)
        self.assertEqual(json.loads(payload)["error"]["message"], "fake upstream error")
        self.assert_complete_stream("fake-burst")

    def test_non_streaming_payload_matches_stream_units(self):
        status, payload, _ = self.request("fake-burst", stream=False)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["choices"][0]["message"]["content"],
                         "".join(fake.fast_stream_units()))

    def test_next_http_stream_is_not_held_by_cancelled_history(self):
        status, payload, _ = self.request("fake-echo", messages=[
            {"role": "user", "content": "ASTRID_E2E_INFLIGHT_CRASH_reload"},
            {"role": "assistant", "content": "still "},
            {"role": "user", "content": "after reload"},
        ])
        self.assertEqual(status, 200)
        self.assertTrue(payload.endswith(b"data: [DONE]\n\n"))


if __name__ == "__main__":
    unittest.main()
