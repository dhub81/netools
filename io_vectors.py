#!/usr/bin/env python3
import argparse
import collections
import json
import math
import sys
from pathlib import Path


class Violation:
    def __init__(self, code, line, message):
        self.code = code
        self.line = line
        self.message = message

    def __str__(self):
        loc = f"line={self.line}" if self.line else "line=?"
        return f"{self.code}: {loc}: {self.message}"


def decode_log(path):
    raw = Path(path).read_bytes()
    for enc in ("utf-8-sig", "utf-16", "utf-16-le"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8-replace"


def parse_jsonl(path, resource_type):
    text, encoding = decode_log(path)
    rows = []
    text_lines = 0
    bad = []
    for line_no, line in enumerate(text.splitlines(), 1):
        s = line.strip("\ufeff\x00\r\n ")
        if not s:
            continue
        if not s.startswith("{"):
            text_lines += 1
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError as exc:
            bad.append(Violation("json_parse_error", line_no, str(exc)))
            continue
        if rec.get("type") != resource_type:
            text_lines += 1
            continue
        rec["_line"] = line_no
        rows.append(rec)
    return rows, text_lines, bad, encoding


def load_spec(path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def type_ok(value, want):
    if want == "str":
        return isinstance(value, str)
    if want == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if want == "bool":
        return isinstance(value, bool)
    if want == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def normalize_result(value):
    return value if value is not None else None


def event_key(rec, keys):
    return tuple(rec.get(k) for k in keys)


def token_key(rec, extra=()):
    keys = ["session", "generation", "op"]
    keys.extend(extra)
    return event_key(rec, keys)


def add_violation(out, code, rec_or_line, message):
    line = rec_or_line.get("_line") if isinstance(rec_or_line, dict) else rec_or_line
    out.append(Violation(code, line, message))


def event_time(rec):
    value = rec.get("time_unix_nano")
    if isinstance(value, int) and value > 0:
        return value
    return None


def span_seconds(rows):
    times = [event_time(rec) for rec in rows]
    times = [t for t in times if t is not None]
    if len(times) < 2:
        return 0.0
    return max(0.0, (max(times) - min(times)) / 1_000_000_000)


def fmt_bytes(value):
    value = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    while abs(value) >= 1000.0 and idx < len(units) - 1:
        value /= 1000.0
        idx += 1
    if idx == 0:
        return f"{int(value)}{units[idx]}"
    return f"{value:.2f}{units[idx]}"


def fmt_rate(bytes_per_sec):
    return f"{fmt_bytes(bytes_per_sec)}/s ({bytes_per_sec * 8 / 1_000_000:.2f}Mbps)"


def record_matches(rec, match):
    for key, want in match.items():
        if rec.get(key) != want:
            return False
    return True


def check_schema(rows, spec):
    violations = []
    events = spec["events"]
    field_types = spec.get("field_types", {})
    for rec in rows:
        event = rec.get("event")
        if event not in events:
            add_violation(violations, "unknown_event", rec, f"event={event!r}")
            continue
        rule = events[event]
        for field in ["type", "event", "time_unix_nano"]:
            if field not in rec:
                add_violation(violations, "missing_base_field", rec, f"event={event} field={field}")
        for field in rule.get("required", []):
            if field not in rec:
                add_violation(violations, "missing_required_field", rec, f"event={event} field={field}")
        allowed = rule.get("allowed_results")
        if allowed is not None:
            result = normalize_result(rec.get("result"))
            if result not in allowed:
                add_violation(violations, "invalid_result", rec, f"event={event} result={result!r} allowed={allowed!r}")
        if rec.get("result") == "error":
            for field in rule.get("error_requires", []):
                if not rec.get(field):
                    add_violation(violations, "missing_error_detail", rec, f"event={event} field={field}")
        for field, value in rec.items():
            if field.startswith("_"):
                continue
            want = field_types.get(field)
            if want and value is not None and not type_ok(value, want):
                add_violation(
                    violations,
                    "invalid_field_type",
                    rec,
                    f"event={event} field={field} value={value!r} want={want}",
                )
    return violations


class RuntimeState:
    def __init__(self, tail_window):
        self.tail_window = tail_window
        self.violations = []
        self.last_line = 0
        self.listener_starts = collections.Counter()
        self.listener_done = collections.Counter()
        self.listener_accepts = collections.defaultdict(collections.deque)
        self.handles = {}
        self.handle_register_counts = collections.Counter()
        self.handle_close_counts = collections.Counter()
        self.runtime_closes = []
        self.buffers = {}
        self.buffer_store_counts = collections.Counter()
        self.buffer_release_counts = collections.Counter()
        self.release_requests = collections.Counter()
        self.span_ok = collections.Counter()
        self.small_write_starts = collections.Counter()
        self.read_starts = collections.Counter()
        self.channel_starts = collections.Counter()
        self.channel_done = collections.Counter()
        self.ssh_dial_starts = collections.Counter()
        self.pending_open_done_by_pool = collections.defaultdict(collections.deque)
        self.health_starts = collections.Counter()
        self.pool_slot_close_starts = collections.Counter()
        self.runtime_reconnect_starts = collections.Counter()
        self.pool_reconnect_claims = collections.Counter()
        self.init_slot_ids = {}
        self.init_slot_id_owner = {}
        self.driver_failures = []
        self.driver_dial_ok = []

    def add(self, code, rec, message):
        add_violation(self.violations, code, rec, message)

    def is_tail(self, rec):
        return self.last_line - rec.get("_line", 0) <= self.tail_window

    def run(self, rows):
        self.last_line = rows[-1]["_line"] if rows else 0
        for rec in rows:
            handler = getattr(self, "on_" + rec["event"], None)
            if handler:
                handler(rec)
        self.finish()
        return self.violations

    def on_listener_start(self, rec):
        self.listener_starts[event_key(rec, ["network", "addr"])] += 1

    def on_listener_done(self, rec):
        self.listener_done[event_key(rec, ["network", "addr"])] += 1

    def on_listener_accept(self, rec):
        if rec.get("result") == "ok":
            self.listener_accepts[(rec.get("local_addr"), rec.get("remote_addr"))].append(rec)

    def on_accept(self, rec):
        key = (rec.get("local_addr"), rec.get("remote_addr"))
        # accept currently logs handle+remote_addr. Treat any previous listener_accept
        # with the same remote_addr as the resource fact for this accepted socket.
        candidates = []
        for k, q in self.listener_accepts.items():
            if k[1] == rec.get("remote_addr") and q:
                candidates.append((k, q))
        if candidates:
            _, q = candidates[0]
            q.popleft()
        else:
            self.add("accept_without_listener_accept", rec, f"remote_addr={rec.get('remote_addr')}")

    def on_handle_register(self, rec):
        handle = rec.get("handle")
        self.handle_register_counts[handle] += 1
        self.handles[handle] = {"register": rec}

    def on_runtime_close(self, rec):
        self.runtime_closes.append(rec)

    def on_handle_close(self, rec):
        handle = rec.get("handle")
        self.handle_close_counts[handle] += 1
        if self.handle_register_counts[handle] < self.handle_close_counts[handle]:
            self.add("handle_close_without_register", rec, f"handle={handle}")

    def on_buffer_store(self, rec):
        key = event_key(rec, ["buffer_id", "buffer_gen"])
        self.buffer_store_counts[key] += 1
        length = rec.get("len", 0)
        cap = rec.get("cap", 0)
        if cap < length:
            self.add("buffer_capacity_smaller_than_len", rec, f"len={length} cap={cap}")
        self.buffers[key] = {"store": rec, "len": length, "cap": cap}

    def on_runtime_release_buffer(self, rec):
        key = event_key(rec, ["buffer_id", "buffer_gen"])
        self.release_requests[key] += 1
        if rec.get("buffer_id") != 0 and self.buffer_store_counts[key] <= 0:
            self.add("runtime_release_without_live_buffer", rec, f"buffer_id={key[0]} buffer_gen={key[1]}")

    def on_buffer_release(self, rec):
        key = event_key(rec, ["buffer_id", "buffer_gen"])
        if rec.get("result") == "ignored_zero":
            if rec.get("buffer_id") != 0:
                self.add("buffer_release_ignored_nonzero", rec, f"buffer_id={rec.get('buffer_id')}")
            return
        self.buffer_release_counts[key] += 1
        state = self.buffers.get(key)
        if self.buffer_store_counts[key] < self.buffer_release_counts[key]:
            self.add("buffer_release_without_store", rec, f"buffer_id={key[0]} buffer_gen={key[1]}")
            return
        if rec.get("result") == "ok" and self.release_requests[key] <= 0:
            self.add("buffer_release_without_runtime_release", rec, f"buffer_id={key[0]} buffer_gen={key[1]}")
        if rec.get("result") == "ok":
            self.release_requests[key] -= 1

    def on_span_lookup(self, rec):
        key = event_key(rec, ["buffer_id", "buffer_gen"])
        state = self.buffers.get(key)
        offset = rec.get("offset", 0)
        length = rec.get("len", 0)
        if rec.get("result") == "ok":
            if not state or self.buffer_store_counts[key] <= 0:
                self.add("span_lookup_ok_without_live_buffer", rec, f"buffer_id={key[0]} buffer_gen={key[1]}")
            elif offset < 0 or length < 0 or offset + length > state.get("len", 0):
                self.add("span_lookup_ok_out_of_bounds", rec, f"offset={offset} len={length} buffer_len={state.get('len')}")
            self.span_ok[(key[0], key[1], offset, length)] += 1

    def on_runtime_write_span_start(self, rec):
        if rec.get("result") != "started":
            return
        key = (rec.get("buffer_id"), rec.get("buffer_gen"), rec.get("span_offset"), rec.get("span_len"))
        if self.span_ok[key] <= 0:
            self.add("runtime_write_span_without_span_lookup_ok", rec, f"span={key}")
        data_len = rec.get("span_data_len")
        span_len = rec.get("span_len")
        if data_len != span_len:
            self.add("runtime_write_span_len_mismatch", rec, f"span_len={span_len} span_data_len={data_len}")

    def on_runtime_write_start(self, rec):
        if rec.get("result") == "started":
            self.small_write_starts[token_key(rec, ["handle", "dest", "data_len"])] += 1

    def on_driver_write_done(self, rec):
        key = token_key(rec, ["handle", "dest", "length"])
        if self.small_write_starts[key] <= 0:
            self.add("driver_write_done_without_start", rec, f"key={key}")
        else:
            self.small_write_starts[key] -= 1

    def on_runtime_read_start(self, rec):
        if rec.get("result") == "started":
            self.read_starts[token_key(rec, ["handle", "source"])] += 1

    def on_driver_read_done(self, rec):
        key = token_key(rec, ["handle", "source"])
        if self.read_starts[key] <= 0:
            self.add("driver_read_done_without_start", rec, f"key={key}")
        else:
            self.read_starts[key] -= 1

    def on_ssh_pool_init_slot_done(self, rec):
        if rec.get("result") != "ok":
            return
        idx = rec.get("pool_idx")
        slot_id = rec.get("pool_slot_id")
        if idx in self.init_slot_ids and self.init_slot_ids[idx] != slot_id:
            self.add("ssh_init_slot_id_changed", rec, f"pool_idx={idx} first={self.init_slot_ids[idx]} next={slot_id}")
        owner = self.init_slot_id_owner.get(slot_id)
        if owner is not None and owner != idx:
            self.add("ssh_init_duplicate_slot_id", rec, f"pool_slot_id={slot_id} first_pool_idx={owner} next_pool_idx={idx}")
        self.init_slot_ids[idx] = slot_id
        self.init_slot_id_owner[slot_id] = idx

    def on_runtime_dial_ssh_start(self, rec):
        if rec.get("result") == "started":
            self.ssh_dial_starts[event_key(rec, ["pool_idx", "pool_slot_id", "host", "port"])] += 1

    def on_ssh_channel_open_start(self, rec):
        self.channel_starts[event_key(rec, ["pool_idx", "pool_slot_id", "host", "port"])] += 1

    def on_ssh_channel_open_done(self, rec):
        key = event_key(rec, ["pool_idx", "pool_slot_id", "host", "port"])
        if self.channel_starts[key] <= 0:
            self.add("ssh_channel_open_done_without_start", rec, f"key={key}")
        else:
            self.channel_starts[key] -= 1
        if self.ssh_dial_starts[key] <= 0:
            self.add("ssh_channel_open_done_without_runtime_dial", rec, f"key={key}")
        else:
            self.ssh_dial_starts[key] -= 1
        self.channel_done[key] += 1
        self.pending_open_done_by_pool[(rec.get("pool_idx"), rec.get("pool_slot_id"), rec.get("result"))].append(rec)

    def on_driver_dial_ssh_done(self, rec):
        if rec.get("result") == "ok":
            key = (rec.get("pool_idx"), rec.get("pool_slot_id"), "ok")
            if not self.pending_open_done_by_pool[key]:
                self.add("driver_dial_ssh_done_without_channel_open_ok", rec, f"pool_idx={rec.get('pool_idx')} slot={rec.get('pool_slot_id')}")
            else:
                self.pending_open_done_by_pool[key].popleft()
            self.driver_dial_ok.append(rec)

    def on_driver_failure(self, rec):
        self.driver_failures.append(rec)
        if rec.get("completion") == "dial_failed" and rec.get("dial_kind") == "ssh":
            key = (rec.get("pool_idx"), rec.get("pool_slot_id"), "error")
            if not self.pending_open_done_by_pool[key]:
                self.add("driver_ssh_dial_failure_without_channel_open_error", rec, f"pool_idx={rec.get('pool_idx')} slot={rec.get('pool_slot_id')}")
            else:
                self.pending_open_done_by_pool[key].popleft()

    def on_runtime_health_check_start(self, rec):
        if rec.get("result") == "started":
            self.health_starts[(rec.get("pool_op_id"), rec.get("pool_idx"))] += 1

    def on_runtime_health_check_done(self, rec):
        key = (rec.get("pool_op_id"), rec.get("pool_idx"))
        if self.health_starts[key] <= 0:
            self.add("runtime_health_check_done_without_start", rec, f"pool_op_id={key[0]} pool_idx={key[1]}")
        else:
            self.health_starts[key] -= 1

    def on_ssh_pool_slot_close_start(self, rec):
        self.pool_slot_close_starts[rec.get("pool_idx")] += 1

    def on_ssh_pool_slot_close_done(self, rec):
        idx = rec.get("pool_idx")
        if self.pool_slot_close_starts[idx] <= 0:
            self.add("ssh_pool_slot_close_done_without_start", rec, f"pool_idx={idx}")
        else:
            self.pool_slot_close_starts[idx] -= 1

    def on_runtime_reconnect_start(self, rec):
        if rec.get("result") == "started":
            self.runtime_reconnect_starts[rec.get("pool_idx")] += 1

    def on_ssh_pool_reconnect_owner(self, rec):
        idx = rec.get("pool_idx")
        if self.runtime_reconnect_starts[idx] <= 0:
            self.add("ssh_pool_reconnect_owner_without_runtime_reconnect", rec, f"pool_idx={idx}")
        else:
            self.runtime_reconnect_starts[idx] -= 1
        self.pool_reconnect_claims[(idx, "owner")] += 1

    def on_ssh_pool_reconnect_wait(self, rec):
        idx = rec.get("pool_idx")
        if self.runtime_reconnect_starts[idx] <= 0:
            self.add("ssh_pool_reconnect_wait_without_runtime_reconnect", rec, f"pool_idx={idx}")
        else:
            self.runtime_reconnect_starts[idx] -= 1
        self.pool_reconnect_claims[(idx, "wait")] += 1

    def on_ssh_pool_reconnect_wait_done(self, rec):
        key = (rec.get("pool_idx"), "wait")
        if self.pool_reconnect_claims[key] <= 0:
            self.add("ssh_pool_reconnect_wait_done_without_wait", rec, f"pool_idx={key[0]}")
        else:
            self.pool_reconnect_claims[key] -= 1

    def on_ssh_pool_reconnect_done(self, rec):
        key = (rec.get("pool_idx"), "owner")
        if self.pool_reconnect_claims[key] <= 0:
            self.add("ssh_pool_reconnect_done_without_owner", rec, f"pool_idx={key[0]}")
        else:
            self.pool_reconnect_claims[key] -= 1

    def finish(self):
        for rec in self.runtime_closes:
            if self.is_tail(rec):
                continue
            handle = rec.get("handle")
            if self.handle_close_counts[handle] <= 0:
                self.add("runtime_close_without_handle_close", rec, f"handle={handle}")
        for key, count in self.small_write_starts.items():
            if count > 0:
                # Small writes should complete quickly; allow only if all starts are in tail.
                pass
        for key, count in self.channel_starts.items():
            if count > 0:
                # Log may end with channel opens in flight.
                pass


def check_state(rows, spec, tail_window):
    return RuntimeState(tail_window).run(rows)


def infer_pool_size(rows, spec):
    fields = spec.get("frequency_rules", {}).get("pool_size_fields", ["pool_size"])
    max_pool_size = 0
    max_pool_idx = -1
    for rec in rows:
        for field in fields:
            value = rec.get(field)
            if isinstance(value, int) and value > max_pool_size:
                max_pool_size = value
        idx = rec.get("pool_idx")
        if isinstance(idx, int) and idx > max_pool_idx:
            max_pool_idx = idx
    if max_pool_size > 0:
        return max_pool_size
    if max_pool_idx >= 0:
        return max_pool_idx + 1
    return 1


def check_frequency(rows, spec):
    violations = []
    rules = spec.get("frequency_rules", {}).get("events", {})
    if not rules:
        return violations
    pool_size = max(1, infer_pool_size(rows, spec))
    by_event = collections.defaultdict(list)
    for rec in rows:
        event = rec.get("event")
        if event in rules:
            t = event_time(rec)
            if t is not None:
                by_event[event].append((t, rec))
    for event, rule in rules.items():
        items = by_event.get(event, [])
        if not items:
            continue
        times = [t for t, _ in items]
        span = max(0.0, (max(times) - min(times)) / 1_000_000_000)
        min_span = float(rule.get("min_event_span_seconds", 0) or 0)
        if span < min_span:
            continue
        count = len(items)
        avg_per_sec = count / span if span > 0 else float(count)
        avg_per_slot = avg_per_sec / pool_size
        max_avg = rule.get("max_avg_per_pool_slot_per_sec")
        if max_avg is not None and avg_per_slot > float(max_avg):
            add_violation(
                violations,
                "event_frequency_avg_too_high",
                items[-1][1],
                f"event={event} count={count} span={span:.3f}s pool_size={pool_size} avg_per_slot={avg_per_slot:.3f}/s max={float(max_avg):.3f}/s",
            )
        per_sec = collections.Counter(t // 1_000_000_000 for t in times)
        peak = max(per_sec.values()) if per_sec else 0
        peak_per_slot = peak / pool_size
        max_peak = rule.get("max_peak_per_pool_slot_per_sec")
        if max_peak is not None and peak_per_slot > float(max_peak):
            sec, _ = max(per_sec.items(), key=lambda kv: kv[1])
            add_violation(
                violations,
                "event_frequency_peak_too_high",
                items[-1][1],
                f"event={event} peak={peak}/s second={sec} pool_size={pool_size} peak_per_slot={peak_per_slot:.3f}/s max={float(max_peak):.3f}/s",
            )
    return violations


def event_frequency_stats(rows):
    if not rows:
        return [], 0.0
    total_span = span_seconds(rows)
    stats = []
    per_event_times = collections.defaultdict(list)
    for rec in rows:
        t = event_time(rec)
        if t is not None:
            per_event_times[rec.get("event")].append(t)
    for event, times in per_event_times.items():
        if not times:
            continue
        event_span = max(0.0, (max(times) - min(times)) / 1_000_000_000)
        denom = event_span if event_span > 0 else (total_span if total_span > 0 else 1.0)
        per_sec = collections.Counter(t // 1_000_000_000 for t in times)
        values = sorted(per_sec.values())
        p95 = values[min(len(values) - 1, int(math.ceil(len(values) * 0.95)) - 1)] if values else 0
        stats.append({
            "event": event,
            "count": len(times),
            "avg_per_sec": len(times) / denom,
            "peak_per_sec": max(values) if values else 0,
            "p95_nonzero_per_sec": p95,
            "active_seconds": len(values),
        })
    stats.sort(key=lambda item: (-item["count"], item["event"]))
    return stats, total_span


def throughput_stats(rows, spec):
    streams = spec.get("throughput_streams", [])
    stats = []
    for stream in streams:
        event = stream["event"]
        match = stream.get("match", {})
        bytes_field = stream.get("bytes_field", "length")
        samples = []
        per_sec = collections.Counter()
        for rec in rows:
            if rec.get("event") != event or not record_matches(rec, match):
                continue
            t = event_time(rec)
            if t is None:
                continue
            value = rec.get(bytes_field, 0)
            if not isinstance(value, int) or value < 0:
                continue
            samples.append((t, value))
            per_sec[t // 1_000_000_000] += value
        if not samples:
            continue
        times = [t for t, _ in samples]
        stream_span = max(0.0, (max(times) - min(times)) / 1_000_000_000)
        total_bytes = sum(value for _, value in samples)
        avg = total_bytes / stream_span if stream_span > 0 else float(total_bytes)
        peak_sec, peak = max(per_sec.items(), key=lambda kv: kv[1]) if per_sec else (0, 0)
        stats.append({
            "name": stream.get("name", event),
            "label": stream.get("label", stream.get("name", event)),
            "direction": stream.get("direction", ""),
            "count": len(samples),
            "bytes": total_bytes,
            "span_seconds": stream_span,
            "avg_bytes_per_sec": avg,
            "peak_bytes_per_sec": peak,
            "peak_second": peak_sec,
        })
    return stats


def summarize(rows):
    events = collections.Counter(r.get("event") for r in rows)
    channel_by_host = collections.defaultdict(collections.Counter)
    errors = collections.Counter()
    for r in rows:
        if r.get("event") == "ssh_channel_open_done":
            channel_by_host[r.get("host", "?")][r.get("result", "?")] += 1
        if r.get("result") == "error":
            errors[(r.get("event"), r.get("error", ""))] += 1
    return events, channel_by_host, errors


def print_summary(rows, text_lines, bad_json, encoding, violations, spec):
    events, channel_by_host, errors = summarize(rows)
    freq_stats, total_span = event_frequency_stats(rows)
    print(f"encoding={encoding} json_events={len(rows)} text_lines={text_lines} parse_errors={len(bad_json)} violations={len(violations)} span={total_span:.3f}s")
    if events:
        print("events:")
        for event, count in events.most_common():
            print(f"  {event}: {count}")
    if freq_stats:
        print("event_frequency:")
        for item in freq_stats:
            print(
                f"  {item['event']}: count={item['count']} avg={item['avg_per_sec']:.2f}/s "
                f"peak={item['peak_per_sec']}/s p95_nonzero={item['p95_nonzero_per_sec']}/s "
                f"active_secs={item['active_seconds']}"
            )
    throughputs = throughput_stats(rows, spec)
    if throughputs:
        print("throughput:")
        for item in throughputs:
            print(
                f"  {item['label']}: count={item['count']} total={fmt_bytes(item['bytes'])} "
                f"span={item['span_seconds']:.3f}s avg={fmt_rate(item['avg_bytes_per_sec'])} "
                f"peak={fmt_rate(item['peak_bytes_per_sec'])}"
            )
    if channel_by_host:
        print("ssh_channel_open_by_host:")
        for host, counts in sorted(channel_by_host.items(), key=lambda kv: (-(kv[1].get("error", 0)), kv[0])):
            detail = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            print(f"  {host}: {detail}")
    if errors:
        print("errors:")
        for (event, err), count in errors.most_common():
            print(f"  {event}: {count} error={err}")
    if violations:
        print("violations:")
        for violation in violations:
            print(f"  {violation}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate ts-proxy --verbose io_resource JSONL logs against spec/io_vectors.json.")
    parser.add_argument("log", help="log file to validate")
    parser.add_argument("--spec", default=str(Path(__file__).resolve().parent / "spec" / "io_vectors.json"))
    parser.add_argument("--tail-window", type=int, default=32, help="line window at the end of a partial log where in-flight operations are allowed")
    args = parser.parse_args(argv)

    spec = load_spec(args.spec)
    rows, text_lines, bad_json, encoding = parse_jsonl(args.log, spec.get("io_resource_type", "io_resource"))
    violations = []
    violations.extend(bad_json)
    violations.extend(check_schema(rows, spec))
    violations.extend(check_state(rows, spec, args.tail_window))
    violations.extend(check_frequency(rows, spec))
    print_summary(rows, text_lines, bad_json, encoding, violations, spec)
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
