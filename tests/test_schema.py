from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from siem.schema import (
    Destination,
    Event,
    EventMeta,
    Host,
    RawEnvelope,
    Source,
    User,
    canonical_json,
    now_utc,
    to_utc,
)


class TestNowUtc:
    def test_returns_iso_string_with_utc_offset(self):
        result = now_utc()
        parsed = datetime.fromisoformat(result)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == UTC.utcoffset(None)


class TestToUtc:
    def test_naive_datetime_is_treated_as_already_utc(self):
        naive = datetime(2024, 1, 1, 12, 0, 0)
        assert to_utc(naive) == "2024-01-01T12:00:00+00:00"

    def test_naive_datetime_is_not_shifted_by_local_timezone(self):
        # Regression test: to_utc() previously checked the imported `tzinfo`
        # class instead of `value.tzinfo`, so this condition was always
        # False and naive datetimes were wrongly run through
        # .astimezone(timezone.utc), which shifts by the system's local
        # offset instead of treating the naive value as already-UTC.
        naive = datetime(2024, 6, 15, 0, 30, 0)
        assert to_utc(naive) == "2024-06-15T00:30:00+00:00"

    def test_naive_datetime_with_microseconds_is_preserved(self):
        naive = datetime(2024, 1, 1, 12, 0, 0, 123456)
        assert to_utc(naive) == "2024-01-01T12:00:00.123456+00:00"

    def test_aware_utc_datetime_is_unchanged(self):
        aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        assert to_utc(aware) == "2024-01-01T12:00:00+00:00"

    def test_aware_non_utc_datetime_is_converted(self):
        plus_five = timezone(timedelta(hours=5))
        aware = datetime(2024, 1, 1, 12, 0, 0, tzinfo=plus_five)
        assert to_utc(aware) == "2024-01-01T07:00:00+00:00"

    def test_epoch_seconds_is_converted(self):
        assert to_utc(1704110400) == "2024-01-01T12:00:00+00:00"

    def test_epoch_millis_is_converted(self):
        assert to_utc(1704110400000) == "2024-01-01T12:00:00+00:00"

    def test_iso_string_without_timezone_is_treated_as_utc(self):
        assert to_utc("2024-01-01T12:00:00") == "2024-01-01T12:00:00+00:00"

    def test_iso_string_with_z_suffix_is_parsed_as_utc(self):
        assert to_utc("2024-01-01T12:00:00Z") == "2024-01-01T12:00:00+00:00"

    def test_iso_string_with_offset_is_converted_to_utc(self):
        assert to_utc("2024-01-01T17:00:00+05:00") == "2024-01-01T12:00:00+00:00"

    def test_invalid_type_raises_value_error(self):
        with pytest.raises(ValueError):
            to_utc(None)

    def test_invalid_string_raises_value_error(self):
        with pytest.raises(ValueError):
            to_utc("not-a-timestamp")


class TestCanonicalJson:
    def test_keys_are_sorted(self):
        assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_no_extra_whitespace(self):
        result = canonical_json({"a": [1, 2, 3]})
        assert " " not in result

    def test_same_data_different_key_order_is_identical(self):
        assert canonical_json({"a": 1, "b": 2}) == canonical_json({"b": 2, "a": 1})

    def test_non_serializable_object_falls_back_to_str(self):
        class Custom:
            def __str__(self):
                return "custom-value"

        result = canonical_json({"x": Custom()})
        assert result == '{"x":"custom-value"}'


class TestRawEnvelopeConstruction:
    def test_required_fields_only_applies_defaults(self):
        env = RawEnvelope(raw="line", source="sshd", transport="manual")
        assert env.raw == "line"
        assert env.source == "sshd"
        assert env.transport == "manual"
        assert env.host is None
        assert env.labels == {}
        parsed = datetime.fromisoformat(env.received_at)
        assert parsed.tzinfo is not None

    def test_extra_field_is_rejected(self):
        with pytest.raises(ValidationError):
            RawEnvelope(raw="line", source="sshd", transport="manual", bogus="nope")


class TestRawEnvelopeSourceTransportValidation:
    def test_surrounding_whitespace_is_stripped(self):
        env = RawEnvelope(raw="line", source="  sshd  ", transport=" manual ")
        assert env.source == "sshd"
        assert env.transport == "manual"

    def test_empty_source_is_rejected(self):
        with pytest.raises(ValidationError):
            RawEnvelope(raw="line", source="", transport="manual")

    def test_whitespace_only_source_is_rejected(self):
        with pytest.raises(ValidationError):
            RawEnvelope(raw="line", source="   ", transport="manual")

    def test_empty_transport_is_rejected(self):
        with pytest.raises(ValidationError):
            RawEnvelope(raw="line", source="sshd", transport="")

    def test_whitespace_only_transport_is_rejected(self):
        with pytest.raises(ValidationError):
            RawEnvelope(raw="line", source="sshd", transport="   ")


class TestRawEnvelopeReceivedAtValidation:
    def test_naive_datetime_is_normalized_to_utc(self):
        env = RawEnvelope(
            raw="line",
            source="sshd",
            transport="manual",
            received_at=datetime(2024, 1, 1, 12, 0, 0),
        )
        assert env.received_at == "2024-01-01T12:00:00+00:00"

    def test_aware_non_utc_datetime_is_converted(self):
        plus_five = timezone(timedelta(hours=5))
        env = RawEnvelope(
            raw="line",
            source="sshd",
            transport="manual",
            received_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=plus_five),
        )
        assert env.received_at == "2024-01-01T07:00:00+00:00"

    def test_epoch_seconds_is_converted(self):
        env = RawEnvelope(
            raw="line", source="sshd", transport="manual", received_at=1704110400
        )
        assert env.received_at == "2024-01-01T12:00:00+00:00"

    def test_epoch_millis_is_converted(self):
        env = RawEnvelope(
            raw="line", source="sshd", transport="manual", received_at=1704110400000
        )
        assert env.received_at == "2024-01-01T12:00:00+00:00"

    def test_iso_string_with_z_suffix_is_parsed_as_utc(self):
        env = RawEnvelope(
            raw="line",
            source="sshd",
            transport="manual",
            received_at="2024-01-01T12:00:00Z",
        )
        assert env.received_at == "2024-01-01T12:00:00+00:00"

    def test_invalid_string_raises_validation_error(self):
        with pytest.raises(ValidationError):
            RawEnvelope(
                raw="line",
                source="sshd",
                transport="manual",
                received_at="not-a-timestamp",
            )

    def test_invalid_type_raises_validation_error(self):
        with pytest.raises(ValidationError):
            RawEnvelope(
                raw="line", source="sshd", transport="manual", received_at=object()
            )


class TestRawEnvelopeRawFieldEdgeCases:
    # Policy (schemaPlanning.md §4): schema.py assumes `raw` is already a
    # valid str. Encoding recovery (e.g. errors="replace" for invalid UTF-8
    # on the wire) is the input/collector layer's job, not this model's —
    # these tests just confirm `raw` passes through completely untouched.

    def test_raw_with_nul_byte_passes_through_unchanged(self):
        raw = "line one\x00line two"
        env = RawEnvelope(raw=raw, source="sshd", transport="manual")
        assert env.raw == raw

    def test_raw_with_unicode_replacement_character_passes_through_unchanged(self):
        # what errors="replace" at the collector layer would have produced
        # from a byte sequence that wasn't valid UTF-8
        raw = "corrupted � byte sequence"
        env = RawEnvelope(raw=raw, source="sshd", transport="manual")
        assert env.raw == raw

    def test_very_large_raw_is_not_truncated(self):
        # Not schema's job to truncate multi-MB payloads (e.g. a stack
        # trace) — just document that it stores the full value as-is.
        raw = "x" * 5_000_000  # ~5 MB
        env = RawEnvelope(raw=raw, source="sshd", transport="manual")
        assert len(env.raw) == 5_000_000
        assert env.raw == raw


class TestRawEnvelopeHostStreamRoundTrip:
    def test_none_host_becomes_empty_string_on_stream_fields(self):
        env = RawEnvelope(raw="line", source="sshd", transport="manual", host=None)
        assert env.to_stream_fields()["host"] == ""

    def test_empty_string_host_round_trips_to_none(self):
        env = RawEnvelope(raw="line", source="sshd", transport="manual", host=None)
        fields = env.to_stream_fields()
        restored = RawEnvelope.from_stream_fields(fields)
        assert restored.host is None
        assert restored == env

    def test_non_empty_host_round_trips_unchanged(self):
        env = RawEnvelope(
            raw="line", source="sshd", transport="manual", host="10.0.0.5"
        )
        restored = RawEnvelope.from_stream_fields(env.to_stream_fields())
        assert restored.host == "10.0.0.5"


class TestRawEnvelopeLabelsValidation:
    def test_non_str_values_are_coerced_to_str(self):
        env = RawEnvelope(
            raw="line",
            source="sshd",
            transport="manual",
            labels={"count": 3, "active": True},
        )
        assert env.labels == {"count": "3", "active": "True"}

    def test_non_str_keys_are_coerced_to_str(self):
        env = RawEnvelope(
            raw="line", source="sshd", transport="manual", labels={1: "one"}
        )
        assert env.labels == {"1": "one"}

    def test_labels_round_trip_through_stream_fields(self):
        env = RawEnvelope(
            raw="line",
            source="sshd",
            transport="manual",
            labels={"count": 3},
        )
        restored = RawEnvelope.from_stream_fields(env.to_stream_fields())
        assert restored.labels == {"count": "3"}

    def test_missing_labels_key_reconstructs_to_empty_dict(self):
        restored = RawEnvelope.from_stream_fields(
            {"raw": "line", "source": "sshd", "transport": "manual"}
        )
        assert restored.labels == {}

    def test_empty_string_labels_reconstructs_to_empty_dict_without_raising(self):
        restored = RawEnvelope.from_stream_fields(
            {"raw": "line", "source": "sshd", "transport": "manual", "labels": ""}
        )
        assert restored.labels == {}


class TestEventConstruction:
    def test_minimal_event_validates(self):
        e = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "message": "hi"})
        assert e.message == "hi"

    def test_dict_and_kwarg_construction_are_equivalent(self):
        via_dict = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "message": "hi"})
        via_kwargs = Event(timestamp="2026-09-10T00:00:00Z", message="hi")
        assert via_dict.timestamp == via_kwargs.timestamp
        assert via_dict.message == via_kwargs.message

    def test_missing_timestamp_raises(self):
        with pytest.raises(ValidationError):
            Event.model_validate({"message": "hi"})

    def test_invalid_timestamp_string_raises(self):
        with pytest.raises(ValidationError):
            Event.model_validate({"@timestamp": "not-a-timestamp"})

    def test_naive_datetime_timestamp_is_normalized_to_utc(self):
        e = Event(timestamp=datetime(2024, 1, 1, 12, 0, 0))
        assert e.timestamp == datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)

    def test_event_meta_defaults_when_omitted(self):
        e = Event(timestamp="2026-09-10T00:00:00Z")
        assert e.event.kind == "event"
        assert e.event.outcome == "unknown"

    def test_event_meta_default_is_not_shared_between_instances(self):
        # Regression guard: Field(default_factory=EventMeta) must produce a
        # fresh EventMeta per Event, not one mutable instance reused for all.
        e1 = Event(timestamp="2026-09-10T00:00:00Z")
        e2 = Event(timestamp="2026-09-10T00:00:00Z")
        e1.event.dataset = "sshd.auth"
        assert e2.event.dataset is None


class TestEventToDoc:
    def test_none_fields_are_excluded(self):
        e = Event(timestamp="2026-09-10T00:00:00Z")
        doc = e.to_doc()
        assert "message" not in doc
        assert "host" not in doc

    def test_absent_sub_model_fieldsets_are_fully_omitted(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", source=Source(ip="8.8.8.8"))
        doc = e.to_doc()
        assert "destination" not in doc
        assert "http" not in doc
        assert "url" not in doc

    def test_timestamp_serializes_as_iso8601(self):
        e = Event(timestamp="2026-09-10T00:00:00Z")
        assert doc_ts_parses(e.to_doc()["@timestamp"])

    def test_ecs_version_is_injected(self):
        e = Event(timestamp="2026-09-10T00:00:00Z")
        assert e.to_doc()["ecs"]["version"] == "8.11"

    def test_unknown_top_level_field_survives(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "custom_field": "value"}
        )
        assert e.to_doc()["custom_field"] == "value"

    def test_unknown_nested_field_survives(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "source": {"ip": "8.8.8.8", "custom_nested": "value"},
            }
        )
        assert e.to_doc()["source"]["custom_nested"] == "value"


def doc_ts_parses(value: str) -> bool:
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return True


class TestEventDocId:
    def test_stable_across_identical_constructions(self):
        payload = {"@timestamp": "2026-09-10T00:00:00Z", "source": {"ip": "8.8.8.8"}}
        e1 = Event.model_validate(payload)
        e2 = Event.model_validate(payload)
        assert e1.doc_id() == e2.doc_id()

    def test_ignores_event_created(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(original="line"))
        before = e.doc_id()
        e.event.created = datetime(2030, 1, 1, tzinfo=UTC)
        assert e.doc_id() == before

    def test_ignores_event_ingested(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(original="line"))
        before = e.doc_id()
        e.event.ingested = datetime(2030, 1, 1, tzinfo=UTC)
        assert e.doc_id() == before

    def test_ignores_source_geo_enrichment(self):
        e = Event(
            timestamp="2026-09-10T00:00:00Z",
            source=Source(ip="8.8.8.8"),
            event=EventMeta(original="line"),
        )
        before = e.doc_id()
        e.source.geo = {"country_name": "United States"}
        assert e.doc_id() == before

    def test_changes_when_event_original_changes(self):
        base = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(original="line one"))
        other = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(original="line two"))
        assert base.doc_id() != other.doc_id()

    def test_changes_when_event_dataset_changes(self):
        base = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(dataset="sshd.auth"))
        other = Event(timestamp="2026-09-10T00:00:00Z", event=EventMeta(dataset="nginx.access"))
        assert base.doc_id() != other.doc_id()

    def test_changes_when_host_name_changes(self):
        base = Event(timestamp="2026-09-10T00:00:00Z", host=Host(name="web-01"))
        other = Event(timestamp="2026-09-10T00:00:00Z", host=Host(name="web-02"))
        assert base.doc_id() != other.doc_id()

    def test_changes_when_timestamp_changes(self):
        base = Event(timestamp="2026-09-10T00:00:00Z")
        other = Event(timestamp="2026-09-10T00:00:01Z")
        assert base.doc_id() != other.doc_id()


class TestEventToBulkAction:
    def test_shape(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", source=Source(ip="8.8.8.8"))
        action = e.to_bulk_action("logs-generic-default")
        assert action["_op_type"] == "create"
        assert action["_index"] == "logs-generic-default"
        assert action["_id"] == e.doc_id()
        assert action["_source"] == e.to_doc()


class TestEventIpSanitization:
    def test_invalid_source_ip_is_dropped_with_tag(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"ip": "999.1.1.1"}}
        )
        assert e.source.ip is None
        assert "_source_ip_invalid" in e.tags

    def test_invalid_destination_ip_is_dropped_with_tag(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "destination": {"ip": "999.1.1.1"}}
        )
        assert e.destination.ip is None
        assert "_destination_ip_invalid" in e.tags

    def test_host_ip_list_keeps_only_valid_entries_and_tags(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "host": {"ip": ["10.0.0.1", "not-an-ip"]},
            }
        )
        assert e.host.ip == [ip_str_to_any("10.0.0.1")]
        assert "_host_ip_invalid" in e.tags

    def test_valid_ipv4_is_accepted_unchanged(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"ip": "8.8.8.8"}}
        )
        assert str(e.source.ip) == "8.8.8.8"
        assert e.tags == []

    def test_valid_ipv6_is_accepted_unchanged(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"ip": "::1"}}
        )
        assert str(e.source.ip) == "::1"
        assert e.tags == []

    def test_already_constructed_source_instance_bypasses_sanitizer(self):
        # A pre-built Source has already gone through its own type validation;
        # the before-validator only inspects raw dicts, so this must not crash.
        e = Event(timestamp="2026-09-10T00:00:00Z", source=Source(ip="8.8.8.8"))
        assert str(e.source.ip) == "8.8.8.8"


def ip_str_to_any(value: str):
    from ipaddress import ip_address

    return ip_address(value)


class TestEventNumericSanitization:
    def test_string_port_is_coerced_to_int(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"port": "22"}}
        )
        assert e.source.port == 22

    def test_non_numeric_port_becomes_none_with_tag(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"port": "notaport"}}
        )
        assert e.source.port is None
        assert "_source_port_invalid" in e.tags

    def test_zero_port_is_preserved_not_treated_as_missing(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"port": 0}}
        )
        assert e.source.port == 0
        assert e.tags == []

    def test_boolean_port_does_not_silently_coerce_to_one(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "source": {"port": True}}
        )
        assert e.source.port is None
        assert "_source_port_invalid" in e.tags

    def test_string_bytes_is_coerced_to_int(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "destination": {"bytes": "1024"}}
        )
        assert e.destination.bytes == 1024

    def test_invalid_http_status_code_becomes_none_with_tag(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "http": {"response": {"status_code": "oops"}},
            }
        )
        assert e.http.response.status_code is None
        assert "_http_status_code_invalid" in e.tags

    def test_invalid_http_response_body_bytes_becomes_none_with_tag(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "http": {"response": {"body": {"bytes": "oops"}}},
            }
        )
        assert e.http.response.body.bytes is None
        assert "_http_response_bytes_invalid" in e.tags

    def test_multiple_invalid_fields_accumulate_multiple_tags(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "source": {"ip": "bad-ip", "port": "bad-port"},
            }
        )
        assert "_source_ip_invalid" in e.tags
        assert "_source_port_invalid" in e.tags
        assert len(e.tags) == 2

    def test_caller_supplied_tags_are_preserved_alongside_new_ones(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "tags": ["_geoip_lookup_failure"],
                "source": {"port": "bad-port"},
            }
        )
        assert "_geoip_lookup_failure" in e.tags
        assert "_source_port_invalid" in e.tags


class TestEventLabelsValidation:
    def test_non_str_values_are_coerced_to_str(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "labels": {"count": 3}}
        )
        assert e.labels == {"count": "3"}

    def test_non_str_keys_are_coerced_to_str(self):
        e = Event.model_validate(
            {"@timestamp": "2026-09-10T00:00:00Z", "labels": {1: "one"}}
        )
        assert e.labels == {"1": "one"}


class TestEventRelatedPopulation:
    def test_populated_from_source_ip(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", source=Source(ip="8.8.8.8"))
        assert str(e.related.ip[0]) == "8.8.8.8"

    def test_populated_from_destination_ip(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", destination=Destination(ip="1.1.1.1"))
        assert str(e.related.ip[0]) == "1.1.1.1"

    def test_populated_from_host_ip_list(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", host=Host(ip=["10.0.0.1"]))
        assert str(e.related.ip[0]) == "10.0.0.1"

    def test_duplicate_ip_across_fields_is_deduped(self):
        e = Event(
            timestamp="2026-09-10T00:00:00Z",
            source=Source(ip="8.8.8.8"),
            destination=Destination(ip="8.8.8.8"),
        )
        assert len(e.related.ip) == 1

    def test_populated_from_user_name(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", user=User(name="root"))
        assert e.related.user == ["root"]

    def test_populated_from_host_name_and_hostname(self):
        e = Event(
            timestamp="2026-09-10T00:00:00Z",
            host=Host(name="web-01", hostname="web-01.internal"),
        )
        assert e.related.hosts == ["web-01", "web-01.internal"]

    def test_related_stays_none_when_nothing_to_populate(self):
        e = Event(timestamp="2026-09-10T00:00:00Z")
        assert e.related is None

    def test_empty_sublist_stays_none_not_empty_list(self):
        e = Event(timestamp="2026-09-10T00:00:00Z", source=Source(ip="8.8.8.8"))
        assert e.related.user is None
        assert e.related.hosts is None


class TestEventStressCases:
    def test_large_tags_list_constructs_without_error(self):
        tags = [f"tag_{i}" for i in range(5000)]
        e = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "tags": tags})
        assert len(e.tags) == 5000

    def test_large_labels_dict_constructs_and_coerces_without_error(self):
        labels = {f"key_{i}": i for i in range(5000)}
        e = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "labels": labels})
        assert len(e.labels) == 5000
        assert e.labels["key_0"] == "0"

    def test_deeply_nested_extra_fieldset_round_trips(self):
        nested = {"a": {"b": {"c": [1, 2, {"d": "deep"}]}}}
        e = Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "weird": nested})
        assert e.to_doc()["weird"] == nested

    def test_large_http_response_body_bytes_value(self):
        five_gb = 5 * 1024**3
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "http": {"response": {"body": {"bytes": five_gb}}},
            }
        )
        assert e.http.response.body.bytes == five_gb

    def test_unicode_content_round_trips(self):
        e = Event.model_validate(
            {
                "@timestamp": "2026-09-10T00:00:00Z",
                "message": "login failed for user 中文 �",
                "user": {"name": "üser-中文"},
            }
        )
        doc = e.to_doc()
        assert doc["message"] == "login failed for user 中文 �"
        assert doc["user"]["name"] == "üser-中文"


class TestEventMalformedInput:
    def test_source_as_plain_string_raises_cleanly(self):
        with pytest.raises(ValidationError):
            Event.model_validate({"@timestamp": "2026-09-10T00:00:00Z", "source": "8.8.8.8"})

    def test_garbage_top_level_input_raises_cleanly(self):
        with pytest.raises(ValidationError):
            Event.model_validate(["not", "a", "dict"])
