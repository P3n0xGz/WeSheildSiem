from datetime import UTC, datetime, timedelta, timezone

import pytest

from siem.schema import canonical_json, now_utc, to_utc


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
