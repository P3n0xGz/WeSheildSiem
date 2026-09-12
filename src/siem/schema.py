from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone, tzinfo 
from ipaddress import ip_address
from typing import Any
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ECS_VERSION = "8.11"
RAW_STREAM_FIELDS = ("raw", "source", "transport", "received_at", "host", "labels")

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def to_utc(value: str | datetime | int | float) -> str:
    if isinstance(value, datetime):
        if tzinfo is None:
            return value.replace(tzinfo=timezone.utc).isoformat()
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, (int, (int,float))):
        if value > 1e11:
            value = value / 1000
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    if isinstance(value, (int, str)):
        cleaned_value = value.replace("Z","+00:00")
        dt = datetime.fromisoformat(cleaned_value)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc).isoformat()
        return dt.astimezone(timezone.utc).isoformat()
    raise ValueError(f"Invalid value for to_utc: {value}")
    
def canonical_json(obj: Any) -> str:
    """Produces sorted, deterministic JSON text with no extra spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


                  
