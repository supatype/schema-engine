#!/usr/bin/env python3
"""Convert flat v1 schema fixtures to AST v2 namespaced format."""
from __future__ import annotations

import json
import sys
from pathlib import Path

KERNEL_SCALAR = {
    "text", "richText", "integer", "float", "boolean", "datetime", "uuid", "email",
    "slug", "enum", "json", "decimal", "bigInt", "bytes", "smallInt", "date",
    "timestamp", "serial", "bigSerial", "money", "url", "ip", "cidr", "macaddr",
    "interval", "tsQuery", "tsVector", "xml", "color", "array", "image", "file",
    "geo", "vector", "blocks", "custom",
}

DB_KEYS = {"pgType", "unique", "index", "foreignKey", "serverGenerated", "elementType"}
PLATFORM_KEYS = {"readOnly", "editor"}


def convert_field(field: dict) -> dict:
    kind = field.get("kind")
    if kind in ("timestamps", "publishable", "softDelete"):
        return {"kind": kind}

    out: dict = {"kind": kind}
    annotations: dict = {"db": {}, "platform": {}}

    for key, val in list(field.items()):
        if key == "kind":
            continue
        if key in DB_KEYS:
            camel = key[0].lower() + key[1:] if key == "pgType" else (
                "foreignKey" if key == "foreignKey" else
                "serverGenerated" if key == "serverGenerated" else
                "elementType" if key == "elementType" else key
            )
            if key == "pgType":
                annotations["db"]["pgType"] = val
            elif key == "foreignKey":
                annotations["db"]["foreignKey"] = val
            elif key == "serverGenerated":
                annotations["db"]["serverGenerated"] = val
            elif key == "elementType":
                annotations["db"]["elementType"] = val
            elif key == "unique":
                annotations["db"]["unique"] = val
            elif key == "index":
                annotations["db"]["index"] = val
        elif key == "readOnly":
            annotations["platform"]["readOnly"] = val
        elif key in ("required", "primaryKey", "default", "cardinality", "target", "values",
                     "from", "sources", "template", "localized", "check", "bucket", "accessMode",
                     "geoType", "srid", "dimensions", "blocks", "precision", "scale",
                     "references", "through", "onDelete", "onUpdate", "uniqueFk", "plugin",
                     "fieldType", "tsType"):
            out[key] = val

    if annotations["db"] or annotations["platform"]:
        out["annotations"] = {k: v for k, v in annotations.items() if v}

    if kind == "richText" and "platform" not in out.get("annotations", {}):
        out.setdefault("annotations", {})["platform"] = {"editor": "rich"}

    return out


def convert_access_field(access: dict, fields: dict) -> dict:
    """Keep kernel field names; map snake_case FK refs to relation field names where obvious."""
    if access.get("type") != "owner":
        return access
    field = access.get("field", "")
    if field in fields or field == "id":
        return access
    # map author_id -> authorId if relation exists
    for fname, fdef in fields.items():
        if fdef.get("kind") != "relation":
            continue
        fk = fdef.get("foreignKey") or fdef.get("annotations", {}).get("db", {}).get("foreignKey")
        if fk == field or f"{fname.replace('Id', '').lower()}_id" == field:
            return {**access, "field": fname}
    return access


def convert_model(model: dict) -> dict:
    fields = {k: convert_field(v) for k, v in model.get("fields", {}).items()}

    platform_access = model.get("access", {})
    if platform_access:
        platform_access = {
            k: convert_access_field(v, fields) if isinstance(v, dict) else v
            for k, v in platform_access.items()
        }

    out = {
        "name": model["name"],
        "fields": fields,
        "options": model.get("options", {}),
        "annotations": {
            "db": {
                "tableName": model.get("tableName", ""),
                "indexes": model.get("indexes", []),
            },
            "platform": {"access": platform_access},
        },
    }
    return out


def convert_schema(data: dict) -> dict:
    return {
        "astVersion": 2,
        "models": [convert_model(m) for m in data.get("models", [])],
        **{k: v for k, v in data.items() if k not in ("models",)},
    }


def main() -> None:
    for path in sys.argv[1:]:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        if data.get("astVersion") == 2:
            continue
        p.write_text(json.dumps(convert_schema(data), indent=2) + "\n", encoding="utf-8")
        print("converted", p)


if __name__ == "__main__":
    main()
