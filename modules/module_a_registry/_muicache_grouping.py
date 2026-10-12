"""Shared post-processing for MUICache's raw extracted records -- used by both
extractors.extract_muicache() (NTUSER.DAT, via regipy's own MUICachePlugin) and
custom_extractors.extract_muicache_usrclass() (UsrClass.dat, hand-written; see that
function's own docstring for why no regipy plugin can reach that data).

Confirmed real-world bug (against a real UsrClass.dat capture, not guessed): Windows
Vista+ MuiCache doesn't store one registry value per program. It stores TWO --
"<path>.FriendlyAppName" and "<path>.ApplicationCompany" -- each a separate value under
the same key, both describing the same program. Treated naively (one raw value = one
finding, which is what both extractors above did before this module existed), the same
single program shows up as two distinct "files" in report.py's cross-hive component
table, with the literal ".FriendlyAppName"/".ApplicationCompany" suffix stuck onto the
basename. group_muicache_values() merges both suffixed values for the same base path into
one record carrying both pieces of information, and strips the suffix from the path/
filename so basename-based correlation with UserAssist/ShimCache/Amcache works correctly.

A bare, unsuffixed value (the older, pre-Vista single-value MuiCache convention, if ever
seen against a legacy hive) passes through unchanged as its own group, using the value's
own `display_name` directly -- there is no separate company for that convention.
"""

from __future__ import annotations

_FRIENDLY_APP_NAME_SUFFIX = ".FriendlyAppName"
_APPLICATION_COMPANY_SUFFIX = ".ApplicationCompany"


def group_muicache_values(raw_entries: list[dict]) -> list[dict]:
    """Groups raw {"key_path","last_write","path","display_name","filename"} records (the
    exact flat shape both extract_muicache() and extract_muicache_usrclass() produce, one
    per regipy/raw registry value) by the base path with the Vista+ suffix stripped,
    merging a FriendlyAppName/ApplicationCompany pair for the same program into one
    record: {"key_path","last_write","path" (base path, suffix stripped),"filename"
    (basename of the stripped path),"display_name" (from .FriendlyAppName, or the bare
    value's own display_name for the unsuffixed convention),"application_company" (from
    .ApplicationCompany, or None when no such value exists for this path)}.

    Order-preserving (first-seen base path order) for deterministic, repeatable output --
    same requirement the rest of this module's pipeline already holds to.
    """
    groups: dict[str, dict] = {}
    order: list[str] = []

    for entry in raw_entries:
        raw_path = entry.get("path") or ""
        base_path = raw_path
        field: str | None = None
        if raw_path.endswith(_FRIENDLY_APP_NAME_SUFFIX):
            base_path = raw_path[: -len(_FRIENDLY_APP_NAME_SUFFIX)]
            field = "display_name"
        elif raw_path.endswith(_APPLICATION_COMPANY_SUFFIX):
            base_path = raw_path[: -len(_APPLICATION_COMPANY_SUFFIX)]
            field = "application_company"

        if base_path not in groups:
            groups[base_path] = {
                "key_path": entry.get("key_path"),
                "last_write": entry.get("last_write"),
                "path": base_path,
                "filename": base_path.rsplit("\\", 1)[-1] if base_path else base_path,
                "display_name": None,
                "application_company": None,
            }
            order.append(base_path)

        group = groups[base_path]
        if field == "display_name":
            group["display_name"] = entry.get("display_name")
        elif field == "application_company":
            group["application_company"] = entry.get("display_name")
        else:
            # Bare, unsuffixed value (pre-Vista convention) -- its own value IS the
            # display name directly.
            group["display_name"] = entry.get("display_name")

    return [groups[path] for path in order]
