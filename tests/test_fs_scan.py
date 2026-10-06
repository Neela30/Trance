from core import fs_scan


def test_walk_pruned_skips_listed_directory_names(tmp_path):
    skipped = tmp_path / "System Volume Information"
    skipped.mkdir()
    (skipped / "marker.txt").write_text("x")
    kept = tmp_path / "normal"
    kept.mkdir()
    (kept / "marker.txt").write_text("x")

    visited = [current for current, _dirnames, _filenames in fs_scan.walk_pruned(tmp_path)]

    assert skipped not in visited
    assert kept in visited


def test_walk_pruned_skips_appdata(tmp_path):
    """AppData is where leftover test fixtures / app caches live, not where a human
    deliberately places a Tor Browser install or a WinPMEM binary -- auto-discovery
    picking up a stale pytest fixture named winpmem.exe under %TEMP% was a real bug."""
    skipped = tmp_path / "AppData"
    skipped.mkdir()
    (skipped / "winpmem.exe").write_text("not a real winpmem binary")

    visited = [current for current, _dirnames, _filenames in fs_scan.walk_pruned(tmp_path)]

    assert skipped not in visited


def test_walk_pruned_respects_max_depth(tmp_path):
    deep = tmp_path
    for _ in range(10):
        deep = deep / "nested"
    deep.mkdir(parents=True)

    visited = [current for current, _d, _f in fs_scan.walk_pruned(tmp_path, max_depth=3)]

    assert deep not in visited


def test_walk_pruned_caller_can_prune_further(tmp_path):
    found_dir = tmp_path / "found"
    (found_dir / "should-not-be-visited").mkdir(parents=True)

    visited = []
    for current, dirnames, _filenames in fs_scan.walk_pruned(tmp_path):
        visited.append(current)
        if current == found_dir:
            dirnames[:] = []

    assert found_dir / "should-not-be-visited" not in visited


def test_staged_scan_uses_explicit_roots_when_given(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()

    calls = []

    def scan_root(root):
        calls.append(root)
        return [root]

    result = fs_scan.staged_scan(scan_root, search_roots=[tmp_path / "a", tmp_path / "b"])

    assert calls == [tmp_path / "a", tmp_path / "b"]
    assert result == [tmp_path / "a", tmp_path / "b"]


def test_staged_scan_falls_back_to_drive_roots_only_if_fast_roots_find_nothing(monkeypatch):
    calls = []

    def scan_root(root):
        calls.append(root)
        return ["match"] if root == "drive-root" else []

    monkeypatch.setattr(fs_scan, "fast_search_roots", lambda: ["fast-root"])
    monkeypatch.setattr(fs_scan, "drive_search_roots", lambda: ["drive-root"])

    result = fs_scan.staged_scan(scan_root)

    assert calls == ["fast-root", "drive-root"]
    assert result == ["match"]


def test_staged_scan_does_not_touch_drive_roots_when_fast_roots_find_something(monkeypatch):
    calls = []

    def scan_root(root):
        calls.append(root)
        return ["match"]

    monkeypatch.setattr(fs_scan, "fast_search_roots", lambda: ["fast-root"])
    monkeypatch.setattr(
        fs_scan,
        "drive_search_roots",
        lambda: (_ for _ in ()).throw(AssertionError("should not run")),
    )

    result = fs_scan.staged_scan(scan_root)

    assert calls == ["fast-root"]
    assert result == ["match"]
