from pathlib import Path

from gui.pipeline_inputs import module_kwargs_from_resolved


def test_module_kwargs_from_resolved_maps_all_fields():
    resolved = {
        "system": "registry/SYSTEM_x",
        "ntuser": "registry/NTUSER_x.DAT",
        "usrclass": "registry/UsrClass_alice_x.dat",
        "dump": "memory/fullmem_x.raw",
        "source_type": "full-memory",
        "disk_profile": "disk/profile",
        "tor_dir": "disk/tor_dir",
    }

    kwargs = module_kwargs_from_resolved(resolved, "abc.onion", "127.0.0.1:5000", "alice")

    assert kwargs["module_a_registry"]["system"] == Path("registry/SYSTEM_x")
    assert kwargs["module_a_registry"]["ntuser"] == Path("registry/NTUSER_x.DAT")
    assert kwargs["module_a_registry"]["amcache"] is None
    assert kwargs["module_a_registry"]["software"] is None
    assert kwargs["module_a_registry"]["usrclass"] == Path("registry/UsrClass_alice_x.dat")
    assert kwargs["module_b_disk"]["profile_dir"] == Path("disk/profile")
    assert kwargs["module_b_disk"]["tor_dir"] == Path("disk/tor_dir")
    assert kwargs["module_c_memory"]["dump"] == Path("memory/fullmem_x.raw")
    assert kwargs["module_c_memory"]["source_type"] == "full-memory"
    assert kwargs["module_c_memory"]["onion"] == "abc.onion"
    assert kwargs["module_c_memory"]["host"] == "127.0.0.1:5000"
    assert kwargs["module_c_memory"]["username"] == "alice"


def test_module_kwargs_from_resolved_empty_fields_become_none():
    kwargs = module_kwargs_from_resolved({}, "", "", "")

    assert kwargs["module_a_registry"] == {
        "ntuser": None,
        "system": None,
        "amcache": None,
        "software": None,
        "usrclass": None,
    }
    assert kwargs["module_c_memory"]["onion"] is None
    assert kwargs["module_c_memory"]["source_type"] == "process"


def test_module_kwargs_from_resolved_passes_the_downloads_scan():
    kwargs = module_kwargs_from_resolved(
        {"downloads_scan": "disk/downloads/zone_identifier_scan.json"}, "", "", ""
    )
    assert kwargs["module_b_disk"]["downloads_scan"] == Path(
        "disk/downloads/zone_identifier_scan.json"
    )


def test_cookie_names_field_is_split_trimmed_and_blank_means_default():
    from gui.pipeline_inputs import module_kwargs_from_resolved

    kwargs = module_kwargs_from_resolved({}, "", "", "", cookie_names=" sid , csrf_token,, ")
    assert kwargs["module_c_memory"]["cookie_names"] == ["sid", "csrf_token"]
    assert module_kwargs_from_resolved({}, "", "", "")["module_c_memory"]["cookie_names"] is None
