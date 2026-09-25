from pathlib import Path

from gui.pipeline_inputs import module_kwargs_from_resolved


def test_module_kwargs_from_resolved_maps_all_fields():
    resolved = {
        "system": "registry/SYSTEM_x",
        "ntuser": "registry/NTUSER_x.DAT",
        "dump": "memory/fullmem_x.raw",
        "source_type": "full-memory",
        "disk_profile": "disk/profile",
        "tor_dir": "disk/tor_dir",
    }

    kwargs = module_kwargs_from_resolved(resolved, "abc.onion", "127.0.0.1:5000", "alice")

    assert kwargs["module_a_registry"]["system"] == Path("registry/SYSTEM_x")
    assert kwargs["module_a_registry"]["ntuser"] == Path("registry/NTUSER_x.DAT")
    assert kwargs["module_a_registry"]["amcache"] is None
    assert kwargs["module_b_disk"]["profile_dir"] == Path("disk/profile")
    assert kwargs["module_b_disk"]["tor_dir"] == Path("disk/tor_dir")
    assert kwargs["module_c_memory"]["dump"] == Path("memory/fullmem_x.raw")
    assert kwargs["module_c_memory"]["source_type"] == "full-memory"
    assert kwargs["module_c_memory"]["onion"] == "abc.onion"
    assert kwargs["module_c_memory"]["host"] == "127.0.0.1:5000"
    assert kwargs["module_c_memory"]["username"] == "alice"


def test_module_kwargs_from_resolved_empty_fields_become_none():
    kwargs = module_kwargs_from_resolved({}, "", "", "")

    assert kwargs["module_a_registry"] == {"ntuser": None, "system": None, "amcache": None}
    assert kwargs["module_c_memory"]["onion"] is None
    assert kwargs["module_c_memory"]["source_type"] == "process"
