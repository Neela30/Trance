"""Module A — Registry & Execution Evidence.

Parses NTUSER.DAT, SYSTEM, and Amcache.hve to establish whether Tor Browser
was installed/run on the target machine and its approximate execution
timeline. See modules/module_a_registry/pipeline.py for the orchestration
and TRANCE_Project_and_ModuleA_Description.pdf section 2 for the design
brief this module implements.
"""

from .pipeline import ModuleAResult, run_module_a, write_output

__all__ = ["run_module_a", "write_output", "ModuleAResult"]
