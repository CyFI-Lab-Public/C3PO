import logging
from typing import Optional

import angr

from forsee.techniques import (  # DegreeOfConcreteness,
    LoopLimiter,
    ProcedureHandler,
    SelectiveSymbolicExecution,
    SSEArgType,
)

from .forsee_project import ForseeProject

log = logging.getLogger(__name__)


class ForseeProjectMinidump(ForseeProject):
    """
    This class is the base class for projects that use Windows minidumps
    """

    def __init__(
        self,
        memory_dump_path: str,
        max_states: int = 50,
        func_models_path: Optional[str] = None,
        loop_bound: Optional[int] = 20,
        return_unconstrained=True,
    ):
        self.func_models_path = func_models_path
        # Load minidump
        log.info(f"Loading minidump: {memory_dump_path}")
        self.angr_project = angr.Project(memory_dump_path)
        self.max_states = max_states
        sections = self.angr_project.loader.main_object.sections
        self.main_object = sections[0].vaddr
        self.loaded_libraries = [
            sect.vaddr for sect in sections if sect.vaddr != self.main_object
        ]
        self._resolve_functions()

        # Create initial state
        opts = angr.sim_options.refs | angr.sim_options.resilience | angr.options.refs
        self.initial_state = self.angr_project.factory.blank_state(add_options=opts)

        proc_handler = ProcedureHandler(
            self._imports,
            self._exports,
            self.angr_project,
            self.func_models_path,
            return_unconstrained=return_unconstrained,
        )
        # doc = DegreeOfConcreteness(self.initial_state, self.max_states)
        sse = SelectiveSymbolicExecution(
            self.angr_project,
            self._main,
            "InternetOpenUrlW",
            [SSEArgType.IGNORE, SSEArgType.STR_U16],
            [0x11B27D0, 0x11B3410],
        )
        # self._techniques = [proc_handler, doc, sse]
        self._techniques = [proc_handler, sse]
        if loop_bound:
            ll = LoopLimiter(loop_bound)
            self._techniques.append(ll)
