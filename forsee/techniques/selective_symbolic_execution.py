import logging
from collections import deque
from enum import Enum

import angr
from angr import BP_AFTER, ExplorationTechnique, SimState, SimulationManager

from forsee.plugins.extract_string import get_string_a, get_string_w

log = logging.getLogger(__name__)


LOOP_LIMIT = 1000


class SSEArgType(Enum):
    """
    Type of argument we wish to extract from hooked sink simprocedure
    """

    IGNORE = 0  # Ignore this argument
    I8 = 1  # 8-bit integer
    I16 = 2  # 16-bit integer
    I32 = 3  # 32-bit integer
    I64 = 4  # 64-bit integer
    STR_A = 9  # Null-terminated ASCII/UTF-8 string
    STR_U8 = 9  # Null-terminated ASCII/UTF-8 string
    STR_U16 = 10  # Null-terminated UTF-16 string


def get_reachability_map(cfg, sink_addr):
    """
    Get a map of basic block start addresses to the minimum number of steps from
    the block to the sink
    """
    reachability_map = {}
    sink_node = cfg.model.get_any_node(sink_addr)
    queue = deque()
    queue.append((sink_node, 0))
    while len(queue) > 0:
        node, num_steps = queue.popleft()
        node_addr = node.addr
        if node_addr not in reachability_map:
            reachability_map[node_addr] = num_steps
            for predecessor in node.predecessors:
                pred_addr = predecessor.addr
                if pred_addr not in reachability_map:
                    queue.append((predecessor, num_steps + 1))
    return reachability_map


class SelectiveSymbolicExecution(ExplorationTechnique):
    def __init__(
        self,
        project: angr.Project,
        bin_start: int,
        sink,
        extract_args: [SSEArgType],
        call_graph_path: [int],
        max_states: int = 50,
    ):
        """
        Initialize the SelectiveSymbolicExecution exploration technique. Params -
        project         - An angr project
        bin_start       - Start address from which to build the CFGEmulation
                          (ideally main/WinMain)
        sink            - Address or name of the sink to end exploration at
        call_graph_path - Addresses of function, from innermost to outermost,
                          which are on the path to the call to `sink`. e.g.,
                          [0x1, 0x2, 0x3]. In this case, all three elements are
                          addresses of functions, such that 0x1 contains a call
                          to the sink, 0x2 contains a call to 0x1, and 0x3
                          contains a call to 0x2.
        """
        super(SelectiveSymbolicExecution, self).__init__()
        self.project = project
        self.address_hit_count = {}
        self.is_complete = False
        self.max_states = max_states
        self.extract_args = extract_args
        if not isinstance(bin_start, int):
            raise "Expected start address (e.g. main)"

        self.cfg = self.project.analyses.CFGEmulated(
            starts=[bin_start], context_sensitivity_level=2, keep_state=True,
        )
        if isinstance(sink, int):
            self.sink_addr = sink
        elif isinstance(sink, str):
            self.sink_addr = self.cfg.kb.functions.function(name=sink).addr
        else:
            raise "Expected either sink name or address"
        self.reachability_map = get_reachability_map(self.cfg, self.sink_addr)

        self.start_states = []
        opts = angr.sim_options.refs | angr.sim_options.resilience
        for addr in call_graph_path:
            state = self.project.factory.blank_state(addr=addr, add_options=opts)
            state.inspect.b("simprocedure", when=BP_AFTER, action=self.simprocedure)
            self.start_states.append(state)
        assert len(self.start_states) > 0

        log.debug("Initialized SelectiveSymbolicExecution exploration technique")

    def simprocedure(self, state: SimState):
        start_addr = state.addr
        if start_addr == self.sink_addr:
            arguments = []
            try:
                proc = state.inspect.simprocedure
                log.info(
                    "Reached sink simprocedure: '{}' at {}".format(
                        proc.display_name, hex(start_addr)
                    )
                )
                for arg_idx in range(len(self.extract_args)):
                    arg = proc.arg(arg_idx)
                    if self.extract_args[arg_idx] == SSEArgType.I8:
                        arguments.append(state.memory.load(arg, size=1))
                    elif self.extract_args[arg_idx] == SSEArgType.I16:
                        arguments.append(state.memory.load(arg, size=2))
                    elif self.extract_args[arg_idx] == SSEArgType.I32:
                        arguments.append(state.memory.load(arg, size=4))
                    elif self.extract_args[arg_idx] == SSEArgType.I64:
                        arguments.append(state.memory.load(arg, size=8))
                    elif self.extract_args[arg_idx] == SSEArgType.STR_A:
                        arguments.append(get_string_a(state, arg))
                    elif self.extract_args[arg_idx] == SSEArgType.STR_U16:
                        arguments.append(get_string_w(state, arg))
                    else:
                        arguments.append(None)
                log.info("Concretized arguments for sink: {}".format(arguments))
                self.is_complete = True
            except angr.SimUnsatError:
                pass

    def setup(self, simgr: SimulationManager):
        """
        Replace the simgr's list of 'active' states with the first state we are
        running from
        """
        simgr.populate("active", [self.start_states[0]])
        log.debug(
            "Starting exploration with state at address: "
            + hex(self.start_states[0].addr)
        )
        self.start_states = self.start_states[1:]

    def step_state(self, simgr: SimulationManager, state: SimState, **kwargs):
        """
        Step the state forward. Check if any states have been pruned that should
        not have been, and move them back to active
        """
        # TODO: Handle non-simprocedure sinks
        stashes = simgr.step_state(state, **kwargs)
        new_actives = []
        for k, v in stashes.items():
            if k is None:
                continue
            keep_states = []
            for state in v:
                if state.addr in self.reachability_map:
                    log.debug(
                        "Moving state at {} from '{}' to None".format(
                            hex(state.addr), k
                        )
                    )
                    new_actives.append(state)
                else:
                    keep_states.append(state)
            stashes[k] = keep_states
        stashes[None] = stashes.get(None, []) + new_actives
        return stashes

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs):
        """
        Step the stash forward. If we have run out of active states, expand and
        re-try concretizing
        """
        simgr = simgr.step(stash, **kwargs)
        simgr.move(
            "active", "sse_pruned", lambda st: st.addr not in self.reachability_map
        )

        if len(simgr.active) == 0:
            simgr.move("sse_stashed", "active")

        if len(simgr.active) == 0:
            # import ipdb; ipdb.set_trace()
            if len(self.start_states) == 0:
                return simgr
            simgr.populate("active", [self.start_states[0]])
            log.debug(
                "Starting exploration with state at address: "
                + hex(self.start_states[0].addr)
            )
            self.start_states = self.start_states[1:]
        elif len(simgr.active) > self.max_states:
            sorted_states = sorted(
                simgr.active, key=lambda x: self.reachability_map[x.addr]
            )
            to_prune = set([hash(st) for st in sorted_states[self.max_states :]])
            log.debug(
                "Max number of states exceeded. Pruning {} states".format(
                    len(simgr.active) - self.max_states
                )
            )
            simgr.move("active", "sse_stashed", lambda st: hash(st) in to_prune)
        return simgr

    def complete(self, simgr):
        return self.is_complete

    def __repr__(self):
        return "<SelectiveSymbEx>"
