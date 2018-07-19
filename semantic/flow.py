class UnknownInstructionError(Exception):
    """Error class inteded for WProtectControlFlow when an unknown
    instruction is encountered during step-by-step emulation.
    """
    def __init__(self):
        """Basic information string
        """
        Exception.__init__(self,
                           "Provided instruction is not present in the \
                           instruction set")


class PositionInstructionError(Exception):
    """Error class intended for WProtectControlFlow when a known
    offset is encountered multiple times with a different interpretation.
    """
    def __init__(self, offset, data, data_new):
        """Basic information string

        Args:
            offset (int): error offset (instruction address)
            data (dict): already saved data
            data_new (dict): new data encountered
        """
        Exception.__init__(self,
                           "Offset %s already contains\r\n %s,\r\n provided %s"
                           % (hex(offset), str(data), str(data_new)))


class WProtectControlFlow(object):
    """Class containing necessary functions to reconstruct the control flow.
    """
    def __init__(self, instruction_set):
        """Set up the instruction set.

        Args:
            instruction_set (list): a list of instructions to be recognized
        """
        self.instruction_set = instruction_set
        self.nodes = {}

    def add_node(self, offset, instruction, parameters, next_offset):
        """Add node to the control flow list. Track the predecessor
        count.

        Args:
            offset (int): new node's offset (instruction's address)
            instruction (vm.Mnemonic): a member of instruction_set
            parameters (list): a list of provided parameters
            next_offset (int): an offset of the following instruction
        """
        if instruction not in self.instruction_set:
            raise UnknownInstructionError()

        if instruction.name == "ret":
            next_offset = []

        if offset not in self.nodes:
            self.nodes[offset] = {"predecessors": 0}
        if "instruction" not in self.nodes[offset]:
            self.nodes[offset]["instruction"] = instruction
            self.nodes[offset]["params"] = parameters
            self.nodes[offset]["successors"] = next_offset

            for succ in next_offset:
                if succ in self.nodes:
                    self.nodes[succ]["predecessors"] += 1
                else:
                    self.nodes[succ] = {"predecessors": 1}
        elif (self.nodes[offset]["instruction"] == instruction
              and self.nodes[offset]["params"] == parameters):
            raise PositionInstructionError(offset, self.nodes[offset],
                                           {"instruction": instruction,
                                            "params": parameters})

    def get_control_flow(self):
        """Create a control flow graph from saved nodes.
        """
        from networkx import Graph
        graph = Graph()
        for offset, node in self.nodes.iteritems():
            for following in node["successors"]:
                graph.add_path([offset, following])
        return graph

    def get_simple_control_flow(self):
        """Create a pruned control flow graph from saved nodes. Every node
        that has degree 2 and its neighbours have also degree 2 is removed
        from the graph.
        """
        graph = self.get_control_flow()
        removal = []
        for node in graph.edge.keys():
            neighbours = graph.neighbors(node)
            if (len(neighbours) == 2
                    and any([len(graph.edge[n]) == 2 for n in neighbours])):
                for nbr in neighbours:
                    graph.remove_edge(node, nbr)
                removal.append(node)
                graph.add_path(neighbours)
        for node in removal:
            graph.remove_node(node)
        return graph

    def get_specials(self):
        """Get a set of addresses to be labeled due to being used by jumps.

        Returns:
            set: a set of all addresses to be labeled
        """
        block_start = set()

        for offset, value in self.nodes.iteritems():
            if not value["predecessors"] == 1:
                block_start.add(offset)
            if len(value["successors"]) >= 2:
                for successor in value["successors"]:
                    block_start.add(successor)

        return block_start

    def compile_blocks(self, offset=None, labeled_offsets=None):
        """Compile nodes into continuous blocks (IDAPro-like blocks).

        Args:
            offset (int): offset of the first instruction to process
            labeled_offsets (list): list of offsets that are targets
                of jumps or contain jumps

        Returns:
            dict: actually dictionary of dictionaries, corresponds
                to initial variable blocks indexed by offsets;
                every value corresponds to a block, every block is
                a dictionary indexed by offset
        """
        if not all([offset, labeled_offsets]):
            labeled_offsets = self.get_specials()

        blocks = {}

        for start in labeled_offsets:
            offset = start
            blocks[start] = []
            while self.nodes[offset]["instruction"].name not in ["ret", "set_key"]:
                assert len(self.nodes[offset]["successors"]) == 1
                blocks[start].append(self.nodes[offset])
                offset = self.nodes[offset]["successors"][0]
            blocks[start].append(self.nodes[offset])
        return blocks
