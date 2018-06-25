class UnknownInstructionError(Exception):
    def __init__(self):
        Exception.__init__(self,
                           "Provided instruction is not present in the \
                           instruction set")


class PositionInstructionError(Exception):
    def __init__(self, offset, data, data_new):
        Exception.__init__(self,
                           "Offset %s already contains\r\n %s,\r\n provided %s"
                           % (hex(offset), str(data), str(data_new)))


class WProtectControlFlow:
    def __init__(self, instruction_set):
        self.instruction_set = instruction_set
        self.nodes = {}

    def add_node(self, offset, instruction, parameters, next_offset):
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
        else:
            raise PositionInstructionError(offset, self.nodes[offset],
                                           {"instruction": instruction.name,
                                            "params": parameters})

    def get_control_flow(self):
        from networkx import Graph
        graph = Graph()
        for offset, node in self.nodes.iteritems():
            for following in node["successors"]:
                graph.add_path([offset, following])
        return graph

    def get_simple_control_flow(self):
        graph = self.get_control_flow()
        removal = []
        for node in graph.edge.keys():
            neighbours = graph.neighbors(node)
            if (len(neighbours) == 2
                    and any([len(graph.edge[n]) == 2 for n in neighbours])):
                for n in neighbours:
                    graph.remove_edge(node, n)
                removal.append(node)
                graph.add_path(neighbours)
        for x in removal:
            graph.remove_node(x)
        return graph

    def get_specials(self):
        entry_point = None
        block_start = set()

        for offset, value in self.nodes.iteritems():
            if value["predecessors"] == 0:
                assert entry_point is None
                entry_point = offset
            elif value["predecessors"] >= 2:
                block_start.add(offset)
            if len(value["successors"]) >= 2:
                for successor in value["successors"]:
                    block_start.add(successor)

        return entry_point, block_start

    def compile_blocks(self, blocks, offset=None, labeled_offsets=None):
        if not all([offset, labeled_offsets]):
            offset, labeled_offsets = self.get_specials()

        if offset in blocks:
            return blocks

        block = {}
        blocks[offset] = block
        while (len(self.nodes[offset]["successors"]) <= 1
               and not all([x in labeled_offsets
                            for x in self.nodes[offset]["successors"]])):
            if offset in block:
                return
            block[offset] = self.nodes[offset]
            try:
                offset = self.nodes[offset]["successors"][0]
            except KeyError:
                return
        for successor in self.nodes[offset]["successors"]:
            self.compile_blocks(blocks, offset=successor,
                                labeled_offsets=labeled_offsets)
        return blocks
