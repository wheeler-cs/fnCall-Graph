from itertools import product, zip_longest

from typing import Dict, List, Set


class AdjacencyMatrix(object):
    def __init__(self) -> None:
        self.matrix: Dict[str: Dict[str: bool]] = dict()
        self.fnList: Set[str] = set()


    def createMatrix(self, associations: Dict[str, List[str]]) -> None:
        # Function list is template of labels for what calls are made and by what
        for caller in associations.keys():
            self.fnList.add(caller)
            self.fnList.update(set(associations[caller]))
        # WARN: The above appears to be nondeterministic; the same input does not yield the same output, even though the
        # representation is unchanged at its core.
        for node in self.fnList:
            # Reinitialize a call list for every function
            nodeCalls = dict.fromkeys(self.fnList, False)
            if node in associations.keys():
                for call in associations[node]:
                    nodeCalls[call] = True
            self.matrix[node] = nodeCalls


    def printMatrix(self) -> None:
        for row in self.matrix.values():
            for v in row.values():
                if v:
                    print("1 ", end='')
                else:
                    print("0 ", end='')
            print('')
