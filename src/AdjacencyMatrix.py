from itertools import product, zip_longest

from typing import Dict, List, Set


class AdjacencyMatrix(object):
    def __init__(self) -> None:
        # Why, yes... this _is_ cursed
        self.matrix: Dict[str: Dict[str: bool]] = {}


    def createMatrix(self, associations: Dict[str, List[str]]) -> None:
        # Function list is template of labels for what calls are made and by what
        fnList: Set[str] = set()
        for caller in associations.keys():
            fnList.add(caller)
            fnList.update(set(associations[caller]))
        falseList = [False] * len(fnList)
        # WARN: The above appears to be nondeterministic; the same input does not yield the same output, even though the
        # representation is unchanged at its core.
        
        # Take note of which callers use which callees
        for node in fnList:
            # I [kinda] have no idea what this does and at this point I'm too afraid to ask
            callsMade = dict(zip_longest(*[iter(fnList)], *[iter(falseList)], fillvalue=False))
            if node in associations.keys():
                for call in associations[node]:
                    callsMade[call] = True
            self.matrix[node] = callsMade


    def printMatrix(self) -> None:
        for row in self.matrix.values():
            for v in row.values():
                if v:
                    print("1 ", end='')
                else:
                    print("0 ", end='')
            print('')
