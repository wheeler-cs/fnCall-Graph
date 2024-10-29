from itertools import product, zip_longest

from typing import Dict, List


class AdjacencyMatrix(object):
    def __init__(self) -> None:
        # Why, yes... this _is_ cursed
        self.matrix: Dict[str: Dict[str: bool]] = {}


    def createMatrix(self, associations: Dict[str, List[str]]) -> None:
        # These lists are used initialize the matrix cells for a function
        nodeList = []
        falseList = []
        for key in associations.keys():
            nodeList.append(key)
            falseList.append(False)
        # Add called functions to the list of nodes so matrix is square
        for callList in associations.values(): # For all the list of calls made by a function
            for element in callList:           # For every element in a given list
                if element not in nodeList:
                    nodeList.append(element)
                    falseList.append(False)

        # Take note of which callers use which callees
        for node in nodeList:
            # I [kinda] have no idea what this does and at this point I'm too afraid to ask
            callsMade = dict(zip_longest(*[iter(nodeList)], *[iter(falseList)], fillvalue=False))
            if node in associations.keys():
                for call in associations[node]:
                    callsMade[call] = True
            self.matrix[node] = callsMade


    def printMatrix(self) -> None:
        for row in self.matrix.values():
            print(row)
