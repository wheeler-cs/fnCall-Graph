from typing import List, Self


class GraphNode(object):
    def __init__(self, nodeName: str = "", isRoot: bool = False) -> None:
        self._name: str = nodeName
        self._childNodes: List[GraphNode] = []
        self._isRoot: bool = isRoot

    
    def addChild(self, newNode: Self) -> None:
        for child in self._childNodes:
            if newNode == child:
                child._childNodes = newNode._childNodes
                return
        self._childNodes.append(newNode)


    def inorderTraversal(self) -> None:
        if self._isRoot and (len(self._childNodes) == 0):
            print("Graph is empty")
        for child in self._childNodes:
            child.inorderTraversal()
            print(child._name)
    

    def __eq__(self, cmp) -> bool:
        if(isinstance(cmp, GraphNode)):
            return self._name == cmp._name
        return NotImplemented
