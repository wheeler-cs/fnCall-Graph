# == Imports ===========================================================================================================
import json
import r2pipe
from sys import argv
from typing import Dict, List

from graphNode import GraphNode



# == Function Definitions ==============================================================================================
def extractData(inputFile: str):
    cmdPipe = r2pipe.open("data/NPP.exe")
    cmdPipe.cmd("aaa")
    cmdPipe.cmd("agCj > data/output.json")


def readJson(inputFile: str):
    with open(inputFile, 'r') as jsonFile:
        jsonData = json.load(jsonFile)
    return jsonData


def buildGraph(jsonData) -> GraphNode:
    rootNode = GraphNode("root", True)
    for data in jsonData:
        newNode = GraphNode(data["name"])
        for child in data["imports"]:
            childNode = GraphNode(child)
            newNode.addChild(childNode)
        rootNode.addChild(newNode)
    return(rootNode)



# == Main ==============================================================================================================
if __name__ == "__main__":
    jsonData = readJson(argv[1])

    graph = buildGraph(jsonData)
    graph.inorderTraversal()

