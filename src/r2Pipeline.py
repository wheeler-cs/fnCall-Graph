# == Imports ===========================================================================================================
import json
import r2pipe
from sys import argv
from typing import Dict, List

from AdjacencyMatrix import AdjacencyMatrix


# == Function Definitions ==============================================================================================
def analyzeProgram(inputFile: str):
    cmdPipe = r2pipe.open(inputFile)
    cmdPipe.cmd("aaa")
    cmdPipe.cmd(f"agCj > {inputFile}.json")


def jsonToAssociations(inputJson: str) -> Dict[str, List[str]]:
    with open(inputJson) as jsonFile:
        jsonData = json.load(jsonFile)

    associations = {}
    for entry in jsonData:
        associations[entry["name"]] = entry["imports"]
    return associations


# == Main ==============================================================================================================
if __name__ == "__main__":
    #analyzeProgram(argv[1])
    assoc = jsonToAssociations(argv[1])
    am = AdjacencyMatrix()
    am.createMatrix(assoc)
    am.printMatrix()
