# == Imports ===========================================================================================================
import json
import r2pipe
from sys import argv
from typing import Dict, List

from AdjacencyMatrix import AdjacencyMatrix


# == Function Definitions ==============================================================================================
def analyzeProgram(inputFile: str) -> None:
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
    assoc = jsonToAssociations(argv[1])
    if len(assoc) == 0:
        raise RuntimeError("Input JSON file could not be parsed")
    am = AdjacencyMatrix()
    am.createMatrix(assoc)
    am.printMatrix()
