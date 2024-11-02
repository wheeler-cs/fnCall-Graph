# == Imports ===========================================================================================================
import json
from os import makedirs, path
import r2pipe
from sys import argv
from typing import Dict, List

from AdjacencyMatrix import AdjacencyMatrix


# == Function Definitions ==============================================================================================
def analyzeProgram(inputFile: str, cacheJson: bool = False) -> str:
    '''
    Use radare2 to analyze the control flow of an executable file.

    @param inputFile: The target executable program for analysis.
    @param cacheJson: Determines if the output JSON from analysis will be written to disk.

    @return jsonData: A string storing the JSON output of the analysis by radare2.
    '''
    cmdPipe = r2pipe.open(inputFile, flags=["-2"])
    jsonData = cmdPipe.cmd("aaa; agCj;")
    if cacheJson:
        parsedPath = inputFile.split('/')
        storePath = path.join(parsedPath[0], "json", parsedPath[1] + ".json")
        makedirs(path.join(parsedPath[0], "json"), exist_ok=True)
        with open(storePath, 'w') as jDump:
            json.dump(jsonData, jDump)
    return jsonData


def jsonToAssociations(inputJson: str, doRawJson: bool = False) -> Dict[str, List[str]]:
    '''
    Convert JSON data into a dictionary of associations.

    @param inputJson: The input JSON data. This is polymorphic and can be either:
        - Raw JSON data as a single string (requires doRawJson = True).
        - A reference JSON file that can be read (requires doRawJson = False)

    @param doRawJson: Defines the datatype supplied through the inputJson parameter.

    @return associations: Returns a dictionary of associations generated from the JSON data. A single association has
                          the following structure: `{"value": ["assocA", "assocB", "assocC", ...]}`
    '''
    if not doRawJson: # Load a JSON file
        with open(inputJson) as jsonFile:
            jsonData = json.load(jsonFile)
    else: # Convert a string into JSON format
        jsonData = json.loads(inputJson)
    # Generate the association dictionary from the provided list
    associations = dict()
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
