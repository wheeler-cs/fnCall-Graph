# == Imports ===========================================================================================================
import json
import networkx as nx
from os import makedirs, path
import r2pipe
from sys import argv
from tqdm import tqdm
from typing import Dict, List



# == Function Definitions ==============================================================================================
def analyzeProgram(inputFile: str, cacheJson: bool = False) -> List[Dict]:
    '''
    Use radare2 to analyze the control flow of an executable file.

    @param inputFile: The target executable program for analysis.
    @param cacheJson: Determines if the output JSON from analysis will be written to disk.

    @return jsonData: JSON output of the analysis by radare2.
    '''
    cmdPipe = r2pipe.open(inputFile, flags=["-2"])
    jsonData = cmdPipe.cmd("aaa; agCj;")
    if cacheJson:
        parsedPath = inputFile.split('/')
        storePath = path.join(parsedPath[0], "json", parsedPath[1] + ".json")
        makedirs(path.join(parsedPath[0], "json"), exist_ok=True)
        with open(storePath, 'w') as jDump:
            json.dump(jsonData, jDump)
    jsonData = json.loads(jsonData)
    return jsonData


def jsonToAdjlist(jsonData: List[Dict]) -> nx.DiGraph:
    '''
    Convert JSON data to a digraph representation using Networkx

    @param jsonData: JSON data to be converted to the graph, stored as a list of dictionaries.

    @return callgraph: Networkx representation of JSON data, specifically, a digraph.
    '''
    callgraph = nx.DiGraph()
    for entry in jsonData:
        for call in entry["imports"]:
            callgraph.add_edge(entry["name"], call)
    return callgraph


def batchAnalyzeJson(inputList: List[str], showProgress: bool = False, cacheJson: bool = False):
    makedirs("data/analysis", exist_ok=True)
    if showProgress:
        for i in enumerate(tqdm((inputList))):
            splitFilename = i[1].split('/')
            jsonData = analyzeProgram(i[1], cacheJson)
            callgraph = jsonToAdjlist(jsonData)
            nx.write_adjlist(callgraph, path.join("data/analysis", splitFilename[-1] + ".adjlist"), delimiter=' ')
    else:
        for i in enumerate(inputList):
            splitFilename = i[1].split('/')
            jsonData = analyzeProgram(i[1], cacheJson)
            callgraph = jsonToAdjlist(jsonData)
            nx.write_adjlist(callgraph, path.join("data/analysis", splitFilename[-1] + ".adjlist"), delimiter=' ')
