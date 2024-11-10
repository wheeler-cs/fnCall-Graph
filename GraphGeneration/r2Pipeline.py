# == Imports ===========================================================================================================
import json
import networkx as nx
import numpy as np
from os import makedirs, path
from r2pipe import open as r2open
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
    cmdPipe = r2open(inputFile, flags=["-2"])
    jsonData = cmdPipe.cmd("aaa; agCj;")
    # Write JSON output of radare2 to file
    if cacheJson:
        parsedPath = inputFile.split('/')
        storePath = path.join(parsedPath[0], "json", parsedPath[1] + ".json")
        makedirs(path.join(parsedPath[0], "json"), exist_ok=True)
        with open(storePath, 'w') as jDump:
            json.dump(jsonData, jDump)
    # Convert string of JSON into a real JSON
    jsonData = json.loads(jsonData)
    return jsonData


def jsonToAdjlist(jsonData: List[Dict]) -> nx.DiGraph:
    '''
    Convert JSON data to a digraph representation using Networkx

    @param jsonData: JSON data to be converted to the graph, stored as a list of dictionaries.

    @return callgraph: Networkx representation of JSON data, specifically, a digraph.
    '''
    callgraph = nx.DiGraph()
    # Build adjacency list from JSON
    for entry in jsonData:
        for call in entry["imports"]:
            if not callgraph.has_edge(entry["name"], call):
                callgraph.add_edge(entry["name"], call)
    return callgraph


def analysisAlgorithm(inputFile: str, cacheJson: bool = False) -> None:
    '''
    Analyzes a given executable file, generates a CFG, and stores the result as a numpy array in a file.

    @param inputFile: Target executable file.
    
    @param cacheJson: Flag for if the JSON output of radare2 should be saved.
    '''
    splitFilename = inputFile.split('/')
    # Analyze EXE and convert to an adjacency list
    jsonData = analyzeProgram(inputFile, cacheJson)
    callgraph = jsonToAdjlist(jsonData)
    fnList = []
    # Add all nodes with no duplicates
    for edge in nx.edge_dfs(callgraph):
        if edge[0] not in fnList:
            fnList.append(edge[0])
        if edge[1] not in fnList:
            fnList.append(edge[1])
    # Write numpy array to file, assuming a list was actually built
    if len(fnList) > 0:
        npArray = np.array(fnList)
        npArray.tofile(path.join("data/analysis", splitFilename[-1] + ".npy"), sep=' ')


def batchAnalyzeJson(inputList: List[str], showProgress: bool = False, cacheJson: bool = False) -> None:
    '''
    Driver code for the batch analysis.

    @param inputList: List of files to be processed as part of the batch.

    @param showProgress: Flag for if TQDM should render a progress bar.

    @param cacheJson: Flag for if the JSON output of radare2 should be saved.
    '''
    makedirs("data/analysis", exist_ok=True)
    for i in enumerate(tqdm((inputList))) if showProgress else enumerate(inputList):
        analysisAlgorithm(i[1], cacheJson)
