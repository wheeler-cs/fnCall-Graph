from AdjacencyMatrix import AdjacencyMatrix
from ProcessManager import ProcessManager

import argparse
from numpy import array_split, ndarray
from os import listdir, path
import r2Pipeline as r2p
from tqdm import tqdm
from typing import List

# ==== Function Definitions ============================================================================================
def parseArgv() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="Batch Process",
                                     description="Python script for batch processing")
    parser.add_argument("-i", "--inputdir",
                        help="Target directory containing executable files",
                        type=str,
                        required=True)
    parser.add_argument("-n", "--procnum",
                        help="Number of subprocesses to spawn for parallel generation",
                        type=int,
                        required=False,
                        default=1)
    arguments = parser.parse_args()
    return(arguments)


def getFileList(inputDir: str, fileExtension: str = ".exe") -> List[str]:
     fileList = list()

    # Get only the files from the directory, ignore subdirectories
     for inode in listdir(inputDir):
          longName = path.join(inputDir, inode)
          # Ensures inode is a file and the last $n$ characters match the extension
          if(path.isfile(longName) and (longName[len(fileExtension) * -1:] == fileExtension)):
               fileList.append(longName)

     return fileList


def generateSublists(inputList: List, divisions: int = 2) -> List[List]:
    # Make sure the list length and number of desired divisions are appropriate
    if((divisions < 2) or (len(inputList) < divisions)):
        raise ValueError("Number of desired divisions is not appropriate for list size")
    # Divide the list into $n$ sublists using numpy
    sublists = array_split(inputList, divisions)
    # Convert np arrays to lists
    for i in enumerate(sublists):
         sublists[i[0]] = ndarray.tolist(i[1])
    return sublists


# ==== Main ============================================================================================================
if __name__ == "__main__":
    # Program setup
    args = parseArgv()
    fileList = getFileList(args.inputdir)
    splitLists = generateSublists(fileList, args.procnum)

    # Create list of adjacency matrices
    matrixList: List[AdjacencyMatrix] = list()
    for i in range(0, args.procnum):
        matrixList.append(AdjacencyMatrix())
    
    # Parallelize matrix generation
    pManager = ProcessManager(args.procnum)
    for i in range(0, args.procnum):
        pManager.addProcess(r2p.batchAnalyzeJson, [splitLists[i], True])
    pManager.startBatch()
    pManager.awaitBatch()
