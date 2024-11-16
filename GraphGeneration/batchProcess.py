from ProcessManager import ProcessManager
import r2Pipeline as r2p

import argparse
from numpy import array_split, ndarray
from os import listdir, path
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
    if(len(inputList) < divisions):
        raise ValueError(f"Number of desired divisions ({divisions}) is not appropriate for list size ({len(inputList)})")
    # Divide the list into $n$ sublists using numpy
    sublists = array_split(inputList, divisions)
    # Convert np arrays to lists
    for i in enumerate(sublists):
         sublists[i[0]] = ndarray.tolist(i[1])
    return sublists


def threadedGeneration(splitLists: List[List], procNum: int = 1) -> None:
    pManager = ProcessManager(procNum)
    # Initialize threads
    for i in range(0, procNum):
        if i != 0:
            pManager.addProcess(r2p.batchAnalyzeJson, [splitLists[i], False, False])
        else:
            pManager.addProcess(r2p.batchAnalyzeJson, [splitLists[i], True, False])
    # Run threads and wait for them to finish
    pManager.startBatch()
    pManager.awaitBatch()


# ==== Main ============================================================================================================
if __name__ == "__main__":
    args = parseArgv()
    fileList = getFileList(args.inputdir)
    if args.procnum == 1:
        r2p.batchAnalyzeJson(fileList, True, False)
    else:
        splitLists = generateSublists(fileList, args.procnum)
        threadedGeneration(splitLists, args.procnum)
    
