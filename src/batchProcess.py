from AdjacencyMatrix import AdjacencyMatrix
import argparse
from os import listdir, path
import r2Pipeline as r2p
from tqdm import tqdm

# ==== Function Definitions ============================================================================================
def parseArgv() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="Batch Process",
                                     description="Python script for batch processing"
                                    )
    parser.add_argument("inputdir", type=str)
    arguments = parser.parse_args()
    return(arguments)


# ==== Main ============================================================================================================
if __name__ == "__main__":
    args = parseArgv()
    am = AdjacencyMatrix()
    for file in tqdm(listdir(args.inputdir)):
        fullPath = path.join(args.inputdir, file)
        if (path.isfile(fullPath)) and (fullPath[-4:] == ".exe"):
                callsAsJson = r2p.analyzeProgram(fullPath, True)
                assoc = r2p.jsonToAssociations(callsAsJson, True)
                am.createMatrix(assoc)
