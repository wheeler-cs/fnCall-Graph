import os
import sys
# I hate this is how Python imports directories as modules
sys.path += ["GraphGeneration", "GraphTransformer"]

import batchProcess
from GraphClassifier import GraphClassifier
from GraphTransformer import GraphTransformer

import argparse



def parseArgv() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="Graph Runner",
                                     description="Run either the graph generation or transformer")
    parser.add_argument("-m", "--mode",
                        help="Determines the mode of operation for the program",
                        type=str,
                        choices=["generator", "transformer", "encoder"],
                        required=True)
    parser.add_argument("-i", "--input",
                        help="Target directory for input files",
                        type=str,
                        required=False,
                        default="./data")
    parser.add_argument("-n", "--procnum",
                        help="[Generator Only] Number of subprocesses to spawn for parallel generation",
                        type = int,
                        required = False,
                        default=1)
    parser.add_argument("-b", "--batchSize",
                        help="[Transformer Only] The batch size to using while training",
                        type=int,
                        required=False,
                        default=32)
    parser.add_argument("-e", "--epochs",
                        help="[Transformer Only] The number of epochs that should occur while training",
                        type=int,
                        required=False,
                        default=5)
    return parser.parse_args()


def generateDataset(inputDir: str, procNum: int):
    # Get list of executables and evenly divide them among {procNum} lists
    # @see GraphGeneration/batchProcess.py
    fileList = batchProcess.getFileList(inputDir)
    if procNum == 1:
        batchProcess.nonThreadedGeneration(fileList)
    else:
        splitLists = batchProcess.generateSublists(fileList, procNum)
        batchProcess.threadedGeneration(splitLists, procNum)



def trainTransformer(dataDir: str, batchSize: int, epochs: int):
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    gt = GraphTransformer(dataDir, batchSize, epochs)
    gt.prepareDatasets()
    gt.prepareModel()
    gt.trainModel()


def encodeFile(argv) -> None:
    gt = GraphClassifier("./PretrainedModel")
    tensor = gt.outputEncoder(argv.input)
    print(tensor)


def main():
    argv = parseArgv()
    # Different run modes, depending on need
    if argv.mode == "generator":
        generateDataset(argv.input, argv.procnum)
    elif argv.mode == "transformer":
        trainTransformer(argv.input, argv.batchSize, argv.epochs)
    elif argv.mode == "encoder":
        encodeFile(argv)
    else: # This should never be reached, but just in case...
        raise ValueError("Incorrect argument provided for mode of operation")


if __name__ == "__main__":
    main()