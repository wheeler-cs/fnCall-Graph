import sys
# I hate this is how Python imports directories as modules
sys.path += ["GraphGeneration", "GraphTransformer"]

import batchProcess
from GraphTransformer import GraphDataLoader, GraphTransformer

import argparse
from transformers import AutoTokenizer, RobertaTokenizer
import evaluate


tokenizer = RobertaTokenizer.from_pretrained("FacebookAI/roberta-base")


def parseArgv() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="Graph Runner",
                                     description="Run either the graph generation or transformer")
    parser.add_argument("-m", "--mode",
                        help="Determines the mode of operation for the program",
                        type=str,
                        choices=["generate", "transformer"],
                        required=True)
    parser.add_argument("-i", "--inputDir",
                        help="Target directory for input files",
                        type=str,
                        required=True)
    parser.add_argument("-n", "--procnum",
                        help="Number of subprocesses to spawn for parallel generation",
                        type = int,
                        required = False,
                        default=1)
    return parser.parse_args()


def generateDataset(inputDir: str, procNum: int):
    # Get list of executables and evenly divide them among {procNum} lists
    # @see GraphGeneration/batchProcess.py
    fileList = batchProcess.getFileList(inputDir)
    splitLists = batchProcess.generateSublists(fileList, procNum)
    batchProcess.threadedGeneration(splitLists, procNum)


def tokenizationPreprocessor(data):
    return tokenizer(data["sequence"], truncation=True)


def getMappedData(dataDir: str = "./data"):
    loader = GraphDataLoader(dataDir)
    dsDict = loader.getDatasetDict()
    tokenizedData = dsDict.map(tokenizationPreprocessor, batched=True)
    id2label, label2id = loader.createLabelIdMappings()
    return tokenizedData, id2label, label2id


def trainTransformer():
    tokenizedData, id2label, label2id = getMappedData()


def main():
    argv = parseArgv()
    # Different run modes, depending on need
    if argv.mode == "generate":
        generateDataset(argv.inputDir, argv.procnum)
    elif argv.mode == "transformer":
        trainTransformer()
    else: # This should never be reached, but just in case...
        raise ValueError("Incorrect argument provided for mode of operation")


if __name__ == "__main__":
    main()