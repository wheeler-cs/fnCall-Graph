from datasets import Dataset
from datasets.dataset_dict import DatasetDict
from math import floor
import numpy as np
from os import listdir, path
import pyarrow as pa
from tqdm import tqdm
from typing import List, Tuple


class GraphDataLoader():
    def __init__(self, inputDir: str = "./data"):
        self.dataDirectory = inputDir
        self.datasets: GraphDataset = list()
        self.loadDataset()


    def loadDataset(self):
        if (len(self.dataDirectory) < 1):
            raise ValueError("Invalid data directory provided")
        # Query target directory for classes based on directory names
        self.getClassesFromDirectories()
    

    def getClassesFromDirectories(self):
        # Assume the name of the directory is the classification of the data
        for inode in listdir(self.dataDirectory):
            fullPath = path.join(self.dataDirectory, inode)
            if(path.isdir(fullPath)):
                data = self.loadNumpyArrays(fullPath)
                self.datasets.append(GraphDataset(inode, data))

    
    def loadNumpyArrays(self, dataDirectory: str) -> List[np.array]:
        arrayList = list()
        # Iterate through files in the directory and load data from them
        print(f"Loading {dataDirectory}...")
        for inode in tqdm(listdir(dataDirectory)):
            fullPath = path.join(dataDirectory, inode)
            if(path.isfile(fullPath)):
                try:
                    # Load the array and store it
                    npArray = np.array(np.loadtxt(fullPath, dtype=str, delimiter=' '))
                    arrayList.append(npArray)
                except Exception as e: # Just ignore invalid files, it's probably okay
                    pass
        return arrayList
    

    def printClasses(self) -> None:
        for set in self.datasets:
            print(set.classification)
            print(set.data[0].tolist())



class GraphDataset(object):
    def __init__(self, classification: str, data: List[np.array]):
        self.classification: str = classification
        self.data: List[np.array] = data
    

    def getDatasetDict(self) -> DatasetDict:
        newDataset = []
        for element in self.data:
            # The np.array2string below is awful... Here's how it works:
            # The np.array is converted into a string in the format "['a' 'b' 'c' ... 'z']" for tokenization
            # The two braces at the ends of the string are removed and all ' are removed.
            # I did this to just get a really long string of function calls.
            newDataset.append({"label": self.classification, "sequence": np.array2string(element, max_line_width=1_000_000_000)[1:-1].replace('\'', '')})
        train, test = splitDataset(newDataset, 0.8)
        trainDataset = Dataset(pa.Table.from_pydict({}))
        testDataset = Dataset(pa.Table.from_pydict({}))
        for element in train:
            trainDataset = trainDataset.add_item(element)
        for element in test:
            testDataset = testDataset.add_item(element)
        dsDict = DatasetDict({"train": trainDataset, "test": testDataset})
        return dsDict


def splitDataset(dataset: List, percentage: float = 0.5) -> Tuple[List, List]:
    if (0 <= percentage <= 1):
        splitIdx = floor(len(dataset) * percentage)
        return dataset[:splitIdx], dataset[splitIdx:]
    else:
        raise ValueError("Percentage must be a decimal between 0 and 1")


if __name__ == "__main__":
    loader = GraphDataLoader()
    altSet = loader.datasets[0].getModifiedDataset()
    dsDict = DatasetDict(altSet)
