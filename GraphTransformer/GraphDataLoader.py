from dataclasses import dataclass
import numpy as np
from os import listdir, path
from typing import List


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
        for inode in listdir(dataDirectory):
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


if __name__ == "__main__":
    loader = GraphDataLoader()
    loader.printClasses()
