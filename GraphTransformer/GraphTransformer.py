from GraphDataLoader import GraphDataLoader
from GraphTokenizer import GraphTokenizer

import torch
from typing import Dict, List


class GraphTransformer():
    def __init__(self):
        # Dataset components
        self.dataLoader = GraphDataLoader()
        self.tokenizationLayer = GraphTokenizer()
        self.tokenizedData: Dict[str, List[str]] = dict()
        # Model components
    

    

    def tokenize(self) -> None:
        for graphDataset in self.dataLoader.datasets:
            self.tokenizedData[graphDataset.classification] = self.tokenizationLayer.tokenize(graphDataset.data)



if __name__ == "__main__":
    gt = GraphTransformer()
    #gt.tokenize()
