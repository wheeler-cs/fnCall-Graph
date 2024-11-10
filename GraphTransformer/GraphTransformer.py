from GraphDataLoader import GraphDataLoader
from GraphTokenizer import GraphTokenizer

from typing import Dict, List


class GraphTransformer():
    def __init__(self):
        self.dataLoader = GraphDataLoader()
        self.tokenizationLayer = GraphTokenizer()
        self.tokenizedData: Dict[str, List[str]] = dict()
    

    def tokenize(self) -> None:
        for graphDataset in self.dataLoader.datasets:
            self.tokenizedData[graphDataset.classification] = self.tokenizationLayer.tokenize(graphDataset.data)



if __name__ == "__main__":
    gt = GraphTransformer()
    gt.tokenize()
