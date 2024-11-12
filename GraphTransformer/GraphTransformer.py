from GraphDataLoader import GraphDataLoader
from GraphTokenizer import GraphTokenizer

import evaluate
import numpy as np
import tensorflow as tf
from transformers import create_optimizer, DataCollatorWithPadding, RobertaTokenizer, TFAutoModelForSequenceClassification
from transformers.keras_callbacks import KerasMetricCallback
from typing import Dict, List


class GraphTransformer():
    def __init__(self, dataDir: str, batchSize: int, epochs: int):
        # Data mapping and tokenization
        self.dataDirectory:          str = dataDir
        self.dataLoader: GraphDataLoader = GraphDataLoader(dataDir)
        self.tokenizer: RobertaTokenizer = RobertaTokenizer.from_pretrained("FacebookAI/roberta-base")
        self.id2label:    Dict[int, str] = dict()
        self.label2id:    Dict[str, int] = dict()
        self.tokenizedData = None
        self.dataCollator = DataCollatorWithPadding(tokenizer=self.tokenizer, return_tensors="tf")
        # Model parameters
        self.batchSize:       int = batchSize
        self.epochs:          int = epochs
        self.batchesPerEpoch: int = 1
        self.trainingSteps:   int = int(self.batchesPerEpoch * self.epochs)
        self.optimizer, self.schedule = create_optimizer(init_lr=2e-5,
                                                         num_warmup_steps=0,
                                                         num_train_steps=self.trainingSteps)
        # Transformer model
        self.model = TFAutoModelForSequenceClassification.from_pretrained("FacebookAI/roberta-base",
                                                                          num_labels=len(self.id2label),
                                                                          id2label=self.id2label,
                                                                          label2id=self.label2id)
        self.trainingSet = None
        self.testingSet  = None
    

    def callDataLoader(self):
        self.dataLoader = GraphDataLoader(self.dataDirectory)
        dsDict = self.dataLoader.getDatasetDict()
        self.tokenizedData = dsDict.map(self._createTokenization, batched=True)
        self.id2label, self.label2id = self.dataLoader.createLabelIdMappings()
        self.batchesPerEpoch = len(self.tokenizedData)
    

    def _createTokenization(self, data):
        return self.tokenizer(data["sequence"], truncation=True)


    def prepareDatasets(self) -> None:
        # BUG: RuntimeError: Unrecognized array dtype object. Nested types and image/audio types are not supported yet.
        self.trainingSet = self.model.prepare_tf_dataset(self.tokenizedData["train"], shuffle=True,  batch_size=16, collate_fn=self.dataCollator)
        self.testingSet  = self.model.prepare_tf_dataset(self.tokenizedData["test"],  shuffle=False, batch_size=16, collate_fn=self.dataCollator)
    

    def computeMetrics(self, evalPrediction) -> None:
        accuracy = evaluate.load("accuracy")
        predictions, labels = evalPrediction
        predictions = np.argmax(predictions, axis=1)
        return accuracy.computer(predictions=predictions, references=labels)


    def prepareModel(self) -> None:
        with tf.device("/CPU:0"):
            self.model.compile(optimizer=self.optimizer)
            self.metricCallback = KerasMetricCallback(metric_fn=self.computeMetrics, eval_dataset=self.testingSet)
            self.model.fit(x=self.trainingSet, validation_data=self.testingSet, epochs=3, callbacks = [self.metricCallback])



if __name__ == "__main__":
    gt = GraphTransformer()
