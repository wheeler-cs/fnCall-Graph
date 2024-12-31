import numpy as np
import os
import tensorflow as tf
from transformers import AutoConfig, AutoTokenizer, TFAutoModelForSequenceClassification


class GraphClassifier(object):
    def __init__(self, modelType: str) -> None:
        self.model = TFAutoModelForSequenceClassification.from_pretrained(modelType)
        self.tokenizer = AutoTokenizer.from_pretrained(modelType)
        self.config = AutoConfig.from_pretrained(modelType)

    
    def outputEncoder(self, filePath: str) -> None | tf.Tensor:
        if os.path.isdir(filePath):
            return None
        else:
            with open(filePath, 'r') as fileBuffer: text = fileBuffer.read()
            text = text.split(sep=' ')
            tokenizedArray = self.tokenizer(text, padding=True, truncation=True, return_tensors="tf")
            tensors = self.model(**tokenizedArray, output_hidden_states=True)
            finalTensor = tensors.hidden_states[-1]
            del tensors
            return finalTensor
