"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq and Sarkar Snigdha Sarathi Das
Contact: abdullah.ishtiaq@psu.edu

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import nltk

from utils.metric import SpanMetric
from nltk import tree
from utils.transform import Tree


pred_path = './current_predictions.txt'
gt_path = './current_predictions.txt'

preds = []
gts = []


with open(pred_path, mode='r', encoding='utf8', newline='\n\n\n') as f:
    lines = f.readlines()
    for l in lines:
        preds.append(nltk.Tree.fromstring(l))

with open(gt_path, mode='r', encoding='utf8', newline='\n\n\n') as f:
    lines = f.readlines()
    for l in lines:
        gts.append(nltk.Tree.fromstring(l))

metric = SpanMetric()
delete={'TOP', 'S1', '-NONE-', ',', ':', '``', "''", '.', '?', '!', '', '<B-control>', '<B-condition>', '<B-action>', '<I-control>', '<I-condition>', '<I-action>', '<other>', '<B-end_state>', '<B-start_state>', '<I-end_state>', '<I-start_state>'}
equal={'ADVP': 'PRT'}

result = metric([Tree.factorize(tree, delete, equal) for tree in preds],
                   [Tree.factorize(tree, delete, equal) for tree in gts])
                   
print(result)