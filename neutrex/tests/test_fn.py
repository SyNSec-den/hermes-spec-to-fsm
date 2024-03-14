# -*- coding: utf-8 -*-
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

from supar.structs.fn import tarjan


def test_tarjan():
    sequences = [[4, 1, 2, 0, 4, 4, 8, 6, 8],
                 [2, 5, 0, 3, 1, 5, 8, 6, 8],
                 [2, 5, 0, 4, 1, 5, 8, 6, 8],
                 [2, 5, 0, 4, 1, 9, 6, 5, 7]]
    answers = [None, [[2, 5, 1]], [[2, 5, 1]], [[2, 5, 1], [9, 7, 6]]]
    for sequence, answer in zip(sequences, answers):
        if answer is None:
            assert next(tarjan(sequence), None) == answer
        else:
            assert list(tarjan(sequence)) == answer
