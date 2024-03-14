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

import os

import supar
from supar import Parser


def test_parse():
    sents = {'en': ['She enjoys playing tennis.', 'Too young too simple!'],
             'zh': '她喜欢打网球.',
             'de': 'Sie spielt gerne Tennis.',
             'fr': 'Elle aime jouer au tennis.',
             'ru': 'Она любит играть в теннис.',
             'he': 'היא נהנית לשחק טניס.'}
    tokenized_sents = {'en': [['She', 'enjoys', 'playing', 'tennis', '.'], ['Too', 'young', 'too', 'simple', '!']],
                       'zh': ['她', '喜欢', '打', '网球', '.'],
                       'de': ['Sie', 'spielt', 'gerne', 'Tennis', '.'],
                       'fr': ['Elle', 'aime', 'jouer', 'au', 'tennis', '.'],
                       'ru': ['Она', 'любит', 'играть', 'в', 'теннис', '.'],
                       'he': ['היא', 'נהנית', 'לשחק', 'טניס', '.']}
    for name, model in supar.NAME.items():
        if 'xlmr' in name or 'roberta' in name or 'electra' in name:
            continue
        parser = Parser.load(name, reload=True)
        if name.endswith(('en', 'zh')):
            lang = name[-2:]
            parser.predict(sents[lang], prob=True, lang=lang)
            parser.predict(tokenized_sents[lang], prob=True, lang=None)
        else:
            for lang in sents:
                parser.predict(sents[lang], prob=True, lang=lang)
            parser.predict(list(tokenized_sents.values()), prob=True, lang=None)
        os.remove(os.path.join(os.path.expanduser('~/.cache/supar'), model))
