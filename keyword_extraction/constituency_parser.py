"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq and Ali Ranjbar
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

import argparse
import stanza
import sys
import threading

from stanza.models.common.bert_embedding import BERT_ARGS
from stanza.models.common.doc import Document
from stanza.models.constituency.parse_tree import Tree
from tqdm import tqdm
from typing import List


s_print_lock = threading.Lock()


def get_args() -> argparse.Namespace:
    _parser = argparse.ArgumentParser(description="Filter constituency tree")
    _parser.add_argument("-f", "--file",
                         type=str,
                         help="input file",
                         required=True)
    _parser.add_argument("--label",
                         type=str,
                         help="label of the node to print",
                         required=True)
    _parser.add_argument("-v",
                         action=argparse.BooleanOptionalAction,
                         help='verbose logging',
                         default=False,
                         required=False)
    group = _parser.add_mutually_exclusive_group()
    group.add_argument("-j",
                       type=int,
                       help="number of threads",
                       default=8,
                       required=False)
    group.add_argument("--threading",
                       action=argparse.BooleanOptionalAction,
                       help="use threading lib",
                       default=True,
                       required=False)
    _args = _parser.parse_args()

    return _args


def dfs_collect_np(tree: Tree, result: List[str]) -> None:
    if not tree.children:
        result.append(tree.label)
        return
    for child in tree.children:
        dfs_collect_np(child, result)


def dfs_filter(tree: Tree, label: str) -> None:
    if not tree.children:
        return
    for child in tree.children:
        dfs_filter(child, label)
        if child.label == label and child.children:
            np: List[str] = []
            dfs_collect_np(child, np)
            with s_print_lock:
                print(" ".join(np), flush=True)


def analyze_sentence(sen: str):
    try:
        text_doc: Document = stanza_pipeline(sen)
        for sentence in text_doc.sentences:
            tree: Tree = sentence.constituency
            dfs_filter(tree, args.label)
    except Exception as e:
        print(e)


def join_all(_threads: List[threading.Thread], _bar: tqdm):
    for t in _threads:
        t.join()
        _bar.update(1)


if __name__ == "__main__":
    args = get_args()

    model_name = "roberta-base"
    if model_name in BERT_ARGS.keys():
        BERT_ARGS[model_name]["model_max_length"] = 1024
    else:
        BERT_ARGS[model_name] = {"model_max_length": 1024}

    stanza_pipeline = stanza.Pipeline(lang='en', processors='tokenize,mwt,pos,lemma,depparse,constituency', package={'constituency': 'wsj_bert'}, verbose=args.v)
    num_lines = sum(1 for line in open(args.file))
    with open(args.file, "r") as f:
        with tqdm(total=num_lines, file=sys.stderr) as bar:
            if not args.threading:
                for line in f:
                    analyze_sentence(line.rstrip())
                    bar.update(1)
            else:
                try:
                    while True:
                        threads: List[threading.Thread] = []
                        for _ in range(args.j):
                            line = f.readline()
                            if not line:
                                break
                            line = line.rstrip()
                            x = threading.Thread(target=analyze_sentence, args=(line,))
                            threads.append(x)
                            x.start()
                        else:
                            join_all(threads, bar)
                            continue
                        join_all(threads, bar)
                        break
                except KeyboardInterrupt:
                    join_all(threads, bar)
