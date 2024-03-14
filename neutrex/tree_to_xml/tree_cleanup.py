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

import argparse
import copy

import nltk
from collections import defaultdict
from nltk.tree import ParentedTree


restrictions = defaultdict(list)
restrictions['top'] = ['<action>', '<end_state>', '<start_state>', '<condition>']
restrictions['<other>'] = ['<control>', '<action>', '<end_state>', '<start_state>', '<condition>']
restrictions['<action>'] = ['<action>', '<end_state>', '<control>']
restrictions['<condition>'] = ['<action>', '<end_state>', '<control>']


def insert_ptree_forced(target_tree, position, chunk):
    target_tree.insert(position, ParentedTree.fromstring(str(chunk)))

def remove_parent(parent):
    gParent = parent.parent()
    target_pos = None

    for i, k in enumerate(gParent):
        if k == parent:
            target_pos = i
            break
    else:
        raise Exception("parent not found in gparent! Probably implementation issue")

    parent_copy = copy.deepcopy(parent)
    parent_copy.reverse()

    for child in parent_copy:
        gParent.insert(target_pos, ParentedTree.fromstring(str(child)))

    gParent.remove(parent)


def make_sibling(parent, chunk):
    gParent = parent.parent()
    target_pos = None
    for i, k in enumerate(gParent):
        if k == parent:
            target_pos = i
            break
    else:
        raise Exception("parent not found in gparent! Probably implementation issue")

    insert_ptree_forced(gParent, target_pos, chunk)

    parent.remove(chunk)

def fix_other(parent: ParentedTree, node: ParentedTree) -> None:
    remove_parent(parent)



def fix_top_simple(parent: ParentedTree, node_idx: int) -> None:

    new_ctl_tree = ParentedTree('<control>', [ParentedTree.fromstring(str(parent[node_idx]))])
    parent.remove(parent[node_idx])
    parent.insert(node_idx, new_ctl_tree)


def fix_top(parent: ParentedTree, node_idx: int) -> None:
    end_idx = node_idx
    for idx in range(node_idx, len(parent)):
        child_node = parent[idx]
        if isinstance(child_node, str) or child_node.label() == "<control>":
            break
        end_idx = idx+1

    new_ctl_tree = ParentedTree('<control>', [ParentedTree.fromstring(str(parent[idx])) for idx in range(node_idx, end_idx)])

    del parent[node_idx:end_idx]
    parent.insert(node_idx, new_ctl_tree)




def fix_action(parent, node):
    # case 1: action -> action
    if len(parent) == 1 and node.label() == '<action>':
        parent.set_label('<control>')

    # case 2: base case. that is if there is any control/action under action, they'll be made siblings
    # make sure after making sibling this parent is not empty, if it is, delete it
    else:
        make_sibling(parent, node)
        if len(parent) == 0:
            parent.parent().remove(parent)


def fix_condition(parent, node):
    # does it have both actions and conditions? then it should probably be control!
    child_labels = [k.label() for k in parent]
    if '<condition>' in child_labels and '<action>' in child_labels:
        parent.set_label('<control>')
        return
    else:
        # base case: if there is any control/action under condition. make it  a sibling.
        # once again check for empty parent.
        make_sibling(parent, node)
        if len(parent) == 0:
            parent.parent().remove(parent)
        return


def parse_fix(tree: ParentedTree, enable_top = True):
    q = []
    q.append(tree)

    while len(q) > 0:
        parent = q.pop(0)
        parent_label = parent.label()

        for idx, node in enumerate(parent):
            if enable_top and parent_label == "top" and not isinstance(node, str) and \
                    node.label() in restrictions[parent_label]:
                fix_top(parent, idx)
                # as tree changed, start parsing from start
                parse_fix(tree)
                return

            if parent_label == "<other>" and not isinstance(node, str) and node.label() in restrictions[parent_label]:
                fix_other(parent, node)
                # as tree changed, start parsing from start
                parse_fix(tree)
                return

            elif parent_label == '<action>' and not isinstance(node, str) and node.label() in restrictions[parent_label]:
                # violation found try action fixes
                fix_action(parent, node)
                # as tree changed, start parsing from start
                parse_fix(tree)
                return

            elif parent_label == '<condition>' and not isinstance(node, str) and node.label() in restrictions[parent_label]:
                # violation in condition, try condition_fixes
                fix_condition(parent, node)
                parse_fix(tree)
                return

            else:
                if not isinstance(node, str):
                    pass

            if not isinstance(node, str):
                q.append(node)
            else:
                pass


def clean_tree(input_tree_str: str) -> str:
    input_tree = ParentedTree.convert(nltk.Tree.fromstring(input_tree_str))

    parse_fix(input_tree, enable_top=False)
    parse_fix(input_tree, enable_top=True)

    return str(input_tree)
