"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq
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

import datetime
from collections import defaultdict
from nltk.tree import ParentedTree, MultiParentedTree
from nltk.treeprettyprinter import TreePrettyPrinter
from requests import ReadTimeout

from script_helpers import *
from script_text2id import *

import stanza
from stanza.server import CoreNLPClient

stanza.install_corenlp()
corenlp_client = CoreNLPClient(annotators=['tokenize', 'ssplit', 'pos', 'lemma', 'ner', 'parse', 'depparse', 'coref'],
                               properties={'annotators': 'coref', 'coref.algorithm': 'neural'}, timeout=30000,
                               memory='4G', endpoint='http://localhost:9001', start_server='DONT_START')

dep_graph_cache_dict = {}


class DepGraph:
    def __init__(self, common_defs_dict, text2id_dict, all_tokens):
        self.edges = defaultdict(list)
        self.nodes = []
        self.root = None
        self.nltk_tree = None
        self.nltk_tree_node_dict = {}
        self.children_copied = set()

        self.common_defs_dict = common_defs_dict
        self.text2id = text2id_dict
        self.all_tokens = all_tokens

        self.context = defaultdict(list)

    def add_node(self, node_label: dict):
        node_label["key_type"] = get_text_type(node_label["word"], self.text2id, self.common_defs_dict)
        node_label["id_word"] = str(len(self.nodes) + 1) + "->" + node_label["word"]
        self.nodes.append(node_label)

    def get_nodes(self):
        return self.nodes

    def get_node_at(self, idx):
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        return self.nodes[idx - 1]

    def set_node_at(self, idx, new_node):
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        self.nodes[idx - 1] = new_node

    def get_num_nodes(self):
        return len(self.nodes)

    def get_id_words(self):
        return [tok["id_word"] for tok in self.nodes]

    def get_id_word_at(self, idx):
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        return self.nodes[idx - 1]["id_word"]

    def get_words(self):
        return [tok["word"] for tok in self.nodes]

    def get_word_at(self, idx):
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        return self.nodes[idx - 1]["word"]

    def get_pos_at(self, idx):
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        return self.nodes[idx - 1]["pos"]

    def get_types_at(self, idx) -> List[str]:
        if idx > len(self.nodes):
            print("ERROR IDX :", idx, ", length :", len(self.nodes))
            return "IDX_OUT_OF_BOUND_ACCESSED"
        return self.nodes[idx - 1]["key_type"]

    def set_root(self, root):
        self.root = root

    def get_root(self):
        return self.root

    def add_edge(self, u, v, edge_label):
        self.edges[u].append((v, edge_label))

    def get_edges(self):
        return self.edges

    def get_edges_at(self, node_idx):
        return self.get_edges()[node_idx]

    def get_parents(self, node_idx):
        parent_list = []
        all_edges = self.get_edges()
        for start_node in all_edges:
            for edge_item in all_edges[start_node]:
                if edge_item[0] == node_idx:
                    parent_list.append(start_node)
                    break

        return parent_list

    def get_children_ids(self, node_idx):
        children = []
        node_edges = self.get_edges_at(node_idx)
        for edge_item in node_edges:
            children.append(edge_item[0])

        return children

    def get_children_nodes(self, node_idx):
        return [self.get_node_at(idx) for idx in self.get_children_ids(node_idx)]

    def get_children_words(self, node_idx):
        return [self.get_word_at(idx) for idx in self.get_children_ids(node_idx)]

    def find_word_in_subtree(self, subtree_root_idx: int, word: str):
        results = []
        children_ids = self.get_children_ids(subtree_root_idx)
        for child_id in children_ids:
            if self.get_word_at(child_id) == word:
                results.append(child_id)
            results.extend(self.find_word_in_subtree(child_id, word))

        return results

    def build_nltk_tree(self, node_idx):
        node_str = self.get_id_word_at(node_idx) + ":" + self.get_pos_at(node_idx) + ":" + str(
            self.get_types_at(node_idx))
        node_edges = self.get_edges()[node_idx]

        if len(node_edges) == 0:
            return node_str

        children_list = []
        for child_item in node_edges:
            child_idx = child_item[0]
            child_rel = child_item[1]
            rel_node = ParentedTree(child_rel, [self.build_nltk_tree(child_idx)])
            children_list.append(rel_node)

        return ParentedTree(node_str, children_list)

    def get_nltk_tree(self):
        if self.nltk_tree is None:
            self.nltk_tree = self.build_nltk_tree(self.get_root())
        return self.nltk_tree

    def get_context(self) -> defaultdict:
        self.context = defaultdict(list)
        for node in self.nodes:
            for key_type in node["key_type"]:
                if node["word"] not in self.context[key_type]:
                    self.context[key_type].append(node["word"])

        return self.context

    def pretty_print(self):
        try:
            return TreePrettyPrinter(self.get_nltk_tree()).text()
        except AttributeError:
            return self.get_nltk_tree()

    def __str__(self):
        return self.pretty_print()

    def toJSON(self):
        return "skip serialize"

    def copy_children(self, src_node_id, dst_node_id, ignore_labels=None):
        if ignore_labels is None:
            ignore_labels = []
        dst_children_words = set(self.get_children_words(dst_node_id))
        src_edges = self.get_edges_at(src_node_id)
        for edge in src_edges:
            edge_node_id = edge[0]
            edge_label = edge[1]
            edge_node = self.get_node_at(edge_node_id)
            edge_word = edge_node["word"]

            if edge_word in dst_children_words:
                continue
            if edge_label in ignore_labels:
                continue
            if edge_node_id == dst_node_id:
                continue

            new_child_node = copy.deepcopy(edge_node)
            self.add_node(new_child_node)
            new_child_id = self.get_num_nodes()

            self.copy_children(edge_node_id, new_child_id)

            self.add_edge(dst_node_id, new_child_id, edge_label)

    def get_child_str(self, child_node_id, visited_set, keywords):
        child_str = self.run_dfs(child_node_id, visited_set, keywords).strip()

        while "()" in child_str or "( )" in child_str or "(," in child_str or ", )" in child_str or "  " in child_str \
                or ", ," in child_str:
            child_str = child_str.replace("()", "").replace("( )", "").replace("(,", "(").replace(", )", ")").replace(
                "  ", " ").replace(", ,", ", ")
        while child_str.startswith("("):
            child_str = child_str[1:-1]

        return child_str.strip()

    def run_dfs(self, node_id, visited_set, keywords, is_root=False):
        this_node = self.get_node_at(node_id)
        node_text = str(self.get_word_at(node_id)).strip().lower()
        node_id_text = str(self.get_id_word_at(node_id)).strip().lower()
        node_pos = self.get_pos_at(node_id).strip()

        edges = self.get_edges_at(node_id)
        children = [item[0] for item in edges]
        num_child = len(children)
        node_labels = [item[1] for item in edges]

        for child_idx, child_node_id in enumerate(children):
            child_label = node_labels[child_idx]
            if child_label in self.common_defs_dict["conj_label"] and (
                    node_id, child_node_id) not in self.children_copied and (
                    child_node_id, node_id) not in self.children_copied:
                self.copy_children(node_id, child_node_id, [child_label])
                self.children_copied.add((node_id, child_node_id))
                self.children_copied.add((child_node_id, node_id))
                return self.run_dfs(node_id, visited_set, keywords)

        visited_set.add(node_id)
        verbs_conv = get_ids_from_text_db(" ".join(get_str_stem(node_text)).strip(), self.text2id["verb2id"], 1,
                                          self.common_defs_dict["ignore_list"])
        if node_text not in keywords and len(verbs_conv) > 0:
            node_text = verbs_conv[0][0]
            node_id_text = str(node_id) + "->" + node_text
            this_node["key_type"].append("verb")
            self.set_node_at(node_id, this_node)

        elif isTimer(node_text):
            keywords.add(node_text)
            this_node["key_type"].append("timer")
            self.set_node_at(node_id, this_node)

        elif node_text in self.common_defs_dict["directive"]:
            node_text = self.common_defs_dict["directive"][node_text]
            node_id_text = str(node_id) + "->" + node_text
            this_node["key_type"].append("directive")
            self.set_node_at(node_id, this_node)

        elif node_text in self.common_defs_dict["preposition"]:
            node_text = self.common_defs_dict["preposition"][node_text]
            node_id_text = str(node_id) + "->" + node_text
            if num_child == 0:
                node_id_text = ""
            this_node["key_type"].append("preposition")
            self.set_node_at(node_id, this_node)

        elif node_text in self.common_defs_dict["conjunction"]:
            node_text = self.common_defs_dict["conjunction"][node_text]
            node_id_text = str(node_id) + "->" + node_text
            if num_child == 0:
                node_id_text = ""
            this_node["key_type"].append("conjunction")
            self.set_node_at(node_id, this_node)

        elif node_text in self.common_defs_dict["special"]:
            node_text = self.common_defs_dict["special"][node_text]
            node_id_text = str(node_id) + "->" + node_text
            if num_child == 0:
                node_id_text = ""
            this_node["key_type"].append("special")
            self.set_node_at(node_id, this_node)

        elif node_text not in self.all_tokens and node_text not in keywords and not isRef(node_text):
            node_text = ""
            node_id_text = str(node_id) + "->"

        if len(children) == 0 and node_text == "":
            node_id_text = ""
            return node_id_text

        result_str = node_id_text + "("
        add_extra_rparen = 0

        for child_idx, child_node_id in enumerate(children):
            child_node = self.get_node_at(child_node_id)
            child_label = node_labels[child_idx]
            child_node_text = self.get_word_at(child_node_id).strip().lower()
            child_node_id_text = self.get_id_word_at(child_node_id).strip().lower()
            child_edges = self.get_edges_at(child_node_id)
            child_children = [item[0] for item in child_edges]
            num_child_child = len(child_children)
            child_labels = [item[1] for item in child_edges]

            if child_node_id in visited_set:
                continue

            if ("nsubj" in child_label or "agent" in child_label) and child_node_text in self.text2id[
                "agent2id"].values():
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                if child_str == "" or child_str.endswith("->") or "->)" in child_str:
                    continue
                result_str = result_str + "_AGENT_(" + child_str + "), "

            elif ((child_node_text.strip() in ["not", "neither", "nor", "never"]) and
                  (child_label in ["advmod", "cc", "cc:preconj"])) or \
                    (child_node_text.strip() == "no" and child_label == "det"):
                result_str = "_NOT_" + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1

            elif node_text.strip() == "other" and child_label == "obl:than":
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                if child_str == "" or child_str.endswith("->") or "->)" in child_str:
                    continue
                result_str = result_str + "_NOT_(" + child_str + "), "

            elif "amod" in child_label and child_node_text.strip() != "other":
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                if child_str == "" or child_str.endswith("->") or "->)" in child_str:
                    continue
                result_str = child_str + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1

            elif child_label in self.common_defs_dict["conj_label"]:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                conj_ids = self.find_word_in_subtree(child_node_id, child_label.split(":")[-1])
                conj_label = self.common_defs_dict["conj_label"][child_label]
                if len(conj_ids) > 0:
                    conj_label = str(conj_ids[0]) + "->" + conj_label

                result_str = conj_label + "(" + child_str + ", " + result_str
                add_extra_rparen = add_extra_rparen + 1
            elif child_label in self.common_defs_dict["preposition_label"]:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                if child_str == "" or child_str.endswith("->") or "->)" in child_str:
                    continue
                prep_ids = self.find_word_in_subtree(child_node_id, child_label.split(":")[-1])
                prep_label = self.common_defs_dict["preposition_label"][child_label]
                if len(prep_ids) > 0:
                    prep_label = str(prep_ids[0]) + "->" + prep_label
                result_str = result_str + prep_label + "(" + child_str + "), "
                if "_EXCEPT_(_EXCEPT_" in result_str:
                    add_extra_rparen = add_extra_rparen - 1
                    result_str = result_str.replace("_EXCEPT_(_EXCEPT_", "_EXCEPT_")
                if "_BEFORE_(_BEFORE_" in result_str:
                    add_extra_rparen = add_extra_rparen - 1
                    result_str = result_str.replace("_BEFORE_(_BEFORE_", "_BEFORE_")

            elif child_label == "mark" and child_node_text in self.common_defs_dict["mark"]:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                result_str = str(child_node_id) + "->" + self.common_defs_dict["mark"][child_node_text] + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1

            elif child_label == "case" and child_node_text in self.common_defs_dict["case"]:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                result_str = str(child_node_id) + "->" + self.common_defs_dict["case"][child_node_text] + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1

            elif self.get_root() in self.get_parents(child_node_id) and child_node_text in \
                    self.common_defs_dict["preposition"]:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                result_str = str(child_node_id) + "->" + self.common_defs_dict["preposition"][
                    child_node_text] + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1
                child_node["key_type"].append("preposition")
                self.set_node_at(child_node_id, child_node)

            elif child_node_text == "any" and child_label == "det" and num_child > child_idx + 1 \
                    and self.get_word_at(children[child_idx + 1]).strip().lower() == "other" \
                    and node_labels[child_idx + 1] == "amod":
                result_str = "_ANY_OTHER_" + "(" + result_str
                add_extra_rparen = add_extra_rparen + 1
            else:
                child_str = self.get_child_str(child_node_id, visited_set, keywords)
                if child_str == "" or child_str.endswith("->") or "->)" in child_str:
                    continue
                else:
                    result_str = result_str + child_str + ", "

        result_str = result_str.strip(", ") + ")"
        for i in range(add_extra_rparen):
            result_str = result_str + ")"
        if add_extra_rparen < 0:
            for i in range(abs(add_extra_rparen)):
                result_str = result_str[:-1]


        if len(result_str.split("->")) == 2 and result_str.endswith("->()"):
            result_str = ""
        elif str(node_id) + "->(" in result_str:
            result_str = result_str.replace(str(node_id) + "->(", "")[:-1]

        return result_str

    def DFS(self, keywords):
        tree_root = self.get_root()
        visited = set()

        result_str = self.run_dfs(tree_root, visited, keywords, True)
        while "()" in result_str or "( )" in result_str or "(," in result_str or ", )" in result_str or "  " in result_str or ", ," in result_str:
            result_str = result_str.replace("()", "").replace("( )", "").replace("(,", "(").replace(", )", ")").replace(
                "  ", " ").replace(", ,", ", ")

        while result_str.startswith("("):
            result_str = result_str[1:-1]

        return result_str.strip()

def get_collapsed_dependency_graph(text: str, common_defs_dict, text2id_dict, all_tokens) -> list:
    if text in dep_graph_cache_dict:
        return copy.deepcopy(dep_graph_cache_dict[text])

    dep_graph_list = "NOT_FOUND"

    if dep_graph_list == "NOT_FOUND":
        dep_graph_list = []
        all_sentences = []
        all_parts = extract_parenthesized(text)
        for part in all_parts:
            try:
                ann = corenlp_client.annotate(part)
                all_sentences.extend(ann.sentence)
            except ReadTimeout:
                print("TIMEOUT ")

        for sent in all_sentences:
            sent_graph = DepGraph(common_defs_dict, text2id_dict, all_tokens)

            root_text = str(sent.collapsedCCProcessedDependencies.root).replace("[", "").replace("]", "").split(",")[0]
            sent_graph.set_root(int(root_text))

            token_str_list = str(sent.token).replace("[", "").replace("]", "").replace(", ", ",\n") \
                .replace("\",\"", "\"_COMMA_\"").split(",")
            for token_str in token_str_list:
                token_dict = {}
                token_parts = token_str.split("\n")
                for token_part in token_parts:
                    if ":" not in token_part:
                        continue
                    part_key = token_part.split()[0].replace(":", "").replace("\"", "")
                    part_val = token_part.split()[1].replace("\"", "")

                    token_dict[part_key] = part_val

                sent_graph.add_node(token_dict)

            edge_str_list = (str(sent.collapsedCCProcessedDependencies.edge).replace("[", "").
                             replace("]", "").replace(", ", ",\n").split(","))
            for edge_str in edge_str_list:
                start_node = None
                end_node = None
                edge_label = None
                edge_parts = edge_str.split("\n")
                for edge_part in edge_parts:
                    if edge_part.startswith("source:"):
                        start_node = int(edge_part.split()[1])
                    elif edge_part.startswith("target:"):
                        end_node = int(edge_part.split()[1])
                    elif edge_part.startswith("dep:"):
                        edge_label = edge_part.split()[1].replace("\"", "")

                if start_node is None or end_node is None or edge_label is None:
                    continue

                sent_graph.add_edge(start_node, end_node, edge_label)

            dep_graph_list.append(sent_graph)

        dep_graph_cache_dict[text] = copy.deepcopy(dep_graph_list)

    else:
        dep_graph_cache_dict[text] = copy.deepcopy(dep_graph_list)

    return dep_graph_list
