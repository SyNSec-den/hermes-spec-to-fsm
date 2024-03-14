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

import nltk.tree
from nltk import Tree
import os

from tree_cleanup import clean_tree

INPUT_FILENAME = "input.pid"
OUTPUT_FILENAME = "output.txt"


def reverse_tag(tag):
    return tag[0] + "/" + tag[1:]


def clean_text(text: str) -> str:
    text = text.replace("[ ", "(").replace(" ]", ")")   # parenthesis
    text = text.replace("# ", "#")  # cause
    text = text.replace("`` ", "\"").replace(" ''", "\"")   # quotes
    text = text.replace(" ,", ",").replace(" .", ".").replace(" ;", ";").replace(" :", ":")  # punctuations
    text = text.replace("& gt;", "&gt;")
    text = text.replace(" (s)", "(s)")  # special cases

    while "  " in text:
        text = text.replace("  ", " ")
    text = text.strip()

    return text

def xml_generator(tree: Tree):
    output_string = ""
    if type(tree) == nltk.tree.Tree and tree.height() > 2:
        for subtree in tree:
            if subtree.label() in ["<control>", "<action>", "<condition>", "<start_state>", "<end_state>"]:
                output_string += subtree.label() + " " + xml_generator(subtree) + reverse_tag(
                    subtree.label()) + " "
            else:
                output_string += xml_generator(subtree)
    elif tree.height() == 2:
        for word in tree.leaves():
            output_string += word + " "

    return output_string


def convert_xml(input_filename, output_filename):

    input_file = open(input_filename, "r")
    lines = input_file.readlines()
    input_file.close()

    tree_strings = lines
    xml_lines = []
    for nltk_tree in tree_strings:
        nltk_tree = clean_tree(nltk_tree)
        converted_text = xml_generator(Tree.fromstring(nltk_tree))
        converted_text = clean_text(converted_text)

        xml_lines.append(converted_text)

    with open(output_filename, "w") as outfile:
        for line in xml_lines:
            outfile.write(line + "\n")
        outfile.close()


if __name__ == '__main__':
    convert_xml(INPUT_FILENAME, OUTPUT_FILENAME)

