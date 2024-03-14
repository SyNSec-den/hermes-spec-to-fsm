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

import re
import copy
import random

import nltk
nltk.download('punkt')
from nltk.tree import Tree
from nltk.tokenize import word_tokenize

INPUT_FILE = "input.txt"

starter_strs = ['<control>', '<condition>', '<action>', '<start_state>', '<end_state>', '<TOP>']
ending_strs = {'<control>': '</control>', '<condition>': '</condition>', '<action>': '</action>',
               '<start_state>': '</start_state>', '<end_state>': '</end_state>', '<TOP>': '</TOP>'}


def clean_text(text: str) -> str:
    text = text.strip()
    text = text.replace("><", "> <")

    while "  " in text:
        text = text.replace("  ", " ")

    for start_tag in starter_strs:
        end_tag = ending_strs[start_tag]
        text = text.replace(start_tag + " " + end_tag, "")

    text = text.replace("(", "[").replace(")", "]")

    quotes = re.findall(r'"[^"]*"', text)
    for quote in quotes:
        if len(quote) > 2:
            text = text.replace(quote, "``" + quote[1:-1] + "''")

    return text


def traverse(curr_str):
    label = ''
    children = []
    curr_str = curr_str.strip()
    for s in starter_strs:
        if curr_str.startswith(s):
            label = s[0:]
            curr_str = curr_str.replace(s, '', 1).strip()  # just the first occurance
            break
    else:
        label = '<other>'

    terminal_string = ""

    while (len(curr_str) > 0):

        if any([curr_str.startswith(k) for k in starter_strs]):  # starts with starting html tag
            if terminal_string.strip() == '':
                child, curr_str = traverse(curr_str)
                children.append(child)
            else:
                if label == '<other>':
                    tokens = word_tokenize(terminal_string)
                    for t in tokens:
                        children.append(Tree(label, [t]))

                    terminal_string = ''
                    return Tree(label, children), curr_str

                tokens = word_tokenize(terminal_string)
                for indx, t in enumerate(tokens):
                    if indx == 0:
                        children.append(Tree(label[0] + 'B-' + label[1:], [t]))
                    else:
                        children.append(Tree(label[0] + 'I-' + label[1:], [t]))

                terminal_string = ''
                child, curr_str = traverse(curr_str)
                children.append(child)

        elif any([curr_str.startswith(k) for k in ending_strs.values()]):  # starts with ending html tag
            for k in ending_strs.values():
                if curr_str.startswith(k):
                    target_end = k

            if target_end != ending_strs[label]:
                raise Exception("Error in bracketing: " + curr_str)
            elif terminal_string.strip() != '':
                if len(children) == 0:
                    tokens = word_tokenize(terminal_string.strip())
                    for indx, t in enumerate(tokens):
                        if indx == 0:
                            children.append(Tree(label[0] + 'B-' + label[1:], [t]))
                        else:
                            children.append(Tree(label[0] + 'I-' + label[1:], [t]))
                    terminal_string = ''
                    return Tree(label, children), curr_str[len(target_end):]
                else:
                    tokens = word_tokenize(terminal_string.strip())
                    for t in tokens:
                        children.append(Tree('<other>', [t]))
                    terminal_string = ''
                    return Tree(label, children), curr_str[len(target_end):]
            else:
                return Tree(label, children), curr_str[len(target_end):]

        else:
            terminal_string += curr_str[0]
            curr_str = curr_str[1:]

    if terminal_string != '':
        if label != '<other>':
            raise Exception("error: " + terminal_string + " " + label)
        else:
            tokens = word_tokenize(terminal_string.strip())
            for t in tokens:
                children.append(Tree('<other>', [t]))
            return Tree(label, children), curr_str


def Main():
    final_str_all = ""
    final_str1_train = ""
    final_str1_val = ""
    final_str1_test = ""
    final_error_str = ""

    input_file = open(INPUT_FILE, 'r')
    lines = input_file.readlines()
    input_file.close()

    print(len(lines))

    for idx, line in enumerate(lines):
        line = clean_text(line)
        if line.strip() == "":
            final_error_str += 'ERROR: Line {} empty!!!\n\n\n'.format(idx+1)
            print('ERROR: Line {} empty!!!\n\n\n'.format(idx+1))
            continue

        mark = 0
        try:
            curr_str = copy.deepcopy(line)
            children = []
            while len(curr_str) > 0:
                child, curr_str = traverse(curr_str)
                children.append(child)

            t = Tree('top', children)
            toss = random.random()
            if toss < 0.80 and mark == 0:
                final_str1_train += str(t) + '\n\n\n'
                final_str_all += str(t) + '\n\n\n'
            elif toss < 0.90 and mark == 0:
                final_str1_val += str(t) + '\n\n\n'
                final_str_all += str(t) + '\n\n\n'
            else:
                final_str1_test += str(t) + '\n\n\n'
                final_str_all += str(t) + '\n\n\n'

        except:
            final_error_str += line + '\n\n\n'

    text_file = open("out_full.pid", "w")
    text_file.write(final_str_all)
    text_file.close()

    text_file = open("out_train.pid", "w")
    text_file.write(final_str1_train)
    text_file.close()

    text_file = open("out_val.pid", "w")
    text_file.write(final_str1_val)
    text_file.close()

    text_file = open("out_test.pid", "w")
    text_file.write(final_str1_test)
    text_file.close()

    text_file = open("errors.txt", "w")
    text_file.write(final_error_str)
    text_file.close()


if __name__ == '__main__':
    Main()
