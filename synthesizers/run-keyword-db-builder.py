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

import json
import math
import copy
import datetime
import time
from multiprocessing import Process, Manager
from xml.etree import ElementTree as ET

from script_helpers import get_text, modify_section_numbers, get_str_stem
from script_build_string_keyword_distance import build_string_distance

import random

random.seed(datetime.datetime.now().microsecond)

import script_config
from keywords_preprocess import preprocess_keywords

NUM_PROCESSES = 4
UPDATE_EXISTING = False
SKIP_EXISTING_SUBSTR = False
SKIP_EXISTING_MATCHED_STR = False
COMMON_DEFS_FILENAME = script_config.common_definitions
INPUT_FILENAME = "input.txt"

preprocess_keywords(script_config.saved_nas_definitions, script_config.nas_definitions)

id2text_file = open(script_config.nas_definitions, 'r')
id2text = json.load(id2text_file)
id2text_file.close()


if "id2field_val" not in id2text:
    id2text["id2field_val"] = {}

text2id = {}
text2id["all2id"] = {}
for key in list(id2text.keys()):
    key_splits = key.strip().split("2")
    new_key = key_splits[1] + "2" + key_splits[0]
    text2id[new_key] = {}

    id2def = id2text[key]
    for lower_key in list(id2def.keys()):
        text_list = id2def[lower_key]
        for text_item in text_list:
            text_item = (text_item.lower().replace("/", " / ").replace(",", " , ").replace(".", " . ").
                         replace(";", " ; ").replace("-", " - ").replace(":", " : "))
            if new_key == "verb2id":
                text2id["all2id"][get_str_stem(text_item)[0]] = lower_key
            else:
                text2id["all2id"][text_item] = lower_key

common_defs_file = open(COMMON_DEFS_FILENAME, 'r')
common_defs_dict = json.load(common_defs_file)
common_defs_file.close()

for item in common_defs_dict["ignore_list"]:
    text2id["all2id"][item] = item

max([len(item) for item in text2id["all2id"]])


def worker(worker_num, worker_lines, shared_searched_strings):
    num_lines = len(worker_lines)
    print(datetime.datetime.now(), ": Worker", worker_num, ": Start with :", num_lines, "lines\n")

    from script_db_handler import get_new_conn_cursor, close_connection
    db_conn, db_cursor = get_new_conn_cursor()

    # searched_strings = set()
    for idx, line in enumerate(worker_lines):
        if idx > 0 and idx % 10 == 0:
            print(datetime.datetime.now(), ": Worker", worker_num, "Line", idx + 1, "of", num_lines, ": Running...\n")

        line = line.strip()
        if line == "":
            continue

        line = "<root> " + line + " </root>"

        line = line.replace("(e.g.", "that is")

        line = line.replace("<", " <").replace(">", "> ").strip()
        # line = " ".join(line.split())
        line = modify_section_numbers(line)

        temp_file = open("temp{}.txt".format(worker_num), 'w')
        temp_file.write(line + "\n")
        temp_file.close()
        line_tree = None

        try:
            # print("\nWorker", worker_num, "Line", i+1, ":", line)
            line_tree = ET.parse("temp{}.txt".format(worker_num))
            full_text = get_text(line_tree.getroot())

        except:
            print(datetime.datetime.now(), ": Worker", worker_num, ": Line", i + 1, ": Parsing error\n")
            full_text = line

        full_text = " ".join(full_text.split())
        build_string_distance(db_conn, db_cursor, full_text, text2id["all2id"], SKIP_EXISTING_SUBSTR,
                              SKIP_EXISTING_MATCHED_STR, UPDATE_EXISTING, shared_searched_strings,
                              thread_num=worker_num)

        stemmed_text = " ".join(get_str_stem(full_text))
        build_string_distance(db_conn, db_cursor, stemmed_text, text2id["all2id"], SKIP_EXISTING_SUBSTR,
                              SKIP_EXISTING_MATCHED_STR, UPDATE_EXISTING, shared_searched_strings,
                              thread_num=worker_num)

        dep_text = " " + copy.deepcopy(full_text).strip() + " "
        dep_text = dep_text.replace("i.e.", "that is").replace("e.g.", "for example,")
        dep_text = dep_text.replace("/", " / ").replace(",", " , "). \
            replace(".", " . ").replace(";", " ; ").replace("(", " ( "). \
            replace(")", " ) ").replace("-", " - ").replace(":", " : ")

        # identify quoted parts as values of IE
        quoted_parts = dep_text.split('"')[1::2]

        for res in quoted_parts:
            replaced_res = "_".join(res.replace(" - ", "_").replace(" / ", " ").
                                    replace("#", " ").split()).lower()
            dep_text = dep_text.replace("\"" + res + "\"", replaced_res)

            text2id["all2id"][res] = replaced_res
            text2id["all2id"][replaced_res] = replaced_res

        dep_text = " ".join(dep_text.split()).strip()

        build_string_distance(db_conn, db_cursor, dep_text, text2id["all2id"], SKIP_EXISTING_SUBSTR,
                              SKIP_EXISTING_MATCHED_STR, UPDATE_EXISTING, shared_searched_strings,
                              thread_num=worker_num)

    close_connection(db_conn, db_cursor)
    print(datetime.datetime.now(), ": Worker", worker_num, ": Complete...\n")


input_file = open(INPUT_FILENAME, 'r')
input_lines = input_file.readlines()
input_file.close()
random.shuffle(input_lines)

manager = Manager()
shared_dict = manager.dict()

process_list = []
num_per_worker = math.ceil(len(input_lines) / NUM_PROCESSES)
for i in range(NUM_PROCESSES):
    if i < NUM_PROCESSES - 1:
        p_lines_list = input_lines[i * num_per_worker:(i + 1) * num_per_worker]
    else:
        p_lines_list = input_lines[i * num_per_worker:]

    pr = Process(target=worker, args=(i, p_lines_list, shared_dict))
    process_list.append(pr)
    pr.start()
    time.sleep(0.5)

for pr in process_list:
    pr.join()

print()
print("*** ALL PROCESSES COMPLETE ***")
