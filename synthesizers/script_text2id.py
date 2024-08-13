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

import copy
import re

import pandas as pd
from script_db_handler import get_new_conn_cursor, get_min_keyword_distance, close_connection, check_conn_closed

from script_build_string_keyword_distance import build_string_distance

DISTANCE_THR = 3
SHORT_THR = 5
max_key_len = 100

text2id_cache = {}

db_conn, db_cursor = get_new_conn_cursor()

def check_db():
    global db_conn, db_cursor
    if check_conn_closed():
        print("REFRESHING DB CONN")
        db_conn, db_cursor = get_new_conn_cursor()


def call_close_db_from_text2id():
    close_connection(db_conn, db_cursor)


def get_word_end_idx(text: str, start_idx: int) -> int:
    text_len = len(text)
    for idx in range(start_idx, text_len):
        if text[idx] == " " or text[idx] == "/":
            return idx

    return text_len


def get_ids_from_text_db(text: str, text2id_dict: dict, threshold=DISTANCE_THR, ignore_list=None,
                         new_keywords=None) -> list:
    if ignore_list is None:
        ignore_list = []
    if new_keywords is None:
        new_keywords = []

    new_keywords_dict = {}
    for key in new_keywords:
        new_keywords_dict[key] = key

    check_db()
    build_string_distance(db_conn, db_cursor, text, new_keywords_dict, False, False, False)

    for ignore_key in ignore_list:
        text2id_dict[ignore_key] = ignore_key

    text = copy.deepcopy(text.lower())
    ids_found = []
    text_len = len(text)

    for start_idx in range(text_len):
        if text[start_idx] == "<" or text[start_idx] == ">":
            continue

        for end_idx in range(start_idx, text_len + 1):
            if text[end_idx - 1] == "<" or text[end_idx - 1] == ">":
                break
            if start_idx == end_idx:
                continue
            if end_idx - start_idx > max_key_len + DISTANCE_THR:
                break

            substr = text[start_idx: end_idx]

            check_db()
            lookup_text, keyword, dist = get_min_keyword_distance(db_cursor, substr)

            lookup_len = len(lookup_text)

            if lookup_len < SHORT_THR and dist > 0:
                continue
            elif lookup_len < SHORT_THR:
                temp_text = " " + text + "    "
                temp_substr = temp_text[start_idx: start_idx + lookup_len + 2]
                temp_lookup_text = " " + lookup_text + " "
                if temp_lookup_text != temp_substr:
                    continue

            end_idx = get_word_end_idx(text, start_idx + lookup_len - 1)

            if dist < threshold:
                ids_found.append((keyword, dist, start_idx, lookup_len, end_idx, lookup_text, substr))

    pos_set = set(range(len(ids_found)))
    for idx1, item1 in enumerate(ids_found):
        for idx2, item2 in enumerate(ids_found):
            if idx1 == idx2:
                continue
            if idx1 not in pos_set or idx2 not in pos_set:
                continue

            key1, dist1, pos1, len1, end1, txt1, substr1 = item1
            key2, dist2, pos2, len2, end2, txt2, substr2 = item2

            if not (pos1 <= pos2 < pos1 + len1 or pos2 <= pos1 < pos2 + len2):
                continue

            if substr1.strip() == substr2.strip():
                pos_set.remove(idx2)
            elif txt1 not in text2id_dict:
                pos_set.remove(idx1)
                break
            elif txt2 not in text2id_dict:
                pos_set.remove(idx2)
            elif dist1 > dist2:
                pos_set.remove(idx1)
                break
            elif dist1 < dist2:
                pos_set.remove(idx2)
            elif len1 > len2:
                pos_set.remove(idx2)
            elif len1 < len2:
                pos_set.remove(idx1)
                break

    for idx, item in enumerate(ids_found):
        key, dist, pos, length, end, txt, substr = item
        if idx not in pos_set:
            continue
        elif key in ignore_list:
            pos_set.remove(idx)
        elif txt not in text2id_dict:
            pos_set.remove(idx)

    result_list = [ids_found[idx] for idx in pos_set]

    result_df = pd.DataFrame(data=result_list, columns=["key", "dist", "pos", "len", "end", "txt", "substr"])
    result_df.sort_values(["pos", "dist", "len"], ascending=[True, False, True], inplace=True)

    result_list = result_df.values.tolist()
    return result_list


def parse_agent_text(texts: list, text2id) -> list:
    agents = []

    for txt in texts:
        txt = txt.replace("/", " / ").replace(",", " , ").replace(".", " . "). \
            replace(";", " ; ").replace("(", " ( ").replace(")", " ) ").replace("-", " - ").replace(":", " : ")

        while "  " in txt:
            txt = txt.replace("  ", " ")

        all_parts = []
        parts = txt.split(" and ")
        for part in parts:
            all_parts.extend(part.split(" or "))

        for part in all_parts:
            ids_from_text = get_ids_from_text_db(part, text2id["agent2id"], 2)
            agents.extend([item[0] for item in ids_from_text])

    return agents


def parse_state_text(state_texts: list, text2id) -> list:
    state_ids = []

    for state_text in state_texts:
        state_text = state_text.replace("/", " / ").replace(",", " , ").replace(".", " . "). \
            replace(";", " ; ").replace("(", " ( ").replace(")", " ) ").replace("-", " - ").replace(":", " : ")

        while "  " in state_text:
            state_text = state_text.replace("  ", " ")

        all_parts = []
        parts = state_text.split(" and ")
        for part in parts:
            all_parts.extend(part.split(" or "))

        for part in all_parts:
            state_ids_from_text = get_ids_from_text_db(part, text2id["state2id"], 2)
            state_ids.extend([item[0] for item in state_ids_from_text])

    return state_ids


def find_start_state(state_texts: list, text2id) -> list:
    pattern = r"<start_state>[^<]*<\/start_state>"
    start_state_texts = []
    for line in state_texts:
        found_state_texts = re.findall(pattern, line)
        start_state_texts.extend(found_state_texts)
    return parse_state_text(start_state_texts, text2id)


def get_state_from_depending_lines(depending_lines, text2id) -> str:
    for line in depending_lines:
        states = find_start_state([line], text2id)
        if len(states) > 0:
            return states[-1]
    return ""

