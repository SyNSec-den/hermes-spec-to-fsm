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
from Levenshtein import distance as levenshtein_distance

LOCAL_DISTANCE_THR = 3
LOCAL_SHORT_THR = 5


def build_string_distance(db_conn, db_cursor, text: str, keywords_dict: dict, skip_substr=False,
                          skip_matched_string=False, update_existing=False, searched_strings=None,
                          thread_num=0) -> None:
    if searched_strings is None:
        searched_strings = {}

    if len(keywords_dict) == 0:
        return

    from script_db_handler import insert_substring_keyword_distance_batch, db_commit, substring_in_db, \
        matched_string_in_db

    max_key_len = max([len(item) for item in keywords_dict])

    text = copy.deepcopy(text.lower())
    text_len = len(text)

    for start_idx in range(text_len):
        insert_list = []

        if text[start_idx] == "<" or text[start_idx] == ">":
            continue
        for end_idx in range(start_idx, text_len):
            if text[end_idx - 1] == "<" or text[end_idx - 1] == ">":
                break
            elif start_idx == end_idx:
                continue
            elif end_idx - start_idx > max_key_len + LOCAL_DISTANCE_THR:
                break

            substr = text[start_idx: end_idx]
            if substr.strip() == "":
                continue
            elif substr in searched_strings:
                continue
            elif skip_substr and substring_in_db(db_cursor, substr):
                searched_strings[substr] = 1
                continue

            searched_strings[substr] = 1

            for lookup_text in keywords_dict:
                lookup_len = len(lookup_text)
                if lookup_len != len(substr):
                    continue
                elif skip_matched_string and matched_string_in_db(db_cursor, lookup_text):
                    continue

                keyword = keywords_dict[lookup_text]

                if lookup_len < LOCAL_SHORT_THR:
                    lookup_text = " " + lookup_text + " "
                    substr = " " + substr + " "

                dist = levenshtein_distance(substr, lookup_text)

                lookup_text = lookup_text.strip()
                if lookup_len < LOCAL_SHORT_THR:
                    substr = substr[1:-1]

                if dist > LOCAL_DISTANCE_THR or dist >= lookup_len:
                    continue

                insert_list.append((substr, lookup_text, keyword, dist))

        insert_substring_keyword_distance_batch(db_conn, db_cursor, insert_list, update_existing, thread_num=thread_num)
        db_commit(db_conn)
