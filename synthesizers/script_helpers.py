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

import math
import re
from nltk.stem.porter import PorterStemmer
import nltk
from nltk.tokenize import sent_tokenize

from typing import List
from Levenshtein import distance as levenshtein_distance
import xml.etree.ElementTree as ET
from num2words import num2words

p_stemmer = PorterStemmer()


def get_str_stem(text: str) -> list:
    words = text.split()
    return [p_stemmer.stem(word) for word in words]


def dumper(obj):
    try:
        a = obj.toJSON()
        return {"message": "EMPTY FOR PRINTING"}
    except:
        return obj


def isNum(text: str) -> bool:
    text = text.strip()
    try:
        num_val = int(text)
        return True
    except:
        return False


def isTimer(text: str) -> bool:
    text = text.strip()
    if not (text.startswith("t") or text.startswith("T")):
        return False

    return isNum(text[1:])


def extract_parenthesized(text: str):
    if text.strip().startswith("#") or text.strip().startswith("cause"):
        return [text]
    substrs = re.findall('\(([^)]+)', text)
    results = []
    for substr in substrs:
        results.append(substr)
        text = text.replace("(" + substr + ")", " ")
    results.append(text)
    return results


def get_text(xml_root: ET.Element) -> str:
    text = ET.tostring(xml_root, encoding='utf8', method='text')
    text = text.decode(encoding='utf8')

    return text.strip()


def remove_xml_from_text(text: str) -> str:
    try:
        tree = ET.fromstring(text)
        return get_text(tree)
    except ET.ParseError:
        return text


def get_middle_texts_list(xml_root) -> List[str]:
    texts = []
    if xml_root.text is not None and xml_root.text.strip() != "":
        texts.append(xml_root.text.strip())
    for child in xml_root:
        if child.tail is not None and child.tail.strip() != "":
            texts.append(child.tail.strip())
    return texts


def get_middle_text(xml_root) -> str:
    return " ".join(get_middle_texts_list(xml_root))


def replace_tokens_key(text: str, id_list: list) -> str:
    if len(id_list) < 1:
        return text

    pos_dict = {}

    for item in id_list:
        key = item[0]
        start_idx = item[2]
        end_idx = item[4]
        pos_dict[start_idx] = (end_idx, key)

    start_indices = list(pos_dict.keys())
    start_indices.sort()

    mod_text = ""
    prev_end_idx = 0

    for start_idx in start_indices:
        end_idx = pos_dict[start_idx][0]
        rep_txt = pos_dict[start_idx][1]
        mod_text = mod_text + text[prev_end_idx: start_idx] + " " + rep_txt + " "
        prev_end_idx = end_idx

    mod_text = mod_text + text[prev_end_idx:]
    mod_text = " ".join(mod_text.split())

    return mod_text


def isRef(word: str):
    if len(word) == 0 or not word[0].isdigit():
        return False

    while len(word) > 0:
        if word[-1].isalpha():
            word = word[:-1]
        else:
            break
    if len(word) == 0:
        return False

    for part in word.split("_"):
        if not part.isnumeric():
            return False

    return True


def isSectionNum(word: str) -> (bool, str):
    if len(word) == 0:
        return False, -1

    for ch in word[:-1]:
        if ch != "_" and not ch.isnumeric():
            return False, -1
    if not word[-1].isalnum():
        return False, -1

    return True, word.count("_")


def get_depending_sections(section_num: str) -> List[str]:
    results = []
    if "_" not in section_num and section_num.isnumeric():
        results.append(section_num)
    else:
        parts = section_num.split("_")
        current = ""
        for part in parts:
            current = current + "_" + part
            current = current.strip("_")
            results.insert(0, current)

    return results


def get_depending_lines(section_lines, current_section_num: str) -> List[str]:
    result_lines = []
    for section_num in get_depending_sections(current_section_num):
        if section_num in section_lines:
            result_lines.extend(section_lines[section_num])

    return result_lines


def get_depending_state(section_states, current_section_num: str) -> str:
    for section_num in get_depending_sections(current_section_num):
        if section_num in section_states and section_states[section_num] != "":
            return section_states[section_num]
    return ""


def clean_gt(text: str) -> str:
    if "&gt;" not in text:
        return text
    else:
        pos = text.find("&gt;")
        text = text[pos + 4:].replace("&gt;", "").replace("<control>", "").replace("</control>", "").strip()
        return text


def get_rrc_cond_state(text: str) -> (str, str):
    states = re.findall(r"<start_state>[^>]*</start_state>", text)
    for state_txt in states:
        text = text.replace(state_txt, "")

    states = [item.replace("<start_state>", "").replace("</start_state>", "") for item in states]

    cond = "<condition> " + text + " </condition>"
    cond = ET.fromstring(cond)

    return cond, states


def isHeader(text: str) -> (bool, str, str, int):
    is_header = False
    header_name = ""
    header_type = ""
    header_level = -1
    header_text = ""

    if text == "" or "<action>" in text:
        return is_header, header_name, header_type, header_level, header_text
    elif "<control>" in text:
        text = text.replace("<control>", "").replace("</control>", "")

    text = text.strip()
    changed_text = remove_xml_from_text(text).strip()

    words = text.split()
    changed_words = changed_text.split()
    try:
        if len(changed_text) > 5 and "&gt;" in text:
            is_header = True
            header_name = changed_words[0]
            header_type = "rrc_point"
            header_level = 200 + int(header_name)
            header_text = text

        elif len(changed_text) > 5 and changed_text.startswith("#") and changed_text.endswith(";"):
            is_header = True
            header_name = changed_words[0]
            header_type = "cause"
            header_level = 100
            header_text = text

        elif len(changed_text) > 5 and changed_text.startswith("\"") and changed_text.endswith("\""):
            is_header = True
            header_name = text
            header_type = "quote"
            header_level = 100
            header_text = text

        elif len(changed_text) > 5 and (changed_text.endswith("shall:") or changed_text.endswith("shall :")):
            is_header = True
            header_name = text
            header_type = "shall"
            header_level = 100
            header_text = text

        elif len(changed_words) > 2 and changed_words[1] == ")" and not changed_text.endswith(".") \
                and changed_words[0].isalpha() and changed_text[0] != "i" and changed_text[0] != "v":
            is_header = True
            header_name = changed_words[0]
            header_type = "alpha_item"
            header_level = 100
            header_text = text

        elif len(words) > 2 and words[1] == ")" and not changed_text.endswith(".") and words[0].isnumeric():
            is_header = True
            header_name = changed_words[0]
            header_type = "num_item"
            header_level = 100
            header_text = text

        elif len(words) > 2 and words[1] == ")" and not changed_text.endswith(".") \
                and words[0].isalpha() and (changed_text[0] == "i" or changed_text[0] == "v"):
            is_header = True
            header_name = changed_words[0]
            header_type = "roman_item"
            header_level = 100
            header_text = text

        else:
            is_section, section_level = isSectionNum(changed_words[0])
            if is_section and len(changed_words) > 1 and changed_words[1] != ")":
                is_header = True
                header_name = changed_words[0]
                header_type = "section_header"
                header_level = section_level
                header_text = text

        return is_header, header_name, header_type, header_level, header_text
    except ValueError:
        return False, "", "", -1, ""


def modify_section_numbers(text: str) -> str:
    text = text.replace("(", " ( ").replace(")", " ) ")
    words = text.split()
    for idx, word in enumerate(words):
        if "." not in word:
            continue

        word_splits = word.split(".")
        flag = True
        for i, word_part in enumerate(word_splits):
            word_part = word_part.strip().strip(",").strip(":")
            if word_part == "":
                continue
            elif isNum(word_part) or isNum(word_part[:-1]):
                continue
            elif word_part != "":
                flag = False
                break
        if flag:
            new_word = word.replace(".", "_")
            if new_word.endswith("_"):
                new_word = new_word.rstrip("_") + "."
            words[idx] = new_word

    return " ".join(words)


substring_pos_cache = {}
edit_distance_cache = {}


def find_substring_pos(line: str, substr: str) -> int:
    global substring_pos_cache
    global edit_distance_cache

    if line not in substring_pos_cache:
        substring_pos_cache[line] = {}
    elif substr in substring_pos_cache[line]:
        return substring_pos_cache[line][substr]

    find_idx = line.find(substr)
    if find_idx >= 0:
        substring_pos_cache[line][substr] = find_idx
        return find_idx

    line_len = len(line)
    substr_len = len(substr)
    if substr_len > line_len:
        return -1

    if substr not in edit_distance_cache:
        edit_distance_cache[substr] = {}

    min_pos = -1
    min_dist = math.inf
    for start_idx in range(line_len - substr_len + 1):
        matching_substr = line[start_idx: start_idx + substr_len]
        matching_dist = math.inf
        if matching_substr not in edit_distance_cache:
            edit_distance_cache[matching_substr] = {}

        if substr in edit_distance_cache[matching_substr]:
            edit_distance_cache[substr][matching_substr] = edit_distance_cache[matching_substr][substr]
            matching_dist = edit_distance_cache[matching_substr][substr]
        elif matching_substr in edit_distance_cache[substr]:
            edit_distance_cache[matching_substr][substr] = edit_distance_cache[substr][matching_substr]
            matching_dist = edit_distance_cache[substr][matching_substr]
        else:
            matching_dist = levenshtein_distance(matching_substr, substr)
            edit_distance_cache[substr][matching_substr] = matching_dist
            edit_distance_cache[matching_substr][substr] = matching_dist

        if matching_dist < min_dist:
            min_pos = start_idx
            min_dist = matching_dist

        if min_dist == 1:
            substring_pos_cache[line][substr] = min_pos
            return min_pos

    if min_dist >= substr_len / 2:
        substring_pos_cache[line][substr] = -1
        return -1
    else:
        substring_pos_cache[line][substr] = min_pos
        return min_pos

def verb_in_txt(txt: str):
    tokenized = sent_tokenize(txt)
    for i in tokenized:
        wordsList = nltk.word_tokenize(i)
        tagged = nltk.pos_tag(wordsList)
        for word, tag in tagged:
            if tag == "VB":
                return True
    return False



def get_text_type(text: str, text2id: dict, common_defs=None) -> List[str]:
    if common_defs is None:
        common_defs = {}
    type_list = []
    for key in text2id:
        if key == "all2id":
            continue
        if text in text2id[key] or text in set(text2id[key].values()):
            type_list.append(key.split("2")[0])

    for key in common_defs:
        if key == "ignore_list":
            if text in common_defs[key]:
                type_list.append("ignored")
        elif text in common_defs[key] or text in set(common_defs[key].values()):
            type_list.append(key)

    return type_list


def get_key_type(target_key: str, text2id: dict) -> List[str]:
    type_list = []
    for key in text2id:
        if key == "all2id":
            continue
        if target_key in set(text2id[key].values()):
            type_list.append(key.split("2")[0])

    return type_list


def replace_start_num_keyword(keyword: str) -> (bool, str):
    keyword = keyword.strip()
    if not len(keyword) == 0 and keyword[0].isnumeric():
        num_word = num2words(int(keyword[0]), to='cardinal')
        if len(keyword) > 1:
            return True, (num_word + "_" + keyword[1:])
        else:
            return True, num_word
    else:
        return False, keyword
