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
import copy
from script_helpers import replace_start_num_keyword

keyword_ignore_list = [
    "nas_procedure",
    "emm_procedure",
    "esm_procedure",
    "emm_message",
    "emm_status",
    "esm_status",
    "esm_message",
    "five_gmm_procedure",
    "five_gsm_procedure",
    "five_gmm_message",
    "five_gmm_status_message",
    "five_gsm_status_message",
    "five_gsm_message",
    "reject_message",
    "request_message"
]


def process_cause(id2text: dict) -> dict:
    if "id2cause" in id2text:
        for key in id2text["id2cause"]:
            phrases = copy.deepcopy(id2text["id2cause"][key])
            cause_num = ""
            cause_texts = []
            for phrase in phrases:
                phrase = phrase.strip()
                if phrase.startswith("#"):
                    cause_num = phrase.split()[0]
                elif not phrase.startswith("Cause"):
                    cause_texts.append(phrase)

                if not phrase.startswith("Cause"):
                    continue
                if phrase[-1].isnumeric():
                    continue

                phrase_parts = phrase.split()
                if len(phrase_parts) < 3:
                    continue

                items = [item.replace("-", "_").replace("/", "_").lower() for item in phrase_parts[2:]]
                new_str = phrase_parts[1] + " " + "_".join(items)
                if new_str not in id2text["id2cause"][key]:
                    id2text["id2cause"][key].append(new_str)

                new_str_2 = "Cause " + new_str
                if new_str_2 not in id2text["id2cause"][key]:
                    id2text["id2cause"][key].append(new_str_2)

            for cause_text in cause_texts:
                new_phrase = cause_num + " ( " + cause_text + " )"
                if new_phrase not in phrases:
                    id2text["id2cause"][key].append(new_phrase)
    return id2text


def process_msg_field(id2text: dict) -> dict:
    if "id2msg_field" in id2text:
        verbs = []
        for verb in id2text["id2verb"]:
            verbs.extend(id2text["id2verb"][verb])
        verbs = set(verbs)

        for key in id2text["id2msg_field"]:
            if key in keyword_ignore_list:
                continue
            phrases = set(copy.deepcopy(id2text["id2msg_field"][key]))
            lower_phrases = set([item.lower() for item in phrases])
            for phrase in id2text["id2msg_field"][key]:
                phrase = phrase.strip().lower()
                if (phrase.lower() + " ").endswith(" ie "):
                    new_phrase = (phrase.lower() + " ").replace(" ie ", "")
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())

                    new_phrase = (phrase.lower() + " ").replace(" ie ", " information element")
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())

                elif phrase.lower().endswith(" information element"):
                    new_phrase = phrase.lower().replace(" information element", "").strip()
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())
                    new_phrase = phrase.lower().replace(" information element", " IE").strip()
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())
                else:
                    new_phrase = phrase + " information element"
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())
                    new_phrase = phrase + " IE"
                    if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                        phrases.add(new_phrase)
                        lower_phrases.add(new_phrase.lower())

            id2text["id2msg_field"][key] = list(phrases)

    return id2text


def process_others(id2text: dict) -> dict:
    verbs = []
    for verb in id2text["id2verb"]:
        verbs.extend(id2text["id2verb"][verb])
    verbs = set(verbs)

    suffix_list = ["message", "procedure", "mode"]
    for suffix in suffix_list:
        dict_key = "id2" + suffix
        if dict_key in id2text:
            key_dict = id2text[dict_key]

            for key in key_dict:
                if key in keyword_ignore_list:
                    continue
                phrases = set(copy.deepcopy(key_dict[key]))
                lower_phrases = set([item.lower() for item in phrases])
                for phrase in key_dict[key]:
                    phrase = phrase.strip()
                    if phrase.lower().endswith(" " + suffix):
                        new_phrase = phrase.replace(" " + suffix, "")
                        if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                            phrases.add(new_phrase)
                            lower_phrases.add(new_phrase.lower())
                    else:
                        new_phrase = phrase + " " + suffix
                        if new_phrase.lower() not in lower_phrases and new_phrase.lower() not in verbs:
                            phrases.add(new_phrase)
                            lower_phrases.add(new_phrase.lower())

                key_dict[key] = list(phrases)

    return id2text


def process_timer(id2text: dict) -> dict:
    key_dict = id2text["id2timer"]
    for key in key_dict:
        if key in keyword_ignore_list:
            continue
        phrases = set(copy.deepcopy(key_dict[key]))
        lower_phrases = set([item.lower() for item in phrases])
        for phrase in key_dict[key]:
            phrase = phrase.strip()
            if "the" not in phrase:
                new_phrase = "the " + phrase
                if new_phrase.lower() not in lower_phrases:
                    phrases.add(new_phrase)
                    lower_phrases.add(new_phrase.lower())

            if "timer" not in phrase:
                new_phrase = "timer " + phrase
                if new_phrase.lower() not in lower_phrases:
                    phrases.add(new_phrase)
                    lower_phrases.add(new_phrase.lower())

                new_phrase = "the timer " + phrase
                if new_phrase.lower() not in lower_phrases:
                    phrases.add(new_phrase)
                    lower_phrases.add(new_phrase.lower())

        key_dict[key] = list(phrases)
    return id2text


def process_key(id2text: dict) -> dict:
    for key in list(id2text.keys()):
        for lower_key in list(id2text[key].keys()):
            updated, new_key = replace_start_num_keyword(lower_key)
            if updated:
                print("UPDATE KEYWORD :", lower_key, "->", new_key)
                id2text[key][new_key] = copy.deepcopy(id2text[key][lower_key])
                del id2text[key][lower_key]

    return id2text


def preprocess_keywords(defs_filename: str, output_filename: str):
    id2text_file = open(defs_filename, 'r')
    id2text = json.load(id2text_file)
    id2text_file.close()

    id2text = process_key(id2text)
    id2text = process_cause(id2text)
    id2text = process_msg_field(id2text)
    id2text = process_others(id2text)
    id2text = process_timer(id2text)

    with open(output_filename, 'w') as outfile:
        json.dump(id2text, outfile, indent=2)
        outfile.close()
