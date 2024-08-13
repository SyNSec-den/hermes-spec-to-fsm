"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq and Syed Md Mukit Rashid
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

import os.path
import pprint
import PyPDF2

pp = pprint.PrettyPrinter(width=200)
INPUT_FILENAME = '5g-rrc.pdf'


def get_definitions():
    definition_keywords = dict()
    if not os.path.exists("assets/definitions.txt"):
        return definition_keywords

    with open("assets/definitions.txt", "r") as f:
        s = f.readlines()
        f.close()
        for org_sen in s:
            org_sen = org_sen.split("\n")[0]
            if ':' in org_sen:
                keyterm = org_sen.split(":")[0]
                if "note" not in keyterm.lower():
                    key = keyterm.lower().replace("\"", "").replace("\'", "").replace(" ", "_")
                    definition_keywords[key + "_"] = [keyterm]

    return definition_keywords


def gather_messages_and_procedures():
    pdfFileObj = open(INPUT_FILENAME, 'rb')
    pdfReader = PyPDF2.PdfReader(pdfFileObj)
    message_dict = dict()
    procedures_dict = dict()

    last_section = ""
    for i in range(1, 24):
        pageObj = pdfReader.pages[i]
        lines = pageObj.extract_text().split("\n")
        for line in lines:
            if "..." not in line:
                continue

            line_splits = line.split()
            if len(line_splits) < 2:
                continue

            section = line_splits[0]

            if len(section) > 0 and section[0].isnumeric():
                last_section = section

                section_splits = section.split(".")
                if not len(section_splits) == 3:
                    continue

                if section_splits[0] == "5" and int(section_splits[1][0]) > 2:
                    proc_text = " ".join(line_splits[1: -2]).replace(".", "")

                    proc_key = proc_text.lower().replace("-", "_").replace(" ", "_").replace("/", "_")

                    if "introduction" in proc_key or "void" in proc_key or proc_key == "" or proc_key == "general":
                        continue

                    if proc_key in procedures_dict and proc_text not in procedures_dict[proc_key]:
                        procedures_dict[proc_key].append(proc_text)
                    else:
                        procedures_dict[proc_key] = [proc_text]

            elif last_section.startswith("6.2.2") and section == "–":
                msg_text = line_splits[1].replace(".", "")
                msg_key = msg_text.lower().replace("-", "_")
                if msg_key in message_dict and msg_text not in message_dict[msg_key]:
                    message_dict[msg_key].append(msg_text)
                else:
                    message_dict[msg_key] = [msg_text]

    pdfFileObj.close()
    return message_dict, procedures_dict


def gather_vars():
    pdfFileObj = open(INPUT_FILENAME, 'rb')
    pdfReader = PyPDF2.PdfReader(pdfFileObj)
    vars_dict = dict()

    last_section = ""
    for i in range(1, 24):
        pageObj = pdfReader.pages[i]
        lines = pageObj.extract_text().split("\n")
        for line in lines:
            if "..." not in line:
                continue

            line_splits = line.split()
            if len(line_splits) < 2:
                continue

            section = line_splits[0]

            if len(section) > 0 and section[0].isnumeric():
                last_section = section

            elif last_section.startswith("7.4") and section == "–":
                var_text = line_splits[1].replace(".", "")
                var_key = var_text.lower().replace("-", "_")
                if var_key in vars_dict and var_text not in vars_dict[var_key]:
                    vars_dict[var_key].append(var_text)
                else:
                    vars_dict[var_key] = [var_text]

    pdfFileObj.close()
    return vars_dict


def gather_state():
    pdfFileObj = open(INPUT_FILENAME, 'rb')
    pdfReader = PyPDF2.PdfReader(pdfFileObj)
    state_dict = dict()

    pdfFileObj.close()
    return state_dict


def get_abbreviations():
    abbreviations_keyword = dict()
    if not os.path.exists("assets/abbreviations.txt"):
        return abbreviations_keyword

    with open("assets/abbreviations.txt", "r") as f:
        s = f.readlines()
        f.close()
        for line in s:
            line_ = line.split("\n")[0]
            words = line_.split(" ")
            abbreviation = words[0]
            meaning = line_.split(abbreviation)[1]
            abbreviations_keyword[abbreviation.replace("\'", "")] = [meaning.strip()]

    return abbreviations_keyword
