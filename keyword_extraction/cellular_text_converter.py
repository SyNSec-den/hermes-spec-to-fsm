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

import pprint

import find_capital_keywords
import gather_keyword_pdf
import ie_from_pdf
import enchant

import re

INPUT_FILENAME = 'assets/5g-rrc.txt'


def convert_to_keyword(file_name, keyword_dict, suffix, check_all_upper=False):
    with open(file_name + ".txt", "r") as f:
        with open(file_name + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                sen = org_sen.split("\n")[0].replace("- ", "-")
                for k, v in sorted(keyword_dict.items(), key=lambda item: len(item[0]), reverse=True):
                    for phrase in sorted(v, key=lambda item: len(item), reverse=True):
                        indices = [m.start() for m in re.finditer(phrase.lower(), sen.lower())]
                        while len(indices) > 0:
                            idx = indices[0]
                            if not (idx + len(phrase) < len(sen) and sen[idx + len(phrase)].isalpha()) and \
                                    (not check_all_upper or
                                     sen[idx: idx + len(phrase)] == sen[idx:idx + len(phrase)].upper()):
                                sen = sen[:idx] + k + "_" + sen[idx + len(phrase):]
                                indices = [m.start() for m in re.finditer(phrase.lower(), sen.lower())]
                            else:
                                indices = indices[1:]

                f2.write(sen + "\n")

    return file_name + "_" + suffix


def convert_firstquotes(file_name, suffix):
    quote_dict = dict()
    with open(file_name, "r") as f:
        with open(file_name + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                sen = org_sen.split("\n")[0].replace("- ", "-")
                split_by_quote = str(sen).split("\"")
                if len(split_by_quote) % 2 == 0:
                    f2.write(sen + "\n")
                    continue
                sen = ""
                if len(split_by_quote) > 1:
                    for i in range(0, len(split_by_quote), 2):
                        if i + 1 < len(split_by_quote):
                            if len(split_by_quote[i + 1].strip()) > 1 \
                                    and len(split_by_quote[i + 1].split(" ")) < 8:
                                content = split_by_quote[i + 1].strip()
                                key = content.replace(" ", "_").lower().replace("(", "").replace(")", "")
                                if key not in quote_dict.keys():
                                    quote_dict[key] = [content]
                                else:
                                    pass
                                sen += split_by_quote[i] + key + "_"
                            else:
                                if len(split_by_quote[i + 1].strip()) >= 2:
                                    sen = sen + split_by_quote[i] + "\"" + split_by_quote[i + 1] + "\""
                                else:
                                    sen = sen + split_by_quote[i] + "\"" + split_by_quote[i + 1]
                        else:
                            sen += split_by_quote[i]
                else:
                    sen = org_sen.split("\n")[0].replace("- ", "-")

                f2.write(sen + "\n")

    return file_name + "_" + suffix, quote_dict


dictionary = enchant.Dict("en_US")
pp = pprint.PrettyPrinter(width=200)

message_dict_pdf = gather_keyword_pdf.gather_messages_and_procedures()[0]
procedures_dict_pdf = gather_keyword_pdf.gather_messages_and_procedures()[1]
state_dict_pdf = gather_keyword_pdf.gather_state()
variable_dict_pdf = gather_keyword_pdf.gather_vars()
ie_dict_pdf_purified = ie_from_pdf.get_IE_keywords_dict(True)


def find_dictionaries():
    fn, quote_dict = convert_firstquotes(INPUT_FILENAME, 'quote')

    fn2, msg_dict_cap = find_capital_keywords.get_message_keywords(fn)
    fn3, state_dict_cap = find_capital_keywords.get_state_keywords(fn2)
    fn4, status_dict_cap = find_capital_keywords.get_status_keywords(fn3)
    fn5, mode_dict_cap = find_capital_keywords.get_mode_keywords(fn4)

    return msg_dict_cap, message_dict_pdf, procedures_dict_pdf, state_dict_pdf, ie_dict_pdf_purified, mode_dict_cap, state_dict_cap, \
           status_dict_cap, variable_dict_pdf

