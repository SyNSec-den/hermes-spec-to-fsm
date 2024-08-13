"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq, Syed Md Mukit Rashid, and Ali Ranjbar
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

import pickle
import pprint
import enchant

pp = pprint.PrettyPrinter(indent=4)
dictionary = enchant.Dict("en_US")

noun_phrases = dict()
with open("assets/5g-rrc_small_lines.np.count.2.txt", "r") as f:
    lines = f.readlines()
    for line in lines:
        phrase_freq = int(line.split("\n")[0].strip().split(" ")[0])
        phrase = ""
        for i in range(1, len(line.split("\n")[0].strip().split(" "))):
            phrase += line.split("\n")[0].strip().split(" ")[i] + " "

        noun_phrases[phrase.strip()] = phrase_freq


def refine_noun_phrases():
    punctuations = ["(", ")", "{", "}", "[", "]", ":", ",", ".", "\"", "#", "and", "or"]

    def break_terms(phrase_dict, delimiter):
        pl_1 = phrase_dict
        pl_1_r = dict()
        for p, pf in pl_1.items():
            if delimiter in p:
                new_phrases = p.split(delimiter)
                new_phrases = [p for p in new_phrases if p != ""]
                for np in new_phrases:
                    np = np.strip()
                    if np not in pl_1_r.keys():
                        pl_1_r[np] = pf
                    else:
                        pl_1_r[np] += pf

            else:
                p = p.strip()
                if p not in pl_1_r.keys():
                    pl_1_r[p] = pf
                else:
                    pl_1_r[p] += pf

        return pl_1_r

    pd_comma = break_terms(noun_phrases, " , ")
    pd_and = break_terms(pd_comma, " and ")
    pd_or = break_terms(pd_and, " or ")

    refined_phrases = dict()
    for phrase, phrase_freq in pd_or.items():
        new_phrase = phrase
        delete = False
        words = phrase.split(" ")
        for i in range(len(words)):
            if i == 0 and (words[i].lower() == "a" or words[i].lower() == "an" or words[i].lower() == "the"
                           or words[i].lower() == "any"):
                new_phrase = ""
                for word in words[1:]:
                    new_phrase += word + " "
                new_phrase = new_phrase.strip()
                continue

            if i != 0 and (words[i].lower() == "a" or words[i].lower() == "an" or words[i].lower() == "the"):
                delete = True

            elif any([p in words[i] for p in punctuations]):
                delete = True

        if words[0].isnumeric() or new_phrase == "":
            delete = True

        if phrase_freq < 7:
            delete = True

        if len(new_phrase.split(" ")) == 1 and new_phrase.split(" ")[0] != "" \
                and dictionary.check(new_phrase.split(" ")[0]):
            delete = True

        if any([p in new_phrase.split(" ")[0] for p in ["/", "\\", ","]]):
            delete = True

        if any([p in new_phrase.split(" ")[0].lower() for p in ["octet", "note", "bit"]]):
            delete = True

        if not delete:
            if new_phrase not in refined_phrases.keys():
                refined_phrases[new_phrase] = phrase_freq
            else:
                refined_phrases[new_phrase] += phrase_freq

    keyword_dict_ = dict()

    for phrase, phrase_freq in sorted(refined_phrases.items(), key=lambda item: item[1], reverse=True):
        phrase = phrase.strip()
        phrase_key = str(phrase).replace("-", "_").replace("/", "_"). \
            replace(" ", "_").replace("__", "_").replace("__", "_")
        keyword_dict_[phrase_key] = [phrase]

    return keyword_dict_


keyword_dict = refine_noun_phrases()

a_file = open("keyword_dict_np.pkl", "wb")
pickle.dump(keyword_dict, a_file)
a_file.close()
