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

pp = pprint.PrettyPrinter(indent=4)


def create_cause_set():
    causes = []
    with open("assets/cause.txt", "r") as fr:
        lines = fr.readlines()
        for line in lines:
            if line.startswith("Cause #"):
                causes.append(line.split("\n")[0])

    keyword_set = dict()
    for line in causes:
        tokens = line.split(" ")

        phrase_1 = str(tokens[0]) + " " + str(tokens[1])
        phrase_2 = str(tokens[1])
        phrase_3 = line.split(" ", 2)[2].replace("-", "").strip()
        phrase_4 = line.split(" ", 1)[1]

        key_str = phrase_1.replace(" ", "_").replace("#", "").lower()
        if key_str in keyword_set.keys():
            keyword_set[key_str] = list(set(keyword_set[key_str] + [phrase_1, phrase_2, phrase_3, phrase_4]))
        else:
            keyword_set[key_str] = [phrase_1, phrase_2, phrase_3, phrase_4]

    return keyword_set

