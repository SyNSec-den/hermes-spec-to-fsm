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

import pickle
import pprint

import PyPDF2
import numpy as np
import pandas
import enchant
from nltk.stem.porter import *

from tabula import read_pdf

# Change this file to accommodate new specs
INPUT_FILENAME = '5g-rrc.pdf'

pp = pprint.PrettyPrinter(width=150)
dictionary = enchant.Dict("en_US")


def get_IE_keywords_dict(get_updated):
    if get_updated:
        keyword_dict_new = get_IE_toc()
        a_file = open("ie_from_pdf.pkl", "wb")
        pickle.dump(keyword_dict_new, a_file)
        a_file.close()
    else:
        a_file = open("ie_from_pdf.pkl", "rb")
        output = pickle.load(a_file)
        keyword_dict_new = dict(output)
        a_file.close()

    return keyword_dict_new


def get_IE_toc():
    pdfFileObj = open(INPUT_FILENAME, 'rb')
    pdfReader = PyPDF2.PdfReader(pdfFileObj)
    ie_dict = dict()

    last_section = ""
    for i in range(4, 24):
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

            elif last_section.startswith("6.3") and section == "–":

                ie_text = line_splits[1].replace(".", "")
                key = ie_text.lower().replace("-", "_")
                if key in ie_dict and ie_text not in ie_dict[key]:
                    ie_dict[key].append(ie_text)
                else:
                    ie_dict[key] = [ie_text]

    remove_list = []
    for k in ie_dict.keys():
        if len(ie_dict[k][0].split(" ")) == 1 and dictionary.check(ie_dict[k][0].split(" ")[0]):
            remove_list.append(k)

    for k in remove_list:
        del ie_dict[k]

    pdfFileObj.close()
    return ie_dict