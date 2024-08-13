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

from nltk.stem.porter import *
import pickle
import pprint
import enchant

pp = pprint.PrettyPrinter(width=200)


def get_merged_dict_myalgo(get_updated):
    if get_updated:
        p_stemmer = PorterStemmer()

        a_file = open("keyword_dict_np.pkl", "rb")
        output = pickle.load(a_file)
        keyword_dict = dict(output)
        a_file.close()

        remove_list = []
        for k, v in keyword_dict.items():
            words = str(k).split("_")
            k_to_compare = ""
            for word_k in words[:-1]:
                k_to_compare += word_k + " "
            k_to_compare += p_stemmer.stem(words[-1])
            for other_k in keyword_dict.keys():
                other_k_words = str(other_k).split("_")
                other_k_to_compare = ""
                for word_k in other_k_words[:-1]:
                    other_k_to_compare += word_k + " "
                other_k_to_compare += p_stemmer.stem(other_k_words[-1])
                if k_to_compare == other_k_to_compare and len(k) > len(other_k):
                    remove_list.append(k)
                    keyword_dict[other_k] = keyword_dict[other_k] + keyword_dict[k]
                elif k_to_compare == other_k_to_compare and len(k) < len(other_k):
                    remove_list.append(other_k)
                    keyword_dict[k] = keyword_dict[k] + keyword_dict[other_k]

        remove_list = list(set(remove_list))
        for key in remove_list:
            del keyword_dict[key]

        for k, v in keyword_dict.items():
            keyword_dict[k] = list(set(keyword_dict[k]))

        a_file = open("keyword_dict_np_merged.pkl", "wb")
        pickle.dump(keyword_dict, a_file)
        a_file.close()

    else:
        a_file = open("keyword_dict_np_merged.pkl", "rb")
        output = pickle.load(a_file)
        keyword_dict = dict(output)
        a_file.close()



get_merged_dict_myalgo(True)