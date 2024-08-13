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

import json
import pickle
import pprint

a_file = open("combined_final.pkl", "rb")
output = pickle.load(a_file)
combined_final = dict(output)
a_file.close()

pp = pprint.PrettyPrinter(width=200)


def add_id():
    global combined_final
    for k_combined, v_combined in combined_final.items():
        category_based_dict = dict(v_combined)
        for k_key, v_valuelist in category_based_dict.items():
            new_valuelist = []
            for phrase in v_valuelist:
                new_valuelist.append(phrase)
                if " id " in phrase.lower() or phrase.endswith("id"):
                    if str(phrase).lower().replace(" id", " identity").replace("id ", "identity ").replace(" id ",
                                                                                                           " identity") not in new_valuelist:
                        new_valuelist.append(str(phrase).lower().replace(" id", " identity")
                                             .replace("id ", "identity ").replace(" id ", " identity"))
                if "identity" in phrase.lower():
                    if str(phrase).lower().replace("identity", "id") not in new_valuelist:
                        new_valuelist.append(str(phrase).lower().replace("identity", "id"))
            category_based_dict[k_key] = sorted(list(set(new_valuelist)), key=lambda item: len(item), reverse=True)

        combined_final[k_combined] = category_based_dict


def correct_keywords():
    global combined_final
    for category_1_iterator in range(len(combined_final.items())):
        category_1_dict = list(combined_final.items())[category_1_iterator][1]
        for category_2_iterator in range(len(combined_final.items())):
            category_2_dict = list(combined_final.items())[category_2_iterator][1]
            c1_dict_iterator = 0
            while c1_dict_iterator < len(category_1_dict.items()):
                key_1 = list(category_1_dict.items())[c1_dict_iterator][0]
                value_1 = list(category_1_dict.items())[c1_dict_iterator][1]
                remove_list = []
                for c2_dict_iterator in range(len(category_2_dict.items())):
                    key_2 = list(category_2_dict.items())[c2_dict_iterator][0]
                    value_2 = list(category_2_dict.items())[c2_dict_iterator][1]
                    if key_1.lower() != key_2.lower():
                        for phrase_1 in value_1:
                            for phrase_2 in value_2:
                                if str(phrase_1).lower() == str(phrase_2).lower():
                                    combined_list = sorted(list(set(value_1 + value_2)))
                                    category_1_dict[key_1] = combined_list
                                    category_2_dict[key_2] = combined_list
                                    if len(key_1) < len(key_2):
                                        category_2_dict[key_1] = combined_list
                                        remove_list.append(key_2)
                for ks in remove_list:
                    if ks in category_2_dict.keys():
                        del category_2_dict[ks]
                c1_dict_iterator += 1


num2word = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine']


def replace_start_num_keyword(keyword: str) -> (bool, str):
    keyword = keyword.strip()
    if not len(keyword) == 0 and keyword[0].isnumeric():
        num_word = num2word[int(keyword[0])]
        return True, (num_word + "_" + keyword[1:])
    else:
        return False, keyword


def remove_extra_underscore():
    global combined_final
    for k, v in combined_final.items():
        for old_key in list(v.keys()):
            new_key = old_key
            new_key = str(new_key).replace("\'", "").replace("/", "_").replace("-", "_").strip("_").strip()
            _, new_key = replace_start_num_keyword(new_key)
            if not new_key == old_key:
                combined_final[k][new_key] = combined_final[k][old_key]
                del combined_final[k][old_key]


def manual_categorization():
    global combined_final
    with open("assets/manual_recategorization.txt", "r") as fr:
        lines = fr.readlines()
        from_category = ""
        to_category = ""
        for line in lines:
            if line.startswith("#"):
                continue
            if line.startswith("-"):
                from_category = line.split(" ")[1].strip()
            elif ":" in line:
                keyword = line.split(":")[0].strip()
                to_category = line.split(":")[1].strip()
                if from_category in combined_final.keys():
                    dict_from_category = combined_final[from_category]
                    if keyword in dict_from_category.keys():
                        keyword_value = dict_from_category[keyword]
                        if to_category in combined_final.keys():
                            dict_to_category = combined_final[to_category]
                            if keyword in dict_to_category:
                                dict_to_category[keyword] += keyword_value
                            else:
                                dict_to_category[keyword] = keyword_value
                            del dict_from_category[keyword]
                        else:
                            to_category = ""
                    else:
                        pass
                else:
                    from_category = ""
            else:
                keyword = line.split("\n")[0].strip()
                if from_category in combined_final.keys():
                    dict_from_category = combined_final[from_category]
                    if keyword in dict_from_category.keys():
                        keyword_value = dict_from_category[keyword]
                        if to_category in combined_final.keys():
                            dict_to_category = combined_final[to_category]
                            if keyword in dict_to_category:
                                dict_to_category[keyword] += keyword_value
                            else:
                                dict_to_category[keyword] = keyword_value
                            del dict_from_category[keyword]
                        else:
                            to_category = ""
                    else:
                        pass
                else:
                    from_category = ""


def combine_dictionaries(dict1: dict, dict2: dict) -> dict:
    result = {}
    result.update(dict1)
    for key in dict2:
        if key in result:
            result[key].extend(dict2[key])
            result[key] = list(set(result[key]))
        else:
            result[key] = dict2[key]

    return result


def change_key_name():
    global combined_final

    combined_final["id2agent"] = {}
    combined_final["id2verb"] = {}
    combined_final["id2adj"] = {}

    combined_final["id2state"] = combined_final["state"]
    combined_final["id2message"] = combined_final["message"]
    combined_final["id2procedure"] = combined_final["procedure"]
    combined_final["id2event"] = {}
    combined_final["id2timer"] = combined_final["timer"]
    combined_final["id2counter"] = combined_final["counter"]
    combined_final["id2var"] = combine_dictionaries(combined_final["status"], combined_final["variable"])
    combined_final["id2mode"] = combined_final["mode"]
    combined_final["id2service"] = combined_final["service"]
    combined_final["id2field_val"] = combined_final["algorithm"]
    combined_final["id2msg_field"] = combined_final["messagefield"]
    combined_final["id2cause"] = combined_final["causes"]
    combined_final["id2misc"] = combine_dictionaries(combined_final["abbreviation"], combined_final["definitions"])
    combined_final["id2misc"] = combine_dictionaries(combined_final["id2misc"], combined_final["misc"])

    combined_final["id2other"] = {}
    combined_final["id2num"] = {}

    del combined_final["message"]
    del combined_final["procedure"]
    del combined_final["messagefield"]
    del combined_final["state"]
    del combined_final["mode"]
    del combined_final["status"]
    del combined_final["service"]
    del combined_final["counter"]
    del combined_final["timer"]
    del combined_final["algorithm"]
    del combined_final["variable"]
    del combined_final["abbreviation"]
    del combined_final["definitions"]
    del combined_final["misc"]
    del combined_final["causes"]


add_id()
correct_keywords()
remove_extra_underscore()
manual_categorization()
change_key_name()

with open("combined.json", 'w') as outfile:
    json.dump(combined_final, outfile, indent=2)
    outfile.close()
