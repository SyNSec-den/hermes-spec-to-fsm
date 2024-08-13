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

import cause_extraction
import categorize_keywords
import gather_keyword_pdf
import cellular_text_converter
import pprint
from nltk.stem.porter import *

abbreviations_pdf = gather_keyword_pdf.get_abbreviations()
definitions_pdf = gather_keyword_pdf.get_definitions()

for k, v in abbreviations_pdf.items():
    abbreviations_pdf[k] = v + [k]

new_dict = dict()
for k, v in abbreviations_pdf.items():
    v_new = []
    for phrase in v:
        v_new.append(str(phrase).lower().strip())

    new_dict[str(k).lower() + "_"] = sorted(list(set(v_new)), key=lambda item: len(item), reverse=True)

abbreviations_pdf = new_dict

pp = pprint.PrettyPrinter(width=200)
p_stemmer = PorterStemmer()

def extend_phrase(p1):
    p1_words = p1.split(" ")
    p1_extended = ""
    for word in p1_words:
        word_n = word
        for k in abbreviations_pdf.keys():
            if str(k[:-1]).lower() == word.lower():
                word_n = str(abbreviations_pdf[k][0])
        p1_extended += " " + word_n

    p1 = p1_extended.strip().lower()

    p1_words = p1.split(" ")
    p1_extended = ""
    for word in p1_words:
        word_n = word
        for k in abbreviations_pdf.keys():
            if str(k[:-1]).lower() == word.lower():
                word_n = str(abbreviations_pdf[k][0])
        p1_extended += " " + word_n
    p1_extended.strip().lower()

    if str(p1_extended) in p1:
        return False, p1.lower()

    return True, p1_extended


def refine_dict(old_dict):
    new_dict = dict()
    for k, v in old_dict.items():
        v_new = []
        for phrase in v:
            is_extended, extended_phrase = extend_phrase(str(phrase))
            v_new.append(str(phrase).lower().strip())
            if is_extended:
                v_new.append(str(extended_phrase).lower().strip())

        new_dict[str(k).lower() + "_"] = sorted(list(set(v_new)), key=lambda item: len(item), reverse=True)

    return new_dict


msg_dict_cap, message_dict_pdf, procedures_dict_pdf, state_dict_pdf, ie_dict_pdf, mode_dict_cap, state_dict_cap, \
    status_dict_cap, variable_dict_pdf = cellular_text_converter.find_dictionaries()

message_dict_myalgo, procedure_dict_myalgo, message_field_dict_myalgo, counter_dict_myalgo, \
    mode_dict_myalgo, service_dict_myalgo, timer_dict_myalgo, \
    variable_dict_myalgo, algorithm_dict_myalgo, others_dict_myalgo = categorize_keywords.get_dictionaries()

msg_dict_cap, message_dict_pdf, procedures_dict_pdf, state_dict_pdf, ie_dict_pdf, mode_dict_cap, state_dict_cap, \
    status_dict_cap, variable_dict_pdf = refine_dict(msg_dict_cap), refine_dict(message_dict_pdf), refine_dict(
    procedures_dict_pdf), \
    refine_dict(state_dict_pdf), \
    refine_dict(ie_dict_pdf), refine_dict(mode_dict_cap), refine_dict(state_dict_cap), \
    refine_dict(status_dict_cap), refine_dict(variable_dict_pdf)

message_dict_myalgo, procedure_dict_myalgo, message_field_dict_myalgo, counter_dict_myalgo, \
    mode_dict_myalgo, service_dict_myalgo, timer_dict_myalgo, \
    variable_dict_myalgo, algorithm_dict_myalgo, others_dict_myalgo = refine_dict(message_dict_myalgo), \
    refine_dict(procedure_dict_myalgo), \
    refine_dict(message_field_dict_myalgo), \
    refine_dict(counter_dict_myalgo), \
    refine_dict(mode_dict_myalgo), \
    refine_dict(service_dict_myalgo), \
    refine_dict(timer_dict_myalgo), \
    refine_dict(variable_dict_myalgo), \
    refine_dict(algorithm_dict_myalgo), \
    refine_dict(others_dict_myalgo)


def phrase_match(list1, list2, strip_list):
    for phrase1 in list1:
        p1 = str(phrase1).lower()
        for strip_word in strip_list:
            p1 = p1.split(strip_word)[0]
        p1 = p1.strip()

        p1_stem = ""
        for word in p1.split(" "):
            p1_stem += str(p_stemmer.stem(str(word))) + " "

        for phrase2 in list2:
            p2 = str(phrase2).lower()
            for strip_word in strip_list:
                p2 = p2.split(strip_word)[0]
            p2 = p2.strip()

            p2_stem = ""
            for word in p2.split(" "):
                p2_stem += str(p_stemmer.stem(str(word))) + " "

            if str(p1_stem.strip()).lower() == str(p2_stem.strip()).lower():
                return True

    return False


def add_dict(original_dict, new_dict_to_add, common_lastwords):
    add_by_newdict = dict()
    for k_p, v_p in sorted(dict(new_dict_to_add).items(), key=lambda item: len(item[0])):
        add_kp = True
        for k_c, v_c in sorted(dict(original_dict).items(), key=lambda item: len(item[0])):
            if str(k_c) == str(k_p) or phrase_match(v_p, v_c, common_lastwords):
                if len(k_c) < len(k_p):
                    original_dict[k_c] = sorted(list(set(v_p + v_c)), key=lambda item: len(item), reverse=True)
                add_kp = False

        if add_kp:
            original_dict[k_p] = new_dict_to_add[k_p]
            add_by_newdict[k_p] = v_p

    return add_by_newdict, original_dict


def combine_messages(msg_dict_cap_, message_dict_pdf_, message_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['message', 'messages']

    add_by_phrase, combined_dict = add_dict(combined_dict, msg_dict_cap_, common_lastwords)
    add_by_pdf, combined_dict = add_dict(combined_dict, message_dict_pdf_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, message_dict_myalgo_, common_lastwords)

    return combined_dict


def combine_procedures(procedures_dict_pdf_, procedure_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['procedure', 'procedures']

    add_by_pdf, combined_dict = add_dict(combined_dict, procedures_dict_pdf_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, procedure_dict_myalgo_, common_lastwords)

    return combined_dict


def combine_states(state_dict_pdf_, state_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['state', 'states']

    add_by_pdf, combined_dict = add_dict(combined_dict, state_dict_pdf_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, state_dict_myalgo_, common_lastwords)

    return combined_dict


def combine_variables(var_dict_pdf_, var_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['variable', 'variables']

    add_by_pdf, combined_dict = add_dict(combined_dict, var_dict_pdf_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, var_dict_myalgo_, common_lastwords)

    return combined_dict


def combine_msg_fields(ie_dict_pdf_, message_field_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['information elements', 'information element', 'ie']

    add_by_pdf, combined_dict = add_dict(combined_dict, ie_dict_pdf_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, message_field_dict_myalgo_, common_lastwords)

    return combined_dict


def combine_modes(mode_dict_phrases_, mode_dict_myalgo_):
    combined_dict = dict()
    common_lastwords = ['mode', 'modes']

    add_by_phrase, combined_dict = add_dict(combined_dict, mode_dict_phrases_, common_lastwords)
    add_by_myalgo, combined_dict = add_dict(combined_dict, mode_dict_myalgo_, common_lastwords)

    return combined_dict


def get_combined_list(get_updated):
    if get_updated:
        msg_final = combine_messages(msg_dict_cap, message_dict_pdf, message_dict_myalgo)
        procedure_final = combine_procedures(procedures_dict_pdf, procedure_dict_myalgo)
        message_fields_final = combine_msg_fields(ie_dict_pdf, message_field_dict_myalgo)
        modes_final = combine_modes(mode_dict_cap, mode_dict_myalgo)
        states_final = combine_states(state_dict_pdf, state_dict_cap)
        statuses_final = status_dict_cap
        services_final = service_dict_myalgo
        counters_final = counter_dict_myalgo
        timers_final = timer_dict_myalgo
        algorithms_final = algorithm_dict_myalgo
        variables_final = combine_variables(variable_dict_pdf, variable_dict_myalgo)


        others_final = others_dict_myalgo

        a_file = open("msg_final.pkl", "wb")
        pickle.dump(msg_final, a_file)
        a_file.close()

        a_file = open("procedure_final.pkl", "wb")
        pickle.dump(procedure_final, a_file)
        a_file.close()

        a_file = open("message_fields_final.pkl", "wb")
        pickle.dump(message_fields_final, a_file)
        a_file.close()

        a_file = open("modes_final.pkl", "wb")
        pickle.dump(modes_final, a_file)
        a_file.close()

        a_file = open("states_final.pkl", "wb")
        pickle.dump(states_final, a_file)
        a_file.close()

        a_file = open("statuses_final.pkl", "wb")
        pickle.dump(statuses_final, a_file)
        a_file.close()

        a_file = open("services_final.pkl", "wb")
        pickle.dump(services_final, a_file)
        a_file.close()

        a_file = open("counters_final.pkl", "wb")
        pickle.dump(counters_final, a_file)
        a_file.close()

        a_file = open("timers_final.pkl", "wb")
        pickle.dump(timers_final, a_file)
        a_file.close()

        a_file = open("algorithms_final.pkl", "wb")
        pickle.dump(algorithms_final, a_file)
        a_file.close()

        a_file = open("variables_final.pkl", "wb")
        pickle.dump(variables_final, a_file)
        a_file.close()

        a_file = open("others_final.pkl", "wb")
        pickle.dump(others_final, a_file)
        a_file.close()

    else:
        a_file = open("msg_final.pkl", "rb")
        output = pickle.load(a_file)
        msg_final = dict(output)
        a_file.close()

        a_file = open("procedure_final.pkl", "rb")
        output = pickle.load(a_file)
        procedure_final = dict(output)
        a_file.close()

        a_file = open("message_fields_final.pkl", "rb")
        output = pickle.load(a_file)
        message_fields_final = dict(output)
        a_file.close()

        a_file = open("modes_final.pkl", "rb")
        output = pickle.load(a_file)
        modes_final = dict(output)
        a_file.close()

        a_file = open("states_final.pkl", "rb")
        output = pickle.load(a_file)
        states_final = dict(output)
        a_file.close()

        a_file = open("services_final.pkl", "rb")
        output = pickle.load(a_file)
        services_final = dict(output)
        a_file.close()

        a_file = open("counters_final.pkl", "rb")
        output = pickle.load(a_file)
        counters_final = dict(output)
        a_file.close()

        a_file = open("timers_final.pkl", "rb")
        output = pickle.load(a_file)
        timers_final = dict(output)
        a_file.close()

        a_file = open("algorithms_final.pkl", "rb")
        output = pickle.load(a_file)
        algorithms_final = dict(output)
        a_file.close()

        a_file = open("statuses_final.pkl", "rb")
        output = pickle.load(a_file)
        statuses_final = dict(output)
        a_file.close()

        a_file = open("variables_final.pkl", "rb")
        output = pickle.load(a_file)
        variables_final = dict(output)
        a_file.close()

        a_file = open("others_final.pkl", "rb")
        output = pickle.load(a_file)
        others_final = dict(output)
        a_file.close()

    return msg_final, procedure_final, message_fields_final, modes_final, states_final, statuses_final, services_final,\
        counters_final, timers_final, algorithms_final, variables_final, others_final


msg_final, procedure_final, message_fields_final, modes_final, states_final, statuses_final, services_final, \
    counters_final, timers_final, algorithms_final, variables_final, others_final = get_combined_list(True)


def weed_rest():
    remove_list = []

    for k, v in sorted(dict(msg_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                msg_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(procedure_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                procedure_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(message_fields_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                message_fields_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(modes_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                modes_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(states_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                states_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(statuses_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, ['status']):
                remove_list.append(k_others)
                statuses_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(services_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, ['service']):
                remove_list.append(k_others)
                statuses_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(counters_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                counters_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(timers_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                timers_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(algorithms_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                algorithms_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(variables_final).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others) == str(k) or phrase_match(v, v_others, []):
                remove_list.append(k_others)
                variables_final[k] = sorted(list(set(v + v_others)), key=lambda item: len(item), reverse=True)

    for k, v in sorted(dict(abbreviations_pdf).items(), key=lambda item: len(item[0])):
        for k_others, v_others in sorted(dict(others_final).items(), key=lambda item: len(item[0])):
            if str(k_others).lower() == str(k).lower() or phrase_match(v, v_others, []):
                remove_list.append(k_others)

    for k in list(set(remove_list)):
        del others_final[k]

weed_rest()

cause_dict = cause_extraction.create_cause_set()


final_keyword_dict = dict()

final_keyword_dict["message"] = msg_final
final_keyword_dict["procedure"] = procedure_final
final_keyword_dict["messagefield"] = message_fields_final
final_keyword_dict["state"] = states_final
final_keyword_dict["mode"] = modes_final
final_keyword_dict["status"] = statuses_final
final_keyword_dict["service"] = services_final
final_keyword_dict["counter"] = counters_final
final_keyword_dict["timer"] = timers_final
final_keyword_dict["algorithm"] = algorithms_final
final_keyword_dict["variable"] = variables_final
final_keyword_dict["abbreviation"] = abbreviations_pdf
final_keyword_dict["definitions"] = definitions_pdf
final_keyword_dict["misc"] = others_final
final_keyword_dict["causes"] = cause_dict

dictionaries = [msg_final, procedure_final, message_fields_final, states_final, modes_final, statuses_final
    , services_final, counters_final, timers_final, algorithms_final, variables_final, abbreviations_pdf,
                definitions_pdf,
                others_final]

dictionaries_names = ["msg_final", "procedure_final", "message_fields_final", "states_final", "modes_final",
                      "statuses_final", "services_final",
                      "counters_final", "timers_final", "algorithms_final", "variables_final", "abbreviations_pdf",
                      "definitions_pdf",
                      "others_final"]

var_dict = dict()
for i in range(len(dictionaries)):
    var_dict[dictionaries_names[i]] = dictionaries[i]

phrase_to_key = dict()
for i in range(len(dictionaries)):
    name = dictionaries_names[i]
    for k, v in dictionaries[i].items():
        for phrase in v:
            if phrase in phrase_to_key.keys():
                phrase_to_key[phrase] += [[k, name]]
            else:
                phrase_to_key[phrase] = [[k, name]]

for k, v in phrase_to_key.items():
    if len(phrase_to_key[k]) > 1:
        all_key_names = sorted([item[0] for item in v], key=lambda item: len(item))
        chosen_name = all_key_names[0]
        for i in range(len(v)):
            dict_n = v[i][1]
            prev_key = v[i][0]
            if dict_n in var_dict:
                dict_v = var_dict[dict_n]
                if prev_key in dict_v:
                    prev_phraselist = dict_v[prev_key].copy()
                    del dict_v[prev_key]
                    dict_v[chosen_name] = prev_phraselist

a_file = open("combined_final.pkl", "wb")
pickle.dump(final_keyword_dict, a_file)
a_file.close()
