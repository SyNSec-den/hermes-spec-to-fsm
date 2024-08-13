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

pp = pprint.PrettyPrinter(width=200)


def get_dictionaries():
    a_file = open("keyword_dict_np_merged.pkl", "rb")
    output = pickle.load(a_file)
    keyword_dict = dict(output)
    a_file.close()

    message_suffixes = ['message', 'messages', 'request']
    message_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in message_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    message_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    procedure_suffixes = ['procedure', 'procedures']
    procedure_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in procedure_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    procedure_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    counter_suffixes = ['count', 'counter', 'counters']
    counter_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in counter_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    counter_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    service_substrings = ['optimization', 'optimisation', 'service', 'services', 'bearer service', 'bearer services',
                          'signalling connection', 'PDN connection', 'RRC connection', 'RR Connection']

    service_suffixes = ['bearer context', 'bearer contexts', 'connection', 'connections', 'capability']

    service_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for substring in service_substrings:
                if str(substring) in str(phrase):
                    service_dictionary[k] = v
                    remove_list.append(k)

            for suffix in service_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    service_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    mode_suffixes = ['mode', 'modes']
    mode_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in mode_suffixes:
                if suffix.lower() in str(phrase).lower():
                    mode_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    ie_substrings = ['information element', 'information elements', ' ie', 'additional', 'type', 'message identity',
                     'policy', 'identifier', 'indication', 'indicator']

    def contains_timer(phrase_):
        words = str(phrase_).split()
        for word in words:
            if word[0].lower() == 't' and str(word[1:]).isnumeric():
                num = int(word[1:])
                if num != 1:
                    return True

        return False

    message_field_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for substring in ie_substrings:
                if str(substring).lower() in str(phrase).lower():
                    message_field_dictionary[k] = v
                    remove_list.append(k)

            if "timer" in str(phrase).lower() and "value" in str(phrase).lower():
                message_field_dictionary[k] = v
                remove_list.append(k)

            if contains_timer(phrase) and "value" in str(phrase).lower():
                message_field_dictionary[k] = v
                remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    timer_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            if contains_timer(phrase):
                timer_dictionary[k] = v
                remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    variable_suffixes = ['security context', 'security contexts', 'list', 'lists', 'key', 'keys']
    variable_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in variable_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    variable_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    algorithm_suffixes = ['algorithm', 'algorithms']
    algorithm_dictionary = dict()
    remove_list = []
    for k, v in keyword_dict.items():
        for phrase in v:
            for suffix in algorithm_suffixes:
                if str(phrase).lower().endswith(suffix.lower()):
                    variable_dictionary[k] = v
                    remove_list.append(k)

                elif len(phrase.split(" ")) > 2 and suffix == phrase.split(" ")[-2]:
                    algorithm_dictionary[k] = v
                    remove_list.append(k)

    for key in list(set(remove_list)):
        del keyword_dict[key]

    return message_dictionary, procedure_dictionary, message_field_dictionary, counter_dictionary, \
           mode_dictionary, service_dictionary, timer_dictionary, variable_dictionary, algorithm_dictionary, keyword_dict