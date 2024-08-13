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

import re
import pprint

pp = pprint.PrettyPrinter(width=200)


def convert_to_keyword(phrase, ret_keyword=False):
    phrase_new = phrase.replace("- ", "-").replace("\'", "").replace(",", "") \
        .replace(";", "").replace("  ", " ").replace(".", "_").replace(" ", "_").lower()
    if not phrase_new[-1].isalpha():
        phrase_new = phrase_new[:-1]
    if len(phrase_new.split("-")) >= 2 or len(phrase_new.split("_")) >= 2 or ret_keyword:
        return phrase_new + "_"

    return phrase


def get_state_keywords(filename, suffix="state"):
    states_list = []
    prefix_list = ['EMM', '5GMM', 'GMM']
    with open(filename + ".txt", "r") as f:
        with open(filename + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                org_sen = org_sen.split("\n")[0]
                new_sen = ""
                words = org_sen.split(" ")
                phrase = ""
                in_phrase = False
                for i in range(len(words)):
                    if not in_phrase:
                        if (i + 1 < len(words) and 'state' in str(words[i + 1]).lower()) or (i - 1 >= 0 and 'state' in
                                                                                             str(words[i - 1]).lower()):
                            if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                    str(words[i][0]).isalnum():
                                phrase = words[i]
                                in_phrase = True

                        if not in_phrase:
                            if i != 0:
                                new_sen += " " + words[i]
                            else:
                                new_sen += words[i]

                    else:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) \
                                and not any(words[i].startswith(prefix) for prefix in prefix_list):
                            phrase += " " + words[i]
                        else:
                            in_phrase = False
                            states_list.append(phrase)
                            new_sen += " " + convert_to_keyword(phrase)
                            phrase = ""

                            if (i + 1 < len(words) and 'state' in str(words[i + 1]).lower()) or (
                                    i - 1 >= 0 and 'state' in
                                    str(words[i - 1]).lower()):
                                if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                        str(words[i][0]).isalnum():
                                    phrase = words[i]
                                    in_phrase = True

                            if not in_phrase:
                                if i != 0:
                                    new_sen += " " + words[i]
                                else:
                                    new_sen += words[i]

                if phrase != "":
                    states_list.append(phrase)
                    new_sen += " " + convert_to_keyword(phrase)

                f2.write(new_sen + "\n")

    states_list_2 = []
    for i in range(len(states_list)):
        states_list[i] = states_list[i].replace("- ", "-").replace("\'", "").replace(",", "") \
            .replace(";", "").replace("  ", " ")
        if not states_list[i][-1].isalpha():
            states_list[i] = states_list[i][:-1]
        if len(states_list[i].split("-")) >= 2 or len(states_list[i].split(" ")) >= 2:
            states_list_2.append(states_list[i])

    states_list = list(set(states_list_2))

    states_dict = dict()
    for i in range(len(states_list)):
        key = states_list[i].replace(".", "_").replace(" ", "_").lower()
        value = states_list[i].lower()
        if not key.endswith("_a"):
            states_dict[key] = [value]

    return filename + "_" + suffix, states_dict


def get_message_keywords(filename, suffix="msgcap"):
    messages_list = []
    prefix_list = ['ESM']
    with open(filename + ".txt", "r") as f:
        with open(filename + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                org_sen = org_sen.split("\n")[0]
                new_sen = ""
                words = org_sen.split(" ")
                phrase = ""
                in_phrase = False
                was_before_start = False
                for i in range(len(words)):
                    if not in_phrase:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                str(words[i][0]).isalpha() and str(words[i]) not in ['A', 'NOTE:']:
                            phrase = words[i]
                            in_phrase = True
                            continue

                        if 'message' in str(words[i]).lower() and not (re.search('[A-Z]', words[i]) and
                                                                       str(words[i]).upper() == str(words[i])):
                            was_before_start = True
                        else:
                            was_before_start = False

                        if not in_phrase:
                            if i != 0:
                                new_sen += " " + words[i]
                            else:
                                new_sen += words[i]

                    else:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) \
                                and not any(words[i].startswith(prefix) for prefix in prefix_list):
                            phrase += " " + words[i]
                        else:
                            in_phrase = False
                            if ('message' in str(words[i]).lower()) or was_before_start:
                                messages_list.append(phrase)
                                new_sen += " " + convert_to_keyword(phrase)
                            else:
                                if i != 0:
                                    new_sen += (" " + phrase)
                                else:
                                    new_sen += phrase

                            phrase = ""

                            if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                    str(words[i][0]).isalpha():
                                phrase = words[i]
                                in_phrase = True
                                continue

                            if 'message' in str(words[i]).lower() and not (re.search('[A-Z]', words[i]) and
                                                                           str(words[i]).upper() == str(words[i])):
                                was_before_start = True
                            else:
                                was_before_start = False

                            if not in_phrase:
                                if i != 0:
                                    new_sen += " " + words[i]
                                else:
                                    new_sen += words[i]

                if phrase != "":
                    if ('message' in str(words[-1]).lower()) or was_before_start:
                        messages_list.append(phrase)
                        new_sen += " " + convert_to_keyword(phrase)
                    else:
                        if i != 0:
                            new_sen += " " + phrase
                        else:
                            new_sen += phrase

                f2.write(new_sen.strip(" ") + "\n")

    messages_list_2 = []
    for i in range(len(messages_list)):
        messages_list[i] = messages_list[i].replace("- ", "-").replace("\'", "").replace(",", "") \
            .replace(";", "").replace("  ", " ")
        if not messages_list[i][-1].isalpha():
            messages_list[i] = messages_list[i][:-1]
        if len(messages_list[i].split("-")) >= 2 or len(messages_list[i].split(" ")) >= 2:
            messages_list_2.append(messages_list[i])

    messages_list = list(set(messages_list_2))

    messages_dict = dict()
    for i in range(len(messages_list)):
        key = messages_list[i].replace(".", "_").replace(" ", "_").lower()
        value = messages_list[i].lower()
        messages_dict[key] = [value]

    return filename + "_" + suffix, messages_dict


def get_status_keywords(filename, suffix="status"):
    statuses_list = []
    prefix_list = ['OR']
    with open(filename + ".txt", "r") as f:
        with open(filename + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                org_sen = org_sen.split("\n")[0]
                new_sen = ""
                words = org_sen.split(" ")
                phrase = ""
                in_phrase = False
                for i in range(len(words)):
                    if not in_phrase:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                str(words[i][0]).isalnum() and str(words[i]) not in ['A', 'NOTE:', 'OR']:
                            phrase = words[i]
                            in_phrase = True
                            continue

                        if not in_phrase:
                            if i != 0:
                                new_sen += " " + words[i]
                            else:
                                new_sen += words[i]

                    else:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) \
                                and not any(words[i].startswith(prefix) for prefix in prefix_list):
                            phrase += " " + words[i]
                        else:
                            in_phrase = False
                            if ('status' in str(words[i]).lower()) or new_sen.endswith("status to") or \
                                    new_sen.endswith("status is different from"):
                                statuses_list.append(phrase)
                                new_sen += " " + convert_to_keyword(phrase)
                            else:
                                if i != 0:
                                    new_sen += (" " + phrase)
                                else:
                                    new_sen += phrase

                            phrase = ""

                            if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                    str(words[i][0]).isalnum() and str(words[i]) not in ['A', 'NOTE:', 'OR']:
                                phrase = words[i]
                                in_phrase = True
                                continue

                            if not in_phrase:
                                if i != 0:
                                    new_sen += " " + words[i]
                                else:
                                    new_sen += words[i]

                if phrase != "":
                    if ('status' in str(words[-1]).lower()) or new_sen.endswith("status to") or \
                            new_sen.endswith("status is different from"):
                        statuses_list.append(phrase)
                        new_sen += " " + convert_to_keyword(phrase)
                    else:
                        if i != 0:
                            new_sen += " " + phrase
                        else:
                            new_sen += phrase

                f2.write(new_sen.strip(" ") + "\n")

    statuses_list_2 = []
    for i in range(len(statuses_list)):
        statuses_list[i] = statuses_list[i].replace("- ", "-").replace("\'", "").replace(",", "") \
            .replace(";", "").replace("  ", " ")
        if not statuses_list[i][-1].isalpha():
            statuses_list[i] = statuses_list[i][:-1]
        if len(statuses_list[i].split("-")) >= 2 or len(statuses_list[i].split(" ")) >= 2:
            statuses_list_2.append(statuses_list[i])

    statuses_list = list(set(statuses_list_2))

    statuses_dict = dict()
    for i in range(len(statuses_list)):
        key = statuses_list[i].replace(".", "_").replace(" ", "_").lower()
        value = statuses_list[i].lower()
        statuses_dict[key] = [value]

    return filename + "_" + suffix, statuses_dict


def get_mode_keywords(filename, suffix="mode"):
    modes_list = []
    prefix_list = ['5GMM']
    with open(filename + ".txt", "r") as f:
        with open(filename + "_" + suffix + ".txt", "w") as f2:
            s = f.readlines()
            for org_sen in s:
                org_sen = org_sen.split("\n")[0]
                new_sen = ""
                words = org_sen.split(" ")
                phrase = ""
                in_phrase = False
                for i in range(len(words)):
                    if not in_phrase:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                str(words[i][0]).isalnum() and str(words[i]) not in ['A', 'NOTE:', 'OR']:
                            phrase = words[i]
                            in_phrase = True
                            continue

                        if not in_phrase:
                            if i != 0:
                                new_sen += " " + words[i]
                            else:
                                new_sen += words[i]

                    else:
                        if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) \
                                and not any(words[i].startswith(prefix) for prefix in prefix_list):
                            phrase += " " + words[i]
                        else:
                            in_phrase = False
                            if ('mode' in str(words[i]).lower()) or new_sen.endswith("mode"):
                                modes_list.append(phrase)
                                new_sen += " " + convert_to_keyword(phrase)
                            else:
                                if i != 0:
                                    new_sen += (" " + phrase)
                                else:
                                    new_sen += phrase

                            phrase = ""

                            if re.search('[A-Z]', words[i]) and str(words[i]).upper() == str(words[i]) and \
                                    str(words[i][0]).isalnum() and str(words[i]) not in ['A', 'NOTE:', 'OR']:
                                phrase = words[i]
                                in_phrase = True
                                continue

                            if not in_phrase:
                                if i != 0:
                                    new_sen += " " + words[i]
                                else:
                                    new_sen += words[i]

                if phrase != "":
                    if ('mode' in str(words[-1]).lower()) or new_sen.endswith("mode"):
                        modes_list.append(phrase)
                        new_sen += " " + convert_to_keyword(phrase)
                    else:
                        if i != 0:
                            new_sen += " " + phrase
                        else:
                            new_sen += phrase

                f2.write(new_sen.strip(" ") + "\n")

    modes_list_2 = []
    for i in range(len(modes_list)):
        modes_list[i] = modes_list[i].replace("- ", "-").replace("\'", "").replace(",", "") \
            .replace(";", "").replace("  ", " ")
        if len(modes_list[i].split("-")) >= 2 or len(modes_list[i].split(" ")) >= 2:
            modes_list_2.append(modes_list[i])

    modes_list = list(set(modes_list_2))

    modes_dict = dict()
    for i in range(len(modes_list)):
        key = modes_list[i].replace(".", "_").replace(" ", "_").lower()
        value = modes_list[i].lower()
        modes_dict[key] = [value]

    return filename + "_" + suffix, modes_dict