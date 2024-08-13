"""
This is the public release of the code of our paper titled
"Hermes: Unlocking Security Analysis of Cellular Network Protocols by Synthesizing Finite State Machines from Natural
    Language Specifications" (USENIX Security '24)
Author: Abdullah Al Ishtiaq
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

import os
import json
import copy
import datetime

import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError

from stanza.server import TimeoutException
from stanza.server import AnnotationException

import script_config
from script_helpers import verb_in_txt, get_middle_texts_list, get_middle_text, get_str_stem, find_substring_pos, \
    replace_tokens_key, get_text, get_rrc_cond_state, modify_section_numbers, clean_gt, isNum
from script_text2id import get_ids_from_text_db, parse_state_text, find_start_state, get_state_from_depending_lines, \
    call_close_db_from_text2id, parse_agent_text
from script_DepGraph import get_collapsed_dependency_graph
from script_build_ir_xml import build_ir_xml
from script_ir2smv import ir2smv_main
from script_dep2ir import get_IR_transitions, call_init_context, call_clear_context, call_get_context_copy, \
    call_update_global_context_with_text, call_update_header_context, call_get_header_context_texts, \
    call_get_header_context



os.system("rm ./corenlp_server-*.props")
os.system("rm ./temp*.txt")

INPUT_FILENAME = "input.txt"
DEFS_FILENAME = script_config.nas_definitions
COMMON_DEFS_FILENAME = script_config.common_definitions

L2_OUT_FILENAME = "transitions.txt"
IR_OUT_FILENAME = "ir-out.xml"
SMV_OUT_FILENAME = "smv-out.smv"



id2text_file = open(DEFS_FILENAME, 'r')
id2text = json.load(id2text_file)
id2text_file.close()

if "id2field_val" not in id2text:
    id2text["id2field_val"] = {}

text2id = {}
text2id["all2id"] = {}
for key in list(id2text.keys()):
    key_splits = key.strip().split("2")
    new_key = key_splits[1] + "2" + key_splits[0]
    text2id[new_key] = {}

    id2def = id2text[key]
    for lower_key in list(id2def.keys()):
        text_list = id2def[lower_key]
        for text_item in text_list:
            text_item = (text_item.lower().replace("/", " / ").replace(",", " , ").replace(".", " . ").
                         replace(";", " ; ").replace("-", " - "))
            if new_key == "verb2id":
                text2id[new_key][get_str_stem(text_item)[0]] = lower_key
            else:
                text2id["all2id"][text_item] = lower_key
                text2id[new_key][text_item] = lower_key



common_defs_file = open(COMMON_DEFS_FILENAME, 'r')
common_defs_dict = json.load(common_defs_file)
common_defs_file.close()

all_tokens = set()
all_tokens.update(text2id["all2id"].values())
all_tokens.update(text2id["verb2id"].values())

dep_out_file = open('dep-out.log', 'w')


def parse_with_dep_tree(part_text: str, line_str: str):
    global text2id
    global id2text
    global all_tokens

    text_position = find_substring_pos(line_str, part_text)

    result_trees = []
    dep_text = " " + copy.deepcopy(part_text).strip() + " "

    dep_text = dep_text.replace("i.e.", "that is").replace("e.g.", "for example,")
    dep_text = dep_text.replace("/", " / ").replace(",", " , ").replace(".", " . "). \
        replace(";", " ; ").replace("(", " ( ").replace(")", " ) ").replace("-", " - ").replace(":", " : ")

    while "  " in dep_text:
        dep_text = dep_text.replace("  ", " ")

    quoted_parts = dep_text.split('"')[1::2]

    new_keywords = []
    for res in quoted_parts:
        replaced_res = "_".join(res.replace(" - ", "_").replace(" / ", " ").replace("#", " ").split()).lower()
        dep_text = dep_text.replace("\"" + res + "\"", replaced_res)

        text2id["all2id"][res] = replaced_res
        text2id["all2id"][replaced_res] = replaced_res
        text2id["field_val2id"][res] = replaced_res
        text2id["field_val2id"][replaced_res] = replaced_res
        id2text["id2field_val"][replaced_res] = [res]
        all_tokens.add(replaced_res)
        new_keywords.append(replaced_res)

    keywords_in_text = get_ids_from_text_db(dep_text, text2id["all2id"], 1, common_defs_dict["ignore_list"],
                                            new_keywords)

    dep_text = replace_tokens_key(dep_text, keywords_in_text)
    dep_trees = get_collapsed_dependency_graph(dep_text, common_defs_dict, text2id, all_tokens)

    dep_out_file.write(part_text + '\n')
    dep_out_file.write(str(keywords_in_text) + '\n')
    dep_out_file.write(dep_text + '\n')

    for ttree in dep_trees:
        dep_parsed_str = ttree.DFS(set([item[0] for item in keywords_in_text]))
        try:
            dep_out_file.write(ttree.pretty_print() + '\n')
        except RecursionError:
            print("\nLine", line_idx + 1, ": pretty_print RecursionError :", dep_text, "\n")
            dep_out_file.write("\nLine " + str(line_idx + 1) + " : pretty_print RecursionError : " + dep_text + "\n")

        dep_out_file.write(dep_parsed_str + '\n\n')

        result_trees.append({
            "tree": ttree,
            "str": part_text,
            "parsed_str": dep_parsed_str,
            "line": line_str,
            "position": text_position
        })

    return result_trees


def get_middle_text_logic(middle_text: str):
    logic_str = ""
    middle_text = " " + middle_text + " "

    if "until" in middle_text:
        logic_str = "_NOT_"
    elif " or " in middle_text:
        logic_str = logic_str + "_OR_"
    elif " and " in middle_text:
        logic_str = logic_str + "_AND_"
    elif " but " in middle_text:
        logic_str = logic_str + "_AND_"

    else:
        logic_str = logic_str + "_AND_"

    return logic_str




def parse_condition_text(condition_text: str, line_str) -> str:
    original_text = copy.deepcopy(condition_text).strip()
    dep_parsed_condition = parse_with_dep_tree(original_text, line_str)

    return dep_parsed_condition




def parse_condition(condition_tree, line_str: str, strict=False) -> dict:
    child_counter = 0
    middle_text = get_middle_text(condition_tree)

    child_data = []
    for condition_child in condition_tree:
        child_counter = child_counter + 1
        child_data.append(parse_condition(condition_child, line_str))

    if child_counter == 0:
        return {"logic": "_NONE_", "data": condition_tree.text,
                "parsed_data": parse_condition_text(condition_tree.text, line_str), "strict": strict}
    elif len(middle_text.strip()) > 5:
        child_data.append(
            {"logic": "_NONE_", "data": middle_text, "parsed_data": parse_condition_text(middle_text, line_str),
             "strict": strict})

    logic_str = get_middle_text_logic(get_middle_text(condition_tree))
    return {"logic": logic_str, "data": child_data}

def parse_action_text(action_text: str, line_str: str) -> list:
    original_text = copy.deepcopy(action_text).strip()
    dep_parsed_action = parse_with_dep_tree(original_text, line_str)
    return dep_parsed_action




def parse_action(action_tree, line_str) -> (list, list):
    actions_list = [get_middle_text(action_tree)]
    conditions_list = []
    for action_child in action_tree:
        if action_child.tag.lower() == "action":
            child_actions_list, child_conditions_list = parse_action(action_child, line_str)
            actions_list.extend(child_actions_list)
            conditions_list.extend(child_conditions_list)
        elif action_child.tag.lower() == "condition":
            new_condition = parse_condition(action_child, line_str)
            conditions_list.append(new_condition)

    return actions_list, conditions_list


def head_condition_recur(head_tree, head_text: str) -> dict:
    condition = {"logic": "_AND_", "data": []}
    for head_condition_child in head_tree:
        if head_condition_child.tag.lower() == "condition":
            if "__SECTION__" in head_text:
                head_condition_child.text = head_condition_child.text.replace("__SECTION__", "")
                head_text = head_text.replace("__SECTION__", "")
                new_condition = parse_condition(head_condition_child, head_text, True)
                if not script_config.GEN == "5g-rrc":
                    continue
            else:
                new_condition = parse_condition(head_condition_child, head_text, False)
            condition["data"].append(new_condition)
        else:
            condition["data"].append(head_condition_recur(head_condition_child, head_text))

    return condition




def get_head_ctx_conditions(head_ctx_text: str):
    if "<control>" not in head_ctx_text:
        head_ctx_text = "<control> <condition> " + head_ctx_text + " </condition> </control>"
    head_ctx_text = "<root> " + head_ctx_text + " </root>"
    try:
        head_tree = ET.fromstring(head_ctx_text)
        head_condition = head_condition_recur(head_tree, head_ctx_text)
        return head_condition
    except ParseError:
        print("ParseError head_ctx_text:", head_ctx_text)
        return {"logic": "_AND_", "data": []}




def parse_control(control_xml, line_str: str, condition_up=None, start_state_up=None, end_state_up=None,
                  last_control_condition=None, rrc_cond=None) -> (list, list):
    if condition_up is None:
        condition_up = {"logic": get_middle_text_logic((get_middle_text(control_xml))), "data": []}
    else:
        condition_up = copy.deepcopy(condition_up)
    if start_state_up is None:
        start_state_up = []
    if end_state_up is None:
        end_state_up = []

    middle_texts = get_middle_texts_list(control_xml)
    transitions = []

    if last_control_condition is None:
        last_control_condition = []
    last_condition = copy.deepcopy(last_control_condition)
    child_condition_counter = 0

    for child in control_xml:
        if child.tag.lower() == "condition":
            new_condition = parse_condition(child, line_str)

            condition_up["data"].append(new_condition)
            if child_condition_counter == 0:
                last_condition = [copy.deepcopy(new_condition)]
            else:
                last_condition.append(copy.deepcopy(new_condition))
            child_condition_counter = child_condition_counter + 1

        elif child.tag.lower() == "start_state":
            start_state_up.append(get_text(child))

    for child in control_xml:
        if child.tag.lower() == "action":
            actions_text_list, action_conditions_list = parse_action(child, line_str)
            action_condition = {"logic": "_AND_", "data": [copy.deepcopy(condition_up)]}
            action_condition["data"].extend(action_conditions_list)
            if rrc_cond is not None and rrc_condition != "":
                extra_rrc_condition, extra_rrc_states = get_rrc_cond_state(rrc_cond)
                start_state_up.extend(extra_rrc_states)
                action_condition["data"].append(parse_condition(extra_rrc_condition, line_str))

            for head_ctx in call_get_header_context_texts():
                action_condition["data"].append(get_head_ctx_conditions(head_ctx))

            for action_text in actions_text_list:
                agents = parse_agent_text([action_text], text2id)
                transitions.append({
                    "start_state": copy.deepcopy(start_state_up),
                    "condition": action_condition,
                    "end_state": "",
                    "action": action_text,
                    "is_ue": "ue" in agents
                })
        elif child.tag.lower() == "end_state":
            end_state_text = get_text(child)
            states_in_text = parse_state_text([end_state_text], text2id)

            agents = parse_agent_text([end_state_text], text2id)

            if len(states_in_text) == 0:
                middle_texts.append("e2a:" + end_state_text)
            else:
                end_state_up.append(end_state_text)
                action_condition = {"logic": "_AND_", "data": [copy.deepcopy(condition_up)]}

                if rrc_cond is not None and rrc_condition != "":
                    extra_rrc_condition, extra_rrc_states = get_rrc_cond_state(rrc_cond)
                    start_state_up.extend(extra_rrc_states)
                    action_condition["data"].append(parse_condition(extra_rrc_condition, line_str))

                for head_ctx in call_get_header_context_texts():
                    action_condition["data"].append(get_head_ctx_conditions(head_ctx))

                for child_child in child:
                    if child_child.tag.lower() == "condition":
                        new_condition = parse_condition(child_child, line_str)
                        action_condition["data"].append(new_condition)
                transitions.append({
                    "start_state": copy.deepcopy(start_state_up),
                    "condition": copy.deepcopy(action_condition),
                    "end_state": copy.deepcopy(end_state_up),
                    "action": "",
                    "is_ue": "ue" in agents
                })

    for mid_txt in middle_texts:
        if verb_in_txt(
                mid_txt) or " shall " in mid_txt or " will " in mid_txt or " may " in mid_txt or "e2a:" in mid_txt:
            mid_txt = mid_txt.replace("e2a:", "")
            child = ET.fromstring("<action> " + mid_txt + "</action>")
            actions_text_list, action_conditions_list = parse_action(child, line_str)
            action_condition = {"logic": "_AND_", "data": [copy.deepcopy(condition_up)]}
            action_condition["data"].extend(action_conditions_list)

            if rrc_cond is not None and rrc_condition != "":
                extra_rrc_condition, extra_rrc_states = get_rrc_cond_state(rrc_cond)
                start_state_up.extend(extra_rrc_states)
                action_condition["data"].append(parse_condition(extra_rrc_condition, line_str))

            for head_ctx in call_get_header_context_texts():
                action_condition["data"].append(get_head_ctx_conditions(head_ctx))

            for action_text in actions_text_list:
                transitions.append({
                    "start_state": copy.deepcopy(start_state_up),
                    "condition": action_condition,
                    "end_state": "",
                    "action": action_text
                })

    last_control_condition = []
    for child in control_xml:
        if child.tag.lower() == "control":
            child_transitions_control, last_control_condition = parse_control(child, line_str,
                                                                              copy.deepcopy(condition_up),
                                                                              copy.deepcopy(start_state_up),
                                                                              copy.deepcopy(end_state_up),
                                                                              last_control_condition)
            transitions.extend(child_transitions_control)

    return transitions, last_condition



def parse_transitions_text(transitions_text, line_str: str):
    transitions_id = []
    for transition_text in transitions_text:
        transitions_id.append({
            "start_state": parse_state_text(transition_text["start_state"], text2id),
            "condition": transition_text["condition"],
            "is_ue": transition_text["is_ue"] if "is_ue" in transition_text else True,
            "end_state": parse_state_text(transition_text["end_state"], text2id),
            "action": parse_action_text(transition_text["action"], line_str)
        })

    transitions_cleaned = []
    for transition in transitions_id:
        if len(transition["start_state"]) == 0 and len(transition["condition"]) == 0 and len(
                transition["end_state"]) == 0 and len(transition["action"]) == 0:
            continue
        transitions_cleaned.append(transition)

    return transitions_cleaned



global_context_dict = call_get_context_copy()
call_init_context()


input_file = open(INPUT_FILENAME, 'r')
input_lines = input_file.readlines()
input_file.close()



out_file_2 = open(L2_OUT_FILENAME, 'w')



current_section = "0"
current_section_last_state = ""
section_lines = {current_section: []}
section_last_state = {current_section: current_section_last_state}

all_transitions = []
paragraph = ""
last_transition_condition = []

for line_idx, line in enumerate(input_lines):
    out_file_2.write("Line " + str(line_idx + 1) + " :\n")
    try:
        line = line.strip()
        if line == "":
            continue

        line = "<root> " + line + " </root>"
        line = line.replace("(e.g.", "that is")

        line = line.replace("<", " <").replace(">", "> ").strip()
        line = modify_section_numbers(line)
        print("Line", line_idx + 1, ":", line)

        section_info = call_update_header_context(line[6:-7].strip())
        header_context = call_get_header_context()

        rrc_condition = None
        if len(line) > 17 and "&gt;" in line:
            rrc_condition = [item["text"] for item in header_context if item["type"] == "rrc_point"
                             and ("<condition>" in item["text"] or "<start_state>" in item["text"])]

            if len(rrc_condition) > 0:
                rrc_condition = [clean_gt(item) for item in rrc_condition]
                rrc_condition = " ".join(rrc_condition)
            else:
                rrc_condition = None

        if not section_info or section_info["type"] != "section_header":
            if current_section not in section_lines:
                section_lines[current_section] = []
            section_lines[current_section].insert(0, line)
            states = find_start_state([line], text2id)
            if len(states) > 0:
                section_last_state[current_section] = states[-1]
        else:
            last_state = get_state_from_depending_lines(section_lines[current_section], text2id)
            section_last_state[current_section] = last_state

            current_section = section_info["header_val"]
            if current_section not in section_lines:
                section_lines[current_section] = []
            section_lines[current_section].insert(0, line)
            states = find_start_state([line], text2id)
            if len(states) > 0:
                section_last_state[current_section] = states[-1]

        line_tree = None
        try:
            line_tree = ET.fromstring(line)
            full_text = get_text(line_tree)
            paragraph = paragraph + "__LINE_BREAK__" + full_text
        except ParseError:
            print("\nLine", line_idx + 1, ": Parsing error\n")
            full_text = line
            if full_text != "" and isNum(full_text[0]):
                call_clear_context()
                paragraph = ""
            paragraph = paragraph + "__LINE_BREAK__" + full_text
            call_update_global_context_with_text(paragraph, text2id, common_defs_dict["ignore_list"])
            continue

        if full_text != "" and isNum(full_text[0]):
            call_clear_context()
            paragraph = ""

        line_transitions_text = []
        for child in line_tree:
            if child.tag.lower() == "control":
                child_transitions, last_transition_condition = parse_control(child, paragraph,
                                                                             last_control_condition=last_transition_condition,
                                                                             rrc_cond=rrc_condition)
                line_transitions_text.extend(child_transitions)
            else:
                continue

        line_transitions_id = parse_transitions_text(line_transitions_text, paragraph)
        call_update_global_context_with_text(paragraph, text2id, common_defs_dict["ignore_list"])

        IR_transitions = get_IR_transitions(line_transitions_id, text2id, common_defs_dict["ignore_list"],
                                            section_last_state, current_section)
        global_context_dict["last_transitions"] = IR_transitions

        all_transitions.extend(IR_transitions)
        for tran in IR_transitions:
            out_file_2.write(str(tran["condition_text"]) + "\n")
            out_file_2.write(str(tran["action_text"]) + "\n")
            out_file_2.write(str(tran["text_plain"]) + "\n")
            out_file_2.write(str(tran["condition_ir"]) + " / " + str(tran["action_ir"]) + "\n")
            out_file_2.write(str(tran["text_ir"]) + "\n")

        out_file_2.write("\n\n\n")
        out_file_2.flush()
        print()

    except RecursionError:
        print("\nLine", line_idx + 1, ": RecursionError\n")
    except TimeoutException:
        print("\nLine", line_idx + 1, ": TimeoutException\n")
    except AnnotationException:
        print("\nLine", line_idx + 1, ": AnnotationException\n")



call_close_db_from_text2id()
dep_out_file.close()
out_file_2.close()



print(datetime.datetime.now(), ": DUMPING TO IR...")
build_ir_xml(IR_OUT_FILENAME, all_transitions, True, True)
print(datetime.datetime.now(), ": DUMPED TO IR...")



print(datetime.datetime.now(), ": DUMPING TO SMV...")
ir2smv_main(IR_OUT_FILENAME, SMV_OUT_FILENAME)
print(datetime.datetime.now(), ": DUMPED TO SMV...")

