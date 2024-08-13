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

import copy
import datetime
from num2words import num2words

from script_z3_solver import check_equivalence, check_entail
from script_verb2ir import get_all_variables, add_state, get_all_states, get_all_msg_field_vars, get_all_sqn
from script_verb2ir import get_new_msg_enumerate_coin_toss, get_new_proc_enumerate_coin_toss
import script_config

USE_ENTAIL = False

transition_counter = 0


def reset_counter():
    global transition_counter
    transition_counter = 0


def remove_duplicate_actions(actions):
    action_labels = set()
    new_actions = []
    for action in actions:
        if action["label"] not in action_labels:
            new_actions.append(action)
            action_labels.add(action["label"])
    return new_actions


def remove_duplicate_actions_from_transitions(transitions_list):
    for idx, transition in enumerate(transitions_list):
        actions = remove_duplicate_actions(transition["action_ir"])
        transitions_list[idx]["action_ir"] = actions
    return transitions_list


def merge_ir_text(s_state, e_state, condition, actions, sqn_set=None):
    if sqn_set is None:
        sqn_set = set()
    if len(actions) == 0 and "_UNK_" in e_state:
        return ""
    if condition.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip() == "":
        return ""
    elif condition.replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip() == "()":
        return ""
    for item in sqn_set:
        if "{} = zero".format(item) in condition:
            condition = condition.replace("{} = zero".format(item), "{} = 0".format(item))

    actions = remove_duplicate_actions(actions)
    global transition_counter
    transition_counter = transition_counter + 1
    result_text = "\t\t\t\t<transition label=\"T{}\">\n".format(transition_counter)
    result_text = result_text + "\t\t\t\t\t<start> {} </start>\n".format(s_state.replace("any", ""))
    result_text = result_text + "\t\t\t\t\t<end> {} </end>\n".format(e_state.replace("_UNK_", ""))
    result_text = result_text + "\t\t\t\t\t<condition> {} </condition>\n".format(condition).replace("&", "&amp;")
    result_text = result_text + "\t\t\t\t\t<actions>\n"
    for action in actions:
        for item in sqn_set:
            if item in action["label"]:
                action["label"] = action["label"].replace("zero", "0")
        result_text = result_text + "\t\t\t\t\t\t<action label=\"{}\">\n".format(action["label"])
        result_text = result_text + "\t\t\t\t\t\t\t<channel label=\"{}\">\n".format(action["channel"])
        result_text = result_text + "\t\t\t\t\t\t\t\t<start>{}</start>\n".format(action["chan_start"])
        result_text = result_text + "\t\t\t\t\t\t\t\t<end>{}</end>\n".format(action["chan_end"])
        result_text = result_text + "\t\t\t\t\t\t\t</channel>\n"
        result_text = result_text + "\t\t\t\t\t\t</action>\n"
    result_text = result_text + "\t\t\t\t\t</actions>\n"
    result_text = result_text + "\t\t\t\t</transition>\n"

    return result_text


def split_transitions(transitions_list: list) -> (list, list):
    ue_transitions = []
    mme_transitions = []

    ue_states = []
    mme_states = []

    for transition in transitions_list:
        if "is_ue" in transition and transition["is_ue"]:
            ue_transitions.append(transition)
            ue_states.append(transition["s_state"])
            ue_states.append(transition["e_state"])
        elif "chan_MU =" in transition["text_ir"] or "<channel label=\"chan_UM\">" in transition["text_ir"]:
            add_state("ue", transition["s_state"])
            add_state("ue", transition["e_state"])
            ue_states.append(transition["s_state"])
            ue_states.append(transition["e_state"])
            ue_transitions.append(transition)
        elif "chan_UM =" in transition["text_ir"] or "<channel label=\"chan_MU\">" in transition["text_ir"]:
            add_state("mme", transition["s_state"])
            add_state("mme", transition["e_state"])
            mme_states.append(transition["s_state"])
            mme_states.append(transition["e_state"])
            mme_transitions.append(transition)
        elif "ue" in transition["agents"]:
            add_state("ue", transition["s_state"])
            add_state("ue", transition["e_state"])
            ue_states.append(transition["s_state"])
            ue_states.append(transition["e_state"])
            ue_transitions.append(transition)
        elif "mme" in transition["agents"]:
            add_state("mme", transition["s_state"])
            add_state("mme", transition["e_state"])
            mme_states.append(transition["s_state"])
            mme_states.append(transition["e_state"])
            mme_transitions.append(transition)
        else:
            add_state("ue", transition["s_state"])
            add_state("ue", transition["e_state"])
            ue_states.append(transition["s_state"])
            ue_states.append(transition["e_state"])
            ue_transitions.append(transition)

    return ue_transitions, mme_transitions, ue_states, mme_states


def merge_transitions(transitions: list, is_ue) -> list:
    skip_idx = set()
    extra_conditions = {}
    for idx1 in range(len(transitions)):
        if idx1 % 10 == 0:
            print(datetime.datetime.now(), ": Merging :", (idx1 + 1), "out of", len(transitions))
        if idx1 in skip_idx:
            continue
        for idx2 in range(idx1 + 1, len(transitions)):
            if idx1 == idx2 or idx1 in skip_idx or idx2 in skip_idx:
                continue
            s_state1 = transitions[idx1]["s_state"].strip()
            if "empty_coin_toss_" in transitions[idx1]["condition_ir"]:
                continue
            cond1 = transitions[idx1]["condition_ir"].replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()
            if (cond1 == "" or cond1 == "()") and s_state1 != "" and s_state1 != "any":
                cond1 = "ue_state = " + s_state1 if is_ue else "mme_state = " + s_state1
            elif s_state1 != "" and s_state1 != "any":
                cond1 = "ue_state = " + s_state1 + " & (" + cond1 + ")" if is_ue \
                    else "mme_state = " + s_state1 + " & (" + cond1 + ")"

            if cond1 == "" or cond1 == "()":
                skip_idx.add(idx1)
                continue
            s_state2 = transitions[idx2]["s_state"].strip()
            if "empty_coin_toss_" in transitions[idx2]["condition_ir"]:
                continue
            cond2 = transitions[idx2]["condition_ir"].replace("<PRIMARY>", "").replace("</PRIMARY>", "").strip()
            if (cond2 == "" or cond2 == "()") and s_state2 != "" and s_state2 != "any":
                cond2 = "ue_state = " + s_state2 if is_ue else "mme_state = " + s_state2
            elif s_state2 != "" and s_state2 != "any":
                cond2 = "ue_state = " + s_state2 + " & (" + cond2 + ")" if is_ue \
                    else "mme_state = " + s_state2 + " & (" + cond2 + ")"
            if cond2 == "" or cond2 == "()":
                skip_idx.add(idx2)
                continue
            if is_conditions_equal(cond1, cond2):
                transitions[idx1]["action_ir"].extend(transitions[idx2]["action_ir"])
                if "_UNK_" in transitions[idx1]["e_state"]:
                    transitions[idx1]["e_state"] = transitions[idx2]["e_state"]
                skip_idx.add(idx2)
            elif USE_ENTAIL and (cond1, cond2):
                transitions[idx2]["action_ir"].extend(transitions[idx1]["action_ir"])
                if idx1 in extra_conditions:
                    extra_conditions[idx1].append(cond2)
                else:
                    extra_conditions[idx1] = [cond2]

            elif USE_ENTAIL and check_entail(cond2, cond1):
                transitions[idx1]["action_ir"].extend(transitions[idx2]["action_ir"])
                if idx2 in extra_conditions:
                    extra_conditions[idx2].append(cond1)
                else:
                    extra_conditions[idx2] = [cond1]

    for idx in range(len(transitions)):
        if idx in extra_conditions and idx not in skip_idx:
            new_cond_str = "".join([" & !({})".format(item) for item in extra_conditions[idx]])
            transitions[idx]["condition_ir"] = "(" + transitions[idx]["condition_ir"] + ")" + new_cond_str

    result_transitions = [transitions[idx] for idx in range(len(transitions)) if idx not in skip_idx]
    result_transitions = remove_duplicate_actions_from_transitions(result_transitions)

    return result_transitions


def add_initiate_prob_transitions(transitions: list) -> list:
    result_transitions = []
    for idx, transition in enumerate(transitions):
        init_proc_labels = []
        init_proc_idx = []
        actions = transition["action_ir"]
        for act_idx, action in enumerate(actions):
            act_label = action["label"]
            if act_label.startswith("initiate_") and act_label.endswith(" TRUE"):
                proc_name = act_label.split()[0].replace("initiate_", "")
                init_proc_labels.append(proc_name)
                init_proc_idx.append(act_idx)
        if len(init_proc_labels) < 2:
            result_transitions.append(transition)
            continue
        else:
            backup_actions = [actions[i] for i in range(len(transition["action_ir"])) if i not in init_proc_idx]
            proc_actions = [actions[i] for i in range(len(transition["action_ir"])) if i in init_proc_idx]
            coin_toss_name = get_new_proc_enumerate_coin_toss(len(proc_actions))

            for i, action in enumerate(proc_actions):
                new_actions = copy.deepcopy(backup_actions)
                new_actions.append(action)
                new_transition = copy.deepcopy(transition)
                new_transition["action_ir"] = new_actions
                for proc_label in init_proc_labels:
                    if proc_label != init_proc_labels[i]:
                        new_transition["condition_ir"] = new_transition["condition_ir"] \
                            .replace("& " + proc_label + "_required", "")
                if "|" in new_transition["condition_ir"]:
                    new_transition["condition_ir"] = "(" + new_transition["condition_ir"] + ")"
                new_transition["condition_ir"] = new_transition["condition_ir"] + " & (" + coin_toss_name + " = {})" \
                    .format(num2words(i, to='cardinal'))
                result_transitions.append(new_transition)

    return result_transitions


def add_message_prob_transitions(transitions: list, accepted_channel="chan_UM") -> list:
    result_transitions = []
    for idx, transition in enumerate(transitions):
        message_labels = []
        message_idx = []
        skip_idx = set()
        actions = transition["action_ir"]
        for act_idx, action in enumerate(actions):
            chan_label = action["channel"]
            if accepted_channel == "chan_UM" and "mme_wait_for" in action["label"]:
                skip_idx.add(act_idx)
            if action["label"] in message_labels:
                skip_idx.add(act_idx)
            elif chan_label == "internal":
                continue
            elif chan_label == accepted_channel:
                message_labels.append(action["label"])
                message_idx.append(act_idx)
            else:
                skip_idx.add(act_idx)

        if len(message_labels) < 2:
            transition["action_ir"] = [actions[i] for i in range(len(actions)) if i not in skip_idx]
            result_transitions.append(transition)
            continue
        else:
            backup_actions = [actions[i] for i in range(len(actions)) if i not in skip_idx and i not in message_idx]
            msg_actions = [actions[i] for i in range(len(transition["action_ir"])) if i in message_idx]
            coin_toss_name = get_new_msg_enumerate_coin_toss(len(msg_actions))

            for i, action in enumerate(msg_actions):
                new_actions = copy.deepcopy(backup_actions)
                new_actions.append(action)
                new_transition = copy.deepcopy(transition)
                new_transition["action_ir"] = new_actions
                if "|" in new_transition["condition_ir"]:
                    new_transition["condition_ir"] = "(" + new_transition["condition_ir"] + ")"
                new_transition["condition_ir"] = new_transition["condition_ir"] + " & (" + coin_toss_name + " = {})" \
                    .format(num2words(i, to='cardinal'))
                result_transitions.append(new_transition)

    return result_transitions


def add_prob_transitions(transitions: list) -> list:
    transitions = add_initiate_prob_transitions(transitions)
    print("Length of transitions after initiate probability :", len(transitions))
    transitions = add_message_prob_transitions(transitions)
    print("Length of transitions after message probability :", len(transitions))
    return transitions


def is_conditions_equal(condition1: str, condition2: str) -> bool:
    condition1 = condition1.strip()
    condition2 = condition2.strip()

    if condition1 == condition2:
        return True

    return check_equivalence(condition1, condition2)


def negate_actions_to_conditions(transitions_list: list) -> list:
    for idx in range(len(transitions_list)):
        extra_condition = set()
        actions = transitions_list[idx]["action_ir"]
        for action in actions:
            label = action["label"]
            channel = action["channel"]
            if channel == "chan_UM":
                cond_str = "chan_UM = chanUM_" + label
            elif channel == "chan_MU":
                cond_str = "chan_MU = chanMU_" + label
            elif label.endswith(" = TRUE"):
                cond_str = label.split("=")[0].strip()
            elif label.endswith(" = FALSE"):
                cond_str = "!(" + label.split("=")[0].strip() + ")"
            else:
                cond_str = label
            extra_condition.add(cond_str)

        extra_condition_str = ""
        for cond_str in extra_condition:
            extra_condition_str = extra_condition_str + " & " + cond_str

        extra_condition_str = extra_condition_str.strip().strip("&").strip()
        if extra_condition_str != "":
            transitions_list[idx]["condition_ir"] = "(" + transitions_list[idx]["condition_ir"] + ") & !(" + \
                                                    extra_condition_str + ")"

    return transitions_list


def add_main_marker(transitions_list: list) -> list:
    for i in range(len(transitions_list)):
        if transitions_list[i]["condition_ir"].strip() == "" or transitions_list[i]["condition_ir"].strip() == "()":
            continue
        transitions_list[i]["condition_ir"] = "<PRIMARY>" + transitions_list[i]["condition_ir"] + "</PRIMARY>"
    return transitions_list


def rebuild_text_ir(transitions_list: list, sqn_set) -> list:
    for idx in range(len(transitions_list)):
        transitions_list[idx]["text_ir"] = \
            merge_ir_text(transitions_list[idx]["s_state"], transitions_list[idx]["e_state"],
                          transitions_list[idx]["condition_ir"], transitions_list[idx]["action_ir"], sqn_set)
    return transitions_list


def build_ir_xml(output_filename: str, transitions_list: list, add_probabilities = True, negate_transitions = True):
    reset_counter()
    transitions_list = add_main_marker(transitions_list)
    sqn_set = get_all_sqn()

    ue_transitions, mme_transitions, ue_states_2, mme_states_2 = split_transitions(transitions_list)
    print("Length of ue_transitions :", len(ue_transitions))
    print("Length of mme_transitions :", len(mme_transitions))

    print(datetime.datetime.now(), ": Merging UE transitions")
    ue_transitions = merge_transitions(ue_transitions, True)
    print("Length of ue_transitions :", len(ue_transitions))
    print(datetime.datetime.now(), ": Merged UE transitions")
    print(datetime.datetime.now(), ": Merging MME transitions")
    mme_transitions = merge_transitions(mme_transitions, False)
    print("Length of mme_transitions :", len(mme_transitions))
    print(datetime.datetime.now(), ": Merged MME transitions")

    if add_probabilities:
        print(datetime.datetime.now(), ": Adding probabilities to UE transitions")
        ue_transitions = add_prob_transitions(ue_transitions)
        print("Length of ue_transitions :", len(ue_transitions))
        print(datetime.datetime.now(), ": Added probabilities to UE transitions")
        print(datetime.datetime.now(), ": Adding probabilities to MME transitions")
        mme_transitions = add_prob_transitions(mme_transitions)
        print("Length of mme_transitions :", len(mme_transitions))
        print(datetime.datetime.now(), ": Added probabilities to MME transitions")

    if negate_transitions:
        print(datetime.datetime.now(), ": Negating actions to UE conditions")
        ue_transitions = negate_actions_to_conditions(ue_transitions)
        print("Length of ue_transitions :", len(ue_transitions))
        print(datetime.datetime.now(), ": Negated actions to UE transitions")
        print(datetime.datetime.now(), ": Negated actions to MME transitions")
        mme_transitions = negate_actions_to_conditions(mme_transitions)
        print("Length of mme_transitions :", len(mme_transitions))
        print(datetime.datetime.now(), ": Negating actions to MME transitions")

    print(datetime.datetime.now(), ": Rebuilding UE conditions")
    ue_transitions = rebuild_text_ir(ue_transitions, sqn_set)
    print("Length of ue_transitions :", len(ue_transitions))
    print(datetime.datetime.now(), ": Rebuilt UE transitions")
    print(datetime.datetime.now(), ": Rebuilding MME transitions")
    mme_transitions = rebuild_text_ir(mme_transitions, sqn_set)
    print("Length of mme_transitions :", len(mme_transitions))
    print(datetime.datetime.now(), ": Rebuilt MME transitions")

    ue_states, mme_states = get_all_states()

    if "any" in ue_states:
        ue_states.remove("any")
    if "_UNK_" in ue_states:
        ue_states.remove("_UNK_")
    if "any" in mme_states:
        mme_states.remove("any")
    if "_UNK_" in mme_states:
        mme_states.remove("_UNK_")

    outfile = open(output_filename, 'w')
    outfile.write("<system label=\"LTE\">\n\n")

    outfile.write("\t<VARS>\n")
    vars_dict = get_all_variables()

    for item in sqn_set:
        if item in vars_dict:
            del vars_dict[item]

    for var_name in vars_dict:
        var_properties = vars_dict[var_name]

        outfile.write("\t\t<VAR label=\"{}\">\n".format(var_name))

        outfile.write("\t\t\t<datatype>{}</datatype>\n".format(var_properties["datatype"]))
        outfile.write("\t\t\t<controltype>{}</controltype>\n".format(var_properties["controltype"]))

        if "possiblevalues" in var_properties:
            outfile.write("\t\t\t<possiblevalues>{}</possiblevalues>\n".format(var_properties["possiblevalues"]))
        if "initialvalue" in var_properties:
            outfile.write("\t\t\t<initialvalue>{}</initialvalue>\n".format(var_properties["initialvalue"]))
        if "fsm" in var_properties:
            outfile.write("\t\t\t<fsm>{}</fsm>\n".format(var_properties["fsm"]))
        if "mutualexlusion" in var_properties:
            outfile.write("\t\t\t<mutualexlusion>{}</mutualexlusion>\n".format(var_properties["mutualexlusion"]))

        outfile.write("\t\t</VAR>\n\n")

    outfile.write("\t</VARS>\n\n")

    outfile.write("\t<sequence_numbers>\n")
    for sqn_name in sqn_set:
        outfile.write("\t\t<seq_num>\n")
        outfile.write("\t\t\t<seq_name>{}</seq_name>\n".format(sqn_name))
        outfile.write("\t\t\t<start> 0 </start>\n")
        outfile.write("\t\t\t<end> 31 </end>\n")
        outfile.write("\t\t\t<possiblevalues>\n")
        outfile.write("\t\t\t\t{} + 1, 0\n".format(sqn_name))
        outfile.write("\t\t\t</possiblevalues>\n")
        outfile.write("\t\t</seq_num>\n")
    outfile.write("\t</sequence_numbers>\n\n")

    outfile.write("\t<MSG_FIELDs>\n")
    msg_fields_dict = get_all_msg_field_vars()

    for msg_key in msg_fields_dict:
        field_vars = list(msg_fields_dict[msg_key])
        field_vars_str = ",".join(field_vars)
        outfile.write("\t\t<MSG_FIELD_LIST>\n")
        outfile.write("\t\t\t<MSG>{}</MSG>\n".format(msg_key))
        outfile.write("\t\t\t<FIELD_VARS>{}</FIELD_VARS>\n".format(field_vars_str))
        outfile.write("\t\t</MSG_FIELD_LIST>\n")
    outfile.write("\t</MSG_FIELDs>\n")

    outfile.write("\t<FSMs>\n")

    outfile.write("\t\t<FSM label=\"UE\">\n")

    outfile.write("\t\t\t<states>\n")
    for state in ue_states:
        outfile.write("\t\t\t\t<state>{}</state>\n".format(state))
    outfile.write("\t\t\t</states>\n\n")
    if script_config.GEN == "4g":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("emm_deregistered"))
    elif script_config.GEN == "5g":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("five_gmm_deregistered"))
    elif script_config.GEN == "5g-rrc":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("rrc_idle"))


    outfile.write("\t\t\t<transitions>\n")
    for transition in ue_transitions:
        outfile.write(transition["text_ir"] + "\n\n")
    outfile.write("\t\t\t</transitions>\n\n")

    outfile.write("\t\t</FSM>\n\n")

    outfile.write("\t\t<FSM label=\"MME\">\n")

    outfile.write("\t\t\t<states>\n")
    for state in mme_states:
        outfile.write("\t\t\t\t<state>{}</state>\n".format(state))
    outfile.write("\t\t\t</states>\n\n")
    if script_config.GEN == "4g":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("emm_deregistered"))
    elif script_config.GEN == "5g":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("five_gmm_deregistered"))
    elif script_config.GEN == "5g-rrc":
        outfile.write("\t\t\t<init_state>{}</init_state>\n\n".format("rrc_idle"))

    outfile.write("\t\t\t<transitions>\n")
    for transition in mme_transitions:
        outfile.write(transition["text_ir"] + "\n\n")
    outfile.write("\t\t\t</transitions>\n\n")

    outfile.write("\t\t</FSM>\n\n")

    outfile.write("\t</FSMs>\n\n")

    manual_in_file = open("script_ir_end_dump.txt", 'r')
    manual_in_lines = manual_in_file.readlines()
    manual_in_file.close()
    outfile.writelines(manual_in_lines)

    outfile.write("</system>\n\n")
