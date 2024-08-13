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

from script_DepGraph import *
from script_verb2ir import *
from script_build_ir_xml import merge_ir_text

EMPTY_COIN_TOSS = True


def call_init_context():
    from script_context import init_context
    init_context()


def call_clear_context():
    from script_context import clear_context
    clear_context()


def call_get_context_copy():
    from script_context import get_context_copy
    return get_context_copy()


def call_update_global_context_with_text(text: str, text2id_dict, ignore_list=None):
    from script_context import update_global_context_with_text

    text_parts = text.replace("</", "<").replace(">", "<").split("<")
    for text_part in text_parts:
        update_global_context_with_text(text_part, text2id_dict, ignore_list)

def call_update_context_key_value(key: str, value) -> None:
    from script_context import update_context_key_value
    update_context_key_value(key, value)


def call_get_last_context(key: str, cond_ctx: dict, act_ctx: dict, global_ctx: dict, order="021",
                          message_dir="") -> list:
    from script_context import get_last_context
    return get_last_context(key, cond_ctx, act_ctx, global_ctx, order, message_dir)


def call_update_header_context(text: str):
    from script_context import update_header_context
    return update_header_context(text)


def call_get_header_context_texts():
    from script_context import get_header_context_texts
    return get_header_context_texts()

def call_get_header_context():
    from script_context import get_header_context
    return get_header_context()

def get_info_from_tree(in_tree, dep_graph: DepGraph) -> (str, List[str], str, str):
    tree_label = in_tree
    if isinstance(in_tree, ParentedTree):
        tree_label = in_tree.label()

    tok_num = None
    tok_types = []
    tok_pos = None
    tok_label = tree_label.split("->")[-1]
    if "->" in tree_label:
        tok_num = int(tree_label.split("->")[-2])

    if tok_num is not None:
        tok_types = dep_graph.get_types_at(tok_num)
        tok_pos = dep_graph.get_pos_at(tok_num)

    return tok_num, tok_types, tok_pos, tok_label


def get_agents(agent_node, dep_graph: DepGraph):
    agent_set = set()
    if not isinstance(agent_node, ParentedTree):
        tok_num, tok_types, tok_pos, tok_label = get_info_from_tree(agent_node, dep_graph)
        if "agent" in tok_types:
            agent_set.add(tok_label)
    else:
        for child in agent_node:
            child_agents = get_agents(child, dep_graph)
            agent_set.update(child_agents)

    return agent_set


def recur_xml_tree(in_tree: ET, dep_graph: DepGraph):
    agent_set = set()

    head_text = in_tree.text.strip()

    if len(in_tree) == 0:
        return head_text, agent_set

    child_idx_list = []
    children = []
    for idx, child in enumerate(in_tree):
        child_tree, child_agent = recur_xml_tree(child, dep_graph)
        children.append(child_tree)
        agent_set.update(child_agent)
        if not isinstance(child_tree, ParentedTree) and \
                (child_tree.strip() == "" or child_tree.strip() == "_AND_" or child_tree.strip() == "_OR_"):
            continue
        elif (isinstance(child_tree, ParentedTree) and child_tree.label().startswith("_AGENT_")) or \
                (not isinstance(child_tree, ParentedTree) and child_tree.startswith("_AGENT_")):
            agent_set.update(get_agents(child_tree, dep_graph))
        else:
            child_idx_list.append(idx)

    result_tree = ParentedTree(head_text, [children[idx] for idx in child_idx_list])

    return result_tree, agent_set


def run_dfs_plain(in_tree) -> str:
    if isinstance(in_tree, str):
        return in_tree

    tree_label = in_tree.label()
    result_text = tree_label + "("
    for child in in_tree:
        result_text = result_text + run_dfs_plain(child) + ", "

    result_text = result_text.strip().strip(",") + ")"

    return result_text


def get_args_of_type(in_tree, req_types: list, dep_graph: DepGraph, ignore_subtree_labels=None) -> List:
    if isinstance(in_tree, str):
        return []
    if ignore_subtree_labels is None:
        ignore_subtree_labels = []

    result = []
    for child in in_tree:
        child_num, child_types, child_pos, child_label = get_info_from_tree(child, dep_graph)
        if child_label in ignore_subtree_labels:
            continue
        for child_type in child_types:
            if child_type in req_types:
                result.append(child)
                break

        result.extend(get_args_of_type(child, req_types, dep_graph))

    return result


def get_args_of_label(in_tree, req_labels: list, dep_graph: DepGraph, ignore_subtree_labels=None) -> List:
    if isinstance(in_tree, str):
        return []
    if ignore_subtree_labels is None:
        ignore_subtree_labels = []

    result = []
    for child in in_tree:
        child_num, child_types, child_pos, child_label = get_info_from_tree(child, dep_graph)
        if child_label in ignore_subtree_labels:
            continue
        if child_label in req_labels:
            result.append(child)
        else:
            result.extend(get_args_of_label(child, req_labels, dep_graph))

    return result


def get_args_of_label_substring(in_tree, req_label: str, dep_graph: DepGraph, ignore_subtree_labels=None) -> List:
    if isinstance(in_tree, str):
        return []
    if ignore_subtree_labels is None:
        ignore_subtree_labels = []

    result = []
    for child in in_tree:
        child_num, child_types, child_pos, child_label = get_info_from_tree(child, dep_graph)
        if child_label in ignore_subtree_labels:
            continue
        if req_label in child_label:
            result.append(child)
        else:
            result.extend(get_args_of_label_substring(child, req_label, dep_graph))

    return result


def is_successor(in_tree, target_node):
    if in_tree == target_node:
        return True
    if isinstance(in_tree, str):
        return False

    for child in in_tree:
        if child == target_node:
            return True
        else:
            if is_successor(child, target_node):
                return True
    return False


def check_or(or_nodes: list, target_node):
    if len(or_nodes) == 0:
        return False
    for or_node in or_nodes:
        if is_successor(or_node, target_node):
            return True
    return False


def check_not(not_nodes: list, target_node):
    if len(not_nodes) == 0:
        return False
    for not_node in not_nodes:
        if is_successor(not_node, target_node):
            return True
    return False


def is_successor_val(in_tree, target_val, dep_graph: DepGraph):
    tok_num, tok_types, tok_pos, tok_label = get_info_from_tree(in_tree, dep_graph)
    if tok_label == target_val:
        return True
    if isinstance(in_tree, str):
        return False

    for child in in_tree:
        child_num, child_types, child_pos, child_label = get_info_from_tree(child, dep_graph)
        if child_label == target_val:
            return True
        else:
            if is_successor_val(child, target_val, dep_graph):
                return True
    return False


def check_or_val(or_nodes: list, target_val, dep_graph: DepGraph):
    if len(or_nodes) == 0:
        return False
    for or_node in or_nodes:
        if is_successor_val(or_node, target_val, dep_graph):
            return True
    return False


def check_not_val(not_nodes: list, target_val, dep_graph: DepGraph):
    if len(not_nodes) == 0:
        return False
    for not_node in not_nodes:
        if is_successor_val(not_node, target_val, dep_graph):
            return True
    return False


NOT_TYPES = {"_NOT_", "_UNTIL_", "_UNLESS_", "_WITHOUT_", "_EXCEPT_", "_BEFORE_", "_INSTEAD_OF_", "other"}


def connect_condition(or_nodes, not_nodes, arg, prev_condition, new_condition, check_tree=True, dep_graph=None):
    if check_tree and check_not(not_nodes, arg) or \
            not check_tree and dep_graph is not None and check_not_val(not_nodes, arg, dep_graph):
        new_condition = "!(" + new_condition + ")"

    if check_tree and check_or(or_nodes, arg) or \
            not check_tree and dep_graph is not None and check_or_val(or_nodes, arg, dep_graph):
        result = "(" + prev_condition + " | " + new_condition + ")"
    else:
        result = prev_condition + " & " + new_condition

    return result


def run_dfs_IR_condition(in_tree, dep_graph: DepGraph, cond_ctx, act_ctx, global_context_dict, agents,
                         strict=False, not_logic=False) -> str:
    if len(agents) == 0:
        if "agent" in cond_ctx:
            agents = set(cond_ctx["agent"])
        elif "agent" in act_ctx:
            agents = set(act_ctx["agent"])
        elif "agent" in act_ctx:
            agents = global_context_dict["agents"]

    result_condition = ""

    tok_num, tok_types, tok_pos, tok_label = get_info_from_tree(in_tree, dep_graph)

    if tok_label.strip() == "" and len(in_tree) > 0:
        return run_dfs_IR_condition(in_tree[0], dep_graph, cond_ctx, act_ctx, global_context_dict, agents, strict,
                                    not_logic)

    message_dir = "mme_to_ue"
    if "ue" not in agents and "mme" in agents:
        message_dir = "ue_to_mme"

    or_nodes = get_args_of_label(in_tree, ["_OR_"], dep_graph)
    not_nodes = get_args_of_label(in_tree, list(NOT_TYPES), dep_graph)

    integrity_check_args = get_args_of_label(in_tree, ["integrity_check"], dep_graph)
    integrity_protection_args = get_args_of_label(in_tree, ["integrity_protection"], dep_graph)

    if (len(integrity_check_args) > 0 or len(integrity_protection_args) > 0) and tok_label == "_WITHOUT_":
        msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
        msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
        if len(msg_labels) == 0:
            msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021", message_dir)

        for arg_label in msg_labels:
            if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                msg_condition = condition_receive_message(arg_label, agents)
                msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                result_condition = connect_condition(or_nodes, [], arg_label, result_condition, msg_condition,
                                                     False, dep_graph)
            else:
                msg_condition = condition_receive_message(arg_label, agents)
                msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                result_condition = connect_condition(or_nodes, [], arg_label, result_condition, msg_condition,
                                                     False, dep_graph)

    elif (len(integrity_check_args) > 0 or len(integrity_protection_args) > 0) and tok_label == "_WITH_":
        msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
        msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
        if len(msg_labels) == 0:
            msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021", message_dir)

        for arg_label in msg_labels:
            if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                msg_condition = condition_receive_message(arg_label, agents)
                msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                result_condition = connect_condition(or_nodes, [], arg_label, result_condition, msg_condition,
                                                     False, dep_graph)
            else:
                msg_condition = condition_receive_message(arg_label, agents)
                msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                result_condition = connect_condition(or_nodes, [], arg_label, result_condition, msg_condition,
                                                     False, dep_graph)

    elif tok_label in NOT_TYPES:
        msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
        msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
        for arg_label in msg_labels:
            msg_condition = "!" + condition_receive_message(arg_label, agents)
            result_condition = connect_condition(or_nodes, [], arg_label, result_condition, msg_condition,
                                                 False, dep_graph)

        if isinstance(in_tree, ParentedTree):
            for child in in_tree:
                child_condition = run_dfs_IR_condition(child, dep_graph, cond_ctx, act_ctx, global_context_dict,
                                                       agents, strict, not_logic=True).strip()
                if child_condition != "":
                    if "|" in result_condition:
                        result_condition = "(" + result_condition + ")"
                    result_condition = result_condition + " & " + child_condition

        result_condition = result_condition.strip().strip("&").strip("|").strip()

        result_condition = result_condition.replace("!()", "")



    elif tok_label == "_AND_":
        if isinstance(in_tree, ParentedTree):
            for child in in_tree:
                child_condition = run_dfs_IR_condition(child, dep_graph, cond_ctx, act_ctx, global_context_dict,
                                                       agents, strict, not_logic).strip()
                if child_condition != "":
                    if "|" in result_condition:
                        result_condition = "(" + result_condition + ")"
                    result_condition = result_condition + " & " + child_condition

        result_condition = result_condition.strip().strip("&").strip("|").strip()
        if not_logic:
            result_condition = "!(" + result_condition + ")"

    elif tok_label == "_OR_":
        if isinstance(in_tree, ParentedTree):
            for child in in_tree:
                child_condition = run_dfs_IR_condition(child, dep_graph, cond_ctx, act_ctx, global_context_dict,
                                                       agents, strict, not_logic).strip()
                if child_condition != "":
                    result_condition = result_condition + " | " + child_condition
        result_condition = "(" + result_condition.strip().strip("&").strip("|").strip() + ")"
        if not_logic:
            result_condition = "!(" + result_condition + ")"

    elif "verb" in tok_types:
        if tok_label == "initiate":
            if strict and tok_pos == "NN":
                return result_condition
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if tok_pos == "VBN":
                    arg_condition = condition_running_procedure(arg_label)
                else:
                    arg_condition = condition_initiate_procedure(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        if tok_label == "success":
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_completed_procedure(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        if tok_label == "complete":
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)

            for arg in procedure_args:
                if not_logic or check_not(not_nodes, arg):
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_running_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                         True, dep_graph)
                else:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_completed_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                         True, dep_graph)

        if tok_label == "fail":
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                if not_logic or check_not(not_nodes, arg):
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_completed_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                         True, dep_graph)
                else:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_fail_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                         True,
                                                         dep_graph)

            integrity_check_args = get_args_of_label(in_tree, ["integrity_check", "integrity_protection"], dep_graph)
            if len(integrity_check_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                       message_dir)
                for arg_label in msg_labels:
                    if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                        msg_condition = condition_receive_message(arg_label, agents)
                        msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             msg_condition,
                                                             False, dep_graph)
                    else:
                        msg_condition = condition_receive_message(arg_label, agents)
                        msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             msg_condition, False, dep_graph)

            event_args = get_args_of_type(in_tree, ["event"], dep_graph)
            for arg in event_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if arg_label == "integrity_check":
                    continue
                arg_condition = condition_not_indicate_event(arg_label)
                result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                     True, dep_graph)


        if tok_label == "pass":
            integrity_check_args = get_args_of_label(in_tree, ["integrity_check", "integrity_protection"], dep_graph)
            if len(integrity_check_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                       message_dir)
                    for arg_label in msg_labels:
                        if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition,False, dep_graph)
                        else:
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition,False, dep_graph)

        if tok_label == "perform":
            if tok_pos == "VBN":
                procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
                for arg in procedure_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_completed_procedure(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            elif tok_pos == "VBG":
                procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
                for arg in procedure_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_running_procedure(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "check":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "change":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            var_args.extend(field_args)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            var_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in var_args]

            if len(msg_args) > 0:
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

                for var in var_labels:
                    for msg in msg_labels:
                        var_condition = condition_changed_var_in_msg(var, msg)
                        if not_logic:
                            var_condition = "!(" + var_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, var, result_condition, var_condition,
                                                             False, dep_graph)

            else:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_changed_var(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "expire":
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            timer_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in timer_args]
            if len(timer_labels) == 0:
                timer_labels = call_get_last_context("timer", cond_ctx, act_ctx, global_context_dict, "012")
            for arg_label in timer_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    arg_condition = condition_running_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         arg_condition, False, dep_graph)
                else:
                    arg_condition = condition_expired_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition, arg_condition,
                                                         False, dep_graph)

        elif tok_label == "indicate":
            field_val_args = get_args_of_type(in_tree, ["field_val"], dep_graph)
            msg_field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)

            if len(field_val_args) > 0:
                field_val_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_val_args]
                msg_field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_field_args]

                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for val in field_val_labels:
                    for field in msg_field_labels:
                        for msg in msg_labels:
                            val_condition = condition_field_in_msg_val(field, msg, val)
                            field_condition = condition_receive_field_in_msg(field, msg)
                            arg_condition = val_condition + " & " + field_condition
                            if not_logic:
                                arg_condition = "!(" + arg_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, val, result_condition,
                                                                 arg_condition, False, dep_graph)

            elif len(msg_field_args) > 0:
                msg_field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_field_args]

                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for field in msg_field_labels:
                    for msg in msg_labels:
                        field_condition = condition_receive_field_in_msg(field, msg)
                        if not_logic:
                            field_condition = "!(" + field_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, field, result_condition,
                                                             field_condition, False, dep_graph)

            else:
                event_args = get_args_of_type(in_tree, ["event"], dep_graph)
                for arg in event_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_indicate_event(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "save":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "know":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "reset":
            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(counter_args)

            if len(to_args) > 0:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_var_equals(arg_label, get_info_from_tree(to_args[0], dep_graph)[3])
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)
            else:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_reset_var(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "set":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(get_args_of_type(in_tree, ["counter"], dep_graph))
            var_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in var_args]

            last_counter_args = get_args_of_label(in_tree, ["last_counter"], dep_graph)
            if len(last_counter_args) > 0:
                var_labels.append(global_context_dict["last_counter"])

            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            val_args = []
            for to_arg in to_args:
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["var"], dep_graph))
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["mode"], dep_graph))
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["num"], dep_graph))
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in
                    get_args_of_type(to_arg, ["field_val"], dep_graph))

            for arg_label in var_labels:
                for to_val in val_args:
                    val_num, val_types, val_pos, val_label = get_info_from_tree(to_val, dep_graph)
                    if val_label == arg_label:
                        continue
                    arg_condition = condition_set_var_to_val(arg_label, val_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg_label, result_condition,
                                                         arg_condition, False, dep_graph)

            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

            if len(get_args_of_label(in_tree, ["last_msg_field"], dep_graph)) > 0:
                field_labels.append(global_context_dict["last_msg_field"])

            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            if len(to_args) > 0:
                val_args = get_args_of_type(to_args[0], ["field_val"], dep_graph)
            else:
                val_args = get_args_of_type(in_tree, ["field_val"], dep_graph)

            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)
            if len(msg_labels) != 0:
                for field in field_labels:
                    for val in val_args:
                        val_num, val_types, val_pos, val_label = get_info_from_tree(val, dep_graph)
                        if field == val_label:
                            continue
                        arg_condition = condition_receive_var_in_msg_val(field, msg_labels[0], val_label) + " & " + \
                                        condition_receive_field_in_msg(field, msg_labels[0])
                        if not_logic:
                            arg_condition = "!(" + arg_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, field, result_condition,
                                                             arg_condition, False, dep_graph)

        elif tok_label == "stop":
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            for arg in timer_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_stopped_timer(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                if not_logic or check_not(not_nodes, arg):
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_running_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                         True, dep_graph)
                else:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_stopped_procedure(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)

        elif tok_label == "accept":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            for arg in msg_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic or check_not(not_nodes, arg):
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_reject_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)
                else:
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_accept_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_completed_procedure(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "process":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            for arg in msg_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic or check_not(not_nodes, arg):
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_reject_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)
                else:
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_accept_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)

        elif tok_label == "reject":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            for arg in msg_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic or check_not(not_nodes, arg):
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_accept_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)
                else:
                    arg_condition = condition_receive_message(arg_label, agents) + " & " + condition_reject_message(
                        arg_label)
                    result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition, True,
                                                         dep_graph)

        elif tok_label == "receive" or tok_label == "send" or tok_label == "respond":
            event_args = get_args_of_type(in_tree, ["event"], dep_graph)
            indicate_args = get_args_of_label(in_tree, ["indicate"], dep_graph)
            establish_args = get_args_of_label(in_tree, ["establish"], dep_graph)
            service_args = []
            for est_arg in establish_args:
                service_args.extend(get_args_of_type(est_arg, ["service"], dep_graph))

            if len(event_args) > 0 and tok_label == "receive":
                for arg in event_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_indicate_event(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            elif len(indicate_args) > 0 and len(establish_args) > 0 and len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_activated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            else:
                if tok_label == "send" and agents is not None:
                    agents = {"ue", "mme"}.difference(agents)

                indicate_args = get_args_of_label(in_tree, ["indicate"], dep_graph)
                if len(indicate_args) > 0:
                    return run_dfs_IR_condition(indicate_args[0], dep_graph, cond_ctx, act_ctx, global_context_dict,
                                                agents, strict, not_logic)

                to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
                with_args = get_args_of_label(in_tree, ["_WITH_"], dep_graph)
                without_args = get_args_of_label(in_tree, ["_WITHOUT_"], dep_graph)
                integrity_protected_args = get_args_of_label(in_tree, ["integrity_protected"], dep_graph)
                valid_args = get_args_of_label(in_tree, ["valid"], dep_graph)
                invalid_args = get_args_of_label(in_tree, ["invalid", "out_of_range"], dep_graph)

                if tok_label == "send" and len(to_args) > 0:
                    for to_arg in to_args:
                        if len(get_args_of_label(to_arg, ["ue"], dep_graph)) > 0:
                            agents = {"ue"}
                            break
                        elif len(get_args_of_label(to_arg, ["mme"], dep_graph)) > 0:
                            agents = {"mme"}
                            break

                if tok_label == "respond" and len(with_args) > 0:
                    if "mme" in agents:
                        agents = {"ue"}
                    elif "ue" in agents:
                        agents = {"mme"}
                    else:
                        agents = {"ue"}

                message_dir = "mme_to_ue"
                if "ue" not in agents and "mme" in agents:
                    message_dir = "ue_to_mme"

                make_integrity_protection_false = False
                make_integrity_protection_true = False

                if len(integrity_protected_args) > 0:
                    for integrity_args in integrity_protected_args:
                        if check_not(not_nodes, integrity_args):
                            make_integrity_protection_false = True
                            break
                    if not make_integrity_protection_false:
                        make_integrity_protection_true = True

                for with_arg in with_args:
                    integrity_protection_args = get_args_of_label(with_arg, ["integrity_protection"], dep_graph)
                    if len(integrity_protection_args) > 0:
                        make_integrity_protection_true = True
                        break
                for with_arg in without_args:
                    integrity_protection_args = get_args_of_label(with_arg, ["integrity_protection"], dep_graph)
                    if len(integrity_protection_args) > 0:
                        make_integrity_protection_false = True

                var_args = get_args_of_type(in_tree, ["var"], dep_graph)
                field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
                cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)
                var_args.extend(field_args)
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                var_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in var_args]

                if make_integrity_protection_false:
                    for arg_label in msg_labels:
                        if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition, False, dep_graph)
                        else:
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition, False, dep_graph)

                if make_integrity_protection_true:
                    for arg_label in msg_labels:
                        if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition, False, dep_graph)
                        else:
                            msg_condition = condition_receive_message(arg_label, agents)
                            msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                            result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                                 msg_condition, False, dep_graph)

                if len(cause_args) > 0:
                    for arg in cause_args:
                        for msg in msg_labels:
                            arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                            arg_condition = condition_message_cause(arg_label, msg)
                            msg_condition = condition_receive_message(msg, agents)
                            arg_condition = arg_condition + " & " + msg_condition
                            if not_logic:
                                arg_condition = "!(" + arg_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition,
                                                                 arg_condition, True, dep_graph)

                            if "emm_cause" in var_labels:
                                field_condition = condition_receive_field_in_msg("emm_cause", msg)
                                if not_logic:
                                    field_condition = "!(" + field_condition + ")"
                                result_condition = connect_condition(or_nodes, not_nodes, "emm_cause", result_condition,
                                                                     field_condition, True, dep_graph)
                            elif "five_gmm_cause" in var_labels:
                                field_condition = condition_receive_field_in_msg("five_gmm_cause", msg)
                                if not_logic:
                                    field_condition = "!(" + field_condition + ")"
                                result_condition = connect_condition(or_nodes, not_nodes, "five_gmm_cause",
                                                                     result_condition,
                                                                     field_condition, True, dep_graph)
                            elif "esm_cause" in var_labels:
                                field_condition = condition_receive_field_in_msg("esm_cause", msg)
                                if not_logic:
                                    field_condition = "!(" + field_condition + ")"
                                result_condition = connect_condition(or_nodes, not_nodes, "esm_cause", result_condition,
                                                                     field_condition, True, dep_graph)

                if len(var_labels) > 0:
                    for var in var_labels:
                        for msg in msg_labels:
                            var_condition = condition_receive_var_in_msg(var, msg)
                            msg_condition = condition_receive_message(msg, agents)
                            arg_condition = var_condition + " & " + msg_condition
                            if len(valid_args) > 0:
                                arg_condition = arg_condition + " & " + condition_valid_var(var)
                            elif len(invalid_args) > 0:
                                arg_condition = arg_condition + " & " + condition_invalid_var(var)

                            if not_logic:
                                arg_condition = "!(" + arg_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, var, result_condition,
                                                                 arg_condition, False, dep_graph)

                for arg_label in msg_labels:
                    msg_condition = condition_receive_message(arg_label, agents)
                    if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                        msg_condition = msg_condition.replace("=", "!=")
                    if msg_condition not in result_condition and "chan_" in result_condition:
                        result_condition = result_condition + " | " + msg_condition
                    else:
                        result_condition = result_condition + " & " + msg_condition

                result_condition = result_condition.strip().strip("|").strip("&").strip()

        elif tok_label == "cipher":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                arg_condition = condition_ciphered_message(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg_label, result_condition, arg_condition,
                                                     False, dep_graph)

        elif tok_label == "protect":
            integrity_args = get_args_of_label(in_tree, ["integrity"], dep_graph)
            if len(integrity_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for arg_label in msg_labels:
                    if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                        msg_condition = condition_receive_message(arg_label, agents)
                        msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             msg_condition, False, dep_graph)
                    else:
                        msg_condition = condition_receive_message(arg_label, agents)
                        msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             msg_condition, False, dep_graph)

        elif tok_label == "include":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            field_args.extend(var_args)
            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

            set_args = get_args_of_label(in_tree, ["set"], dep_graph)
            if len(set_args) > 0:
                for set_arg in set_args:
                    field_args = get_args_of_type(set_arg, ["msg_field"], dep_graph)
                    field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

                    to_args = get_args_of_label(set_arg, ["_TO_"], dep_graph)
                    if len(to_args) > 0:
                        val_args = get_args_of_type(to_args[0], ["field_val"], dep_graph)
                    else:
                        val_args = get_args_of_type(set_arg[0], ["field_val"], dep_graph)

                    msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                    if len(msg_labels) == 0:
                        msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                           message_dir)

                    if len(msg_labels) > 0:
                        for field in field_labels:
                            for val in val_args:
                                val_num, val_types, val_pos, val_label = get_info_from_tree(val, dep_graph)
                                val_condition = condition_field_in_msg_val(field, msg_labels[-1], val_label)
                                if not_logic:
                                    val_condition = "!(" + val_condition + ")"
                                result_condition = connect_condition(or_nodes, not_nodes, val, result_condition,
                                                                     val_condition, True, dep_graph)

            cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)
            if len(cause_args) > 0:
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for arg in cause_args:
                    for msg in msg_labels:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                        arg_condition = condition_message_cause(arg_label, msg)
                        msg_condition = condition_receive_message(msg, agents)
                        arg_condition = arg_condition + " & " + msg_condition
                        if not_logic:
                            arg_condition = "!(" + arg_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                             True, dep_graph)

                        if "emm_cause" in field_labels or len(get_args_of_label(in_tree, ["emm"], dep_graph)) > 0:
                            field_condition = condition_receive_field_in_msg("emm_cause", msg)
                            if not_logic:
                                field_condition = "!(" + field_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, "emm_cause", result_condition,
                                                                 field_condition, True, dep_graph)
                        elif "five_gmm_cause" in field_labels or len(get_args_of_label(in_tree, ["emm"], dep_graph)) > 0:
                            field_condition = condition_receive_field_in_msg("five_gmm_cause", msg)
                            if not_logic:
                                field_condition = "!(" + field_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, "five_gmm_cause", result_condition,
                                                                 field_condition, True, dep_graph)
                        elif "esm_cause" in field_labels or len(get_args_of_label(in_tree, ["esm"], dep_graph)) > 0:
                            field_condition = condition_receive_field_in_msg("esm_cause", msg)
                            if not_logic:
                                field_condition = "!(" + field_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, "esm_cause", result_condition,
                                                                 field_condition, True, dep_graph)

            elif len(field_labels) > 0:
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for field in field_labels:
                    for msg in msg_labels:
                        field_condition = condition_receive_var_in_msg(field, msg)
                        msg_condition = condition_receive_message(msg, agents)
                        field_condition = field_condition + " & " + msg_condition
                        if not_logic:
                            field_condition = "!(" + field_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, field, result_condition,
                                                             field_condition, False, dep_graph)

        elif tok_label == "support":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            service_args.extend(mode_args)
            service_args.extend(timer_args)
            service_args.extend(msg_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_support_service(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "configure":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            misc_args = get_args_of_type(in_tree, ["misc"], dep_graph)
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            service_args.extend(misc_args)
            service_args.extend(mode_args)
            service_args.extend(timer_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_configure_service(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "activate":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_activated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)


        elif tok_label == "find":
            valid_args = get_args_of_label(in_tree, ["valid"], dep_graph)
            invalid_args = get_args_of_label(in_tree, ["invalid", "out_of_range"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if len(valid_args) > 0:
                    arg_condition = condition_valid_var(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True,
                                                         dep_graph)
                elif len(invalid_args) > 0:
                    arg_condition = condition_invalid_var(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "use":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_activated_service(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                     True, dep_graph)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for msg_label in msg_labels:
                for arg in field_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_receive_var_in_msg(arg_label, msg_label)
                    msg_condition = condition_receive_message(msg_label, agents)
                    arg_condition = arg_condition + " & " + msg_condition
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "request":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_requested_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "enable":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_activated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "establish":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)

            if tok_pos == "VBG":
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    proc_name = arg_label + "_establishment"
                    arg_condition = condition_running_procedure(proc_name)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            else:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_activated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "deactivate":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_deactivated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "release":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_deactivated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "disable":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_deactivated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "camp":
            cell_args = get_args_of_label_substring(in_tree, "cell", dep_graph)
            for arg in cell_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_camp_cell(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                     True, dep_graph)

        elif tok_label == "exist":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_activated_service(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "provide":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            field_args.extend(var_args)

            set_args = get_args_of_label(in_tree, ["set"], dep_graph)
            if len(set_args) > 0:
                for set_arg in set_args:
                    field_args = get_args_of_type(set_arg, ["msg_field"], dep_graph)
                    field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

                    to_args = get_args_of_label(set_arg, ["_TO_"], dep_graph)
                    if len(to_args) > 0:
                        val_args = get_args_of_type(to_args[0], ["field_val"], dep_graph)
                    else:
                        val_args = get_args_of_type(set_arg[0], ["field_val"], dep_graph)

                    msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                    if len(msg_labels) == 0:
                        msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                           message_dir)

                    if len(msg_labels) > 0:
                        for field in field_labels:
                            for val in val_args:
                                for msg in msg_labels:
                                    val_num, val_types, val_pos, val_label = get_info_from_tree(val, dep_graph)
                                    val_condition = condition_field_in_msg_val(field, msg, val_label)
                                    receive_condition = condition_receive_message(msg, agents)
                                    val_condition = val_condition + " & " + receive_condition
                                    if not_logic:
                                        val_condition = "!(" + val_condition + ")"
                                    result_condition = connect_condition(or_nodes, not_nodes, val, result_condition,
                                                                         val_condition, True, dep_graph)

            if len(field_args) > 0:
                field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for field in field_labels:
                    for msg in msg_labels:
                        var_condition = condition_receive_var_in_msg(field, msg)
                        msg_condition = condition_receive_message(msg, agents)
                        var_condition = var_condition + " & " + msg_condition
                        if not_logic:
                            var_condition = "!(" + var_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, field, result_condition,
                                                             var_condition, False, dep_graph)

            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            service_args.extend(mode_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_activated_service(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "leave":
            state_args = get_args_of_type(in_tree, ["state"], dep_graph)
            for arg in state_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_leave_state(arg_label, agents)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "maintain":
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            for arg in counter_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_maintain_counter(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

    elif not strict and "service" in tok_types:
        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(in_tree, dep_graph)
        arg_condition = condition_activated_service(arg_label)
        if not_logic:
            arg_condition = "!(" + arg_condition + ")"
        result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                             dep_graph)

    elif "procedure" in tok_types:
        running_args = get_args_of_label(in_tree, ["running"], dep_graph)
        complete_args = get_args_of_label(in_tree, ["complete"], dep_graph)
        if len(running_args) > 0:
            arg_condition = condition_running_procedure(tok_label)
            if not_logic:
                arg_condition = "!(" + arg_condition + ")"
            result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                                 dep_graph)
        elif len(complete_args) > 0:
            arg_condition = condition_completed_procedure(tok_label)
            if not_logic:
                arg_condition = "!(" + arg_condition + ")"
            result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                                 dep_graph)
        elif not strict:
            arg_condition = condition_running_procedure(tok_label)
            if not_logic:
                arg_condition = "!(" + arg_condition + ")"
            result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                                 dep_graph)

    elif "event" in tok_types:
        if tok_label == "integrity_check":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(item, dep_graph)[3] for item in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)
                else:
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)

        elif tok_label == "time_out":
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            timer_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in timer_args]
            if len(timer_labels) == 0:
                timer_labels = call_get_last_context("timer", cond_ctx, act_ctx, global_context_dict, "012")
            for arg_label in timer_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    arg_condition = condition_running_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         arg_condition, False, dep_graph)
                else:
                    arg_condition = condition_expired_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition, arg_condition,
                                                         False, dep_graph)

        else:
            arg_condition = condition_indicate_event(tok_label)
            if not_logic:
                arg_condition = "!(" + arg_condition + ")"
            result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition,
                                                 True, dep_graph)

    elif not strict and "var" in tok_types:
        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(in_tree, dep_graph)
        arg_condition = condition_valid_var(arg_label)
        if not_logic:
            arg_condition = "!(" + arg_condition + ")"
        result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                             dep_graph)

    elif not strict and "message" in tok_types:
        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(in_tree, dep_graph)
        arg_condition = condition_receive_message(arg_label, agents)
        if not_logic:
            arg_condition = "!(" + arg_condition + ")"
        result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition, True,
                                             dep_graph)

    elif not strict and "cause" in tok_types:
        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(in_tree, dep_graph)
        msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021", message_dir)

        if len(msg_labels) > 0:
            msg = msg_labels[0]
            arg_condition = condition_message_cause(arg_label, msg)
            msg_condition = condition_receive_message(msg, agents)
            arg_condition = arg_condition + " & " + msg_condition
            if not_logic:
                arg_condition = "!(" + arg_condition + ")"
            result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, arg_condition,
                                                 True, dep_graph)

    elif "msg_field" in tok_types:
        cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)
        msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
        msg_labels = [get_info_from_tree(item, dep_graph)[3] for item in msg_args]
        if len(msg_labels) == 0:
            msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021", message_dir)

        if len(cause_args) > 0:
            for arg in cause_args:
                for msg in msg_labels:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_message_cause(arg_label, msg)
                    msg_condition = condition_receive_message(msg, agents)
                    arg_condition = arg_condition + " & " + msg_condition
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)
                    if tok_label == "emm_cause":
                        field_condition = condition_receive_field_in_msg("emm_cause", msg)
                        msg_condition = condition_receive_message(msg, agents)
                        field_condition = field_condition + " & " + msg_condition
                        if not_logic:
                            field_condition = "!(" + field_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, "emm_cause", result_condition,
                                                             field_condition, True, dep_graph)
                    elif tok_label == "five_gmm_cause":
                        field_condition = condition_receive_field_in_msg("five_gmm_cause", msg)
                        msg_condition = condition_receive_message(msg, agents)
                        field_condition = field_condition + " & " + msg_condition
                        if not_logic:
                            field_condition = "!(" + field_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, "five_gmm_cause", result_condition,
                                                             field_condition, True, dep_graph)
                    elif tok_label == "esm_cause":
                        field_condition = condition_receive_field_in_msg("esm_cause", msg)
                        msg_condition = condition_receive_message(msg, agents)
                        field_condition = field_condition + " & " + msg_condition
                        if not_logic:
                            field_condition = "!(" + field_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, "esm_cause", result_condition,
                                                             field_condition, True, dep_graph)
        else:
            include_args = get_args_of_label(in_tree, ["include"], dep_graph)
            include_args.extend(get_args_of_label(in_tree, ["receive"], dep_graph))
            for msg in msg_labels:
                var_condition = condition_receive_field_in_msg(tok_label, msg)
                msg_condition = condition_receive_message(msg, agents)
                var_condition = var_condition + " & " + msg_condition
                if not_logic:
                    var_condition = "!(" + var_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, in_tree, result_condition, var_condition,
                                                     True, dep_graph)

    elif "adj" in tok_types:
        if tok_label == "available":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_activated_service(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "valid":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_valid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

            integrity_arg = get_args_of_label(in_tree, ["integrity_protection"], dep_graph)
            if len(integrity_arg) > 0:
                arg_condition = condition_validate_integrity()
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, integrity_arg[0], result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "invalid":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_invalid_var(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

        elif tok_label == "integrity_protected":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_not_integrity_protected_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)
                else:
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_integrity_protected_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)

        elif tok_label == "ciphered":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_unciphered_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)
                else:
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_ciphered_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)

        elif tok_label == "unciphered":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_ciphered_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)
                else:
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_unciphered_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)

        elif tok_label == "partially_ciphered":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & !(" + condition_parially_ciphered_message(arg_label) + ")"
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)
                else:
                    msg_condition = condition_receive_message(arg_label, agents)
                    msg_condition = msg_condition + " & " + condition_parially_ciphered_message(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         msg_condition, False, dep_graph)

        elif tok_label == "running":
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            timer_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in timer_args]
            if len(timer_labels) == 0:
                timer_labels = call_get_last_context("timer", cond_ctx, act_ctx, global_context_dict, "012")
            for arg_label in timer_labels:
                if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                    arg_condition = condition_stopped_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         arg_condition,
                                                         False, dep_graph)
                else:
                    arg_condition = condition_running_timer(arg_label)
                    result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                         arg_condition,
                                                         False, dep_graph)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_condition = condition_running_procedure(arg_label)
                if not_logic:
                    arg_condition = "!(" + arg_condition + ")"
                result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition, True,
                                                     dep_graph)

            if len(timer_args) == 0 and len(procedure_args) == 0:
                timer_labels = call_get_last_context("timer", cond_ctx, act_ctx, global_context_dict, "012")
                for arg_label in timer_labels:
                    if not_logic or check_not_val(not_nodes, arg_label, dep_graph):
                        arg_condition = condition_stopped_timer(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             arg_condition, False, dep_graph)
                    else:
                        arg_condition = condition_running_timer(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg_label, result_condition,
                                                             arg_condition, False, dep_graph)
    elif "preposition" in tok_types:
        if tok_label == "_IN_":
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)

            if len(mode_args) > 0:
                for arg in mode_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    if arg_label == "ue" or arg_label == "mme":
                        continue
                    arg_condition = condition_mode(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

            response_args = get_args_of_label(in_tree, ["response"], dep_graph)
            if len(response_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    msg_condition = condition_receive_message(arg_label, agents)
                    if not_logic or check_not(not_nodes, arg):
                        msg_condition = msg_condition.replace("=", "!=")
                    result_condition = result_condition + " | " + msg_condition

                result_condition = result_condition.strip().strip("|").strip()

        elif tok_label == "_AFTER_":
            send_args = get_args_of_label(in_tree, ["send"], dep_graph)
            proc_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            if len(send_args) == 0 and len(proc_args) > 0:
                for arg in proc_args:
                    if not_logic or check_not(not_nodes, arg):
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                        arg_condition = condition_running_procedure(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                             True, dep_graph)
                    else:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                        arg_condition = condition_completed_procedure(arg_label)
                        result_condition = connect_condition(or_nodes, [], arg, result_condition, arg_condition,
                                                             True, dep_graph)

        elif tok_label == "_DURING_":
            proc_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            if len(proc_args) > 0:
                for arg in proc_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_condition = condition_running_procedure(arg_label)
                    if not_logic:
                        arg_condition = "!(" + arg_condition + ")"
                    result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, arg_condition,
                                                         True, dep_graph)

        elif tok_label == "_WITH_":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            var_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in var_args]

            if len(var_labels) > 0:
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                       message_dir)

                for var in var_labels:
                    for msg in msg_labels:
                        var_condition = condition_receive_var_in_msg(var, msg)
                        msg_condition = condition_receive_message(msg, agents)
                        var_condition = var_condition + " & " + msg_condition
                        if not_logic:
                            var_condition = "!(" + var_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, var, result_condition, var_condition,
                                                             False, dep_graph)

            else:
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    msg_sublayer = get_msg_sublayer(arg_label)
                    if msg_sublayer == "emm_sublayer":
                        msg_condition = condition_receive_message(arg_label, agents)
                        if not_logic:
                            msg_condition = "!(" + msg_condition + ")"
                        result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition, msg_condition,
                                                             True, dep_graph)
                    elif msg_sublayer == "esm_sublayer":
                        prev_msg_labels = [get_info_from_tree(item, dep_graph)[3] for item in msg_args]
                        prev_msg_labels = [item for item in prev_msg_labels
                                           if get_msg_sublayer(item) == "emm_sublayer"]
                        if len(prev_msg_labels) == 0:
                            prev_msg_labels = cond_ctx["message"]
                            prev_msg_labels = [item for item in prev_msg_labels
                                               if get_msg_sublayer(item) == "emm_sublayer"]
                        if len(prev_msg_labels) == 0:
                            prev_msg_labels = act_ctx["message"]
                            prev_msg_labels = [item for item in prev_msg_labels
                                               if get_msg_sublayer(item) == "emm_sublayer"]
                        if len(prev_msg_labels) == 0:
                            prev_msg_labels = [global_context_dict["last_message"]]
                            prev_msg_labels = [item for item in prev_msg_labels
                                               if get_msg_sublayer(item) == "emm_sublayer"]

                        if len(prev_msg_labels) > 0:
                            msg_condition = condition_receive_esm_msg_in_msg(arg_label, prev_msg_labels[-1])
                            if not_logic:
                                msg_condition = "!(" + msg_condition + ")"
                            result_condition = connect_condition(or_nodes, not_nodes, arg, result_condition,
                                                                 msg_condition, True, dep_graph)

    result_condition = result_condition.replace("!()", "").replace("()", "")
    result_condition = result_condition.strip().strip("&").strip("|").strip()
    if result_condition.strip() == "" and isinstance(in_tree, ParentedTree):
        for child in in_tree:
            child_condition = run_dfs_IR_condition(child, dep_graph, cond_ctx, act_ctx, global_context_dict,
                                                   agents, strict, not_logic).strip()
            if child_condition != "":
                if "|" in result_condition:
                    result_condition = "(" + result_condition + ")"
                result_condition = result_condition + " & " + child_condition

    result_condition = result_condition.replace("!()", "").replace("()", "")

    result_condition = result_condition.strip().strip("&").strip("|").strip()
    return result_condition


def run_dfs_IR_action(in_tree, dep_graph: DepGraph, agents, cond_ctx, act_ctx, global_context_dict,
                      not_logic, top_level, probable) -> (list, str):
    actions = []
    extra_conditions = ""

    not_nodes = get_args_of_label(in_tree, list(NOT_TYPES), dep_graph)

    if len(agents) == 0:
        agents.update(global_context_dict["agents"])

    tok_num, tok_types, tok_pos, tok_label = get_info_from_tree(in_tree, dep_graph)

    message_dir = "ue_to_mme"
    if "ue" not in agents and "mme" in agents:
        message_dir = "mme_to_ue"

    if top_level and not probable:
        directive_args = get_args_of_type(in_tree, ["directive"], dep_graph)
        directive_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in directive_args]
        if len(directive_labels) == 0:
            directive_labels = call_get_last_context("directive", cond_ctx, act_ctx, global_context_dict, "210")

        for dir_label in directive_labels:
            if dir_label in {"_MAY_", "_SHOULD_"}:
                new_coin_toss = get_new_boolean_coin_toss()
                extra_conditions = extra_conditions + " & " + new_coin_toss
                extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
                probable = True
                break
            elif dir_label in {"_CAN_"} and tok_label not in NOT_TYPES and tok_label.strip() != "":
                new_coin_toss = get_new_boolean_coin_toss()
                extra_conditions = extra_conditions + " & " + new_coin_toss
                extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
                probable = True
                break
            elif dir_label in {"_NEED_"} and tok_label in NOT_TYPES and tok_label.strip() != "":
                new_coin_toss = get_new_boolean_coin_toss()
                extra_conditions = extra_conditions + " & " + new_coin_toss
                extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
                probable = True
                break

    if top_level and tok_label.strip() == "":
        for child in in_tree:
            child_actions, child_extra_conditions = run_dfs_IR_action(child, dep_graph, agents, cond_ctx, act_ctx,
                                                                      global_context_dict, False, True, probable)

            actions.extend(child_actions)
            if child_extra_conditions.strip() != "":
                extra_conditions = extra_conditions + " & " + child_extra_conditions
        extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
        return actions, extra_conditions

    if tok_label in NOT_TYPES and not probable:
        for child in in_tree:
            child_actions, child_extra_conditions = run_dfs_IR_action(child, dep_graph, agents, cond_ctx, act_ctx,
                                                                      global_context_dict, True, False, probable)

            actions.extend(child_actions)
            if child_extra_conditions.strip() != "":
                extra_conditions = extra_conditions + " & " + child_extra_conditions
        extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
        extra_conditions = "!(" + extra_conditions + ")"
        extra_conditions = extra_conditions.replace("!()", "")
        return actions, extra_conditions

    elif "preposition" in tok_types:
        if tok_label == "_IN_":
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            if len(mode_args) > 0:
                for arg in mode_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    if arg_label == "ue" or arg_label == "mme":
                        continue
                    arg_actions = action_activate_mode(arg_label, agents)
                    actions.extend(arg_actions)

        if tok_label == "_WITH_":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)
            cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)


            if len(cause_args) > 0:
                for arg in cause_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_send_message(msg_labels[0], agents)
                    actions.extend(arg_actions)
                    arg_actions = action_message_cause(arg_label, msg_labels[0], agents)
                    actions.extend(arg_actions)

    elif "verb" in tok_types:
        if tok_label == "start":
            if not_logic and not probable:
                return actions, extra_conditions
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            for arg in timer_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_start_timer(arg_label, agents)
                actions.extend(arg_actions)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_initiate_proc(arg_label, agents)
                actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_require_procedure(arg_label)

        elif tok_label == "initiate":
            if not_logic and not probable:
                return actions, extra_conditions
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            procedure_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in procedure_args]
            last_proc_args = get_args_of_label(in_tree, ["last_procedure"], dep_graph)
            if len(procedure_labels) == 0 and len(last_proc_args) > 0:
                procedure_labels = call_get_last_context("procedure", cond_ctx, act_ctx, global_context_dict, "120")

            send_args = get_args_of_label(in_tree, ["send"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(send_args) > 0 and len(msg_labels) > 0 and len(procedure_labels) > 0:
                for arg_label in msg_labels:
                    arg_actions = action_send_message(arg_label, agents)
                    actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_initiate_procedure(procedure_labels[0])
            else:
                for arg_label in procedure_labels:
                    if "common_procedure" in arg_label:
                        for new_arg_label in ["sm_control", "identification_proc", "authentication"]:
                            arg_actions = action_initiate_proc(new_arg_label, agents)
                            actions.extend(arg_actions)
                            extra_conditions = extra_conditions + " & " + condition_require_procedure(new_arg_label)
                        continue
                    arg_actions = action_initiate_proc(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_require_procedure(arg_label)

        elif tok_label == "perform":
            if not_logic and not probable:
                return actions, extra_conditions
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_initiate_proc(arg_label, agents)
                actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_require_procedure(arg_label)

            integrity_check_args = get_args_of_label(in_tree, ["integrity_check"], dep_graph)
            if len(integrity_check_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                       message_dir)
                for arg_label in msg_labels:
                    arg_actions = action_check_integrity_protect_message(arg_label, agents)
                    actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_activated_service("integrity_protection")


        elif tok_label == "complete":
            if not_logic and not probable:
                return actions, extra_conditions
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            procedure_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in procedure_args]
            if len(procedure_labels) == 0:
                procedure_labels = call_get_last_context("procedure", cond_ctx, act_ctx, global_context_dict, "120")

            send_args = get_args_of_label(in_tree, ["send"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(send_args) > 0 and len(msg_labels) > 0 and len(procedure_labels) > 0:
                for arg_label in msg_labels:
                    arg_actions = action_send_message(arg_label, agents)
                    actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_completed_procedure(procedure_labels[0])
            else:
                for arg_label in procedure_labels:
                    arg_actions = action_complete_procedure(arg_label, agents)
                    actions.extend(arg_actions)


        elif tok_label == "fail":
            if not_logic and not probable:
                return actions, extra_conditions
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_fail_procedure(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "suspend":
            if not_logic and not probable:
                return actions, extra_conditions
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_suspend_procedure(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "stop":
            if not_logic and not probable:
                return actions, extra_conditions
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            timer_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in timer_args]
            last_timer_args = get_args_of_label(in_tree, ["last_timer"], dep_graph)
            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)

            if len(timer_labels) == 0 and len(procedure_args) == 0 and len(last_timer_args) > 0:
                timer_labels = call_get_last_context("timer", cond_ctx, act_ctx, global_context_dict, "120")

            for arg_label in timer_labels:
                arg_actions = action_stop_timer(arg_label, agents)
                actions.extend(arg_actions)

            procedure_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in procedure_args]
            if len(timer_args) == 0 and len(procedure_labels) == 0:
                procedure_labels = call_get_last_context("procedure", cond_ctx, act_ctx, global_context_dict, "120")

            send_args = get_args_of_label(in_tree, ["send"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(send_args) > 0 and len(msg_labels) > 0 and len(procedure_labels) > 0:
                for arg_label in msg_labels:
                    arg_actions = action_send_message(arg_label, agents)
                    actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_stopped_procedure(procedure_labels[0])
            else:
                for arg_label in procedure_labels:
                    arg_actions = action_stop_procedure(arg_label, agents)
                    actions.extend(arg_actions)

        elif tok_label == "exist":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            if len(service_args) > 0:
                for arg in service_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_activate_service(arg_label, agents)
                    actions.extend(arg_actions)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_save_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "activate":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "apply":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic and not probable:
                    arg_actions = action_deactivate_service(arg_label, agents)
                else:
                    arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "support":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            service_args.extend(mode_args)
            service_args.extend(timer_args)
            service_args.extend(msg_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_support_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "configure":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            misc_args = get_args_of_type(in_tree, ["misc"], dep_graph)
            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            service_args.extend(misc_args)
            service_args.extend(mode_args)
            service_args.extend(timer_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_configure_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "use":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_save_var(arg_label, agents)
                actions.extend(arg_actions)


        elif tok_label == "take":
            if not_logic and not probable:
                return actions, extra_conditions

            use_args = get_args_of_label(in_tree, ["use"], dep_graph)
            if len(use_args) > 0:
                var_args = get_args_of_type(in_tree, ["var"], dep_graph)
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_save_var(arg_label, agents)
                    actions.extend(arg_actions)

        elif tok_label == "request":
            if not_logic and not probable:
                return actions, extra_conditions
            release_args = get_args_of_label(in_tree, ["release"], dep_graph)
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if len(release_args) == 0:
                    arg_actions = action_request_service(arg_label, agents)
                    actions.extend(arg_actions)
                else:
                    arg_actions = action_deactivate_service(arg_label, agents)
                    actions.extend(arg_actions)

        elif tok_label == "enable":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "continue":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if check_not(not_nodes, arg):
                    arg_actions = action_deactivate_service(arg_label, agents)
                else:
                    arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "establish":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph, ["_FOR_"])
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

            misc_args = get_args_of_type(in_tree, ["misc"], dep_graph, ["_FOR_"])
            for arg in misc_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "deactivate":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_deactivate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "release":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_deactivate_service(arg_label, agents)
                actions.extend(arg_actions)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_invalid_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "disable":
            if not_logic and not probable:
                return actions, extra_conditions
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_deactivate_service(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "camp":
            if not_logic and not probable:
                return actions, extra_conditions
            cell_args = get_args_of_label_substring(in_tree, "cell", dep_graph)
            for arg in cell_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_camp_cell(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "exchange":
            if not_logic and not probable:
                return actions, extra_conditions
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_send_var(arg_label, agents)
                actions.extend(arg_actions)


        elif tok_label == "send":
            if not_logic and not probable:
                return actions, extra_conditions

            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            if len(to_args) > 0:
                for to_arg in to_args:
                    ue_args = get_args_of_label(to_arg, ["ue"], dep_graph)
                    mme_args = get_args_of_label(to_arg, ["mme"], dep_graph)
                    if len(ue_args) > 0:
                        agents = {"mme"}
                    elif len(mme_args) > 0:
                        agents = {"ue"}

            integrity_nodes = get_args_of_label(in_tree, ["integrity_protected"], dep_graph)
            ciphered_nodes = get_args_of_label(in_tree, ["ciphered"], dep_graph)
            unciphered_nodes = get_args_of_label(in_tree, ["unciphered"], dep_graph)

            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args.extend(var_args)
            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]
            cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)

            if "nas_message" in msg_labels:
                if len(integrity_nodes) > 0:
                    arg_actions = action_activate_service("integrity_protection")
                    actions.extend(arg_actions)
                if len(ciphered_nodes) > 0:
                    arg_actions = action_activate_service("nas_ciphering")
                    actions.extend(arg_actions)
                if len(unciphered_nodes) > 0:
                    arg_actions = action_deactivate_service("nas_ciphering")
                    actions.extend(arg_actions)
                msg_labels.remove("nas_message")

            if len(cause_args) > 0:
                for arg in cause_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    for msg_label in msg_labels:
                        arg_actions = action_message_cause(arg_label, msg_label, agents)
                        actions.extend(arg_actions)
                        arg_actions = action_send_message(msg_label, agents)
                        actions.extend(arg_actions)
                        if "emm_cause" in field_labels or len(get_args_of_label(in_tree, ["emm"], dep_graph)) > 0:
                            arg_actions = action_send_field_in_msg("emm_cause", msg_label, agents)
                            actions.extend(arg_actions)
                        elif "five_gmm_cause" in field_labels or len(get_args_of_label(in_tree, ["five_gmm_cause"], dep_graph)) > 0:
                            arg_actions = action_send_field_in_msg("five_gmm_cause", msg_label, agents)
                            actions.extend(arg_actions)
                        elif "esm_cause" in field_labels or len(get_args_of_label(in_tree, ["esm"], dep_graph)) > 0:
                            arg_actions = action_send_field_in_msg("esm_cause", msg_label, agents)
                            actions.extend(arg_actions)

            with_args = get_args_of_label(in_tree, ["_WITH_"], dep_graph)
            with_message_labels = []
            for with_arg in with_args:
                with_message_labels.extend(get_info_from_tree(with_msg_arg, dep_graph)[3]
                                           for with_msg_arg in get_args_of_type(with_arg, ["message"], dep_graph))
            msg_labels = [item for item in msg_labels if item not in with_message_labels]

            without_args = get_args_of_label(in_tree, ["_WITHOUT_"], dep_graph)
            without_field_labels = []
            for without_arg in without_args:
                without_field_labels.extend(get_args_of_type(without_arg, ["msg_field"], dep_graph))
            without_field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in without_field_labels]



            for arg_label in msg_labels:
                for field_label in field_labels:
                    if field_label in without_field_labels:
                        arg_actions = action_not_send_field_in_msg(field_label, arg_label, agents)
                        actions.extend(arg_actions)
                    else:
                        arg_actions = action_send_field_in_msg(field_label, arg_label, agents)
                        actions.extend(arg_actions)

                if len(integrity_nodes) > 0:
                    arg_actions = action_integrity_protect_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_activated_service(
                        "integrity_protection")
                if len(ciphered_nodes) > 0:
                    arg_actions = action_cipher_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_activated_service(
                        "nas_ciphering")
                if len(unciphered_nodes) > 0:
                    arg_actions = action_not_cipher_message(arg_label, agents)
                    actions.extend(arg_actions)

                msg_sublayer = get_msg_sublayer(arg_label)
                if msg_sublayer == "emm_sublayer":
                    arg_actions = action_send_message(arg_label, agents)
                    actions.extend(arg_actions)
                    for with_arg_label in with_message_labels:
                        if get_msg_sublayer(with_arg_label) == "esm_sublayer":
                            arg_actions = action_send_esm_msg_in_msg(with_arg_label, arg_label, agents)
                            actions.extend(arg_actions)

                elif msg_sublayer == "esm_sublayer":
                    emm_msg_labels = [item for item in msg_labels if get_msg_sublayer(item) == "emm_sublayer"]
                    if len(emm_msg_labels) == 0:
                        emm_msg_labels = cond_ctx["message"]
                        emm_msg_labels = [item for item in emm_msg_labels
                                          if get_msg_sublayer(item) == "emm_sublayer"]

                    if len(emm_msg_labels) > 0:
                        arg_actions = action_send_esm_msg_in_msg(arg_label, emm_msg_labels[-1], agents)
                        actions.extend(arg_actions)
                    else:
                        arg_actions = action_send_message(arg_label, agents)
                        actions.extend(arg_actions)

                else:
                    arg_actions = action_send_message(arg_label, agents)
                    actions.extend(arg_actions)

        elif tok_label == "cipher":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            for arg_label in msg_labels:
                if arg_label == "nas_message":
                    if not_logic and not probable:
                        arg_actions = action_deactivate_service("nas_ciphering")
                    else:
                        arg_actions = action_activate_service("nas_ciphering")
                else:
                    if not_logic and not probable:
                        arg_actions = action_not_cipher_message(arg_label, agents)
                    else:
                        arg_actions = action_cipher_message(arg_label, agents)
                        extra_conditions = extra_conditions + " & " + condition_activated_service("nas_ciphering")
                actions.extend(arg_actions)

        elif tok_label == "ignore":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            last_msg_args = get_args_of_label(in_tree, ["last_message"], dep_graph)
            unciphered_args = get_args_of_label(in_tree, ["unciphered"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0 and len(last_msg_args) > 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic and not probable:
                    arg_actions = action_not_drop_message(arg_label, agents)
                else:
                    arg_actions = action_drop_message(arg_label, agents)
                actions.extend(arg_actions)
                extra_conditions = extra_conditions + " & " + condition_receive_message(arg_label)
                if len(unciphered_args) > 0:
                    extra_conditions = extra_conditions + " & " + condition_unciphered_message(arg_label)

        elif tok_label == "protect":
            integrity_args = get_args_of_label(in_tree, ["integrity"], dep_graph)
            if len(integrity_args) > 0:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
                if len(msg_labels) == 0:
                    msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                       message_dir)

                for arg_label in msg_labels:
                    if arg_label == "nas_message":
                        if not_logic and not probable:
                            arg_actions = action_deactivate_service("integrity_protection")
                        else:
                            arg_actions = action_activate_service("integrity_protection")
                    else:
                        if not_logic and not probable:
                            arg_actions = action_not_integrity_protect_message(arg_label, agents)
                        else:
                            arg_actions = action_integrity_protect_message(arg_label, agents)
                            extra_conditions = extra_conditions + " & " + condition_activated_service(
                                "integrity_protection")
                    actions.extend(arg_actions)

        elif tok_label == "accept":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            last_msg_args = get_args_of_label(in_tree, ["last_message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0 and len(last_msg_args) > 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021",
                                                   message_dir)

            for arg_label in msg_labels:
                if not_logic and not probable:
                    arg_actions = action_reject_message(arg_label, agents)
                else:
                    arg_actions = action_accept_message(arg_label, agents)
                actions.extend(arg_actions)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic and not probable:
                    arg_actions = action_stop_procedure(arg_label, agents)
                else:
                    arg_actions = action_complete_procedure(arg_label, agents)
                actions.extend(arg_actions)

            agent_args = get_args_of_type(in_tree, ["agent"], dep_graph)
            for arg in agent_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic and not probable:
                    arg_actions = action_invalid_var(arg_label, agents)
                else:
                    arg_actions = action_valid_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "process":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            if not_logic and not probable:
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_reject_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & !" + condition_receive_message(arg_label, agents)

            else:
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_accept_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_receive_message(arg_label, agents)

        elif tok_label == "reject":
            if not_logic and not probable:
                return actions, extra_conditions
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            for arg in msg_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_reject_message(arg_label, agents)
                actions.extend(arg_actions)

            procedure_args = get_args_of_type(in_tree, ["procedure"], dep_graph)
            for arg in procedure_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic and not probable:
                    arg_actions = []
                else:
                    arg_actions = action_reject_procedure(arg_label, agents)
                actions.extend(arg_actions)

            agent_args = get_args_of_type(in_tree, ["agent"], dep_graph)
            for arg in agent_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if not_logic and not probable:
                    arg_actions = []
                else:
                    arg_actions = action_invalid_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "enter":
            if not_logic and not probable:
                return actions, extra_conditions
            state_args = get_args_of_type(in_tree, ["state"], dep_graph)
            for arg in state_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_enter_state(arg_label, agents)
                actions.extend(arg_actions)

            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            for arg in mode_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                if arg_label == "ue" or arg_label == "mme":
                    continue
                arg_actions = action_activate_mode(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "include":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            val_args = get_args_of_type(in_tree, ["field_val"], dep_graph)
            cause_args = get_args_of_type(in_tree, ["cause"], dep_graph)
            field_args.extend(var_args)

            last_msg_field_args = get_args_of_label(in_tree, ["last_msg_field"], dep_graph)
            if len(last_msg_field_args) > 0:
                field_args.append(global_context_dict["last_msg_field"])

            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]
            field_labels = set(field_labels)

            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            for field in field_labels:
                for msg in msg_labels:
                    arg_actions = action_send_field_in_msg(field, msg, agents)
                    actions.extend(arg_actions)
                    if field == "emm_cause" or field == "esm_cause":
                        for cause_arg in cause_args:
                            arg_actions = action_send_field_in_msg_val(
                                field, msg, get_info_from_tree(cause_arg, dep_graph)[3], agents)
                            actions.extend(arg_actions)
                    elif len(val_args) > 0:
                        for val_arg in val_args:
                            arg_actions = action_send_field_in_msg_val(
                                field, msg, get_info_from_tree(val_arg, dep_graph)[3], agents)
                            actions.extend(arg_actions)

            for arg in msg_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                msg_sublayer = get_msg_sublayer(arg_label)
                if msg_sublayer == "esm_sublayer":
                    emm_msg_labels = [get_info_from_tree(item, dep_graph)[3] for item in msg_args]
                    emm_msg_labels = [item for item in emm_msg_labels if get_msg_sublayer(item) == "emm_sublayer"]
                    if len(emm_msg_labels) == 0:
                        emm_msg_labels = cond_ctx["message"]
                        emm_msg_labels = [item for item in emm_msg_labels if get_msg_sublayer(item) == "emm_sublayer"]
                    if len(emm_msg_labels) == 0:
                        emm_msg_labels = act_ctx["message"]
                        emm_msg_labels = [item for item in emm_msg_labels if get_msg_sublayer(item) == "emm_sublayer"]
                    if len(emm_msg_labels) == 0:
                        emm_msg_labels = [global_context_dict["last_message"]]
                        emm_msg_labels = [item for item in emm_msg_labels if get_msg_sublayer(item) == "emm_sublayer"]

                    if len(emm_msg_labels) > 0:
                        arg_actions = action_send_esm_msg_in_msg(arg_label, emm_msg_labels[-1], agents)
                        if check_not(not_nodes, arg):
                            for idx, action in enumerate(arg_actions):
                                if "TRUE" in action["label"]:
                                    arg_actions[idx]["label"] = action["label"].replace("TRUE", "FALSE")
                        actions.extend(arg_actions)

                    if not_logic and not probable:
                        for idx, action in enumerate(actions):
                            if "TRUE" in action["label"]:
                                actions[idx]["label"] = action["label"].replace("TRUE", "FALSE")

            if not_logic and not probable:
                for idx, action in enumerate(actions):
                    if "TRUE" in action["label"]:
                        actions[idx]["label"] = action["label"].replace("TRUE", "FALSE")

        elif tok_label == "provide":
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            field_args.extend(var_args)
            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]
            field_labels = set(field_labels)

            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            for field in field_labels:
                for msg in msg_labels:
                    arg_actions = action_send_field_in_msg(field, msg, agents)
                    actions.extend(arg_actions)

            mode_args = get_args_of_type(in_tree, ["mode"], dep_graph)
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            service_args.extend(mode_args)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                actions.extend(arg_actions)

            if not_logic and not probable:
                for idx, action in enumerate(actions):
                    if "TRUE" in action["label"]:
                        actions[idx]["label"] = action["label"].replace("TRUE", "FALSE")

        elif tok_label == "authenticate":
            if not_logic and not probable:
                return actions, extra_conditions
            arg_actions = action_initiate_proc("authentication", agents)
            actions.extend(arg_actions)
            extra_conditions = extra_conditions + " & " + condition_require_procedure("authentication")

        elif tok_label == "respond":
            if not_logic and not probable:
                return actions, extra_conditions
            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            with_args = get_args_of_label(in_tree, ["_WITH_"], dep_graph)
            if len(with_args) > 0:
                for with_arg in with_args:
                    msg_args = get_args_of_type(with_arg, ["message"], dep_graph)
                    for arg in msg_args:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                        arg_actions = action_send_message(arg_label, agents)
                        actions.extend(arg_actions)
            elif len(to_args) > 0:
                for to_arg in to_args:
                    msg_args = get_args_of_type(to_arg, ["message"], dep_graph)
                    for arg in msg_args:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                        arg_actions = action_respond_to_message(arg_label, agents)
                        actions.extend(arg_actions)
                        extra_conditions = extra_conditions + " & " + condition_receive_message(arg_label, agents)
            else:
                msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_respond_to_message(arg_label, agents)
                    actions.extend(arg_actions)

        elif tok_label == "save":
            if not_logic and not probable:
                return actions, extra_conditions
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_save_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "delete":
            if not_logic and not probable:
                return actions, extra_conditions
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_delete_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "check":
            if not_logic and not probable:
                return actions, extra_conditions

            accept_args = get_args_of_label(in_tree, ["accept"], dep_graph)
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            if len(accept_args) > 0:
                for arg in msg_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_check_accept_message(arg_label, agents)
                    actions.extend(arg_actions)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_check_valid_var(arg_label, agents)
                actions.extend(arg_actions)

            return actions, extra_conditions

        elif tok_label == "require":
            if not_logic and not probable:
                return actions, extra_conditions

        elif tok_label == "set":
            if not_logic and not probable:
                return actions, extra_conditions
            send_args = get_args_of_label(in_tree, ["send"], dep_graph)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in var_args]

            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            counter_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in counter_args]
            last_counter_args = get_args_of_label(in_tree, ["last_counter"], dep_graph)

            if len(counter_labels) == 0 and len(last_counter_args) > 0:
                counter_labels = call_get_last_context("counter", cond_ctx, act_ctx, global_context_dict, "102")

            var_labels.extend(counter_labels)

            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            val_args = []
            for to_arg in to_args:
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["var"], dep_graph))
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["mode"], dep_graph))
                val_args.extend(
                    get_info_from_tree(item, dep_graph)[3] for item in get_args_of_type(to_arg, ["num"], dep_graph))
                val_args.extend(get_info_from_tree(
                    item, dep_graph)[3] for item in get_args_of_type(to_arg, ["field_val"], dep_graph))

            for arg_label in var_labels:
                for to_val in val_args:
                    val_num, val_types, val_pos, val_label = get_info_from_tree(to_val, dep_graph)
                    if val_label == arg_label:
                        continue
                    arg_actions = action_set_var_to_val(arg_label, val_label, agents)
                    actions.extend(arg_actions)

            field_args = get_args_of_type(in_tree, ["msg_field"], dep_graph)
            field_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in field_args]

            if len(get_args_of_label(in_tree, ["last_msg_field"], dep_graph)) > 0:
                field_labels.append(global_context_dict["last_msg_field"])

            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            if len(to_args) > 0:
                val_args = get_args_of_type(to_args[0], ["field_val"], dep_graph)
            else:
                val_args = get_args_of_type(in_tree, ["field_val"], dep_graph)

            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]
            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)
            if len(msg_labels) != 0:
                for field in field_labels:
                    for val in val_args:
                        val_num, val_types, val_pos, val_label = get_info_from_tree(val, dep_graph)
                        if field == val_label:
                            continue
                        arg_actions = action_set_msg_field_to_val(field, msg_labels[0], val_label, agents)
                        actions.extend(arg_actions)
                        arg_actions = action_send_field_in_msg(field, msg_labels[0], agents)
                        actions.extend(arg_actions)
                        arg_actions = action_send_message(msg_labels[0], agents)
                        actions.extend(arg_actions)

        elif tok_label == "reset":
            if not_logic and not probable:
                return actions, extra_conditions
            to_args = get_args_of_label(in_tree, ["_TO_"], dep_graph)
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(counter_args)
            if len(to_args) > 0:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_set_var_to_val(arg_label, get_info_from_tree(to_args[0], dep_graph)[3], agents)
                    actions.extend(arg_actions)
            else:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_reset_var(arg_label, agents)
                    actions.extend(arg_actions)

            timer_args = get_args_of_type(in_tree, ["timer"], dep_graph)
            for arg in timer_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_start_timer(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "update":
            if not_logic and not probable:
                return actions, extra_conditions
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(counter_args)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_update_var(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "increase":
            if not_logic and not probable:
                return actions, extra_conditions
            by_args = get_args_of_label(in_tree, ["_BY_"], dep_graph)
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(counter_args)
            if len(by_args) > 0:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_increase_var_by_val(arg_label, get_info_from_tree(by_args[0], dep_graph)[3],
                                                             agents)
                    actions.extend(arg_actions)
            else:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_increase_var_by_val(arg_label, "1", agents)
                    actions.extend(arg_actions)

        elif tok_label == "decrease":
            if not_logic and not probable:
                return actions, extra_conditions
            by_args = get_args_of_label(in_tree, ["_BY_"], dep_graph)
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            var_args.extend(counter_args)
            if len(by_args) > 0:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_decrease_var_by_val(arg_label, get_info_from_tree(by_args[0], dep_graph)[3],
                                                             agents)
                    actions.extend(arg_actions)
            else:
                for arg in var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                    arg_actions = action_decrease_var_by_val(arg_label, "1", agents)
                    actions.extend(arg_actions)

        elif tok_label == "maintain":
            if not_logic and not probable:
                return actions, extra_conditions
            counter_args = get_args_of_type(in_tree, ["counter"], dep_graph)
            for arg in counter_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_maintain_counter(arg_label, agents)
                actions.extend(arg_actions)

        elif tok_label == "consider":
            if not_logic and not probable:
                return actions, extra_conditions
            new_args = get_args_of_label(in_tree, ["new"], dep_graph)
            old_args = get_args_of_label(in_tree, ["old"], dep_graph)
            if len(new_args) > 0:
                for new_arg in new_args:
                    new_var_args = get_args_of_type(new_arg, ["var"], dep_graph)
                    for new_var in new_var_args:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(new_var, dep_graph)

                        adj_args = get_args_of_type(new_arg, ["adj"], dep_graph)
                        adj_labels = [get_info_from_tree(adj, dep_graph)[3] for adj in adj_args]
                        if "valid" in adj_labels:
                            arg_actions = action_valid_var(arg_label, agents)
                            actions.extend(arg_actions)
                            arg_actions = action_update_var(arg_label, agents)
                            actions.extend(arg_actions)
            elif len(new_args) == 0 and len(old_args) > 0:
                for old_arg in old_args:
                    old_var_args = get_args_of_type(old_arg, ["var"], dep_graph)
                    for old_var in old_var_args:
                        arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(old_var, dep_graph)

                        adj_args = get_args_of_type(old_arg, ["adj"], dep_graph)
                        adj_labels = [get_info_from_tree(adj, dep_graph)[3] for adj in adj_args]
                        if "valid" in adj_labels:
                            arg_actions = action_valid_var(arg_label, agents)
                            actions.extend(arg_actions)
                            arg_actions = action_not_update_var(arg_label, agents)
                            actions.extend(arg_actions)
            else:
                new_var_args = get_args_of_type(in_tree, ["var"], dep_graph)
                for new_var in new_var_args:
                    arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(new_var, dep_graph)

                    adj_args = get_args_of_type(in_tree, ["adj"], dep_graph)
                    adj_labels = [get_info_from_tree(adj, dep_graph)[3] for adj in adj_args]
                    if "valid" in adj_labels:
                        arg_actions = action_valid_var(arg_label, agents)
                        actions.extend(arg_actions)
                    elif "invalid" in adj_labels:
                        arg_actions = action_invalid_var(arg_label, agents)
                        actions.extend(arg_actions)

    elif "adj" in tok_types:
        if tok_label == "available":
            service_args = get_args_of_type(in_tree, ["service"], dep_graph)
            for arg in service_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_activate_service(arg_label, agents)
                if not_logic and not probable:
                    for act in arg_actions:
                        if "TRUE" in act["label"]:
                            act["label"] = act["label"].replace("TRUE", "FALSE")
                        elif "FALSE" in act["label"]:
                            act["label"] = act["label"].replace("FALSE", "TRUE")
                actions.extend(arg_actions)

            var_args = get_args_of_type(in_tree, ["var"], dep_graph)
            for arg in var_args:
                arg_num, arg_types, arg_pos, arg_label = get_info_from_tree(arg, dep_graph)
                arg_actions = action_save_var(arg_label, agents)
                actions.extend(arg_actions)
                if not_logic and not probable:
                    for act in arg_actions:
                        if "TRUE" in act["label"]:
                            act["label"] = act["label"].replace("TRUE", "FALSE")
                        elif "FALSE" in act["label"]:
                            act["label"] = act["label"].replace("FALSE", "TRUE")

        elif tok_label == "integrity_protected":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            if "nas_message" in msg_labels:
                arg_actions = action_activate_service("integrity_protection")
                actions.extend(arg_actions)
            else:
                for arg_label in msg_labels:
                    arg_actions = action_integrity_protect_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_activated_service("integrity_protection")

        elif tok_label == "ciphered":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            if "nas_message" in msg_labels:
                arg_actions = action_activate_service("nas_ciphering")
                actions.extend(arg_actions)
            else:
                for arg_label in msg_labels:
                    arg_actions = action_cipher_message(arg_label, agents)
                    actions.extend(arg_actions)
                    extra_conditions = extra_conditions + " & " + condition_activated_service("nas_ciphering")

        elif tok_label == "unciphered":
            msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
            msg_labels = [get_info_from_tree(arg, dep_graph)[3] for arg in msg_args]

            if len(msg_labels) == 0:
                msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "120",
                                                   message_dir)

            if "nas_message" in msg_labels:
                arg_actions = action_deactivate_service("nas_ciphering")
                actions.extend(arg_actions)
            else:
                for arg_label in msg_labels:
                    arg_actions = action_not_cipher_message(arg_label, agents)
                    actions.extend(arg_actions)

    elif "state" in tok_types:
        arg_actions = action_enter_state(tok_label, agents)
        actions.extend(arg_actions)

    elif "mode" in tok_types:
        if tok_label == "ue" or tok_label == "mme":
            pass
        else:
            arg_actions = action_activate_mode(tok_label, agents)
            actions.extend(arg_actions)

    elif "timer" in tok_types:
        if not_logic and not probable:
            return actions, extra_conditions
        verb_args = get_args_of_type(in_tree, ["verb"], dep_graph)
        verb_args = [get_info_from_tree(arg, dep_graph) for arg in verb_args]
        verb_args = [arg[3] for arg in verb_args]
        if "start" in verb_args or "set" in verb_args:
            arg_actions = action_start_timer(tok_label, agents)
            actions.extend(arg_actions)
        elif "stop" in verb_args:
            arg_actions = action_stop_timer(tok_label, agents)
            actions.extend(arg_actions)

    elif "msg_field" in tok_types:
        include_args = get_args_of_label(in_tree, ["include"], dep_graph)
        include_args.extend(get_args_of_label(in_tree, ["receive"], dep_graph))
        msg_args = get_args_of_type(in_tree, ["message"], dep_graph)
        msg_labels = [get_info_from_tree(item, dep_graph)[3] for item in msg_args]
        if len(msg_labels) == 0:
            msg_labels = call_get_last_context("message", cond_ctx, act_ctx, global_context_dict, "021", message_dir)

        for msg in msg_labels:
            arg_actions = action_send_field_in_msg(tok_label, msg, agents)
            actions.extend(arg_actions)
            if not_logic and not probable:
                for act in arg_actions:
                    if "TRUE" in act["label"]:
                        act["label"] = act["label"].replace("TRUE", "FALSE")
                    elif "FALSE" in act["label"]:
                        act["label"] = act["label"].replace("FALSE", "TRUE")

    elif "conjunction" in tok_types:
        if tok_label == "_OR_":
            for child in in_tree:
                child_actions, child_extra_conditions = run_dfs_IR_action(child, dep_graph, agents, cond_ctx, act_ctx,
                                                                          global_context_dict, not_logic, False,
                                                                          probable)

                actions.extend(child_actions)
                if child_extra_conditions.strip() != "":
                    extra_conditions = extra_conditions + " | " + child_extra_conditions
            return actions, extra_conditions

    if len(actions) == 0 and isinstance(in_tree, ParentedTree):
        for child in in_tree:
            child_actions, child_extra_conditions = run_dfs_IR_action(child, dep_graph, agents, cond_ctx, act_ctx,
                                                                      global_context_dict, not_logic, False, probable)

            actions.extend(child_actions)
            if child_extra_conditions.strip() != "":
                extra_conditions = extra_conditions + " & " + child_extra_conditions

    extra_conditions = extra_conditions.strip()
    while extra_conditions.startswith("&") or extra_conditions.endswith("&") \
            or extra_conditions.startswith("|") or extra_conditions.endswith("|") \
            or extra_conditions.endswith("!"):
        extra_conditions = extra_conditions.strip().strip("&").strip("|").strip()
    return actions, extra_conditions


def parse_cond_act_IR(parsed_data_list: list, is_condition, cond_ctx, act_ctx, text2id_dict, ignore_list,
                      strict=False) -> (str, set):
    from script_context import get_line_part_context
    if len(parsed_data_list) == 0:
        return "", "", set(), []

    full_plain_text = ""
    full_parsed_condition_text = ""
    actions = []
    full_agent_set = set()

    for parsed_data in parsed_data_list:
        in_text = parsed_data["parsed_str"]
        in_dep_tree = parsed_data["tree"]
        in_line = parsed_data["line"]
        in_position = parsed_data["position"]
        global_context_dict = get_line_part_context(in_line[:in_position], text2id_dict, ignore_list)

        temp_text = "<tree> <tree>" + in_text.replace("(", " <tree> ").replace(")", " </tree> ") \
            .replace(",", " </tree> <tree> ") + " </tree> </tree>"
        temp_file = open("temp2.txt", 'w')
        temp_file.write(temp_text + "\n")
        temp_file.close()

        try:
            in_xml_tree = ET.parse("temp2.txt")
        except:
            print("\n*** Parsing error in parse_cond_act_IR ***")
            print(in_text)
            print(temp_text)
            continue

        parsed_tree, agent = recur_xml_tree(in_xml_tree.getroot(), in_dep_tree)
        full_agent_set.update(agent)

        plain_text = run_dfs_plain(parsed_tree).strip()
        if plain_text == "()":
            plain_text = ""
        if full_plain_text == "":
            full_plain_text = plain_text
        else:
            full_plain_text = full_plain_text + " & " + plain_text

        if is_condition:
            parsed_text = run_dfs_IR_condition(parsed_tree, in_dep_tree, cond_ctx, act_ctx, global_context_dict,
                                               full_agent_set, strict, False).strip()
            if parsed_text == "()":
                parsed_text = ""
            elif full_parsed_condition_text == "":
                full_parsed_condition_text = parsed_text
            else:
                full_parsed_condition_text = full_parsed_condition_text + " & " + parsed_text
        else:
            new_actions, full_parsed_condition_text = run_dfs_IR_action(parsed_tree, in_dep_tree, full_agent_set,
                                                                        cond_ctx, act_ctx, global_context_dict, False,
                                                                        True, False)
            actions.extend(new_actions)

    return full_plain_text, full_parsed_condition_text, full_agent_set, actions


def clean_string(text: str) -> str:
    while "  " in text or "& &" in text or "| |" in text \
            or "!!" in text or "& ! &" in text or "| ! |" in text \
            or "(&" in text or "& )" in text or "! |" in text \
            or "! &" in text or "!()" in text or "() &" in text \
            or "( |" in text or "( &" in text or "& |" in text \
            or text.startswith("&") or text.endswith("&") \
            or text.startswith("|") or text.endswith("|") \
            or text.startswith(" ") or text.endswith(" ") \
            or text.endswith("!") or text.endswith("& !"):
        text = text.replace("  ", " ").replace("& &", "&").replace("| |", "|") \
            .replace("& ! &", "&").replace("| ! |", "|").replace("(&", "(").replace("& )", ")").replace("!!", "") \
            .replace("! |", "").replace("! &", "").replace("!()", "").replace("() &", "").replace("( |", "(") \
            .replace("( &", "(").replace("& |", "&")
        text = text.strip().strip("&").strip("|").rstrip("!").strip()

    return text


def get_IR_condition(condition, cond_ctx, act_ctx, text2id_dict, ignore_list) -> (str, set):
    connector = ""
    if condition["logic"] == "_AND_":
        connector = " & "
    if condition["logic"] == "_OR_":
        connector = " | "
    if condition["logic"] == "_NOT_":
        connector = " & !"
    if condition["logic"] == "_NOT__OR_":
        connector = " & !"
    if condition["logic"] == "_NOT__AND_":
        connector = " | !"

    if connector == "":
        return parse_cond_act_IR(condition["parsed_data"], True, cond_ctx, act_ctx, text2id_dict, ignore_list,
                                 condition["strict"]) if "parsed_data" in condition else ("", "", set(), [])

    result_str_plain = ""
    result_str_ir = ""
    agents = set()
    for sub_cond in condition["data"]:
        sub_cond_plain, sub_cond_ir, sub_agent, _ = get_IR_condition(sub_cond, cond_ctx, act_ctx, text2id_dict,
                                                                     ignore_list)
        if not sub_cond_plain.strip() == "":
            agents.update(sub_agent)
            if "|" in sub_cond_plain or "!" in sub_cond_plain:
                result_str_plain = result_str_plain + connector + "(" + sub_cond_plain + ")"
            else:
                result_str_plain = result_str_plain + connector + sub_cond_plain
            if "|" in sub_cond_ir or "!" in sub_cond_ir:
                result_str_ir = result_str_ir + connector + "(" + sub_cond_ir + ")"
            else:
                result_str_ir = result_str_ir + connector + sub_cond_ir

    result_str_plain = clean_string(result_str_plain)
    result_str_ir = clean_string(result_str_ir)

    return result_str_plain, result_str_ir, agents, {}


def recur_condition_context(condition: dict):
    condition_context = defaultdict(list)
    if isinstance(condition["data"], str):
        if "parsed_data" not in condition:
            return condition_context

        for cond in condition["parsed_data"]:
            cond_context = cond["tree"].get_context()
            for k in cond_context:
                condition_context[k].extend(cond_context[k])
        return condition_context

    for sub_cond in condition["data"]:
        sub_context = recur_condition_context(sub_cond)
        for k in sub_context:
            condition_context[k].extend(sub_context[k])

    return condition_context


def find_transition_context(transition: dict):
    condition_context = recur_condition_context(transition["condition"])

    action_context = defaultdict(list)
    for act in transition["action"]:
        act_context = act["tree"].get_context()
        for k in act_context:
            action_context[k].extend(act_context[k])

    return condition_context, action_context


def check_msg_condition(condition, msg_label):
    condition = condition.replace("(chan_UM = chanUM_{})".format(msg_label), "")
    condition = condition.replace("(chan_MU = chanMU_{})".format(msg_label), "")
    condition = condition.replace("(mme_wait_for = {})".format(get_check_mme_wait_for(msg_label)), "")
    condition = clean_string(condition)
    return condition


def get_cond_str(condition_dict: dict) -> List[str]:
    results = []
    if "data" in condition_dict:
        if isinstance(condition_dict["data"], str):
            results.append(condition_dict["data"].strip())
        else:
            for child_cond in condition_dict["data"]:
                results.extend(get_cond_str(child_cond))
    return results


def get_IR_transitions(transition_list: list, text2id_dict, ignore_list, section_states, current_section) -> list:
    result_transitions = []
    global_context_dict = call_get_context_copy()

    for transition in transition_list:
        if len(transition["start_state"]) == 0:
            if "any" not in global_context_dict["last_start_states"]:
                transition["start_state"] = copy.deepcopy(global_context_dict["last_start_states"])
            elif global_context_dict["last_state"].strip() != "":
                transition["start_state"] = [copy.deepcopy(global_context_dict["last_state"])]
            else:
                depending_state = get_depending_state(section_states, current_section)
                if depending_state != "":
                    transition["start_state"].append(depending_state)
                else:
                    transition["start_state"].append("any")
        else:
            call_update_context_key_value("last_start_states", copy.deepcopy(transition["start_state"]))

        if len(transition["end_state"]) == 0:
            transition["end_state"].append("_UNK_")
        else:
            call_update_context_key_value("last_end_states", copy.deepcopy(transition["end_state"]))

        cond_ctx, act_ctx = find_transition_context(transition)

        for s_state in transition["start_state"]:
            for e_state in transition["end_state"]:

                agents = set()

                condition_plain, condition_ir, cond_agents, _ = get_IR_condition(transition["condition"], cond_ctx,
                                                                                 act_ctx, text2id_dict, ignore_list)
                if condition_plain.strip() == "":
                    condition_plain = "EMPTY_plain???"
                if condition_ir.strip() == "":
                    condition_ir = ""

                agents.update(cond_agents)
                if len(agents) > 0:
                    call_update_context_key_value("agents", agents)
                else:
                    agents = global_context_dict["agents"]

                action_plain, _, act_agents, action_ir = "", "", set(), {}
                if transition["action"] is not None:
                    action_plain, action_condition, act_agents, action_ir, = \
                        parse_cond_act_IR(transition["action"], False, cond_ctx, act_ctx, text2id_dict, ignore_list,
                                          False)
                    action_condition = action_condition.strip().strip("&").strip("|").strip()

                    if EMPTY_COIN_TOSS and condition_ir.strip() == "" and action_condition.strip() == "" and len(action_ir) > 0:
                        condition_ir = get_new_empty_condition_coin_toss()
                    if action_condition.strip() != "" and condition_ir.strip() != "":
                        condition_ir = "(" + copy.deepcopy(condition_ir) + ") & " + action_condition
                        condition_ir = condition_ir.strip().strip("&").strip("|").strip()
                    elif action_condition.strip() != "" and condition_ir.strip() == "":
                        condition_ir = action_condition
                        condition_ir = condition_ir.strip().strip("&").strip("|").strip()

                agents.update(act_agents)

                if len(agents) == 0:
                    agents = global_context_dict["agents"]
                else:
                    call_update_context_key_value("agents", agents)

                t_text_plain = \
                    s_state + " -> " + e_state + "[label = \"" + condition_plain + " / " + action_plain + "\"]"

                new_transition = {
                    "condition_text": "condition : " + str(get_cond_str(transition["condition"])),
                    "action_text": "action : " +
                                   ", ".join([action1["str"] for action1 in transition["action"]]).strip().strip(
                                       ",").strip(),
                    "text_plain": t_text_plain,
                    "agents": agents,
                    "s_state": s_state,
                    "e_state": e_state,
                    "is_ue": transition["is_ue"] if "is_ue" in transition else False,
                    "condition_plain": condition_plain,
                    "action_plain": action_plain,
                    "condition_ir": condition_ir,
                    "action_ir": action_ir,
                    "text_ir": merge_ir_text(s_state, e_state, condition_ir, action_ir)
                }

                result_transitions.append(new_transition)

    return result_transitions
