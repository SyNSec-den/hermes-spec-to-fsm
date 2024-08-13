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

from script_helpers import get_text_type, isHeader
from script_text2id import get_ids_from_text_db


def init_context() -> None:
    import script_context_config
    script_context_config.global_context = {
        "last_start_states": {"any"},
        "last_end_states": {"_UNK_"},
        "agents": {"agent_ue"},
        "last_state": "",
        "last_agent": "",
        "last_message": "",
        "last_message_list": [],
        "last_chanMU": "",
        "last_chanUM": "",
        "last_var": "",
        "last_event": "",
        "last_procedure": "",
        "last_timer": "",
        "last_msg_field": "",
        "last_directive": "",
        "last_counter": ""
    }


def clear_context() -> None:
    import script_context_config
    script_context_config.global_context["last_start_states"] = {"any"}
    script_context_config.global_context["last_end_states"] = {"_UNK_"}
    script_context_config.global_context["agents"] = {"agent_ue"}
    script_context_config.global_context["last_state"] = ""
    script_context_config.global_context["last_agent"] = ""
    script_context_config.global_context["last_directive"] = ""
    script_context_config.global_context["last_counter"] = ""
    script_context_config.global_context["last_chanMU"] = ""
    script_context_config.global_context["last_chanUM"] = ""


def get_context_copy() -> dict:
    import script_context_config
    return copy.deepcopy(script_context_config.global_context)


def update_context_key_value(key: str, value) -> None:
    import script_context_config
    script_context_config.global_context[key] = value


def update_context_with_text(global_context, para: str, text2id_dict, ignore_list=None) -> None:
    if ignore_list is None:
        ignore_list = []

    keywords_list = get_ids_from_text_db(para, text2id_dict["all2id"], 2, ignore_list)
    keywords_list.reverse()
    keywords_list = [item[0] for item in keywords_list]

    messages = []

    for item in keywords_list:
        if "agent" in get_text_type(item, text2id_dict):
            global_context["last_agent"] = item
            break
    for item in keywords_list:
        if "message" in get_text_type(item, text2id_dict):
            messages.append(item)
            global_context["last_message"] = item
            break
    for item in keywords_list:
        if "var" in get_text_type(item, text2id_dict):
            global_context["last_var"] = item
            break
    for item in keywords_list:
        if "event" in get_text_type(item, text2id_dict):
            global_context["last_event"] = item
            break
    for item in keywords_list:
        if "procedure" in get_text_type(item, text2id_dict):
            global_context["last_procedure"] = item
            break
    for item in keywords_list:
        if "timer" in get_text_type(item, text2id_dict):
            global_context["last_timer"] = item
            break
    for item in keywords_list:
        if "msg_field" in get_text_type(item, text2id_dict):
            global_context["last_msg_field"] = item
            break
    for item in keywords_list:
        if "counter" in get_text_type(item, text2id_dict):
            global_context["last_counter"] = item
            break
    for item in keywords_list:
        if "directive" in get_text_type(item, text2id_dict):
            global_context["last_directive"] = item
            break

    if len(messages) > 0:
        global_context["last_message_list"] = messages


def update_global_context_with_text(para: str, text2id_dict, ignore_list=None) -> None:
    import script_context_config
    update_context_with_text(script_context_config.global_context, para, text2id_dict, ignore_list)


def update_header_context(text: str):
    import script_context_config
    header_context = script_context_config.header_context
    is_header, header_name, header_type, header_level, header_text = isHeader(text)
    if not is_header:
        return False

    result = False
    if header_type == "section_header":
        for idx, item in enumerate(header_context):
            if item["level"] >= header_level:
                header_context = header_context[:idx]
        result = {"level": header_level, "type": header_type, "text": "__SECTION__" + header_text,
                  "header_val": header_name}
        header_context.append(result)

    elif header_type == "rrc_point":
        new_header_context = []
        for idx, item in enumerate(header_context):
            if item["type"] >= "section_header":
                new_header_context.append(item)
            elif item["type"] >= "rrc_point" and item["level"] < header_level:
                new_header_context.append(item)

        result = {"level": header_level, "type": header_type, "text": header_text, "header_val": header_name}
        new_header_context.append(result)

        header_context = new_header_context

    else:
        for idx, item in enumerate(header_context):
            if item["type"] == header_type:
                header_context = header_context[:idx]
        result = {"level": header_level, "type": header_type, "text": header_text, "header_val": header_name}
        header_context.append(result)

    script_context_config.header_context = header_context
    return result


def get_header_context() -> list:
    import script_context_config
    return script_context_config.header_context


def get_header_context_texts() -> list:
    header_context = get_header_context()
    result = []
    for ctx in header_context:
        if "text" in ctx:
            result.append(ctx["text"])
    return result


def get_line_part_context(line_part: str, text2id_dict, ignore_list=None):
    new_context = get_context_copy()

    update_context_with_text(new_context, line_part, text2id_dict, ignore_list)
    return new_context


def get_last_context(key: str, cond_ctx: dict, act_ctx: dict, global_ctx: dict, order="012", dir="") -> list:
    res_list = []
    for char in order:
        if len(res_list) == 0:
            if char == "0":
                res_list = cond_ctx[key]
            if char == "1":
                res_list = act_ctx[key]
            if char == "2" and key == "message" and dir == "ue_to_mme" and global_ctx["last_chanUM"] != "":
                res_list = [global_ctx["last_chanUM"]]
            elif char == "2" and key == "message" and dir == "mme_to_ue" and global_ctx["last_chanMU"] != "":
                res_list = [global_ctx["last_chanMU"]]
            elif char == "2" and key == "message" and len(global_ctx["last_message_list"]) > 0:
                res_list = global_ctx["last_message_list"]
            elif char == "2" and global_ctx["last_" + key] != "":
                res_list = [global_ctx["last_" + key]]
    if len(res_list) > 1 and not key == "message" and not key == "timer":
        res_list = [res_list[-1]]

    return res_list
