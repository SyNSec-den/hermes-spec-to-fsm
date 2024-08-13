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

from word2number import w2n
from num2words import num2words

from script_msg_helpers import get_msg_direction, get_msg_response, get_mme_wait_for, \
    get_check_mme_wait_for, check_valid_msg
from script_helpers import replace_start_num_keyword
import script_config


INTEGRITY_SERVICE = "integrity_protection"
CIPHERING_SERVICE = "nas_ciphering"
PARTIAL_CIPHERING_SERVICE = "partial_ciphering"

ERROR_CAUSE_SUFFIX = "_error_cause_value"
ERROR_CAUSE = "_error_cause"
if script_config.GEN == "4g":
    ERROR_CAUSE_SUFFIX = "_emm_cause_value"
    ERROR_CAUSE = "emm_cause"
elif script_config.GEN == "5g":
    ERROR_CAUSE_SUFFIX = "_five_gmm_cause_value"
    ERROR_CAUSE = "five_gmm_cause"


variables_dict = {}
msg_field_vars = {}
sqn_dict = set()
ue_states = set()
mme_states = set()
coin_toss_counter = 0

def add_variable(var_name: str, data_type: str, control_type: str, possible_values=None, initial_value=None, fsm=None,
                 mutual_exlusion=False):
    global variables_dict

    if possible_values is None:
        possible_values = []
    possible_values_str = ""

    if var_name in variables_dict and "possiblevalues" in variables_dict[var_name]:
        previous_values = variables_dict[var_name]["possiblevalues"].split(",")
        possible_values.extend(previous_values)
        possible_values = set(possible_values)

    for val in possible_values:
        possible_values_str = possible_values_str + "," + str(val)
    possible_values_str = possible_values_str.strip(",")

    var_dict = {}
    if var_name in variables_dict:
        var_dict = variables_dict[var_name]

    var_dict["datatype"] = data_type
    var_dict["controltype"] = control_type

    if possible_values_str != "":
        var_dict["possiblevalues"] = possible_values_str

    if initial_value is not None and control_type != "environment":
        var_dict["initialvalue"] = str(initial_value)

    if fsm is not None:
        var_dict["fsm"] = str(fsm)

    if mutual_exlusion:
        var_dict["mutualexlusion"] = "yes"

    variables_dict[var_name] = var_dict


def get_all_variables() -> dict:
    return variables_dict


def get_all_sqn() -> set:
    return sqn_dict


def add_state(fsm: str, state_name: str):
    state_name = state_name.strip()
    if state_name == "" or state_name == "any" or state_name == "_UNK_":
        return

    global ue_states
    global mme_states

    if fsm == "ue" or fsm == "UE":
        ue_states.add(state_name)
        mme_states.add(state_name)
    elif fsm == "mme" or fsm == "MME":
        mme_states.add(state_name)
        ue_states.add(state_name)


def get_all_states() -> (set, set):
    return ue_states, mme_states

def add_msg_field_var(msg: str, field_var: str):
    global msg_field_vars
    if msg not in msg_field_vars:
        msg_field_vars[msg] = set()

    msg_field_vars[msg].add(field_var)


def get_all_msg_field_vars() -> dict:
    return msg_field_vars

def get_new_boolean_coin_toss() -> str:
    global coin_toss_counter
    coin_name = "coin_toss_" + str(coin_toss_counter)
    coin_toss_counter = coin_toss_counter + 1
    add_variable(coin_name, "boolean", "environment", ["TRUE", "FALSE"])
    return coin_name


def get_new_empty_condition_coin_toss() -> str:
    global coin_toss_counter
    coin_name = "empty_coin_toss_" + str(coin_toss_counter)
    coin_toss_counter = coin_toss_counter + 1
    add_variable(coin_name, "boolean", "environment", ["TRUE", "FALSE"])
    return coin_name


def get_new_enumerate_coin_toss(num_cases: int) -> str:
    global coin_toss_counter
    coin_name = "coin_toss_" + str(coin_toss_counter)
    coin_toss_counter = coin_toss_counter + 1
    possible_values = [num2words(item, to='cardinal') for item in range(num_cases)]

    add_variable(coin_name, "enumerate", "environment", possible_values)
    return coin_name


def get_new_proc_enumerate_coin_toss(num_cases: int) -> str:
    global coin_toss_counter
    coin_name = "proc_coin_toss_" + str(coin_toss_counter)
    coin_toss_counter = coin_toss_counter + 1
    possible_values = [num2words(item, to='cardinal') for item in range(num_cases)]

    add_variable(coin_name, "enumerate", "environment", possible_values)
    return coin_name


def get_new_msg_enumerate_coin_toss(num_cases: int) -> str:
    global coin_toss_counter
    coin_name = "msg_coin_toss_" + str(coin_toss_counter)
    coin_toss_counter = coin_toss_counter + 1
    possible_values = [num2words(item, to='cardinal') for item in range(num_cases)]

    add_variable(coin_name, "enumerate", "environment", possible_values)
    return coin_name



def get_chan_start_end(ue_to_mme: bool) -> (str, str):
    if ue_to_mme:
        return "UE", "MME"
    else:
        return "MME", "UE"


def get_channel(action_type, action_details, agents=None) -> (str, str, str):
    channel = "internal"
    chan_start, chan_end = get_chan_start_end(ue_to_mme=True)

    if agents is None:
        agents = set()

    if action_type in ["timer", "var", "procedure"]:
        channel = "internal"
        if "ue" in agents:
            chan_start, chan_end = get_chan_start_end(ue_to_mme=True)
        if "mme" in agents:
            chan_start, chan_end = get_chan_start_end(ue_to_mme=False)

    elif action_type in ["message"]:
        if not check_valid_msg(action_details):
            channel = "chan_UM"
            chan_start, chan_end = get_chan_start_end(ue_to_mme=True)
        else:
            msg_dir = get_msg_direction(action_details)
            if msg_dir == "ue_to_mme":
                channel = "chan_UM"
                chan_start, chan_end = get_chan_start_end(ue_to_mme=True)

            elif msg_dir == "mme_to_ue":
                channel = "chan_MU"
                chan_start, chan_end = get_chan_start_end(ue_to_mme=False)

            elif msg_dir == "both_dir":
                if "ue" in agents:
                    channel = "chan_UM"
                    chan_start, chan_end = get_chan_start_end(ue_to_mme=True)
                elif "mme" in agents:
                    channel = "chan_MU"
                    chan_start, chan_end = get_chan_start_end(ue_to_mme=False)
                else:
                    channel = "chan_UM"
                    chan_start, chan_end = get_chan_start_end(ue_to_mme=True)
            else:
                channel = "chan_UM"
                chan_start, chan_end = get_chan_start_end(ue_to_mme=True)

    return channel, chan_start, chan_end




def condition_initiate_procedure(procedure: str) -> str:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")
    return "initiate_" + procedure


def condition_require_procedure(procedure: str) -> str:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")
    return procedure + "_required"


def condition_running_procedure(procedure: str) -> str:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")
    return "procedure_{}_state = RUNNING".format(procedure)


def condition_stopped_procedure(procedure: str) -> str:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")
    return "procedure_{}_state = STOPPED".format(procedure)


def condition_fail_procedure(procedure: str) -> str:
    return condition_stopped_procedure(procedure)


def condition_reject_procedure(procedure: str) -> str:
    return condition_stopped_procedure(procedure)


def condition_completed_procedure(procedure: str) -> str:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")
    return "procedure_{}_state = COMPLETED".format(procedure)


def condition_running_timer(timer: str) -> str:
    add_variable("timer_{}_started".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable("timer_{}_expired".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "(timer_{}_started & !timer_{}_expired)".format(timer, timer)


def condition_expired_timer(timer: str) -> str:
    add_variable("timer_{}_started".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable("timer_{}_expired".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "(timer_{}_started & timer_{}_expired)".format(timer, timer)


def condition_stopped_timer(timer: str) -> str:
    add_variable("timer_{}_started".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable("timer_{}_expired".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!timer_{}_started".format(timer)


def condition_receive_message(message: str, agents=None) -> str:
    from script_dep2ir import call_update_context_key_value
    if agents is None:
        agents = {}
    channel, _, _ = get_channel("message", message, agents)
    if get_msg_direction(message) == "both_dir":
        if "ue" in agents:
            channel = "chan_MU"
            if check_valid_msg(message):
                call_update_context_key_value("last_chanMU", message)
        elif "mme" in agents:
            channel = "chan_UM"
            if check_valid_msg(message):
                call_update_context_key_value("last_chanUM", message)
        else:
            channel = "chan_MU"
            if check_valid_msg(message):
                call_update_context_key_value("last_chanMU", message)

    if channel == "chan_UM":
        check_mme_wait_for_status = get_check_mme_wait_for(message)
        if check_mme_wait_for_status != "":
            add_variable("mme_wait_for", "enumerate", "state", ["NONE", check_mme_wait_for_status], "NONE")
            return "(chan_UM = chanUM_" + message + ") & (mme_wait_for = " + check_mme_wait_for_status + ")"
        else:
            return "(chan_UM = chanUM_" + message + ")"
    else:
        return "(chan_MU = chanMU_" + message + ")"


def condition_accept_message(message: str) -> str:
    add_variable("accept_message_{}".format(message), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "accept_message_{}".format(message)


def condition_reject_message(message: str) -> str:
    add_variable("accept_message_{}".format(message), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!accept_message_{}".format(message)


def condition_dropped_message(message: str) -> str:
    return "!(" + condition_accept_message(message) + ")"


def condition_integrity_protected_message(message: str) -> str:
    add_variable(message + "_integrity_protected", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return message + "_integrity_protected" + " & " + condition_activated_service(INTEGRITY_SERVICE)


def condition_not_integrity_protected_message(message: str) -> str:
    add_variable(message + "_integrity_protected", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!(" + message + "_integrity_protected" + " & " + condition_activated_service(INTEGRITY_SERVICE) + ")"


def condition_ciphered_message(message: str) -> str:
    add_variable(message + "_ciphered", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return message + "_ciphered" + " & " + condition_activated_service(CIPHERING_SERVICE)


def condition_unciphered_message(message: str) -> str:
    add_variable(message + "_ciphered", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!(" + message + "_ciphered" + " & " + condition_activated_service(CIPHERING_SERVICE) + ")"


def condition_parially_ciphered_message(message: str) -> str:
    add_variable(message + "_partially_ciphered", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return message + "_partially_ciphered" + " & " + condition_activated_service(PARTIAL_CIPHERING_SERVICE)


def condition_valid_var(var: str) -> str:
    if var == "mac_code":
        return condition_not_indicate_event("mac_code_failure")
    elif var == "sqn":
        return condition_not_indicate_event("sqn_failure")
    var_name = var + "_valid"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return var_name


def condition_validate_integrity() -> str:
    add_variable("integrity_validated", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return "integrity_validated"


def condition_invalid_var(var: str) -> str:
    if var == "mac_code":
        return condition_indicate_event("mac_code_failure")
    elif var == "sqn":
        return condition_indicate_event("sqn_failure")
    var_name = var + "_valid"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!" + var_name


def condition_changed_var(var: str) -> str:
    var_name = var + "_changed"
    add_variable(var_name, "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return var_name


def condition_changed_var_in_msg(var: str, msg: str) -> str:
    var_name = msg + "_" + var + "_changed"
    add_variable(var_name, "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return var_name


def condition_receive_var_in_msg(var: str, msg: str) -> str:
    var_name = msg + "_" + var + "_present"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_msg_field_var(msg, var_name)
    return var_name


def condition_receive_var_in_msg_val(var: str, msg: str, val: str) -> str:
    if msg == "" or val == ";" or val == "." or val == "" or var == "":
        return ""
    _, val = replace_start_num_keyword(val)
    var_name = msg + "_" + var + "_value"
    add_variable(var_name, "enumerate", "state", ["NONE", val], "NONE")
    add_msg_field_var(msg, var_name)
    return "(" + var_name + " = " + val + ")"


def condition_receive_esm_msg_in_msg(esm_msg: str, msg: str) -> str:
    if msg == "" or esm_msg == "":
        return ""
    return condition_receive_var_in_msg(esm_msg, msg)


def condition_receive_field_in_msg(field: str, msg: str) -> str:
    if msg == "" or field == "":
        return ""
    return condition_receive_var_in_msg(field, msg)


def condition_field_in_msg_val(field: str, msg: str, val: str) -> str:
    if msg == "" or field == "" or val == "":
        return ""
    return condition_receive_var_in_msg_val(field, msg, val) + " & " + condition_receive_var_in_msg(field, msg)


def condition_message_cause(cause: str, msg: str) -> str:
    var_name = msg + ERROR_CAUSE_SUFFIX
    add_variable(var_name, "enumerate", "state", ["NONE", cause], "NONE")
    add_msg_field_var(msg, var_name)
    return "(" + var_name + " = " + cause + ")"


def condition_mode(mode: str) -> str:
    add_variable(mode, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return mode


def condition_support_service(service: str) -> str:
    add_variable("support_" + service, "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return "support_" + service


def condition_configure_service(service: str) -> str:
    add_variable(service + "_configured", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return service + "_configured"


def condition_activated_service(service: str) -> str:
    add_variable(service + "_activated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return service + "_activated"


def condition_deactivated_service(service: str) -> str:
    add_variable(service + "_activated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return "!" + service + "_activated"


def condition_requested_service(service: str) -> str:
    add_variable(service + "_requested", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return service + "_requested"


def condition_indicate_event(event: str) -> str:
    add_variable(event, "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return event


def condition_not_indicate_event(event: str) -> str:
    add_variable(event, "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    return "!" + event


def condition_leave_state(state: str, agents=None) -> str:
    if agents is None:
        agents = {}
    if "ue" in agents:
        add_state("ue", state)
        return "(ue_state = " + state + ")"
    elif "mme" in agents:
        add_state("mme", state)
        return "(mme_state = " + state + ")"
    else:
        add_state("ue", state)
        return "(ue_state = " + state + ")"


def condition_maintain_counter(counter: str) -> str:
    add_variable(counter + "_present", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return counter + "_present"


def condition_camp_cell(cell: str) -> str:
    add_variable(cell + "_camping", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    return cell + "_camping"


def condition_var_equals(var: str, val: str) -> str:
    if val == ";" or val == "." or val == "" or var == "":
        return ""
    _, val = replace_start_num_keyword(val)
    add_variable(var + "_value", "enumerate", "environment", ["NONE", val], "NONE")
    return "(" + var + "_value" + " = " + val + ")"


def condition_set_var_to_val(var: str, val: str) -> str:
    return condition_var_equals(var, val)


def condition_set_msg_field_to_val(field: str, message: str, val: str) -> str:
    if message == "" or field == "" or val == "":
        return ""
    return condition_receive_var_in_msg_val(field, message, val)


def condition_reset_var(var: str) -> str:
    global sqn_dict
    sqn_dict.add(var + "_value")
    add_variable(var + "_value", "enumerate", "state", ["NONE", "0"], "NONE")
    return "(" + var + "_value = 0)"



def action_start_timer(timer: str, agents=None) -> list:
    add_variable("timer_{}_started".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable("timer_{}_expired".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")

    label = "timer_{}_started = TRUE".format(timer)
    channel, chan_start, chan_end = get_channel("timer", timer, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_stop_timer(timer: str, agents=None) -> list:
    add_variable("timer_{}_started".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable("timer_{}_expired".format(timer), "boolean", "state", ["TRUE", "FALSE"], "FALSE")

    label = "timer_{}_started = FALSE".format(timer)
    channel, chan_start, chan_end = get_channel("timer", timer, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_send_message(message: str, agents=None) -> list:
    from script_dep2ir import call_update_context_key_value
    label = message
    channel, chan_start, chan_end = get_channel("message", message, agents)
    actions = [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]

    if check_valid_msg(message) and channel == "chan_MU":
        call_update_context_key_value("last_chanMU", message)
    elif check_valid_msg(message) and channel == "chan_UM":
        call_update_context_key_value("last_chanUM", message)

    wait_for_state = get_mme_wait_for(message)
    if wait_for_state != "":
        add_variable("mme_wait_for", "enumerate", "state", ["NONE", wait_for_state], "FALSE")
        channel2, chan_start2, chan_end2 = get_channel("var", "mme_wait_for", agents)
        actions.append({"label": "mme_wait_for = " + wait_for_state, "channel": channel2, "chan_start": chan_start2,
                        "chan_end": chan_end2})

    return actions


def action_accept_message(message: str, agents=None) -> list:
    add_variable("accept_message_{}".format(message), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = "accept_message_{} = TRUE".format(message)
    channel, chan_start, chan_end = get_channel("var", "accept_message_{}".format(message), agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_reject_message(message: str, agents=None) -> list:
    add_variable("accept_message_{}".format(message), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = "accept_message_{} = FALSE".format(message)
    channel, chan_start, chan_end = get_channel("var", "accept_message_{}".format(message), agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_check_accept_message(message: str, agents=None) -> list:
    add_variable("accept_message_{}".format(message), "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = "accept_message_{} = {}".format(message, get_new_boolean_coin_toss())
    channel, chan_start, chan_end = get_channel("var", "accept_message_{}".format(message), agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_check_valid_var(var: str, agents=None) -> list:
    add_variable(var + "_valid", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var + "_valid = " + get_new_boolean_coin_toss()
    channel, chan_start, chan_end = get_channel("var", var + "_valid", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_respond_to_message(message: str, agents=None) -> list:
    from script_dep2ir import call_update_context_key_value
    label = get_msg_response(message)
    if label == "unk_resp":
        return []
    channel, chan_start, chan_end = get_channel("message", label, agents)

    if check_valid_msg(message) and channel == "chan_MU":
        call_update_context_key_value("last_chanMU", message)
    elif check_valid_msg(message) and channel == "chan_UM":
        call_update_context_key_value("last_chanUM", message)

    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_cipher_message(message: str, agents=None) -> list:
    add_variable(message + "_ciphered", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = message + "_ciphered = TRUE"
    channel, chan_start, chan_end = get_channel("var", message + "_ciphered", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_not_cipher_message(message: str, agents=None) -> list:
    add_variable(message + "_ciphered", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = message + "_ciphered = FALSE"
    channel, chan_start, chan_end = get_channel("var", message + "_ciphered", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_drop_message(message: str, agents=None) -> list:
    return action_reject_message(message, agents)


def action_not_drop_message(message: str, agents=None) -> list:
    return action_accept_message(message, agents)


def action_integrity_protect_message(message: str, agents=None) -> list:
    add_variable(message + "_integrity_protected", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = message + "_integrity_protected = TRUE"
    channel, chan_start, chan_end = get_channel("var", message + "_integrity_protected", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_not_integrity_protect_message(message: str, agents=None) -> list:
    add_variable(message + "_integrity_protected", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = message + "_integrity_protected = FALSE"
    channel, chan_start, chan_end = get_channel("var", message + "_integrity_protected", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_check_integrity_protect_message(message: str, agents=None) -> list:
    add_variable(message + "_integrity_protected", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = message + "_integrity_protected = {}".format(get_new_boolean_coin_toss())
    channel, chan_start, chan_end = get_channel("var", message + "_integrity_protected", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_initiate_proc(procedure: str, agents=None) -> list:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")

    label = "initiate_" + procedure + " = TRUE"
    channel, chan_start, chan_end = get_channel("procedure", procedure, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_start_procedure(procedure: str, agents=None) -> list:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")

    label = "procedure_{}_state = RUNNING".format(procedure)
    channel, chan_start, chan_end = get_channel("procedure", procedure, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_stop_procedure(procedure: str, agents=None) -> list:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")

    label = "procedure_{}_state = STOPPED".format(procedure)
    channel, chan_start, chan_end = get_channel("procedure", procedure, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_fail_procedure(procedure: str, agents=None) -> list:
    return action_stop_procedure(procedure, agents)


def action_reject_procedure(procedure: str, agents=None) -> list:
    return action_stop_procedure(procedure, agents)


def action_suspend_procedure(procedure: str, agents=None) -> list:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")

    label = "procedure_{}_state = SUSPENDED".format(procedure)
    channel, chan_start, chan_end = get_channel("procedure", procedure, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_complete_procedure(procedure: str, agents=None) -> list:
    add_variable("initiate_" + procedure, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(procedure + "_required", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    add_variable("procedure_{}_state".format(procedure), "enumerate", "state",
                 ["NONE", "RUNNING", "SUSPENDED", "STOPPED", "COMPLETED"], "NONE")

    label = "procedure_{}_state = COMPLETED".format(procedure)
    channel, chan_start, chan_end = get_channel("procedure", procedure, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_save_var(var: str, agents=None) -> list:
    add_variable(var + "_valid", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(var + "_deleted", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var + "_valid = TRUE"
    label2 = var + "_deleted = FALSE"
    channel, chan_start, chan_end = get_channel("var", var + "_valid", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end},
            {"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_delete_var(var: str, agents=None) -> list:
    add_variable(var + "_valid", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_variable(var + "_deleted", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var + "_valid = FALSE"
    label_2 = var + "_deleted = TRUE"
    channel, chan_start, chan_end = get_channel("var", var + "_valid", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end},
            {"label": label_2, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_valid_var(var: str, agents=None) -> list:
    return action_save_var(var, agents)


def action_invalid_var(var: str, agents=None) -> list:
    return action_delete_var(var, agents)


def action_update_var(var: str, agents=None) -> list:
    add_variable(var + "_updated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var + "_updated = TRUE"
    channel, chan_start, chan_end = get_channel("var", var, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_not_update_var(var: str, agents=None) -> list:
    add_variable(var + "_updated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var + "_updated = FALSE"
    channel, chan_start, chan_end = get_channel("var", var, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_send_var(var: str, agents=None) -> list:
    var_name = var + "_sent"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = var_name + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", var_name, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_send_var_in_msg(var: str, msg: str, agents=None) -> list:
    if msg == "" or var == "":
        return []

    var_name = msg + "_" + var + "_present"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_msg_field_var(msg, var_name)
    label = var_name + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", var_name, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_not_send_var_in_msg(var: str, msg: str, agents=None) -> list:
    if msg == "" or var == "":
        return []

    var_name = msg + "_" + var + "_present"
    add_variable(var_name, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_msg_field_var(msg, var_name)
    label = var_name + " = FALSE"
    channel, chan_start, chan_end = get_channel("var", var_name, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_send_field_in_msg(field: str, msg: str, agents=None) -> list:
    return action_send_var_in_msg(field, msg, agents)


def action_not_send_field_in_msg(field: str, msg: str, agents=None) -> list:
    return action_not_send_var_in_msg(field, msg, agents)


def action_send_var_in_msg_val(var: str, msg: str, val: str, agents=None) -> list:
    if msg == "" or val == "" or val == "." or val == ";" or var == "":
        return []
    return action_set_msg_field_to_val(var, msg, val, agents)


def action_send_field_in_msg_val(field: str, msg: str, val: str, agents=None) -> list:
    return action_send_var_in_msg_val(field, msg, val, agents)


def action_consume_var_in_msg(var: str, msg: str, agents=None) -> list:
    if msg == "" or var == "":
        return []
    var_name = msg + "_" + var + "_present"
    add_variable(msg + "_" + var + "_present", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    add_msg_field_var(msg, var_name)
    label = var_name + " = FALSE"
    channel, chan_start, chan_end = get_channel("var", var, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_send_esm_msg_in_msg(esm_msg: str, msg: str, agents=None) -> list:
    if msg == "" or esm_msg == "":
        return []
    return action_send_var_in_msg(esm_msg, msg, agents)


def action_message_cause(cause: str, msg: str, agents=None) -> list:
    var_name = msg + ERROR_CAUSE_SUFFIX
    add_variable(var_name, "enumerate", "state", ["NONE", cause], "NONE")
    add_msg_field_var(msg, var_name)
    label = var_name + " = " + cause
    channel, chan_start, chan_end = get_channel("var", var_name, agents)

    results = action_send_field_in_msg(ERROR_CAUSE, msg, agents)
    results.append({"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end})

    return results


def action_exist_var(var: str, agents=None) -> list:
    return action_valid_var(var, agents)


def action_activate_service(service: str, agents=None) -> list:
    add_variable(service + "_activated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = service + "_activated = TRUE"
    channel, chan_start, chan_end = get_channel("var", service, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_support_service(service: str, agents=None) -> list:
    add_variable("support_" + service, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = "support_" + service + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", "support_" + service, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_configure_service(service: str, agents=None) -> list:
    add_variable(service + "_configured", "boolean", "environment", ["TRUE", "FALSE"], "FALSE")
    label = service + "_configured" + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", service + "_configured", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_deactivate_service(service: str, agents=None) -> list:
    add_variable(service + "_activated", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = service + "_activated = FALSE"
    channel, chan_start, chan_end = get_channel("var", service, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_request_service(service: str, agents=None) -> list:
    add_variable(service + "_requested", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = service + "_requested = TRUE"
    channel, chan_start, chan_end = get_channel("var", service + "_requested", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_activate_mode(mode: str, agents=None) -> list:
    add_variable(mode, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = mode + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", mode, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_deactivate_mode(mode: str, agents=None) -> list:
    add_variable(mode, "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = mode + " = FALSE"
    channel, chan_start, chan_end = get_channel("var", mode, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_set_var_to_val(var: str, val: str, agents=None) -> list:
    if val == "" or val == "." or val == ";" or var == "":
        return []
    _, val = replace_start_num_keyword(val)
    add_variable(var + "_value", "enumerate", "state", ["NONE", val], "NONE")
    label = var + "_value" + " = " + val
    channel, chan_start, chan_end = get_channel("var", var + "_value", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_set_msg_field_to_val(field: str, message: str, val: str, agents=None) -> list:
    if val == "" or val == "." or val == ";" or field == "" or message == "":
        return []
    _, val = replace_start_num_keyword(val)
    var_name = message + "_" + field + "_value"
    add_variable(var_name, "enumerate", "state", ["NONE", val], "NONE")
    add_msg_field_var(message, var_name)
    label = var_name + " = " + val
    channel, chan_start, chan_end = get_channel("var", var_name, agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_reset_var(var: str, agents=None) -> list:
    add_variable(var + "_value", "enumerate", "state", ["NONE", "0"], "NONE")
    label = var + "_value" + " = 0"
    channel, chan_start, chan_end = get_channel("var", var + "_value", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_camp_cell(cell: str, agents=None) -> list:
    add_variable(cell + "_camping", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = cell + "_camping" + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", cell + "_camping", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_maintain_counter(counter: str, agents=None) -> list:
    add_variable(counter + "_present", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
    label = counter + "_present" + " = TRUE"
    channel, chan_start, chan_end = get_channel("var", counter + "_present", agents)
    return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]


def action_increase_var_by_val(var: str, val: str, agents=None) -> list:
    global sqn_dict

    if val == ";" or val == "." or val == "" or var == "":
        return []
    _, val = replace_start_num_keyword(val)
    sqn_dict.add(var + "_value")

    try:
        label = var + "_value" + " = " + var + "_value + " + str(1)
        channel, chan_start, chan_end = get_channel("var", var + "_value", agents)
        return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
    except:
        return []


def action_decrease_var_by_val(var: str, val: str, agents=None) -> list:
    if val == ";" or val == "." or val == "" or var == "":
        return []
    _, val = replace_start_num_keyword(val)
    add_variable(var + "_value", "enumerate", "state", ["NONE", val], "NONE")

    if val.isnumeric():
        add_variable(var + "_value_decreament", "boolean", "state", ["TRUE", "FALSE"], "FALSE")
        label = var + "_value_decreament = TRUE"
        channel, chan_start, chan_end = get_channel("var", var + "_value", agents)
        return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
    else:
        try:
            label = var + "_value" + " = " + var + "_value - " + str(w2n.word_to_num(val))
            channel, chan_start, chan_end = get_channel("var", var + "_value", agents)
            return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
        except:
            return []


def action_enter_state(state: str, agents=None) -> list:
    if agents is None:
        agents = {}
    if "ue" in agents:
        label = "ue_state = " + state
        channel, chan_start, chan_end = get_channel("var", "ue_state", agents)
        return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
    elif "mme" in agents:
        label = "mme_state = " + state
        channel, chan_start, chan_end = get_channel("var", "mme_state", agents)
        return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
    else:
        label = "ue_state = " + state
        channel, chan_start, chan_end = get_channel("var", "ue_state", agents)
        return [{"label": label, "channel": channel, "chan_start": chan_start, "chan_end": chan_end}]
