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

import logging
import os
import sys
import io
import xml.etree.ElementTree as ET

from typing import Dict

PY2 = sys.version_info[0] == 2
StringIO = io.BytesIO if PY2 else io.StringIO

logger = logging.getLogger(__name__)
action_channel_dict = {}


class Variable(object):
    def __init__(self, varname, datatype, controltype, initial_value, possible_values, mutualexclusion, fsm):
        self.varname = varname
        self.datatype = datatype
        self.controltype = controltype
        self.initial_value = initial_value
        self.possible_values = possible_values
        self.mutualexclusion = mutualexclusion
        self.fsm = fsm

    def set_varname(self, varname):
        self.varname = varname

    def set_datatype(self, datatype='boolean'):
        self.datatype = datatype

    def set_controltype(self, controltype='environment'):
        self.controltype = controltype


class MsgField(object):
    def __init__(self, msg: str, var_name: str, var_obj: Variable):
        self.msg = msg
        self.var_name = var_name
        self.var_obj = var_obj


class SequenceNumber(object):
    def __init__(self, seqname, start, end, possible_values):
        self.seqname = seqname
        self.start = start
        self.end = end
        self.possible_values = possible_values


class Channel(object):
    def __init__(self, channel_label, start, end, noisy=False):
        self.channel_label = channel_label
        self.start = start
        self.end = end
        self.noisy = noisy


class Action(object):
    def __init__(self, action_label, channel):
        self.action_label = action_label
        self.channel = channel


class Transition(object):
    def __init__(self, transition_label, start, end, condition, actions):
        self.transition_label = transition_label
        self.start = start
        self.end = end
        self.condition = condition
        self.actions = actions
        self.contending_transitions = []

    def set_contending_transitions(self, contending_transitions):
        self.contending_transitions = contending_transitions


class FSM(object):
    def __init__(self, fsm_label, states, init_state, transitions):
        self.fsm_label = fsm_label
        self.states = states
        self.init_state = init_state
        self.transitions = transitions

    def set_states(self, states):
        states = []
        for state in states:
            self.states.append(state)

    def add_state(self, state):
        self.states.append(state)

    def set_actions(self, actions):
        self.actions = []
        for action in actions:
            self.actions.append(action)

    def add_action(self, action):
        self.actions.append(action)


class InjectiveAdversary(object):
    def __init__(self, inj_adv_label, active_channel, alwayson):
        self.inj_adv_label = inj_adv_label
        self.active_channel_label = active_channel
        self.alwayson = alwayson


def parseXML(xmlfile):
    tree = ET.parse(xmlfile)
    root = tree.getroot()

    vars = []
    vars_dict = {}

    msg_fields = []
    msg_fields_dict = {}

    seq_nums = []
    system_fsms = []
    system_channels = []
    injective_adversaries = []

    for var in root.iter('VAR'):
        var_label = str(var.attrib['label']).strip()
        datatype = str(var.find('datatype').text).strip()
        controltype = str(var.find('controltype').text).strip()
        initial_value = ''
        possible_values = []
        if controltype.lower() == 'state':
            possible_values_list = str(var.find('possiblevalues').text).split(',')
            initial_value = str(var.find('initialvalue').text).strip()
            for i in range(len(possible_values_list)):
                possible_values.append(possible_values_list[i].strip())
        elif controltype.lower() == 'environment' and var.find('possiblevalues') is not None:
            possible_values_list = str(var.find('possiblevalues').text).split(',')
            for i in range(len(possible_values_list)):
                possible_values.append(possible_values_list[i].strip())

        mutualexclusion = False
        if var.find('mutualexclusion') is not None:
            mutualexclusion = var.find('mutualexclusion').text.strip()
        fsm = ''
        if var.find('fsm') is not None:
            fsm = var.find('fsm').text.strip()

        new_var = Variable(var_label, datatype, controltype, initial_value, possible_values, mutualexclusion, fsm)
        vars.append(new_var)
        vars_dict[var_label] = new_var

    for field_list_item in root.iter('MSG_FIELD_LIST'):
        msg_name = str(field_list_item.find('MSG').text).strip()
        field_vars_str = str(field_list_item.find('FIELD_VARS').text).strip()
        field_vars = field_vars_str.split(",")

        for field_var_name in field_vars:
            if field_var_name not in vars_dict:
                print("parse msg_fields :", field_var_name, "not found in vars_dict!!!")
                continue

            var_obj = vars_dict[field_var_name]
            new_msg_field_obj = MsgField(msg_name, field_var_name, var_obj)
            msg_fields.append(new_msg_field_obj)
            msg_fields_dict[field_var_name] = new_msg_field_obj

    for seq in root.iter('seq_num'):
        seq_name = str(seq.find('seq_name').text).strip()
        start = str(seq.find('start').text).strip()
        end = str(seq.find('end').text).strip()
        possible_values = []
        possible_values_list = []
        if seq.find('possiblevalues') is not None:
            possible_values_list = str(seq.find('possiblevalues').text).strip().split(',')

        for i in range(len(possible_values_list)):
            possible_values.append(possible_values_list[i].strip())

        new_seq_num = SequenceNumber(seq_name, start, end, possible_values)
        seq_nums.append(new_seq_num)

    for fsm in root.iter('FSM'):
        fsm_label = str(fsm.attrib['label']).strip()
        states = fsm.find('states')
        fsm_states = []

        for state in states:
            state = str(state.text).strip()
            fsm_states.append(state)

        init_state = str(fsm.find('init_state').text).strip()

        transitions = fsm.find('transitions')
        fsm_transitions = []
        if fsm.find('transitions'):
            i = 0
            for transition in transitions:
                i = i + 1
                transition_label = str(transition.attrib['label']).strip()
                transition_label = transition_label.split('_')[0] + '_T' + str(i)
                transition.attrib['label'] = transition_label
                tree.write(xmlfile)
                start_state = str(transition.find('start').text).strip()
                end_state = str(transition.find('end').text).strip()
                condition = str(transition.find('condition').text)
                if end_state not in fsm_states and end_state.strip() != '':
                    logger.warning(end_state + ' is not in the list of states of the ' + fsm_label + ' FSM')
                actions = []
                acts = transition.find('actions')
                for action in acts:
                    action_label = str(action.attrib['label']).strip()
                    chan_label = action.find('channel')
                    chan_label = str(chan_label.attrib['label']).strip()
                    chan_start = str(action.find('channel').find('start').text).strip()
                    chan_end = str(action.find('channel').find('end').text).strip()
                    channel_new = Channel(chan_label, chan_start, chan_end)
                    new_action = Action(action_label, channel_new)
                    actions.append(new_action)

                new_transition = Transition(transition_label, start_state, end_state, condition, actions)
                fsm_transitions.append(new_transition)

        new_fsm = FSM(fsm_label, fsm_states, init_state, fsm_transitions)

        if not fsm.find('transitions'):
            new_fsm = FSM(fsm_label, fsm_states, init_state, [])

        system_fsms.append(new_fsm)

    channels = root.find('channels')
    if root.find('channels'):
        if channels.find('channel'):
            for channel in channels:
                channel_label = str(channel.attrib['label']).strip()
                start = str(channel.find('start').text).strip()
                end = str(channel.find('end').text).strip()
                noisy = str(channel.find('noisy').text).strip()
                new_channel = Channel(channel_label, start, end, noisy)
                system_channels.append(new_channel)

    inj_advs = root.find('injective_adversaries')
    if root.find('injective_adversaries'):
        for inj_adv in inj_advs:
            inj_adv_label = str(inj_adv.attrib['label']).strip()
            active_channel_label = str(inj_adv.find('activechannel').text).strip()
            alwayson_boolean = str(inj_adv.find('alwayson').text).strip()
            new_injective_adversary = InjectiveAdversary(inj_adv_label, active_channel_label, alwayson_boolean)
            injective_adversaries.append(new_injective_adversary)

    return vars, vars_dict, msg_fields, msg_fields_dict, seq_nums, system_fsms, system_channels, injective_adversaries


def find_contendition_transitions(fsm):
    transition_contendingTransition_map = []
    for i in range(len(fsm.transitions)):
        transition = fsm.transitions[i]
        contendingTransitions = []
        for j in range(len(fsm.transitions)):
            if i == j:
                continue
            if fsm.transitions[i].start == fsm.transitions[j].start:
                contendingTransitions.append(fsm.transitions[j].transition_label)
        transition_contendingTransition_map.append((transition, contendingTransitions))
    return transition_contendingTransition_map


def dump_variables(output_file, vars, injective_adversaries):
    output_file.write('\nVAR\n\n')
    output_file.write('\n------------------- Environment and State variables --------------------\n')
    for var in vars:
        if var.datatype == 'boolean':
            output_file.write(var.varname + '\t:\t' + var.datatype + ';\t\n')
        elif var.datatype == 'enumerate':
            output_file.write(var.varname + '\t:\t{')
            for i in range(len(var.possible_values)):
                if i == len(var.possible_values) - 1:
                    output_file.write(var.possible_values[i])
                else:
                    output_file.write(var.possible_values[i] + ', ')
            output_file.write('};\t\n')

    for injective_adversary in injective_adversaries:
        output_file.write('attacker_inject_message_' + injective_adversary.active_channel_label.replace('_',
                                                                                                        '') + '\t:\t' + 'boolean\t;\n')
    return


def dump_sequence_numbers(output_file, seq_nums):
    output_file.write('\n----------------- Sequence numbers -------------------\n')

    for seq_num in seq_nums:
        output_file.write(seq_num.seqname + '\t:\t' + str(seq_num.start) + '..' + str(seq_num.end) + '\t;\n')
    return


def dump_states(output_file, fsms):
    for fsm in fsms:
        output_file.write('\n---------------- state for ' + fsm.fsm_label + ' state machine ----------------\n')
        output_file.write('\n' + str(fsm.fsm_label).lower() + '_state\t:\n')
        output_file.write('{\n')
        for i in range(len(fsm.states)):
            if i < len(fsm.states) - 1:
                output_file.write(str('\t' + fsm.states[i]) + ',\n')
            else:
                output_file.write('\t' + str(fsm.states[i]) + '\n')
        output_file.write('};\n')
    return


def get_actions_from_conditions(fsm_label, all_fsms) -> set:
    action_labels = set()
    for fsm in all_fsms:
        for transition in fsm.transitions:
            condition_parts = str(transition.condition).replace("&amp;", " ").replace("|", " ") \
                .replace("(", " ").replace(")", " ").split()

            for part in condition_parts:
                if fsm_label == "UE" and "chanUM_" in part:
                    action_labels.add(part.replace("chanUM_", "").strip())
                elif fsm_label == "MME" and "chanMU_" in part:
                    action_labels.add(part.replace("chanMU_", "").strip())

    return action_labels


def get_unique_action_names(fsm, all_fsms) -> set:
    action_labels = set()
    for transition in fsm.transitions:
        for action in transition.actions:
            if action.channel.channel_label.lower() != 'internal':
                action_labels.add(action.action_label)

    action_labels.update(get_actions_from_conditions(fsm.fsm_label, all_fsms))
    return action_labels


def dump_actions(output_file, fsms):
    for fsm in fsms:
        output_file.write('------------ Possible ' + fsm.fsm_label + ' actions ----------------\n')
        action_labels = get_unique_action_names(fsm, fsms)
        action_labels.add('null_action')
        action_labels = list(action_labels)

        output_file.write('\n' + fsm.fsm_label.lower() + '_action\t:\n')
        output_file.write('{\n')
        for i in range(len(action_labels)):
            if i < len(action_labels) - 1:
                output_file.write('\t' + fsm.fsm_label.lower() + '_' + action_labels[i] + ',\n')
            else:
                output_file.write('\t' + fsm.fsm_label.lower() + '_' + action_labels[i] + '\n')

        if len(action_labels) == 0:
            output_file.write('\t' + fsm.fsm_label.lower() + '_null_action\n')
        output_file.write('};\n')
    return


def get_channel_actions(channel_start, channel_end, fsms) -> set:
    action_labels = set()
    for fsm in fsms:
        for transition in fsm.transitions:
            for action in transition.actions:
                if (action.channel.start.lower() == channel_start.lower() and
                        action.channel.end.lower() == channel_end.lower() and
                        action.channel.channel_label != 'internal'):
                    action_labels.add(action.action_label)

    extra_actions = get_actions_from_conditions(channel_start, fsms)
    action_labels.update(extra_actions)

    return action_labels


def get_channel_actions_map(channels, fsms):
    channel_actions_map = []
    for i in range(len(channels)):
        channel_actions_map.append((channels[i], list(get_channel_actions(channels[i].start, channels[i].end, fsms))))
    return channel_actions_map


def dump_adversary_channel(output_file, channels, fsms):
    for channel in channels:
        output_file.write(
            '\n--------------- Adversarial channel from ' + channel.start.upper() + ' to ' + channel.end.upper() +
            ' ---------------\n')
        actions = get_channel_actions(channel.start, channel.end, fsms)
        actions.add('null_action')
        actions = list(actions)

        output_file.write('\n' + channel.channel_label + '\t:\n')
        output_file.write('{\n')
        for i in range(len(actions)):
            if i < len(actions) - 1:
                output_file.write('\t' + channel.channel_label.replace('_', '') + '_' + str(actions[i]).strip() + ',\n')
            else:
                output_file.write('\t' + channel.channel_label.replace('_', '') + '_' + str(actions[i]).strip() + '\n')
        output_file.write('};\n')


def dump_injective_adversary(output_file, channels, injective_adversaries, fsms):
    global action_channel_dict
    for injective_adversary in injective_adversaries:
        active_channel_label = injective_adversary.active_channel_label
        for channel in channels:
            if active_channel_label.lower() == channel.channel_label.lower():
                action_labels = get_channel_actions(channel.start, channel.end, fsms)
                action_labels.add('null_action')
                action_labels = list(action_labels)
                inj_adv_act_ch_name = injective_adversary.inj_adv_label
                output_file.write('\n--------------- Injection adversary action for channel ' + channel.channel_label +
                                  ' ---------------\n')
                inj_adv_act_ch_name = inj_adv_act_ch_name[
                                      0:inj_adv_act_ch_name.rfind('_')] + '_act_' + inj_adv_act_ch_name[
                                                                                    inj_adv_act_ch_name.rfind('_') + 1:]
                output_file.write('\n' + inj_adv_act_ch_name + '\t:\n')
                output_file.write('{\n')
                for i in range(len(action_labels)):
                    if action_labels[i] not in action_channel_dict:
                        action_channel_dict[action_labels[i]] = set()
                    action_channel_dict[action_labels[i]].add(channel.channel_label)

                    prefix = injective_adversary.inj_adv_label[injective_adversary.inj_adv_label.rfind('_') + 1:]
                    if i < len(action_labels) - 1:

                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + ',\n')
                    else:
                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + '\n')
                output_file.write('};\n')
    return


def dump_injective_msg_fields(output_file, msg_fields_dict: Dict[str, MsgField]):
    output_file.write('\n--------------- Injection adversary msg fields ---------------\n')

    for msg_field_name in msg_fields_dict:
        msg_field_var_obj = msg_fields_dict[msg_field_name].var_obj
        datatype = msg_field_var_obj.datatype
        if datatype == "boolean":
            output_file.write("adv_{}\t:\tboolean;\n".format(msg_field_name))
        elif datatype == "enumerate":
            possible_values = msg_field_var_obj.possible_values
            possible_values_str = "{" + ", ".join(possible_values) + "}"
            output_file.write("adv_{}\t:\t{};\n".format(msg_field_name, possible_values_str))


def dump_transitions(output_file, fsms):
    for fsm in fsms:
        output_file.write('\n-----------------' + fsm.fsm_label + ' transitions --------------------\n')
        transition_contendingTransitions_map = find_contendition_transitions(fsm)
        for i in range(len(fsm.transitions)):
            condition = fsm.transitions[i].condition

            if (fsm.transitions[i].start is None or fsm.transitions[i].start.strip() == 'None' or
                    fsm.transitions[i].start.strip() == ''):
                output_file.write(fsm.transitions[i].transition_label + '\t:=\t (' + condition + ')\t;\n')
            else:
                output_file.write(
                    fsm.transitions[i].transition_label + '\t:=\t (' + fsm.fsm_label.lower() + '_state = ' +
                    fsm.transitions[i].start + ' & ' + condition + ')\t;\n')

    return


def dump_noisy_channel_controls(output_file, channels):
    output_file.write('\n------------------- Noisy Channels --------------------\n')
    for channel in channels:
        prefix = channel.channel_label[channel.channel_label.rfind('_') + 1:]
        if channel.noisy.lower() == 'yes' or channel.noisy.lower() == 'true':
            output_file.write('noisy_channel_' + prefix.strip() + ':=\tTRUE;\n')
        elif channel.noisy.lower() == 'no' or channel.noisy.lower() == 'false':
            output_file.write('noisy_channel_' + prefix.strip() + ':=\tFALSE;\n')

    return


def dump_adversarial_channel_controls(output_file, injective_adversaries):
    output_file.write('\n------------------- Adversary enabled or not --------------------\n')
    for injective_adversary in injective_adversaries:
        prefix = injective_adversary.inj_adv_label + '_enabled'
        if injective_adversary.alwayson.lower() == 'yes' or injective_adversary.alwayson.lower() == 'true':
            output_file.write(prefix.strip() + ':=\tTRUE;\n')
        elif injective_adversary.alwayson.lower() == 'no' or injective_adversary.alwayson.lower() == 'false':
            output_file.write(prefix.strip() + ':=\tFALSE;\n')

    return


def dump_manual(input_file, output_file, section_name):
    output_file.write('\n------------------- dump_manual --------------------\n')
    tree = ET.parse(input_file)
    root = tree.getroot()

    manual_dumps = root.find('manual_dump')
    if root.find('manual_dump'):
        for instance in manual_dumps:
            section = instance.find('section').text
            section = str(section).strip().upper()
            if section in str(section_name).upper():
                text = instance.find('text').text
                lines = str(text).split('\n')
                for line in lines:
                    output_file.write(line.lstrip() + '\n')
    return


def dump_defines(input_file, output_file, channels, injective_adversaries, fsms):
    output_file.write('\n------------------- dump_defines --------------------\n')
    output_file.write('\n\nDEFINE\n')
    dump_transitions(output_file, fsms)
    dump_noisy_channel_controls(output_file, channels)
    dump_adversarial_channel_controls(output_file, injective_adversaries)
    dump_manual(input_file, output_file, 'DEFINE')
    return


def dump_adversarial_state_machines(output_file, injective_adversaries, channel_actions_map):
    output_file.write('\n------------------- Adversarial state machines --------------------\n')
    for injective_adversary in injective_adversaries:
        inj_adv_act_chanLabel = injective_adversary.inj_adv_label[:injective_adversary.inj_adv_label.rfind(
            '_')] + '_act_' + injective_adversary.inj_adv_label[injective_adversary.inj_adv_label.rfind('_') + 1:]
        output_file.write('\ninit(' + inj_adv_act_chanLabel + ')\t:=\n')
        output_file.write('{\n')
        for i in range(len(channel_actions_map)):
            if channel_actions_map[i][0].channel_label.lower() == injective_adversary.active_channel_label.lower():
                action_labels = channel_actions_map[i][1]
                for i in range(len(action_labels)):
                    prefix = injective_adversary.inj_adv_label[injective_adversary.inj_adv_label.rfind('_') + 1:]
                    if i < len(action_labels) - 1:
                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + ',\n')
                    else:
                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + '\n')
                output_file.write('};\n')
        output_file.write('\nnext(' + inj_adv_act_chanLabel + ')\t:=\tcase\n')
        output_file.write('TRUE\t:\t{\n')
        for i in range(len(channel_actions_map)):
            if channel_actions_map[i][0].channel_label.lower() == injective_adversary.active_channel_label.lower():
                action_labels = channel_actions_map[i][1]
                for i in range(len(action_labels)):
                    prefix = injective_adversary.inj_adv_label[injective_adversary.inj_adv_label.rfind('_') + 1:]
                    if i < len(action_labels) - 1:
                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + ',\n')
                    else:
                        output_file.write('\tadv_' + prefix + '_' + action_labels[i] + '\n')
                output_file.write('};\n')
                output_file.write('esac\t;\n')

    return


def get_fsm_deststate_transition_map(fsms):
    fsm_deststate_transition_map = []
    for fsm in fsms:
        deststate_transition_map = []
        for state in fsm.states:
            transitions = []
            for transition in fsm.transitions:
                if str(state).lower().strip() == str(transition.end).lower().strip():
                    transitions.append(transition.transition_label)
            deststate_transition_map.append((state, transitions))
        fsm_deststate_transition_map.append((fsm, deststate_transition_map))

    return fsm_deststate_transition_map


def dump_state_machines(output_file, fsms):
    fsm_deststate_transition_map = get_fsm_deststate_transition_map(fsms)
    for i in range(len(fsm_deststate_transition_map)):
        fsm = fsm_deststate_transition_map[i][0]
        output_file.write('\n\n---------------' + fsm.fsm_label + ' state machine ------------------\n')
        output_file.write("\ninit(" + fsm.fsm_label.lower() + '_state)\t:=' +
                          fsm.init_state.lower() + ';\n')
        output_file.write("\nnext(" + fsm.fsm_label.lower() + '_state)\t:=\t case\n\n')
        deststate_transition_map = fsm_deststate_transition_map[i][1]
        for j in range(len(deststate_transition_map)):
            deststate = deststate_transition_map[j][0]
            transition_labels = deststate_transition_map[j][1]
            if len(transition_labels) != 0:
                output_file.write('(')
            for k in range(len(transition_labels)):
                if k < len(transition_labels) - 1:
                    output_file.write(transition_labels[k] + ' | ')
                else:
                    output_file.write(transition_labels[k])
            if len(transition_labels) != 0:
                output_file.write(' )\t:\t' + deststate.lower() + '\t;\n')
        output_file.write('TRUE\t:\t' + fsm_deststate_transition_map[i][0].fsm_label.lower() + '_state\t;\n')
        output_file.write('esac\t;')

    return


def get_fsm_action_transition_map(fsms):
    fsm_action_transition_map = []
    for fsm in fsms:
        action_transition_map = []
        action_labels = get_unique_action_names(fsm, fsms)
        action_labels = list(action_labels)
        for action_label in action_labels:
            transitions = []
            for transition in fsm.transitions:
                for action in transition.actions:
                    if action_label.lower() == action.action_label.lower():
                        transitions.append(transition.transition_label)
            action_transition_map.append((action_label, transitions))
        fsm_action_transition_map.append((fsm, action_transition_map))
    return fsm_action_transition_map


def dump_action_state_machines(output_file, fsms):
    output_file.write('\n\n--------------- dump_action_state_machines ------------------\n')

    fsm_action_transition_map = get_fsm_action_transition_map(fsms)
    for i in range(len(fsm_action_transition_map)):
        output_file.write("\n\n\ninit(" + fsm_action_transition_map[i][0].fsm_label.lower() + '_action)\t:= ' +
                          fsm_action_transition_map[i][0].fsm_label.lower() + '_null_action\t;\n')
        output_file.write("\nnext(" + fsm_action_transition_map[i][0].fsm_label.lower() + '_action)\t:=\t case\n\n')
        action_transition_map = fsm_action_transition_map[i][1]
        for j in range(len(action_transition_map)):
            action_label = action_transition_map[j][0]
            transition_labels = action_transition_map[j][1]
            if len(transition_labels) == 0:
                continue

            output_file.write('(')
            for k in range(len(transition_labels)):
                if k < len(transition_labels) - 1:
                    output_file.write(transition_labels[k] + ' | ')
                else:
                    output_file.write(transition_labels[k])
            output_file.write(
                ' )\t:\t' + fsm_action_transition_map[i][0].fsm_label.lower() + '_' + action_label + '\t;\n')
        output_file.write('TRUE\t:\t' + fsm_action_transition_map[i][0].fsm_label.lower() + '_null_action\t;\n')
        output_file.write('esac\t;')

    return


def dump_adv_channel_state_machines(output_file, channels, injective_adversaries, fsms):
    output_file.write('\n\n--------------- dump_adv_channel_state_machines ------------------\n')

    for injective_adversary in injective_adversaries:
        output_file.write('\n\ninit(' + injective_adversary.active_channel_label + ')\t:=\t' +
                          injective_adversary.active_channel_label.replace('_', '') + '_null_action;\n')
        output_file.write('\nnext(' + injective_adversary.active_channel_label + ')\t:=\t case\n')
        attacher_inject_msg = 'attacker_inject_message_' + injective_adversary.active_channel_label.replace('_', '')
        inj_adv_chan_enabled = 'inj_adv_' + injective_adversary.inj_adv_label[
                                            injective_adversary.inj_adv_label.rfind('_') + 1:] + '_enabled'
        inj_adv_act_chan = 'inj_adv_act_' + injective_adversary.inj_adv_label[
                                            injective_adversary.inj_adv_label.rfind('_') + 1:]
        for channel in channels:
            if channel.channel_label.lower() == injective_adversary.active_channel_label.lower():
                action_labels = list(get_channel_actions(channel.start, channel.end, fsms))
                for action_label in action_labels:
                    adv_chan_act = 'adv_' + injective_adversary.inj_adv_label[
                                            injective_adversary.inj_adv_label.rfind('_') + 1:] + '_' + action_label
                    output_file.write(
                        attacher_inject_msg + '\t&\t' + inj_adv_chan_enabled + '\t&\t' + inj_adv_act_chan + '\t=\t')
                    output_file.write(adv_chan_act + '\t:\t' + injective_adversary.active_channel_label.replace('_', '')
                                      + '_' + action_label + '\t;\n')

                noisy_channel_chan = 'noisy_channel_' + channel.channel_label[channel.channel_label.rfind('_') + 1:]
                entity_action = channel.start.lower() + '_action'
                for action_label in action_labels:
                    entity_action_value = channel.start.lower() + '_' + action_label
                    chan_value = channel.channel_label.replace('_', '') + '_' + action_label
                    output_file.write(
                        '! ' + noisy_channel_chan + '\t&\t' + entity_action + '\t=\t ' + entity_action_value + '\t:\t' +
                        chan_value + '\t;\n')

                output_file.write('\nTRUE\t:\n')
                output_file.write('{\n')
                for i in range(len(action_labels)):
                    chan_value = channel.channel_label.replace('_', '') + '_' + action_labels[i]
                    if i < len(action_labels) - 1:
                        output_file.write('\t' + chan_value + ',\n')
                    else:
                        output_file.write('\t' + chan_value + '\n')
                output_file.write('}\t;\n')
                output_file.write('esac\t;\n')
    return


def dump_state_variable_state_machines(output_file, vars, fsms, msg_fields_dict: Dict[str, MsgField]):
    output_file.write('\n\n--------------- dump_state_variable_state_machines ------------------\n')
    var_value_transition_map = []
    for var in vars:
        if var.controltype.strip() in 'state':
            state_variable = var.varname
            value_transition_map = []
            all_possible_values = var.possible_values
            all_possible_values.extend([item.varname for item in vars])

            for possible_value in all_possible_values:
                transitions = []
                for fsm in fsms:
                    for transition in fsm.transitions:
                        for action in transition.actions:
                            if action.channel.channel_label.lower() == 'internal':
                                state_variable = action.action_label.split('=')[0]

                                if state_variable.strip() == var.varname:
                                    value = action.action_label.split('=')[1]

                                    if possible_value == value.strip():
                                        transitions.append(transition)
                if len(transitions) > 0:
                    value_transition_map.append((possible_value, transitions))

            if len(value_transition_map) > 0:
                var_value_transition_map.append((var, value_transition_map))

    for i in range(len(var_value_transition_map)):
        var = var_value_transition_map[i][0]
        state_variable = var.varname
        value_transition_map = var_value_transition_map[i][1]

        if var.datatype == 'boolean':
            output_file.write(
                "\n\n\ninit(" + state_variable + ')\t:= ' + var.initial_value.upper() + '\t;\n')
        elif var.datatype == 'enumerate':
            output_file.write("\n\n\ninit(" + state_variable + ')\t:= ' + var.initial_value + '\t;\n')

        output_file.write("\nnext(" + state_variable + ')\t:=\t case\n')

        if state_variable in msg_fields_dict:
            msg_field_obj = msg_fields_dict[state_variable]
            msg_name = msg_field_obj.msg
            if msg_name in action_channel_dict:
                chan_labels = list(action_channel_dict[msg_name])
                for chan_label in chan_labels:
                    if chan_label == "chan_UM":
                        chan_label = "UM"
                    elif chan_label == "chan_MU":
                        chan_label = "MU"
                    cond_str = ("attacker_inject_message_chan{}\t&\tinj_adv_{}_enabled\t&\tinj_adv_act_{}\t=\tadv_{}_{"
                                "}\t:\tadv_{}\t;\n"). \
                        format(chan_label, chan_label, chan_label, chan_label, msg_name, state_variable)
                    output_file.write(cond_str)

        for j in range(len(value_transition_map)):
            val = value_transition_map[j][0]
            transitions = value_transition_map[j][1]
            output_file.write('(')
            for k in range(len(transitions)):
                if k == len(transitions) - 1:
                    output_file.write(transitions[k].transition_label)
                else:
                    output_file.write(transitions[k].transition_label + ' | ')
            output_file.write(' )\t:\t' + val + '\t;\n')
        output_file.write('TRUE\t:\t' + var.varname + '\t;\n')
        output_file.write('esac\t;\n')

    return


def dump_seq_num_state_machines(output_file, seq_nums, fsms):
    output_file.write('\n\n--------------- dump_seq_num_state_machines ------------------\n')

    seqnum_value_transition_map = []
    for seq_num in seq_nums:
        seqname = seq_num.seqname
        value_transition_map = []
        for possible_value in seq_num.possible_values:
            possible_value = possible_value.lstrip()
            transitions = []
            for fsm in fsms:
                for transition in fsm.transitions:
                    for action in transition.actions:
                        if action.channel.channel_label.lower() == 'internal':
                            sname = str(action.action_label.split('=')[0]).strip()
                            if seqname.strip() == sname:
                                next_value = str(action.action_label.split('=')[1]).strip()

                                if possible_value == next_value.strip():
                                    transitions.append(transition)
            if len(transitions) > 0:
                value_transition_map.append((possible_value, transitions))

        if len(value_transition_map) > 0:
            seqnum_value_transition_map.append((seq_num, value_transition_map))

    output_file.write('\n\n')
    for i in range(len(seq_nums)):
        output_file.write('init(' + seq_nums[i].seqname + ')\t:= ' + seq_nums[i].start + '\t;\n')

    for i in range(len(seqnum_value_transition_map)):
        seqname = seqnum_value_transition_map[i][0].seqname
        value_transition_map = seqnum_value_transition_map[i][1]
        output_file.write('\nTRANS\n')
        output_file.write('case\n')
        for j in range(len(value_transition_map)):
            val = value_transition_map[j][0]
            transitions = value_transition_map[j][1]
            output_file.write('(')
            for k in range(len(transitions)):
                if k == len(transitions) - 1:
                    output_file.write(transitions[k].transition_label)
                else:
                    output_file.write(transitions[k].transition_label + ' | ')
            output_file.write(' )\t:\tnext(' + seqname + ')\t=\t' + val + '\t;\n')

        output_file.write('TRUE\t:\tnext(' + seqname + ')\t=\t' + seqname + '\t;\n')
        output_file.write('esac\t;\n')

    return


def dump_assigns(input_file, output_file, vars, seq_nums, fsms, channels, injective_adversaries, msg_fields_dict):
    output_file.write('\n\n--------------- dump_assigns ------------------\n')
    output_file.write('\n\nASSIGN\n\n')
    channel_actions_map = get_channel_actions_map(channels, fsms)
    dump_adversarial_state_machines(output_file, injective_adversaries, channel_actions_map)
    dump_state_machines(output_file, fsms)
    dump_action_state_machines(output_file, fsms)
    dump_adv_channel_state_machines(output_file, channels, injective_adversaries, fsms)
    dump_state_variable_state_machines(output_file, vars, fsms, msg_fields_dict)
    dump_seq_num_state_machines(output_file, seq_nums, fsms)

    return


def draw_fsms(fsms):
    for fsm in fsms:
        fsm_digraph = 'digraph ' + fsm.fsm_label + '{\n'
        fsm_digraph += 'rankdir = LR;\n'
        fsm_digraph += 'size = \"8,5\"\n'
        for state in fsm.states:
            fsm_digraph += 'node [shape = circle, label=\"' + state + '\"]' + state + ';\n'

        for transition in fsm.transitions:
            fsm_digraph += transition.start + ' -> ' + transition.end + ' [label = \"' + transition.transition_label + ': ' + transition.condition + '/\n'
            for i in range(len(transition.actions)):
                if i == len(transition.actions) - 1:
                    fsm_digraph += transition.actions[i].action_label.lstrip()
                else:
                    fsm_digraph += transition.actions[i].action_label.lstrip() + ', '
            fsm_digraph += '\"]\n'
        fsm_digraph += '}\n'
        fsmOutPutFileName = fsm.fsm_label + '.dot'
        f = open(fsmOutPutFileName, "w")
        f.write(fsm_digraph)
        f.close()

    return


def ir2smv_main(inputFileName, outputFile):
    input_file = open(inputFileName, 'r')
    input_lines = input_file.readlines()
    input_file.close()

    for i in range(len(input_lines)):
        input_lines[i] = input_lines[i].replace("<PRIMARY>", "").replace("</PRIMARY>", "")

    inputFileName = "ir-temp.xml"
    input_file = open(inputFileName, 'w')
    input_file.writelines(input_lines)
    input_file.close()

    vars, vars_dict, msg_fields, msg_fields_dict, seq_nums, fsms, channels, injective_adversaries = parseXML(
        inputFileName)
    f = open(outputFile, "w")
    f.write("MODULE main\n")
    dump_variables(f, vars, injective_adversaries)
    dump_sequence_numbers(f, seq_nums)
    dump_states(f, fsms)
    dump_actions(f, fsms)
    dump_adversary_channel(f, channels, fsms)
    dump_injective_adversary(f, channels, injective_adversaries, fsms)
    dump_injective_msg_fields(f, msg_fields_dict)
    dump_defines(inputFileName, f, channels, injective_adversaries, fsms)
    dump_assigns(inputFileName, f, vars, seq_nums, fsms, channels, injective_adversaries, msg_fields_dict)

    f.close()
    os.system("rm -rf " + inputFileName)

