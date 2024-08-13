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

from script_config import GEN

if GEN == "5g":
    from script_msg_defs_5 import *
elif GEN == "4g":
    from script_msg_defs_4 import *
elif GEN == "5g-rrc":
    from script_msg_defs_5_rrc import *


def get_msg_direction(message_name: str) -> str:
    if message_name in um_msg_list:
        return "ue_to_mme"
    elif message_name in mu_msg_list:
        return "mme_to_ue"
    elif message_name in both_dir_msg_list:
        return "both_dir"
    else:
        return "unk_msg"


def get_msg_sublayer(message_name: str) -> str:
    if message_name in emm_sublayer_msg_list:
        return "emm_sublayer"
    elif message_name in esm_sublayer_msg_list:
        return "esm_sublayer"
    elif message_name in special_msg_list:
        return "special"
    else:
        return "unk_msg"


def get_msg_response(message_name: str) -> str:
    if message_name in msg_response:
        return msg_response[message_name]
    else:
        return "unk_resp"


def get_mme_wait_for(msg: str):
    if msg in mme_wait_for_message:
        return mme_wait_for_message[msg]
    else:
        return ""


def get_check_mme_wait_for(msg: str):
    if msg in check_mme_wait_for:
        return check_mme_wait_for[msg]
    else:
        return ""


def check_valid_msg(msg: str):
    if msg in um_msg_list or msg in mu_msg_list or msg in both_dir_msg_list or msg in emm_sublayer_msg_list \
            or msg in esm_sublayer_msg_list or msg in special_msg_list:
        return True
    else:
        return False
