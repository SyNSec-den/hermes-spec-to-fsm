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

um_msg_list = {
    "attach_req", "attach_complete", "identity_resp", "auth_resp", "auth_failure", "sm_complete", "sm_reject",
    "tau_req", "tau_complete", "guti_realloc_complete", "service_req", "ext_service_req", "control_service_req",
    "uplink_nas_transport", "uplink_generic_nas_transport",
    "activate_dedicated_eps_bearer_reject", "activate_default_eps_bearer_reject", "activate_default_eps_bearer_accept",
    "activate_dedicated_eps_bearer_accept", "bearer_resource_allocation_req", "bearer_resource_modification_req",
    "deactivate_eps_bearer_accept", "esm_info_resp", "modify_eps_bearer_accept", "modify_eps_bearer_reject",
    "pdn_connectivity_req", "pdn_disconnect_req", "remote_ue_report",
    "uplink_signalling"
}

mu_msg_list = {
    "attach_accept", "attach_reject", "identity_req", "auth_req", "auth_reject", "sm_command",
    "tau_accept", "tau_reject", "guti_realloc_command", "service_accept", "service_reject", "cs_service_notification",
    "downlink_nas_transport", "downlink_generic_nas_transport", "emm_information", "paging",
    "activate_dedicated_eps_bearer_req", "activate_default_eps_bearer_req", "bearer_resource_allocation_reject",
    "bearer_resource_modification_reject", "deactivate_eps_bearer_req", "esm_info_req", "modify_eps_bearer_req",
    "notification_msg", "pdn_connectivity_reject", "pdn_disconnect_reject", "remote_ue_report_resp",
    "downlink_signalling"
}

both_dir_msg_list = {
    "detach_req", "detach_accept", "emm_status", "security_protected_nas_msg",
    "esm_dummy", "esm_status", "esm_data_transport",
    "nas_message", "initial_nas_message", "user_data"
}

emm_sublayer_msg_list = {
    "attach_req", "attach_accept", "attach_reject", "attach_complete", "auth_req", "auth_resp", "auth_failure",
    "auth_reject", "cs_service_notification", "detach_req", "detach_accept", "downlink_nas_transport", "paging",
    "uplink_nas_transport", "downlink_generic_nas_transport", "uplink_generic_nas_transport", "emm_information",
    "emm_status", "service_req", "service_accept", "service_reject", "ext_service_req", "control_service_req",
    "guti_realloc_command", "guti_realloc_complete", "identity_req", "identity_resp", "sm_command", "sm_complete",
    "sm_reject", "security_protected_nas_msg", "tau_req", "tau_accept", "tau_reject", "tau_complete", "registration_req"
}

esm_sublayer_msg_list = {
    "activate_dedicated_eps_bearer_req", "activate_dedicated_eps_bearer_accept", "activate_dedicated_eps_bearer_reject",
    "activate_default_eps_bearer_req", "activate_default_eps_bearer_accept", "activate_default_eps_bearer_reject",
    "bearer_resource_allocation_req", "bearer_resource_allocation_reject", "bearer_resource_modification_req",
    "bearer_resource_modification_reject", "deactivate_eps_bearer_req", "deactivate_eps_bearer_accept",
    "modify_eps_bearer_req", "modify_eps_bearer_accept", "modify_eps_bearer_reject", "esm_dummy", "esm_info_req",
    "esm_info_resp", "esm_status", "notification_msg", "pdn_connectivity_req", "pdn_connectivity_reject",
    "pdn_disconnect_req", "pdn_disconnect_reject", "remote_ue_report", "remote_ue_report_resp", "esm_data_transport"
}

special_msg_list = {
    "nas_message", "initial_nas_message", "user_data", "uplink_signalling", "downlink_signalling"
}

msg_response = {
    "identity_req": "identity_resp",
    "auth_req": "auth_resp",
    "sm_command": "sm_complete",
    "guti_realloc_command": "guti_realloc_complete",
    "tau_req": "tau_accept",
    "tau_accept": "tau_complete",
    "esm_info_req": "esm_info_resp",
    "activate_default_eps_bearer_req": "activate_default_eps_bearer_req",
    "remote_ue_report": "remote_ue_report_resp"
}

mme_wait_for_message = {
    "attach_accept": "attach_resp",
    "identity_req": "identity_resp",
    "auth_req": "auth_resp",
    "sm_command": "sm_resp",
    "tau_accept": "tau_resp",
    "guti_realloc_command": "guti_realloc_resp"
}

check_mme_wait_for = {
    "attach_complete": "attach_resp",
    "identity_resp": "identity_resp",
    "auth_resp": "auth_resp",
    "auth_failure": "auth_resp",
    "sm_complete": "sm_resp",
    "sm_reject": "sm_resp",
    "tau_complete": "tau_resp",
    "guti_realloc_complete": "guti_realloc_resp"
}

