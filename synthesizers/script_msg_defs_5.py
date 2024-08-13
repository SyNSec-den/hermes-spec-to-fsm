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
    "authentication_response", "authentication_failure", "registration_request", "registration_complete",
    "ul_nas_transport", "service_request", "configuration_update_complete", "identity_response",
    "notification_response", "security_mode_complete", "security_mode_reject", "control_plane_service_request",
    "network_slice_specific_authentication_complete", "relay_key_request",  "relay_authentication_response",

    "pdu_session_establishment_request", "pdu_session_authentication_complete", "pdu_session_modification_request",
    "pdu_session_modification_complete", "pdu_session_modification_command_reject", "pdu_session_release_request",
    "pdu_session_release_complete", "remote_ue_report",

    "tracking_area_update_request",

    "uplink_data"
}

mu_msg_list = {
    "authentication_request", "authentication_result", "authentication_reject", "registration_accept",
    "registration_reject", "dl_nas_transport", "service_accept", "service_reject", "configuration_update_command",
    "identity_request", "notification_message", "security_mode_command",
    "network_slice_specific_authentication_command", "network_slice_specific_authentication_result", "relay_key_accept",
    "relay_key_reject", "relay_authentication_request",

    "pdu_session_establishment_accept", "pdu_session_establishment_reject", "pdu_session_authentication_command",
    "pdu_session_authentication_result", "pdu_session_modification_reject", "pdu_session_modification_command",
    "pdu_session_release_reject", "pdu_session_release_command", "five_gsm_status_message", "remote_ue_report_resp",

    "activate_default_eps_bearer_context_request", "downlink_data"
}

both_dir_msg_list = {
    "deregistration_request", "deregistration_accept", "security_protected_5gs_nas_message", "five_gmm_status_message",
    "five_gsm_status_message",
    "nas_message", "initial_nas_message", "five_gmm_message", "five_gsm_message", "user_data"
    "detach_request"
}

emm_sublayer_msg_list = {
    "authentication_response", "authentication_failure", "registration_request", "registration_complete",
    "ul_nas_transport", "service_request", "configuration_update_complete", "identity_response",
    "notification_response", "security_mode_complete", "security_mode_reject", "control_plane_service_request",
    "network_slice_specific_authentication_complete", "relay_key_request",  "relay_authentication_response",
    "authentication_request", "authentication_result", "authentication_reject", "registration_accept",
    "registration_reject", "dl_nas_transport", "service_accept", "service_reject", "configuration_update_command",
    "identity_request", "notification_message", "security_mode_command",
    "network_slice_specific_authentication_command", "network_slice_specific_authentication_result", "relay_key_accept",
    "relay_key_reject", "relay_authentication_request", "five_gmm_message"


}

esm_sublayer_msg_list = {
    "pdu_session_establishment_request", "pdu_session_authentication_complete", "pdu_session_modification_request",
    "pdu_session_modification_complete", "pdu_session_modification_command_reject", "pdu_session_release_request",
    "pdu_session_release_complete", "pdu_session_establishment_accept", "pdu_session_establishment_reject",
    "pdu_session_authentication_command", "pdu_session_authentication_result", "pdu_session_modification_reject",
    "pdu_session_modification_command", "pdu_session_release_reject", "pdu_session_release_command",
    "five_gsm_status_message", "remote_ue_report", "remote_ue_report_resp", "five_gsm_message"

}

special_msg_list = {
    "nas_message", "initial_nas_message", "user_data", "uplink_signalling", "uplink_data", "downlink_signalling",
    "downlink_data", "five_gmm_message", "five_gsm_message"
}

msg_response = {
    "authentication_request": "authentication_response",
    "registration_request": "registration_accept",
    "identity_request": "identity_response",
    "service_request": "service_accept",
    "control_plane_service_request": "service_accept",
    "relay_key_request": "relay_key_accept",
    "relay_authentication_request": "relay_authentication_response",
    "security_mode_command": "security_mode_complete",
    "configuration_update_command": "configuration_update_complete",
    "network_slice_specific_authentication_command": "network_slice_specific_authentication_complete",
    "pdu_session_authentication_command": "pdu_session_authentication_complete",
    "pdu_session_modification_command": "pdu_session_modification_complete",
    "pdu_session_release_command": "pdu_session_release_complete",
    "pdu_session_establishment_request": "pdu_session_establishment_accept",
    "remote_ue_report": "remote_ue_report_resp"
}

mme_wait_for_message = {
    "registration_accept": "registration_resp",
    "identity_request": "identity_resp",
    "authentication_request": "auth_resp",
    "security_mode_command": "sm_resp",
    "configuration_update_command": "conf_resp",
    "network_slice_specific_authentication_command": "network_slice_auth_resp"
}

check_mme_wait_for = {
    "registration_complete": "registration_resp",
    "identity_response": "identity_resp",
    "authentication_response": "auth_resp",
    "authentication_failure": "auth_resp",
    "security_mode_complete": "sm_resp",
    "security_mode_reject": "sm_resp",
    "configuration_update_complete": "conf_resp",
    "network_slice_specific_authentication_complete": "network_slice_auth_resp"
}

