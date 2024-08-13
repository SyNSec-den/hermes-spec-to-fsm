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
    "countercheckresponse", "dedicatedsibrequest", "uldedicatedmessagesegment", "ulinformationtransferirat",
    "ulinformationtransfermrdc", "failureinformation", "locationmeasurementindication", "mcgfailureinformation",
    "mbsinterestindication", "measurementreport", "measurementreportapplayer", "rrcresumerequest1",  "rrcsetuprequest",
    "rrcresumerequest", "ueinformationresponse", "rrcreestablishmentrequest", "rrcreestablishmentcomplete",
    "rrcsetupcomplete", "rrcresumecomplete", "rrcreconfigurationcomplete", "rrcsysteminforequest",
    "ulinformationtransfer", "scgfailureinformationeutra", "scgfailureinformation", "securitymodefailure",
    "securitymodecomplete", "sidelinkueinformationnr", "ueassistanceinformation", "uecapabilityinformation",
    "rrcreconfigurationcompletesidelink_message"
}

mu_msg_list = {
    "rrcsetup", "countercheck", "dldedicatedmessagesegment", "dlinformationtransfermrdc", "dlinformationtransfer",
    "loggedmeasurementconfiguration",  "mbsbroadcastconfiguration", "mib", "paging", "mobilityfromnrcommand",
    "ueinformationrequest", "systeminformation", "rrcreestablishment",  "rrcreconfiguration",  "rrcreject", "rrcresume",
    "rrcrelease", "securitymodecommand", "uecapabilityenquiry", "rrcreconfigurationsidelink_message"


}

both_dir_msg_list = {
    "iabotherinformation", "rrc_message", "nas_message", "warning_message"
}


special_msg_list = {
    "iabotherinformation", "rrc_message", "nas_message", "warning_message"
    "initial_nas_message", "user_data", "uplink_signalling", "uplink_data", "downlink_signalling",
    "downlink_data", "five_gmm_message", "five_gsm_message"
}


msg_response = {
    "countercheck": "countercheckresponse",
    "securitymodecommand": "securitymodecomplete",
    "uecapabilityenquiry": "uecapabilityinformation",
    "rrcreconfiguration": "rrcreconfigurationcomplete",
    "rrcreconfigurationsidelink_message": "rrcreconfigurationcompletesidelink_message",
    "rrcreestablishmentrequest": "rrcreestablishment",
    "rrcreestablishment": "rrcreestablishmentcomplete",
    "rrcsetuprequest": "rrcsetup",
    "rrcsetup": "rrcsetupcomplete",
    "rrcresumerequest": "rrcresume",
    "rrcresumerequest1": "rrcresume",
    "rrcresume": "rrcresume",

}

mme_wait_for_message = {
}

check_mme_wait_for = {

}


emm_sublayer_msg_list = {
}

esm_sublayer_msg_list = {
}