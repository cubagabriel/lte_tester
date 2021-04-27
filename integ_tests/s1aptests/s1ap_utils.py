"""
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import ctypes
import ipaddress
import logging
import os
import shlex
import threading
import time
from enum import Enum
from queue import Queue
from typing import Optional

import grpc
import subprocess

import s1ap_types


DEFAULT_GRPC_TIMEOUT = 10


class S1ApUtil(object):
    """
    Helper class to wrap the initialization and API interface of S1APTester
    Note that some of the values that are not that interesting are set
    through config files, that this class doesn't override. Examples include
    the various interface timeout params.
    """

    # Extracted from TestCntlrApp/src/ueApp/ue_esm.h
    CM_ESM_PDN_IPV4 = 0b01
    CM_ESM_PDN_IPV6 = 0b10
    CM_ESM_PDN_IPV4V6 = 0b11

    lib_name = "libtfw.so"

    _cond = threading.Condition()
    _msg = Queue()

    MAX_NUM_RETRIES = 5

    class Msg(object):
        def __init__(self, msg_type, msg_p, msg_len):
            self.msg_type = msg_type
            self.msg_p = ctypes.create_string_buffer(msg_len)
            ctypes.memmove(self.msg_p, msg_p, msg_len)
            self.msg_len = msg_len

        def cast(self, msg_class):
            return ctypes.cast(self.msg_p, ctypes.POINTER(msg_class)).contents

    @staticmethod
    def s1ap_callback(msg_type, msg_p, msg_len):
        """ S1ap tester compatible callback"""
        with S1ApUtil._cond:
            S1ApUtil._msg.put(S1ApUtil.Msg(msg_type, msg_p, msg_len))
            S1ApUtil._cond.notify_all()

    def __init__(self):
        """
        Initialize the s1aplibrary and its callbacks.
        """
        lib_path = os.environ["S1AP_TESTER_ROOT"]
        lib = os.path.join(lib_path, "bin", S1ApUtil.lib_name)
        os.chdir(lib_path)
        self._test_lib = ctypes.cdll.LoadLibrary(lib)
        self._callback_type = ctypes.CFUNCTYPE(
            None, ctypes.c_short, ctypes.c_void_p, ctypes.c_short
        )
        # Maintain a reference to the function object so GC doesn't release it.
        self._callback_fn = self._callback_type(S1ApUtil.s1ap_callback)
        self._test_lib.initTestFrameWork(self._callback_fn)
        self._test_api = self._test_lib.tfwApi
        self._test_api.restype = ctypes.c_int16
        self._test_api.argtypes = [ctypes.c_uint16, ctypes.c_void_p]

        # Mutex for state change operations
        self._lock = threading.RLock()

        # Maintain a map of UE IDs to IPs
        self._ue_ip_map = {}
        #self.gtpBridgeUtil = GTPBridgeUtils()

    def cleanup(self):
        """
        Cleanup the dll loaded explicitly so the next run doesn't reuse the
        same globals as ctypes LoadLibrary uses dlopen under the covers

        Also clear out the UE ID: IP mappings
        """
        # self._test_lib.dlclose(self._test_lib._handle)
        self._test_lib = None
        self._ue_ip_map = {}

    def issue_cmd(self, cmd_type, req):
        """
        Issue a command to the s1aptester and blocks until response is recvd.
        Args:
            cmd_type: The cmd type enum
            req: The request Structure
        Returns:
            None
        """
        c_req = None
        if req:
            # For non NULL requests obtain the address.
            c_req = ctypes.byref(req)
        with self._cond:
            rc = self._test_api(cmd_type.value, c_req)
            if rc:
                logging.error("Error executing command %s" % repr(cmd_type))
                return rc
        return 0

    def get_ip(self, ue_id):
        """ Returns the IP assigned to a given UE ID

        Args:
            ue_id: the ue_id to query

        Returns an ipaddress.ip_address for the given UE ID, or None if no IP
        has been observed to be assigned to this IP
        """
        with self._lock:
            if ue_id in self._ue_ip_map:
                return self._ue_ip_map[ue_id]
            return None

    def get_response(self):
        # Wait until callback is invoked.
        return self._msg.get(True)

    def populate_pco(self, protCfgOpts_pr, pcscf_addr_type):
        """
        Populates the PCO values.
        Args:
            protCfgOpts_pr: PCO structure
            pcscf_addr_type: ipv4/ipv6/ipv4v6 flag
        Returns:
            None
        """
        # PCO parameters
        # Presence mask
        protCfgOpts_pr.pres = 1
        # Length
        protCfgOpts_pr.len = 4
        # Configuration protocol
        protCfgOpts_pr.cfgProt = 0
        # Extension bit for the additional parameters
        protCfgOpts_pr.ext = 1
        # Number of protocol IDs
        protCfgOpts_pr.numProtId = 0

        # Fill Number of container IDs and Container ID
        if pcscf_addr_type == "ipv4":
            protCfgOpts_pr.numContId = 1
            protCfgOpts_pr.c[0].cid = 0x000C

        elif pcscf_addr_type == "ipv6":
            protCfgOpts_pr.numContId = 1
            protCfgOpts_pr.c[0].cid = 0x0001

        elif pcscf_addr_type == "ipv4v6":
            protCfgOpts_pr.numContId = 2
            protCfgOpts_pr.c[0].cid = 0x000C
            protCfgOpts_pr.c[1].cid = 0x0001

    def attach(
        self,
        ue_id,
        attach_type,
        resp_type,
        resp_msg_type,
        sec_ctxt=s1ap_types.TFW_CREATE_NEW_SECURITY_CONTEXT,
        id_type=s1ap_types.TFW_MID_TYPE_IMSI,
        eps_type=s1ap_types.TFW_EPS_ATTACH_TYPE_EPS_ATTACH,
        pdn_type=1,
        pcscf_addr_type=None,
    ):
        """
        Given a UE issue the attach request of specified type

        Caches the assigned IP address, if any is assigned

        Args:
            ue_id: The eNB ue_id
            attach_type: The type of attach e.g. UE_END_TO_END_ATTACH_REQUEST
            resp_type: enum type of the expected response
            sec_ctxt: Optional param allows for the reuse of the security
                context, defaults to creating a new security context.
            id_type: Optional param allows for changing up the ID type,
                defaults to s1ap_types.TFW_MID_TYPE_IMSI.
            eps_type: Optional param allows for variation in the EPS attach
                type, defaults to s1ap_types.TFW_EPS_ATTACH_TYPE_EPS_ATTACH.
            pdn_type:1 for IPv4, 2 for IPv6 and 3 for IPv4v6
            pcscf_addr_type:IPv4/IPv6/IPv4v6
        """
        attach_req = s1ap_types.ueAttachRequest_t()
        attach_req.ue_Id = ue_id
        attach_req.mIdType = id_type
        attach_req.epsAttachType = eps_type
        attach_req.useOldSecCtxt = sec_ctxt
        attach_req.pdnType_pr.pres = True
        attach_req.pdnType_pr.pdn_type = pdn_type

        # Populate PCO only if pcscf_addr_type is set
        if pcscf_addr_type:
            self.populate_pco(attach_req.protCfgOpts_pr, pcscf_addr_type)
        assert self.issue_cmd(attach_type, attach_req) == 0

        response = self.get_response()

        # The MME actually sends INT_CTX_SETUP_IND and UE_ATTACH_ACCEPT_IND in
        # one message, but the s1aptester splits it and sends the tests 2
        # messages. Usually context setup comes before attach accept, but
        # it's possible it may happen the other way
        if s1ap_types.tfwCmd.INT_CTX_SETUP_IND.value == response.msg_type:
            response = self.get_response()
        elif s1ap_types.tfwCmd.UE_ATTACH_ACCEPT_IND.value == response.msg_type:
            context_setup = self.get_response()
            assert (
                context_setup.msg_type
                == s1ap_types.tfwCmd.INT_CTX_SETUP_IND.value
            )
        print("s1ap response expected, received: {}, {}".format(resp_type.value,response.msg_type))
        logging.debug(
            "s1ap response expected, received: %d, %d",
            resp_type.value,
            response.msg_type,
        )
        assert resp_type.value == response.msg_type

        msg = response.cast(resp_msg_type)

        # We only support IPv4 right now, as max PDN address in S1AP tester is
        # currently 13 bytes, which is too short for IPv6 (which requires 16)
        if resp_msg_type == s1ap_types.ueAttachAccept_t:
            pdn_type = msg.esmInfo.pAddr.pdnType
            addr = msg.esmInfo.pAddr.addrInfo
            if S1ApUtil.CM_ESM_PDN_IPV4 == pdn_type:
                # Cast and cache the IPv4 address
                ip = ipaddress.ip_address(bytes(addr[:4]))
                with self._lock:
                    self._ue_ip_map[ue_id] = ip
            elif S1ApUtil.CM_ESM_PDN_IPV6 == pdn_type:
                print("IPv6 PDN type received")
            elif S1ApUtil.CM_ESM_PDN_IPV4V6 == pdn_type:
                print("IPv4v6 PDN type received")
        return msg

    def receive_emm_info(self):
        response = self.get_response()
        logging.debug(
            "s1ap message expected, received: %d, %d",
            s1ap_types.tfwCmd.UE_EMM_INFORMATION.value,
            response.msg_type,
        )
        assert response.msg_type == s1ap_types.tfwCmd.UE_EMM_INFORMATION.value

    def detach(self, ue_id, reason_type, wait_for_s1_ctxt_release=True):
        """ Given a UE issue a detach request """
        detach_req = s1ap_types.uedetachReq_t()
        detach_req.ue_Id = ue_id
        detach_req.ueDetType = reason_type
        assert (
            self.issue_cmd(s1ap_types.tfwCmd.UE_DETACH_REQUEST, detach_req)
            == 0
        )
        if reason_type == s1ap_types.ueDetachType_t.UE_NORMAL_DETACH.value:
            #response1 = self.get_response()
            response = self.get_response()
            print(s1ap_types.tfwCmd.UE_DETACH_ACCEPT_IND.value, response.msg_type)
            assert (
                s1ap_types.tfwCmd.UE_DETACH_ACCEPT_IND.value
                == response.msg_type
            )

        # Now wait for the context release response
        if wait_for_s1_ctxt_release:
            response = self.get_response()
            #response = response1
            print(s1ap_types.tfwCmd.UE_CTX_REL_IND.value, response.msg_type)
            assert s1ap_types.tfwCmd.UE_CTX_REL_IND.value == response.msg_type

        with self._lock:
            del self._ue_ip_map[ue_id]


class SubscriberUtil(object):
    """
    Helper class to manage subscriber data for the tests.
    """

    SID_PREFIX = "IMSI71617"
    IMSI_LEN = 15

    def __init__(self, subscriber_client):
        """
        Initialize subscriber util.

        Args:
            subscriber_client (subscriber_db_client.SubscriberDbClient):
                client interacting with our subscriber APIs
        """
        self._sid_idx = 1
        self._ue_id = 1
        # Maintain references to UE configs to prevent GC
        self._ue_cfgs = []

        self._subscriber_client = subscriber_client

    def _gen_next_sid(self):
        """
        Generate the sid based on index offset and prefix
        """
        idx = str(self._sid_idx)
        # Find the 0 padding we need to add
        padding = self.IMSI_LEN - len(idx) - len(self.SID_PREFIX[4:])
        sid = self.SID_PREFIX + "0" * padding + idx
        self._sid_idx += 1
        print("Using subscriber IMSI %s" % sid)
        return sid

    def _get_s1ap_sub(self, sid):
        """
        Get the subscriber data in s1aptester format.
        Args:
            The string representation of the subscriber id
        """
        ue_cfg = s1ap_types.ueConfig_t()
        ue_cfg.ue_id = self._ue_id
        ue_cfg.auth_key = 1
        # Some s1ap silliness, the char field is modelled as an int and then
        # cast into a uint8.
        for i in range(0, 15):
            ue_cfg.imsi[i] = ctypes.c_ubyte(int(sid[4 + i]))
            ue_cfg.imei[i] = ctypes.c_ubyte(int("1"))
        ue_cfg.imei[15] = ctypes.c_ubyte(int("1"))
        ue_cfg.imsiLen = self.IMSI_LEN
        self._ue_cfgs.append(ue_cfg)
        self._ue_id += 1
        return ue_cfg

    def add_sub(self, num_ues=1):
        """ Add subscribers to the EPC, is blocking """
        # Add the default IMSI used for the tests
        subscribers = []
        for _ in range(num_ues):
            sid = self._gen_next_sid()
            self._subscriber_client.add_subscriber(sid)
            subscribers.append(self._get_s1ap_sub(sid))
        self._subscriber_client.wait_for_changes()
        return subscribers

    def config_apn_data(self, imsi, apn_list):
        """ Add APN details """
        #self._subscriber_client.config_apn_details(imsi, apn_list)
        pass

    def cleanup(self):
        """ Cleanup added subscriber from subscriberdb """
        self._subscriber_client.clean_up()
        # block until changes propagate
        self._subscriber_client.wait_for_changes()

