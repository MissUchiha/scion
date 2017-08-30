# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`cert_mgmt` --- SCION cert/trc managment packets
=====================================================
"""
# External
import capnp  # noqa

import struct
import time
from nacl.public import PublicKey


# SCION
import proto.cert_mgmt_capnp as P
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.packet.scion_addr import ISD_AS
from lib.types import CertMgmtType, PayloadClass
from lib.crypto.asymcrypto import encrypt, decrypt, sign
from lib.crypto.symcrypto import mac


class CertMgmtBase(SCIONPayloadBaseProto):  # pragma: no cover
    PAYLOAD_CLASS = PayloadClass.CERT

    def _pack_full(self, p):
        wrapper = P.CertMgmt.new_message(**{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)


class CertMgmtRequest(CertMgmtBase):  # pragma: no cover

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    @classmethod
    def from_values(cls, isd_as, version, cache_only=False):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), version=version,
                                         cacheOnly=cache_only))


class CertChainRequest(CertMgmtRequest):
    NAME = "CertChainRequest"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REQ
    P_CLS = P.CertChainReq

    def short_desc(self):
        return "%sv%s (Cache only? %s)" % (self.isd_as(), self.p.version,
                                           self.p.cacheOnly)

class CertChainReply(CertMgmtBase):  # pragma: no cover
    NAME = "CertChainReply"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REPLY
    P_CLS = P.CertChainRep

    def __init__(self, p):
        super().__init__(p)
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, chain):
        return cls(cls.P_CLS.new_message(chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%sv%s" % self.chain.get_leaf_isd_as_ver()

    def __str__(self):
        isd_as, ver = self.chain.get_leaf_isd_as_ver()
        return "%s: ISD-AS: %s Version: %s" % (self.NAME, isd_as, ver)


class TRCRequest(CertMgmtRequest):
    NAME = "TRCRequest"
    PAYLOAD_TYPE = CertMgmtType.TRC_REQ
    P_CLS = P.TRCReq

    def short_desc(self):
        return "%sv%s (Cache only? %s)" % (self.isd_as()[0], self.p.version,
                                           self.p.cacheOnly)


class TRCReply(CertMgmtBase):  # pragma: no cover
    NAME = "TRCReply"
    PAYLOAD_TYPE = CertMgmtType.TRC_REPLY
    P_CLS = P.TRCRep

    def __init__(self, p):
        super().__init__(p)
        self.trc = TRC.from_raw(p.trc, lz4_=True)

    @classmethod
    def from_values(cls, trc):
        return cls(cls.P_CLS.new_message(trc=trc.pack(lz4_=True)))

    def short_desc(self):
        return "%sv%s" % self.trc.get_isd_ver()

    def __str__(self):
        isd, ver = self.trc.get_isd_ver()
        return "%s: ISD: %s version: %s TRC: %s" % (
            self.NAME, isd, ver, self.trc)


class CertIssueRequest(CertMgmtRequest):
    """ Certificate issuance request. """
    NAME = "CertIssueRequest"
    PAYLOAD_TYPE = CertMgmtType.CERT_ISSUE_REQ
    P_CLS = P.CertIssueReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.isd_as_core = ISD_AS(p.isdasCore)

    @classmethod
    def from_values(cls, isd_as_core, isd_as, timestamp, signature, cert_ver, trc_ver):
        """
        Get Certificate issuance request from values.

        :param ISD_AS isd_as_core: source ISD-AS of the requested cert.
        :param ISD_AS isd_as: ISD-AS of the requested cert.
        :param int timestamp: signature creation time.
        :param bytes signature: signature of (isd_as, timestamp).
        :param int cert_ver: version of the certificate used to create signature.
        :param int trc_ver: version of the trc associated with the certificate.
        :returns: the resulting CertIssueReq object.
        :rtype: CertIssueReq
        """
        p = cls.P_CLS.new_message(isdasCore=ISD_AS(isd_as_core).int(), isdas=int(isd_as), timestamp=timestamp, signature=signature,
                                  certVer=cert_ver, trcVer=trc_ver)
        return cls(p)

    def short_desc(self):
        return ("ISD-AS: %s TS: %s" %
                (self.isd_as, self.p.timestamp))


class CertIssueReply(CertChainReply):  # pragma: no cover
    NAME = "CertIssueReply"
    PAYLOAD_TYPE = CertMgmtType.CERT_ISSUE_REPLY
    P_CLS = P.CertIssueRep

    def __init__(self, p):
        super().__init__(p)
        self.timestamp = p.timestamp

    @classmethod
    def from_values(cls, chain, ts):
        """
        Get the CertIssueReply from values.

        :param CertificateChain chain: New cert chain
        :param Int ts: Signature created timestamp
        :returns: the resulting CertIssueReply.
        :rtype: CertIssueReply
        """
        return cls(cls.P_CLS.new_message(chain=chain, timestamp=ts))

    @classmethod
    def from_values(cls, chain, ts):
        return cls(cls.P_CLS.new_message(chain=chain.pack(lz4_=True), timestamp=ts))

    def short_desc(self):
        return "%sv%s" % self.chain.get_leaf_isd_as_ver()

    def __str__(self):
        isd_as, ver = self.chain.get_leaf_isd_as_ver()
        return "%s: ISD-AS: %s Version: %s, Timestamp: %s" % (self.NAME, isd_as, ver, self.timestamp)


def get_signing_input_cert_issue_req(isd_as, ts):
    ts = struct.pack("!Q", ts)
    isd_as_obj = ISD_AS(isd_as)
    return b"".join([isd_as_obj.pack(), ts])


def get_cert_issue_request(isd_as_core, isd_as, signing_key, cert_ver, trc_ver):
    """
    Generate a CertIssueRequest. The Request is signed with the signing key of the
    specified certificate.

    :param ISD_AS isd_as_core: destination (core) ISD_AS of the CertIssue request
    :param ISD_AS isd_as: ISD_AS of the requested certificate
    :param SigningKey signing_key: the signing key
    :param int cert_ver: version of the certificate associated with singing key
    :param int trc_ver: version of the trc associated with the certificate
    :returns: the signed CertIssueRequest
    :rtype: CertIssueRequest
    """
    timestamp = int(time.time())
    signature_string = get_signing_input_cert_issue_req(isd_as_core, timestamp)
    signature = sign(signature_string, signing_key)
    return CertIssueRequest.from_values(isd_as_core, isd_as, timestamp, signature, cert_ver, trc_ver)


def parse_certmgmt_payload(wrapper):  # pragma: no cover
    type_ = wrapper.which()
    for cls_ in CertChainRequest, CertChainReply,  TRCRequest, TRCReply, CertIssueRequest, CertIssueReply:
        if cls_.PAYLOAD_TYPE == type_:
            return cls_(getattr(wrapper, type_))
    raise SCIONParseError("Unsupported cert management type: %s" % type_)
