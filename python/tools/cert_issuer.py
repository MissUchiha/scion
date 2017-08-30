# Copyright 2014 ETH Zurich
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
:mod:`certificate_issuer` --- SCION certificate issuer
=======================================================
"""

# Stdlib
import base64
import os

# External
from nacl.signing import SigningKey

# SCION
from lib.crypto.certificate import Certificate
from lib.crypto.certificate_chain import CertificateChain
from lib.defines import GEN_PATH, PROJECT_ROOT
from lib.crypto.util import CERT_DIR, get_online_key_file_path
from lib.crypto.asymcrypto import get_sig_key, get_enc_key,get_enc_key_file_path,get_sig_key_file_path
from lib.util import read_file, write_file


class CertificateIssuer(object):
    @classmethod
    def reissue_cert_chain(self, old_cert_chain, issuer_cert_chain, issuer_priv_key):
        """
        Reissuing a new version of certificate chain for AS.
        """
        new_cert = Certificate.from_values(old_cert_chain.as_cert.subject, old_cert_chain.as_cert.issuer,
                                           old_cert_chain.as_cert.trc_version, old_cert_chain.as_cert.version+1,
                                           "AS Certificate", old_cert_chain.as_cert.can_issue,
                                           Certificate.AS_VALIDITY_PERIOD, base64.b64decode(old_cert_chain.as_cert.subject_enc_key),
                                           base64.b64decode(old_cert_chain.as_cert.subject_sig_key), issuer_priv_key)

        return CertificateChain([new_cert, issuer_cert_chain.core_as_cert])
