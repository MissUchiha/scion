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
:mod:`cert_issuer_test` --- tools.cert_issuer unit tests
========================================================
"""

# SCION
from tools.cert_issuer import CertificateIssuer

# External packages
import nose.tools as ntools

class TestCertIssuer(object):
    """
    Unit tests for lib.cert_issuer.issue_cert
    """
    def _init(self):
        inst = CertificateIssuer()
        return inst

    def test_issue_cert(self):
        inst = self._init()
        # Call
        ntools.ok_(inst.issue_cert_chain('10', '1', '11','0','0','', False), None)

    def test_reissue_cert(self):
        inst = self._init()
        # Call
        cert = inst.issue_cert_chain('10', '1', '11','0','0','', False)
        ntools.ok_(inst.reissue_cert_chain(cert,cert))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
