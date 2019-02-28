
# -*- coding: utf-8 -*-

# FOGLAMP_BEGIN
# See: http://foglamp.readthedocs.io/
# FOGLAMP_END

from OpenSSL.crypto import (
    FILETYPE_ASN1, X509Store, X509StoreContext, X509StoreContextError,
    load_certificate)
from base64 import b64decode
from foglamp.common import logger

__author__ = "Amarendra Kumar Sinha"
__copyright__ = "Copyright (c) 2017 OSIsoft, LLC"
__license__ = "Apache 2.0"
__version__ = "${VERSION}"

_logger = logger.setup(__name__)


# Credits: https://www.osso.nl/blog/checking-client-ssl-certificate-from-python/
class VerificationError(ValueError):
    pass


class BaseCert:
    @classmethod
    def from_pem(cls, pem_data):
        try:
            assert isinstance(pem_data, str), pem_data
            pem_lines = [l.strip() for l in pem_data.strip().split('\n')]
            assert pem_lines, 'Empty data'
            assert pem_lines[0] == '-----BEGIN CERTIFICATE-----', 'Bad begin'
            assert pem_lines[-1] == '-----END CERTIFICATE-----', 'Bad end'
        except AssertionError as e:
            raise ValueError('{} in {!r}'.format(e.args[0], pem_data)) from e

        try:
            der_data = b64decode(''.join(pem_lines[1:-1]))
        except ValueError as e:
            raise ValueError('Illegal base64 in {!r}'.format(pem_data)) from e

        return cls.from_der(der_data)

    @classmethod
    def from_der(cls, der_data):
        assert isinstance(der_data, bytes)
        cert = load_certificate(FILETYPE_ASN1, der_data)
        return cls(cert)

    def __init__(self, x509):
        self._x509 = x509
        self._revoked_fingerprints = set()

    def __str__(self):
        try:
            cn = self.get_common_name()
        except Exception:
            cn = '<could_not_get_common_name>'
        try:
            issuer = self.get_issuer_common_name()
        except Exception:
            issuer = '<could_not_get_issuer>'

        return '{} issued by {}'.format(cn, issuer)

    def get_common_name(self):
        return self._get_common_name_from_components(self._x509.get_subject())

    def get_fingerprints(self):
        ret = {
            'SHA-1': self._x509.digest('sha1').decode('ascii'),
            'SHA-256': self._x509.digest('sha256').decode('ascii'),
        }
        assert len(ret['SHA-1']) == 59, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-1']), ret
        assert len(ret['SHA-256']) == 95, ret
        assert all(i in '0123456789ABCDEF:' for i in ret['SHA-256']), ret
        return ret

    def get_issuer_common_name(self):
        return self._get_common_name_from_components(self._x509.get_issuer())

    def _get_common_name_from_components(self, obj):
        return (
            # May contain other components as well, 'C', 'O', etc..
            dict(obj.get_components())[b'CN'].decode('utf-8'))

    def set_trusted_ca(self, cert):
        self._trusted_ca = cert

    def add_revoked_fingerprint(self, fingerprint_type, fingerprint):
        if fingerprint_type not in ('SHA-1', 'SHA-256'):
            raise ValueError('fingerprint_type should be SHA-1 or SHA-256')

        fingerprint = fingerprint.upper()
        assert all(i in '0123456789ABCDEF:' for i in fingerprint), fingerprint
        self._revoked_fingerprints.add((fingerprint_type, fingerprint))

    def verify(self):
        self.verify_expiry()
        self.verify_against_revoked()
        self.verify_against_ca()

    def verify_expiry(self):
        if self._x509.has_expired():
            raise VerificationError(str(self), 'is expired')

    def verify_against_revoked(self):
        fingerprints = self.get_fingerprints()
        for fingerprint_type, fingerprint in self._revoked_fingerprints:
            if fingerprints.get(fingerprint_type) == fingerprint:
                raise VerificationError(
                    str(self), 'matches revoked fingerprint', fingerprint)

    def verify_against_ca(self):
        if not hasattr(self, '_trusted_ca'):
            raise VerificationError(str(self), 'did not load trusted CA')

        store = X509Store()
        store.add_cert(self._trusted_ca._x509)
        store_ctx = X509StoreContext(store, self._x509)
        try:
            store_ctx.verify_certificate()
        except X509StoreContextError as e:
            # [20, 0, 'unable to get local issuer certificate']
            raise VerificationError(str(self), *e.args)

if __name__ == '__main__':
    def example():
        # "Creating a CA with openssl"
        # openssl genrsa -out ca.key 4096
        # openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
        #   -subj '/C=NL/CN=MY-CA'
        cacert = '''-----BEGIN CERTIFICATE-----
            MIIE8zCCAtugAwIBAgIJAN6Zb03+GwJUMA0GCSqGSIb3DQEBCwUAMBAxDjAMBgNV
            BAMMBU1ZLUNBMB4XDTE4MDMyMzA5MTg1NFoXDTE5MDMyMzA5MTg1NFowEDEOMAwG
            A1UEAwwFTVktQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCTKOv/
            /rLvSh4Emdjhlsp7/1SFMlRbPJCZFHTtr0iFAENYdvMXShL/5EQVnt92e0zFD5kj
            m3dx5WrKhc60CgF2fwJ9g0X64s8UQ0160BidboyLWgPQxUtYuJZfCa1Jp2at35Rb
            KTTcgcvGHHM9Bl3tRvE6r3MeBtHvAgZHhjqd59g73svILVVyM0n/SHNbQiv+yOfU
            87nPgbIq0hgs5v5atycFUzvzNimUH8vKmiCkYWuwM+UuHUUBDN/FESyANUJm2Eoi
            hJcPnQX+JBfhGcgRUrvLiA59fMJEVU2s16vix55evnoZbe2hN2QQ9FH9LbZp6evR
            qoNa9BoJVEFGHR6DCUfPDHT9EhPYe70w3Wlv3wO8vFsmKiCJivFQQCx21M8tXQug
            b47x0vhbpR0gi8Cz+UsOWZvrAOKqoBGwtxEjmuc+eFKiU3h4/Mv1v3yb5W41S+eM
            IGaCnXDW32X+ypHW0RirhRuRoGu67hAGVAP3KWKWuBtwaMoYErGPCSeoAy3fD0Dw
            0l762mnqn5BIJmvMwjeM+CBRylXfRj/xsBs/+G6Com1zRgzkkbU+G2yYOF+2MgxK
            mak/RLCx13u/VMUJDQzP3thUABCn+ZTCu+yCsFhPlj/zJU1QFu0uiGqTiqAHWYSQ
            spvY6NXel2JPk/nFE1HWpyXBVyF8Ksm1XkGF8wIDAQABo1AwTjAdBgNVHQ4EFgQU
            Ptqs7zPsJS7oEi76bZNHayUhzi0wHwYDVR0jBBgwFoAUPtqs7zPsJS7oEi76bZNH
            ayUhzi0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAMBzjxsBLbXBI
            TWHG4bPmHu/3Pv7p1gkiNNPh7GNA3Q9zMiN4NrstsuAFqDGBHWB5G8mfJ5v9F5qS
            fX0MUQWCOqhJCopt+03l/mo6O068POZ6aGrNf9staGA1x0hJaDlAM5HusEZ6WVA4
            EJySDSCmRlonzkAqOmN8mT1jzYzjCK1Q53O8/41Dv6I9RcDeU5gBs4MvFTOCmzrD
            AsXX9UyOkcRMNJUBq1t9oQipciu0y2bAZSOHA0JxSiGEijRtEbnBJ1Z74orgBvYk
            rPt9oEgEKkkYzT5jLL9aShSMm3UiHIhaDtCiky3qmH4GcXYZMCc3f3TF+L9Fl1YT
            ExDQJvFkx1h8nWdpMFroWLX3gIawW3mWMbpokt6quW1ndnH/6i0cva7nr+5CYBJq
            +RKnuF2M1z8NNDXzSLypX4MFa/LL+oj/q4r7dcELjYTClHzQ5i2ztGuyltAQSged
            ECkO8b9BqXGxGbWQv4L7OXy/fjrzMw3a3ErgDcTtRdL4IUF3pTsJuhkosPSM+REs
            OevV+s0sXRGRl/IlWo8mLXJp9ZKWXi+aTShitxu/FNp6LR/9/0TmVblMx0mjubfS
            06lMltPa7mep4m9rfhowgf1ElSXquWTjj3bMzfvOsHrreq50NMxWCJjCeYHM2oNI
            JzIhDr6afzQ62acSEV3/w7SAtkDsfFw=
            -----END CERTIFICATE-----'''

        # "Creating a CA-signed client cert with openssl"
        # openssl genrsa -out client.key 1024
        # openssl req -new -key client.key -out client.csr \
        #   -subj '/C=NL/CN=MY-CLIENT'
        # openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key \
        #    -set_serial 01 -out client.crt
        clientcert = '''-----BEGIN CERTIFICATE-----
            MIIDEzCB/AIBATANBgkqhkiG9w0BAQsFADAQMQ4wDAYDVQQDDAVNWS1DQTAeFw0x
            ODAzMjMwOTIwNTNaFw0xOTAzMjMwOTIwNTNaMBQxEjAQBgNVBAMMCU1ZLUNMSUVO
            VDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAueUyGPY5JrZcWT9MdjsxmZB/
            XexDT+cKif1dxq+rxLZO7qt5jMVPZLnxCX3cypTZ1u3cvnwGkqfkYT1hRDTfs6WU
            b9qwEYKz9W/9WEbh1hvVmaxRK3k+UspN1WdwOFer5k1zORzYCVZATHBj05QRztF1
            +Wx9m9avXMxqLnRsRuUCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAAJ922lE2qm8k
            OSCc/+BlyWJN78gxjE46S6/EnFEUgFBJhzqhIDIAApf5FDuA+5xeXt2RzrtJO/+0
            vFwVuyXssbZB6R6433VN8KsyEwEp+dxaP3u4tzZ+82J6VlCDnGt1t5smXUPUzEzh
            NdSeGe/11OvxKVV8b9gyy+007+l4u30vvatrpMaXRM2LpcKtmTu1B+FAPiP93G0U
            vMCw6+PbMGoQitwAIHW+86aycfUzYq5mivjVaaf4wgwo3rbAwcKK8aFmCarDbtwy
            cuzzvcsTdT/OxaPvGO3mOQpbcZpOFTjwNBc5LAOBRGDvbg3VOoPwOnS0lFJD5uc+
            MZOKcYOmHUeKqWOyCW6svGqlvZnuDDd808tqzVnBqTYo6UoV+dj4wEL2iRE+6zFg
            GuUKfbi2wV6exRisr6dBDLxIX068wbWVOHxAJrW/Ww0hKB78IqtSUXuBNuPUQg2m
            8JOFkMRrNtMZCyjF+ijEEFvfvqakLk+IzXuXXDS8h0A8O7jG4ehAxe1pkbZ/g3E9
            OUiJfKws5LVBLxh3HfpQe8JGfVI/5/naaqrB77gqf8Ub7YePczAEdJMiSgWBL5/l
            SIW14UwkbyH6fAbbVQC5O1Px0GhpiRV0hfBLx4ZaQ5wuDU3O866endNp48Ho6mM4
            /hnbcHOCf6zlThuDSGPkb76D54HdO1s=
            -----END CERTIFICATE-----'''

        ca = BaseCert.from_pem(cacert)
        cert = BaseCert.from_pem(clientcert)
        cert.set_trusted_ca(ca)

        print('Certificate:', cert)
        print('Fingerprints:', cert.get_fingerprints())
        # cert.add_revoked_fingerprint('SHA-1',
        #     cert.get_fingerprints()['SHA-1'])
        # cert.add_revoked_fingerprint(
        #     'SHA-1',
        #     '05:62:27:A5:6E:A1:52:F3:E7:E7:44:16:D6:F4:BD:27:B4:D8:1B:E5')

        cert.verify()
        print('Verification: OK')

    example()
