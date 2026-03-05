from typing import Any, Dict
from .rulemeta import RuleMeta


cl_ja3_meta = RuleMeta(
    sid=79000001,
    rev=0,
    msg="ET MALWARE ABUSE.CH JA3 HASH Blacklist Malware",
    classtype=None,
    metadata={},
    references=('url,sslbl.abuse.ch',)
)


sv_ja3_meta = RuleMeta(
    sid=79000002,
    rev=0,
    msg="ET MALWARE ABUSE.CH JA3 HASH Blacklist Malware",
    classtype=None,
    metadata={},
    references=('url,sslbl.abuse.ch',)
)


sv_cert_meta = RuleMeta(
    sid=79000003,
    rev=0,
    msg="ET MALWARE ABUSE.CH SSL Fingerprint Blacklist Malicious "
        "SSL certificate",
    classtype=None,
    metadata={},
    references=('url,sslbl.abuse.ch',)
)


blacklist_rules: Dict[str, Any] = {
    str(cl_ja3_meta.sid): cl_ja3_meta._asdict(),
    str(sv_ja3_meta.sid): sv_ja3_meta._asdict(),
    str(sv_cert_meta.sid): sv_cert_meta._asdict(),
}
