@0xec3b2b10a5e23975;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

struct CertChainReq {
    isdas @0 :UInt32;
    version @1 :UInt32;
    cacheOnly @2 :Bool;
}

struct CertChainRep {
    chain @0 :Data;
}

struct CertIssueReq {
    isdasCore @0 :UInt32;  # Core ISD-AS of the requested cert
    isdas @1 :UInt32;      # ISD-AS of the requested cert
    timestamp @2 :UInt64;  # Timestamp
    signature @3 :Data;    # Signature of (isdas, timestamp)
    certVer @4 :UInt32;    # Version cert used to sign
    trcVer @5 :UInt32;     # Version of TRC, which signed cert
}

struct CertIssueRep {
    chain @0 :Data; # New cert chain
    timestamp @1 :UInt64;  # Timestamp
}

struct TRCReq {
    isdas @0 :UInt32;
    version @1 :UInt32;
    cacheOnly @2 :Bool;
}

struct TRCRep {
    trc @0 :Data;
}

struct CertMgmt {
    union {
        unset @0 :Void;
        certChainReq @1 :CertChainReq;
        certChainRep @2 :CertChainRep;
        trcReq @3 :TRCReq;
        trcRep @4 :TRCRep;
        certIssueReq @5 :CertIssueReq;
        certIssueRep @6 :CertIssueRep;
    }
}
