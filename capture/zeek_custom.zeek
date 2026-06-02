# capture/zeek_custom.zeek
# Extracts TLS metadata, DNS queries, and connection features
# Run: zeekctl deploy

@load base/protocols/ssl
@load base/protocols/dns
@load base/protocols/conn
@load policy/protocols/ssl/ja3

module PhantomFlow;

export {
    redef enum Log::ID += { CONN_FEATURES, DNS_FEATURES, TLS_FEATURES };

    # Enhanced connection log
    type ConnFeatureInfo: record {
        ts:              time        &log;
        uid:             string      &log;
        src:             addr        &log;
        dst:             addr        &log;
        sport:           port        &log;
        dport:           port        &log;
        proto:           transport_proto &log;
        duration:        interval    &log &optional;
        orig_bytes:      count       &log &optional;
        resp_bytes:      count       &log &optional;
        orig_pkts:       count       &log &optional;
        resp_pkts:       count       &log &optional;
        orig_ip_bytes:   count       &log &optional;
        resp_ip_bytes:   count       &log &optional;
        # Derived features
        bytes_ratio:     double      &log &optional;  # upload/download
        pkt_size_mean:   double      &log &optional;
        pkt_size_std:    double      &log &optional;
        pkts_per_sec:    double      &log &optional;
        bytes_per_sec:   double      &log &optional;
    };

    # DNS tunneling features
    type DNSFeatureInfo: record {
        ts:              time        &log;
        uid:             string      &log;
        src:             addr        &log;
        query:           string      &log &optional;
        qtype:           string      &log &optional;
        qclass:          string      &log &optional;
        rtt:             interval    &log &optional;
        # Entropy features
        query_length:    count       &log &optional;
        label_count:     count       &log &optional;
        max_label_len:   count       &log &optional;
        unique_chars:    count       &log &optional;
        # Computed by Python
        shannon_entropy: double      &log &optional;
        is_dga_like:     bool        &log &optional;
    };

    # TLS fingerprinting
    type TLSFeatureInfo: record {
        ts:              time        &log;
        uid:             string      &log;
        src:             addr        &log;
        dst:             addr        &log;
        dport:           port        &log;
        version:         string      &log &optional;
        cipher:          string      &log &optional;
        curve:           string      &log &optional;
        server_name:     string      &log &optional;
        resumed:         bool        &log &optional;
        ja3:             string      &log &optional;
        ja3s:            string      &log &optional;
        cert_subject:    string      &log &optional;
        cert_issuer:     string      &log &optional;
        cert_not_valid_before: time  &log &optional;
        cert_not_valid_after:  time  &log &optional;
        cert_key_alg:    string      &log &optional;
        validation_status: string   &log &optional;
    };

    global log_conn_features: event(rec: ConnFeatureInfo);
    global log_dns_features: event(rec: DNSFeatureInfo);
    global log_tls_features: event(rec: TLSFeatureInfo);
}

# === Connection Features ===
event connection_state_remove(c: connection) {
    local orig = c$orig;
    local resp = c$resp;
    
    local duration = c$duration;
    local ob = c?$orig ? c$orig$size : 0;
    local rb = c?$resp ? c$resp$size : 0;
    local op = c?$orig ? c$orig$num_pkts : 0;
    local rp = c?$resp ? c$resp$num_pkts : 0;
    
    local bytes_ratio = (rb > 0) ? (ob + 0.0) / rb : -1.0;
    local pps = (duration > 0sec) ? (op + rp) / interval_to_double(duration) : 0.0;
    local bps = (duration > 0sec) ? (ob + rb) / interval_to_double(duration) : 0.0;
    
    local rec: ConnFeatureInfo = [
        $ts            = c$start_time,
        $uid           = c$uid,
        $src           = c$id$orig_h,
        $dst           = c$id$resp_h,
        $sport         = c$id$orig_p,
        $dport         = c$id$resp_p,
        $proto         = get_port_transport_proto(c$id$resp_p),
        $duration      = duration,
        $orig_bytes    = ob,
        $resp_bytes    = rb,
        $orig_pkts     = op,
        $resp_pkts     = rp,
        $bytes_ratio   = bytes_ratio,
        $pkts_per_sec  = pps,
        $bytes_per_sec = bps,
    ];
    Log::write(PhantomFlow::CONN_FEATURES, rec);
}

# === DNS Features ===
event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count) {
    local labels = split_string(query, /\./);
    local max_len = 0;
    local chars: set[string];
    
    for (i in labels) {
        if (|labels[i]| > max_len) max_len = |labels[i]|;
        for (j in split_string(labels[i], //)) {
            add chars[j];
        }
    }
    
    local rec: DNSFeatureInfo = [
        $ts           = c$start_time,
        $uid          = c$uid,
        $src          = c$id$orig_h,
        $query        = query,
        $qtype        = DNS::query_types[qtype] ? DNS::query_types[qtype] : "UNKNOWN",
        $query_length = |query|,
        $label_count  = |labels|,
        $max_label_len = max_len,
        $unique_chars = |chars|,
    ];
    Log::write(PhantomFlow::DNS_FEATURES, rec);
}

# === TLS Features ===
event ssl_established(c: connection) {
    if (!c?$ssl) return;
    local ssl = c$ssl;
    
    local rec: TLSFeatureInfo = [
        $ts          = c$start_time,
        $uid         = c$uid,
        $src         = c$id$orig_h,
        $dst         = c$id$resp_h,
        $dport       = c$id$resp_p,
        $version     = ssl?$version ? ssl$version : "",
        $cipher      = ssl?$cipher ? ssl$cipher : "",
        $curve       = ssl?$curve ? ssl$curve : "",
        $server_name = ssl?$server_name ? ssl$server_name : "",
        $resumed     = ssl?$resumed ? ssl$resumed : F,
        $ja3         = ssl?$ja3 ? ssl$ja3 : "",
        $ja3s        = ssl?$ja3s ? ssl$ja3s : "",
        $validation_status = ssl?$validation_status ? ssl$validation_status : "",
    ];
    
    if (ssl?$cert_chain && |ssl$cert_chain| > 0) {
        local cert = ssl$cert_chain[0]$x509$certificate;
        rec$cert_subject = cert$subject;
        rec$cert_issuer  = cert$issuer;
        rec$cert_not_valid_before = cert$not_valid_before;
        rec$cert_not_valid_after  = cert$not_valid_after;
        rec$cert_key_alg = cert$key_alg;
    }
    
    Log::write(PhantomFlow::TLS_FEATURES, rec);
}
