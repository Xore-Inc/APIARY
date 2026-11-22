# Wire-level file extraction for the decoy-side sensor (#1738).
#
# Runs here and only here. The VPS is the internet-facing host; writing live
# attacker-delivered malware onto it would put payloads on the one machine an
# attacker can already reach, for no analytical gain -- this sensor sees the
# same transfers in plaintext after Traefik terminates TLS, which is the half
# that matters for carving files out.
#
# What this buys: today a file crossing the wire is recorded and its bytes
# thrown away. Suricata's fileinfo counted 16,059 such records over seven days
# and kept none of them. Anything delivered over a protocol our honeypots do
# not fully emulate was observed and discarded.
#
# ---------------------------------------------------------------------------
# Handling posture
# ---------------------------------------------------------------------------
# 1. Names are Zeek's own file id, never the attacker-supplied filename. A
#    filename off the wire is attacker-controlled input and belongs nowhere
#    near a path.
# 2. Per-file size is capped. Without it, one large transfer fills the disk.
# 3. The extract directory is not executable and is never served. Files leave
#    it only by being pulled into the analysis pipeline, which already treats
#    its input as hostile.
# 4. Nothing here decompresses, parses or executes what it writes. This script
#    moves bytes to disk and stops.
#
# Scope is deliberately wide: every protocol Zeek can carve from, and every
# MIME type. The narrow HTTP/FTP-only policy the VPS script carries was a
# concession to running on the perimeter host with ~60 GB free. Here the
# constraint is different, and the noise -- 404 bodies, scanner HTML -- is
# worth accepting to avoid deciding in advance which delivery path matters.
# If disk becomes the problem, reintroduce a skip list rather than narrowing
# the protocols: it is the volume that hurts, not the coverage.

@load base/files/extract
@load base/files/hash

module ProxyFileExtract;

export {
    ## Largest single file to write. Comfortably above the largest sample this
    ## deployment has actually captured (a repeatedly-delivered 5 MB DLL),
    ## with room for archives, and small enough that one transfer cannot run
    ## away with the disk.
    const max_file_bytes = 25 * 1024 * 1024 &redef;

    ## Our own services, reached over the same tunnel.
    ##
    ## This sensor watches wg0, which carries every VPS-to-homeserver flow --
    ## not only the relayed attacker sessions. The dashboard, its API and the
    ## internal health traffic all cross it, and "extract everything" happily
    ## carves those too. Measured in the first five minutes after enabling
    ## extraction: 11 of 11 indexed files came from the dashboard's port.
    ## Not one was attacker-delivered. The port moved from 19090 (the retired
    ## in-repo dashboard) to 19092 (hp-apiary-dashboard) in #3834, after the
    ## stale exclusion let the new dashboard through: 32,036 of the 40,124
    ## files carved on 2026-11-15/16 came from 19092.
    ##
    ## Excluded by destination port because that is what actually separates
    ## the two here -- both ends of every flow on this interface are our own
    ## addresses, so a source/destination address filter cannot tell relayed
    ## attacker traffic from our own service traffic.
    const skip_dest_ports: set[port] = {
        19092/tcp,   # dashboard (hp-apiary-dashboard)
        18080/tcp,   # keycloak (was labelled "dashboard API")
        9200/tcp,    # elasticsearch
        5601/tcp,    # kibana
        3552/tcp,    # arcane
    } &redef;
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
    {
    # Decided here rather than in file_sniff because file_sniff fires before
    # the file is reliably associated with a connection: f$conns was empty for
    # roughly half the files, so a port filter there let our own dashboard
    # traffic through anyway (measured: 3 of 6 still landed from the dashboard
    # port).
    # file_over_new_connection hands us the connection directly, and fires
    # early enough that no payload has been missed.
    if ( ! f?$id || f$id == "" )
        return;

    # Skip our own services. Without this the store fills with the dashboard
    # talking to itself, which costs disk and buries the files that matter.
    if ( c$id$resp_p in skip_dest_ports )
        return;

    # add_analyzer is idempotent per file, so a file seen over several
    # connections is not extracted repeatedly.
    Files::add_analyzer(f, Files::ANALYZER_EXTRACT,
                        [$extract_filename = fmt("%s.bin", f$id),
                         $extract_limit = max_file_bytes]);
    }
