global src_ip_2_usr_agent: table[addr] of set[string] = table();

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    local src_ip: addr = c$id$orig_h;
    if (c$http?$user_agent) {
        local agent: string = to_lower(c$http$user_agent);
        if (src_ip in src_ip_2_usr_agent) {
            add (src_ip_2_usr_agent[src_ip])[agent];
        } else {
            src_ip_2_usr_agent[src_ip] = set(agent);
        }
    }
}

event zeek_done() {
    for (source_ip in src_ip_2_usr_agent) {
        if (|src_ip_2_usr_agent[source_ip]| >= 3) {
            print(addr_to_uri(source_ip) + " is a proxy");
        }
    }
}
