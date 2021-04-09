global ip_agent_table :table[addr] of set[string] = table();

event http_header (c: connection, is_orig: bool, name: string, value: string){
	if(c$http?$user_agent){
		local src_ip = c$id$orig_h;
		local usr_agent = to_lower(c$http$user_agent);
		if(src_ip in ip_agent_table){
			add (ip_agent_table[src_ip])[usr_agent];
		}
        else{
			ip_agent_table[src_ip] = set(usr_agent);
		}
	}
}
event zeek_done()
{
	for (src_ip in ip_agent_table){
		if(|ip_agent_table[src_ip]| >= 3)
			print fmt("%s is a proxy", src_ip);
	}
}
