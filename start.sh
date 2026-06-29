#!/bin/sh
python -c "
from spiderfoot import SpiderFootDb
db = SpiderFootDb({'__database': '/var/lib/spiderfoot/spiderfoot.db'})
try:
    db.configSet({
        'sfp_tool_nmap:nmappath': '/usr/bin/nmap',
        'sfp_tool_dnstwist:dnstwistpath': '/usr/local/bin/dnstwist',
        'sfp_tool_cmseek:cmseekpath': '/tools/CMSeeK/cmseek.py',
        'sfp_tool_whatweb:whatweb_path': '/tools/WhatWeb/whatweb',
        'sfp_tool_wafw00f:wafw00f_path': '/usr/local/bin/wafw00f',
        'sfp_tool_onesixtyone:onesixtyone_path': '/usr/bin/onesixtyone',
        'sfp_tool_retirejs:retirejs_path': '/usr/bin/retire',
        'sfp_tool_testsslsh:testsslsh_path': '/tools/testssl.sh/testssl.sh',
        'sfp_tool_snallygaster:snallygaster_path': '/usr/local/bin/snallygaster',
        'sfp_tool_trufflehog:trufflehog_path': '/go/bin/trufflehog',
        'sfp_tool_nuclei:nuclei_path': '/go/bin/nuclei',
        'sfp_tool_nuclei:template_path': '/root/nuclei-templates',
        'sfp_tool_nbtscan:nbtscan_path': '/usr/bin/nbtscan',
    })
except Exception as e:
    print('Config setup warning:', e)
"
exec python sf.py -l 0.0.0.0:5001
