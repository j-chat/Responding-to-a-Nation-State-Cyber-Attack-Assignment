rule threat_detector {
        meta:
                Author = "@jchat"
		Date - "7/25/2021"
                Description = "This rule detects the unique malware that was undetected by ClamAV scan"
        strings:
                $command = "chkconfig iptables off"
		$path = "/etc/rc.local"
		$domain = "darkl0rd.com"
        condition:
                all

}
