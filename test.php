<?php

require_once 'vendor/autoload.php';

$mdns = new mDNS\mDNS();
		// Search for chromecast devices
		// For a bit more surety, send multiple search requests
		$mdns->query('_googlecast._tcp.local',1,12,'');
		$mdns->query('_googlecast._tcp.local',1,12,'');
		$mdns->query('_googlecast._tcp.local',1,12,'');
		$cc = 15;
		$chromecasts = array();
		while ($cc>0) {
			$inpacket = $mdns->readIncoming();
			$mdns->printPacket($inpacket);
			// If our packet has answers, then read them
			if ($inpacket->packetheader->getAnswerRRs()> 0) {
				for ($x=0, $xMax = count($inpacket->answerrrs); $x < $xMax; $x++) {
					if ($inpacket->answerrrs[$x]->qtype === 12) {
						//print_r($inpacket->answerrrs[$x]);
						if ($inpacket->answerrrs[$x]->name == '_googlecast._tcp.local') {
							$name = '';
							for ($y = 0, $yMax = count($inpacket->answerrrs[$x]->data); $y < $yMax; $y++) {
								$name .= chr($inpacket->answerrrs[$x]->data[$y]);
							}
							// The chromecast name is in $name. Send a a SRV query
							$mdns->query($name, 1, 33, '');
							$cc=15;
						}
					}
					if ($inpacket->answerrrs[$x]->qtype === 33) {
						$d = $inpacket->answerrrs[$x]->data;
						$port = ($d[4] * 256) + $d[5];
						// We need the target from the data
						$offset = 6;
						$size = $d[$offset];
						$offset++;
						$target = '';
						for ($z=0; $z < $size; $z++) {
							$target .= chr($d[$offset + $z]);
						}
						$target .= '.local';
						$chromecasts[$inpacket->answerrrs[$x]->name] = array('port'=>$port, 'ip'=>'', 'target'=>$target);
						// We know the name and port. Send an A query for the IP address
						$mdns->query($target,1,1,'');
						$cc=15;
					}
					if ($inpacket->answerrrs[$x]->qtype == 1) {
						$d = $inpacket->answerrrs[$x]->data;
						$ip = $d[0] . '.' . $d[1] . '.' . $d[2] . '.' . $d[3];
						// Loop through the chromecasts and fill in the ip
						foreach ($chromecasts as $key=>$value) {
							if ($value['target'] == $inpacket->answerrrs[$x]->name) {
								$value['ip'] = $ip;	
								$chromecasts[$key] = $value;
							}
						}
					}
				}
			}
			$cc--;
		}

		var_dump($chromecasts);
