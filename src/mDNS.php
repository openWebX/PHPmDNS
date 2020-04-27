<?php
namespace mDNS;

/**
 * Class mDNS
 */
class mDNS {
    /**
     * @var false|resource
     */
    private $mdnssocket; // Socket to listen to port 5353
    // A = 1;
    // PTR = 12;
    // SRV = 33;
    // TXT = 16;

    // query cache for the last query packet sent
    /**
     * @var string
     */
    private string $querycache = '';

    /**
     * mDNS constructor.
     */
    public function __construct() {
        error_reporting(E_ERROR | E_PARSE);
        // Create $mdnssocket, bind to 5353 and join multicast group 224.0.0.251
        $this->mdnssocket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if (PHP_OS === 'Darwin' || PHP_OS === 'FreeBSD') {
            socket_set_option($this->mdnssocket, SOL_SOCKET, SO_REUSEPORT, 1);
        } else {
            socket_set_option($this->mdnssocket,SOL_SOCKET,SO_REUSEADDR, 1);
        }
        //socket_set_option($this->mdnssocket, SOL_SOCKET, SO_BROADCAST, 1);
        socket_set_option($this->mdnssocket, IPPROTO_IP, MCAST_JOIN_GROUP, array('group'=>'224.0.0.251', 'interface'=>0));
        socket_set_option($this->mdnssocket, SOL_SOCKET,SO_RCVTIMEO,array('sec' =>1, 'usec' =>0));
        $bind = socket_bind($this->mdnssocket, '0.0.0.0', 5353);
    }

    /**
     * @param $name
     * @param $qclass
     * @param $qtype
     * @param string $data
     * @throws \Exception
     */
    public function query($name, $qclass, $qtype, $data= ''): void {
        // Sends a query
        $p = new DNSPacket;
        $p->clear();
        $p->packetheader->setTransactionID(random_int(1,32767));
        $p->packetheader->setQuestions(1);
        $q = new DNSQuestion();
        $q->name = $name;
        $q->qclass = $qclass;
        $q->qtype = $qtype;
        $p->questions[] = $q;
        $b = $p->makePacket();
        // Send the packet

        foreach ($b as $xValue) {
            $data .= chr($xValue);
        }
        $this->querycache = $data;
        $r = socket_sendto($this->mdnssocket, $data, strlen($data), 0, '224.0.0.251',5353);
    }

    /**
     *
     */
    public function requery(): void {
        // resend the last query
        $r = socket_sendto($this->mdnssocket, $this->querycache, strlen($this->querycache), 0, '224.0.0.251',5353);
    }

    /**
     * @return DNSPacket|string
     */
    public function readIncoming() : ?DNSPacket{
        // Read some incoming data. Timeout after 1 second
        $from = '0.0.0.0';
        $port = 0;
        $buf = '';
        $response = '';
        try {
            $response = socket_read($this->mdnssocket, 1024, PHP_BINARY_READ);
        } catch (\Exception $e) {
        }
        if ($response === '') {
            return null;
        }
        // Create an array to represent the bytes
        $bytes = array();
        for ($x = 0, $xMax = strlen($response); $x < $xMax; $x++) {
            $bytes[] = ord($response[$x]);
        }
        return (new DNSPacket())
            ->load($bytes);
    }

    /**
     * @param $data
     * @return DNSPacket
     */
    public function load($data): DNSPacket {
        return (new DNSPacket())
            ->load($data);
    }

    /**
     * @param $p
     */
    public function printPacket($p): void {
        // Echo a summary of packet contents to the screen
        echo 'Questions: ' . $p->packetheader->getQuestions() . "\n";
        if ($p->packetheader->getQuestions() > 0) {
            // List the AnswerRRs
            for ($x=0; $x < $p->packetheader->getQuestions(); $x++) {
                echo '  Question Number: ' . $x . "\n";
                $a = $p->questions[$x];
                $this->printRR($a);
            }
        }
        echo 'AnswerRRs: ' . $p->packetheader->getAnswerRRs() . "\n";
        if ($p->packetheader->getAnswerRRs() > 0) {
            // List the AnswerRRs
            for ($x=0; $x < $p->packetheader->getAnswerRRs(); $x++) {
                echo '  Answer Number: ' . $x . "\n";
                $a = $p->answerrrs[$x];
                $this->printRR($a);
            }
        }
        echo 'AuthorityRRs: ' . $p->packetheader->getAuthorityRRs() . "\n";
        if ($p->packetheader->getAuthorityRRs() > 0) {
            // List the AnswerRRs
            for ($x=0; $x < $p->packetheader->getAuthorityRRs(); $x++) {
                echo '  AuthorityRR Number: ' . $x . "\n";
                $a = $p->authorityrrs[$x];
                $this->printRR($a);
            }
        }
        echo 'AdditionalRRs: ' . $p->packetheader->getAdditionalRRs() . "\n";
        if ($p->packetheader->getAdditionalRRs() > 0) {
            // List the AnswerRRs
            for ($x=0; $x < $p->packetheader->getAdditionalRRs(); $x++) {
                echo '  Answer Number: ' . $x . "\n";
                $a = $p->additionalrrs[$x];
                $this->printRR($a);
            }
        }
    }

    /**
     * @param $a
     */
    private function printRR($a): void {
        echo '    Name: ' . $a->name . "\n";
        echo '    QType: ' . $a->qtype . "\n";
        echo '    QClass: ' . $a->qclass . "\n";
        echo '    TTL: ' . $a->ttl . "\n";
        $s = '';
        foreach ($a->data as $xValue) {
            $s .= chr($xValue);
        }
        echo '    Data: ' . $s . "\n";
    }
}