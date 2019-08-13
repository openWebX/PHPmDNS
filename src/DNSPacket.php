<?php


namespace PHPmDNS;


/**
 * Class DNSPacket
 * @package PHPmDNS
 */
class DNSPacket {
    // Represents and processes a DNS packet
    /**
     * @var
     */
    public $packetheader; // DNSPacketHeader
    /**
     * @var
     */
    public $questions; // array
    /**
     * @var
     */
    public $answerrrs; // array
    /**
     * @var
     */
    public $authorityrrs; // array
    /**
     * @var
     */
    public $additionalrrs; // array
    /**
     * @var int
     */
    public $offset = 0;

    /**
     * DNSPacket constructor.
     */
    public function __construct() {
        $this->clear();
    }

    /**
     *
     */
    public function clear() {
        $this->packetheader = new PHPmDNS\DNSPacketHeader();
        $this->packetheader->clear();
        $this->questions = array();
        $this->answerrrs = array();
        $this->authorityrrs = array();
        $this->additionalrrs = array();
    }

    /**
     * @param array $data
     */
    public function load(array $data) {
        // $data is an array of integers representing the bytes.
        // Load the data into the DNSPacket object.
        $this->clear();

        // Read the first 12 bytes and load into the packet header
        $headerbytes = array();
        for ($x = 0; $x < 12; $x++) {
            $headerbytes[$x] = $data[$x];
        }
        $this->packetheader->load($headerbytes);
        $this->offset = 12;

        if ($this->packetheader->getQuestions() > 0) {
            // There are some questions in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getQuestions(); $xq++) {
                $name = "";
                $size = 0;
                $resetoffsetto = 0;
                $firstreset = 0;
                while ($data[$this->offset] <> 0) {
                    if ($size == 0) {
                        $size = $data[$this->offset];
                        if (($size & 192) == 192) {
                            if ($firstreset == 0 && $resetoffsetto <> 0) {
                                $firstrest = $resetoffsetto;
                            }
                            $resetoffsetto = $this->offset;
                            $this->offset = $data[$this->offset + 1];
                            $size = $data[$this->offset];
                        }
                    } else {
                        $name = $name . chr($data[$this->offset]);
                        $size--;
                        if ($size == 0) {
                            $name = $name . ".";
                        }
                    }
                    $this->offset++;
                }
                if ($firstreset <> 0) {
                    $resetoffsetto = $firstreset;
                }
                if ($resetoffsetto <> 0) {
                    $this->offset = $resetoffsetto + 1;
                }
                if (strlen($name) > 0) {
                    $name = substr($name, 0, strlen($name) - 1);
                }
                $this->offset = $this->offset + 1;
                $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
                $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
                $this->offset = $this->offset + 4;
                $r = new PHPmDNS\DNSQuestion();
                $r->name = $name;
                $r->qclass = $qclass;
                $r->qtype = $qtype;
                array_push($this->questions, $r);
            }
        }
        if ($this->packetheader->getAnswerRRs() > 0) {
            // There are some answerrrs in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getAnswerRRs(); $xq++) {
                $qr = $this->readRR($data);
                array_push($this->answerrrs, $qr);
            }
        }
        if ($this->packetheader->getAuthorityRRs() > 0) {
            // Read the authorityrrs
            for ($xq = 1; $xq <= $this->packetheader->getAuthorityRRs(); $xq++) {
                $qr = $this->readRR($data);
                array_push($this->authorityrrs, $qr);
            }
        }
        if ($this->packetheader->getAdditionalRRs() > 0) {
            // Finally read any additional rrs
            for ($xq = 1; $xq <= $this->packetheader->getAdditionalRRs(); $xq++) {
                $qr = $this->readRR($data);
                array_push($this->additionalrrs, $qr);
            }
        }
    }

    /**
     * @param $data
     * @return PHPmDNS\DNSResourceRecord
     */
    public function readRR($data) {
        // Returns a DNSResourceRecord object representing the $data (array of integers)
        $name = "";
        $size = 0;
        $resetoffsetto = 0;
        $firstreset = 0;
        $sectionstart = $this->offset;
        $sectionsize = 0;
        while ($data[$this->offset] <> 0) {
            if ($size == 0) {
                $size = $data[$this->offset];
                if ($sectionsize == 0) {
                    $sectionsize = $size;
                }
                if (($size & 192) == 192) {
                    if ($firstreset == 0 && $resetoffsetto <> 0) {
                        $firstreset = $resetoffsetto;
                    }
                    $resetoffsetto = $this->offset;
                    $this->offset = $data[$this->offset + 1] + (($data[$this->offset] - 192) * 256);
                    $size = $data[$this->offset];
                }
            } else {
                $name = $name . chr($data[$this->offset]);
                $size--;
                if ($size == 0) {
                    $name = $name . ".";
                }
            }
            $this->offset++;
        }
        if ($firstreset <> 0) {
            $resetoffsetto = $firstreset;
        }
        if ($resetoffsetto <> 0) {
            $this->offset = $resetoffsetto + 1;
        }
        if (strlen($name) > 0) {
            $name = substr($name, 0, strlen($name) - 1);
        }
        $this->offset = $this->offset + 1;
        $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
        $this->offset = $this->offset + 4;
        $ttl = 1000;
        $this->offset = $this->offset + 4;
        // The next two bytes are the length of the data section
        $dl = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $this->offset = $this->offset + 2;
        $oldoffset = $this->offset;
        $ddata = array();
        for ($x = 0; $x < $dl; $x++) {
            array_push($ddata, $data[$this->offset]);
            $this->offset = $this->offset + 1;
        }
        $storeoffset = $this->offset;
        // For PTR, SRV, and TXT records we need to uncompress the data
        $datadecode = "";
        $size = 0;
        $resetoffsetto = 0;
        if ($qtype == 12) {
            $this->offset = $oldoffset;
            $firstreset = 0;
            while ($data[$this->offset] <> 0) {
                if ($size == 0) {
                    $size = $data[$this->offset];
                    if (($size & 192) == 192) {
                        if ($firstreset == 0 && $resetoffsetto <> 0) {
                            $firstreset = $resetoffsetto;
                        }
                        $resetoffsetto = $this->offset;
                        $this->offset = $data[$this->offset + 1];
                        $size = $data[$this->offset];
                    }
                } else {
                    $datadecode = $datadecode . chr($data[$this->offset]);
                    $size = $size - 1;
                    if ($size == 0) {
                        $datadecode = $datadecode . ".";
                    }
                }
                $this->offset++;
            }
            if ($firstreset <> 0) {
                $resetoffsetto = $firstreset;
            }
            if ($resetoffsetto <> 0) {
                $offset = $resetoffsetto + 1;
            }
            $datadecode = substr($datadecode, 0, strlen($datadecode) - 1);
            $ddata = array();
            for ($x = 0; $x < strlen($datadecode); $x++) {
                array_push($ddata, ord(substr($datadecode, $x, 1)));
                $this->offset++;
            }
        }
        $this->offset = $storeoffset;
        $r = new PHPmDNS\DNSResourceRecord();
        $r->name = $name;
        $r->qclass = $qclass;
        $r->qtype = $qtype;
        $r->ttl = $ttl;
        $r->data = $ddata;
        return $r;
    }

    /**
     * @return array
     */
    public function makePacket() {
        // For the current DNS packet produce an array of bytes to send.
        // Should make this support unicode, but currently it doesn't :(
        $bytes = array();
        // First copy the header in
        $header = $this->packetheader->getBytes();
        for ($x = 0; $x < sizeof($header); $x++) {
            array_push($bytes, $header[$x]);
        }
        $this->offset = 12;
        if (sizeof($this->questions) > 0) {
            // We have some questions to encode
            for ($pp = 0; $pp < sizeof($this->questions); $pp++) {
                $thisq = $this->questions[$pp];
                $thisname = $thisq->name;
                $undotted = "";
                while (strpos($thisname, ".") > 0) {
                    $undotted .= chr(strpos($thisname, ".")) . substr($thisname, 0, strpos($thisname, "."));
                    $thisname = substr($thisname, strpos($thisname, ".") + 1);
                }
                $undotted .= chr(strlen($thisname)) . $thisname . chr(0);
                for ($pq = 0; $pq < strlen($undotted); $pq++) {
                    array_push($bytes, ord(substr($undotted, $pq, 1)));
                }
                $this->offset = $this->offset + strlen($undotted);
                array_push($bytes, (int)($thisq->qtype / 256));
                array_push($bytes, $thisq->qtype % 256);
                $this->offset = $this->offset + 2;
                array_push($bytes, (int)($thisq->qclass / 256));
                array_push($bytes, $thisq->qclass % 256);
                $this->offset = $this->offset + 2;
            }
        }
        // Questions are done. Others go here.
        // Maybe do this later, but for now we're only asking questions!
        return $bytes;
    }
}