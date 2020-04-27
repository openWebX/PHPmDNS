<?php
namespace mDNS;

/**
 * Class DNSPacket
 *
 * @package mDNS
 */
class DNSPacket {

    public ?DNSPacketHeader $packetheader = null; // DNSPacketHeader
    public array $questions = []; // array
    public array $answerrrs = []; // array
    public array $authorityrrs = []; // array
    public array $additionalrrs = []; // array
    public int $offset = 0;

    /**
     * DNSPacket constructor.
     */
    public function __construct() {
        $this->clear();
    }

    /**
     *
     */
    public function clear(): void {
        $this->packetheader = new DNSPacketHeader();
        $this->packetheader->clear();
        $this->questions = [];
        $this->answerrrs = [];
        $this->authorityrrs = [];
        $this->additionalrrs = [];
    }

    /**
     * @param $data
     * @return $this
     */
    public function load($data): DNSPacket {
        // $data is an array of integers representing the bytes.
        // Load the data into the DNSPacket object.
        $this->clear();

        // Read the first 12 bytes and load into the packet header
        $headerbytes = [];
        for ($x=0; $x< 12; $x++) {
            $headerbytes[$x] = $data[$x];
        }
        $this->packetheader->load($headerbytes);
        $this->offset = 12;

        if ($this->packetheader->getQuestions() > 0) {
            // There are some questions in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getQuestions(); $xq++) {
                $name = '';
                $size = 0;
                $resetoffsetto = 0;
                $firstreset = 0;
                while ($data[$this->offset] !== 0) {
                    if ($size === 0) {
                        $size = $data[$this->offset];
                        if (($size & 192) === 192) {
                            if ($firstreset === 0 && $resetoffsetto !== 0) {
                                $firstrest = $resetoffsetto;
                            }
                            $resetoffsetto = $this->offset;
                            $this->offset = $data[$this->offset + 1];
                            $size = $data[$this->offset];
                        }
                    } else {
                        $name .= chr($data[$this->offset]);
                        $size--;
                        if ($size === 0) {
                            $name .= '.';
                        }
                    }
                    $this->offset++;
                }
                if ($firstreset !== 0) {
                    $resetoffsetto = $firstreset;
                }
                if ($resetoffsetto !== 0) {
                    $this->offset = $resetoffsetto + 1;
                }
                if ($name !== '') {
                    $name = substr($name,0, -1);
                }
                ++$this->offset;
                $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
                $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
                $this->offset += 4;
                $r = new DNSQuestion();
                $r->name = $name;
                $r->qclass = $qclass;
                $r->qtype = $qtype;
                $this->questions[] = $r;
            }
        }
        if ($this->packetheader->getAnswerRRs() > 0) {
            // There are some answerrrs in this DNS Packet. Read them!
            for ($xq = 1; $xq <= $this->packetheader->getAnswerRRs(); $xq++) {
                $qr = $this->readRR($data);
                $this->answerrrs[] = $qr;
            }
        }
        if ($this->packetheader->getAuthorityRRs() > 0) {
            // Read the authorityrrs
            for ($xq = 1; $xq <= $this->packetheader->getAuthorityRRs(); $xq++) {
                $qr = $this->readRR($data);
                $this->authorityrrs[] = $qr;
            }
        }
        if ($this->packetheader->getAdditionalRRs() > 0) {
            // Finally read any additional rrs
            for ($xq = 1; $xq <= $this->packetheader->getAdditionalRRs(); $xq++) {
                $qr = $this->readRR($data);
                $this->additionalrrs[] = $qr;
            }
        }
        return $this;
    }

    /**
     * @param $data
     * @return DNSResourceRecord
     */
    public function readRR($data): DNSResourceRecord {
        // Returns a DNSResourceRecord object representing the $data (array of integers)
        $name = '';
        $size = 0;
        $resetoffsetto = 0;
        $firstreset = 0;
        $sectionstart = $this->offset;
        $sectionsize = 0;
        while ($data[$this->offset] !== 0) {
            if ($size === 0) {
                $size = $data[$this->offset];
                if ($sectionsize === 0) {
                    $sectionsize = $size;
                }
                if (($size & 192) === 192) {
                    if ($firstreset === 0 && $resetoffsetto !== 0) {
                        $firstreset = $resetoffsetto;
                    }
                    $resetoffsetto = $this->offset;
                    $this->offset = $data[$this->offset + 1] + (($data[$this->offset] - 192)*256);
                    $size = $data[$this->offset];
                }
            } else {
                $name .= chr($data[$this->offset]);
                $size--;
                if ($size === 0) {
                    $name .= '.';
                }
            }
            $this->offset++;
        }
        if ($firstreset !== 0) {
            $resetoffsetto = $firstreset;
        }
        if ($resetoffsetto !== 0) {
            $this->offset = $resetoffsetto + 1;
        }
        if ($name !== '') {
            $name = substr($name,0, -1);
        }
        ++$this->offset;
        $qtype = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $qclass = ($data[$this->offset + 2] * 256) + $data[$this->offset + 3];
        $this->offset += 4;
        $ttl = 1000;
        $this->offset += 4;
        // The next two bytes are the length of the data section
        $dl = ($data[$this->offset] * 256) + $data[$this->offset + 1];
        $this->offset += 2;
        $oldoffset = $this->offset;
        $ddata = [];
        for ($x=0; $x < $dl; $x++) {
            $ddata[] = $data[$this->offset];
            ++$this->offset;
        }
        $storeoffset = $this->offset;
        // For PTR, SRV, and TXT records we need to uncompress the data
        $datadecode = '';
        $size = 0;
        $resetoffsetto = 0;
        if ($qtype === 12) {
            $this->offset = $oldoffset;
            $firstreset = 0;
            while ($data[$this->offset] !== 0) {
                if ($size === 0) {
                    $size = $data[$this->offset];
                    if (($size & 192) === 192) {
                        if ($firstreset === 0 && $resetoffsetto !== 0) {
                            $firstreset = $resetoffsetto;
                        }
                        $resetoffsetto = $this->offset;
                        $this->offset = $data[$this->offset + 1];
                        $size = $data[$this->offset];
                    }
                } else {
                    $datadecode .= chr($data[$this->offset]);
                    --$size;
                    if ($size === 0) {
                        $datadecode .= '.';
                    }
                }
                $this->offset++;
            }
            if ($firstreset !== 0) {
                $resetoffsetto = $firstreset;
            }
            if ($resetoffsetto !== 0) {
                $offset = $resetoffsetto + 1;
            }
            $datadecode = substr($datadecode, 0, -1);
            $ddata = [];
            for ($x = 0, $xMax = strlen($datadecode); $x < $xMax; $x++) {
                $ddata[] = ord($datadecode[$x]);
                $this->offset++;
            }
        } else {
            $this->offset = $storeoffset;
        }
        $r = new DNSResourceRecord();
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
    public function makePacket(): array {
        // For the current DNS packet produce an array of bytes to send.
        // Should make this support unicode, but currently it doesn't :(
        $bytes = [];
        // First copy the header in
        $header = $this->packetheader->getBytes();
        foreach ($header as $xValue) {
            $bytes[] = $xValue;
        }
        $this->offset = 12;
        if (count($this->questions) > 0) {
            // We have some questions to encode
            foreach ($this->questions as $ppValue) {
                $thisq = $ppValue;
                $thisname = $thisq->name;
                $undotted = '';
                while (strpos($thisname, '.') > 0) {
                    $undotted .= chr(strpos($thisname, '.')) . substr($thisname, 0,strpos($thisname, '.'));
                    $thisname = substr($thisname, strpos($thisname, '.') + 1);
                }
                $undotted .= chr(strlen($thisname)) . $thisname . chr(0);
                for ($pq = 0, $pqMax = strlen($undotted); $pq < $pqMax; $pq++) {
                    $bytes[] = ord($undotted[$pq]);
                }
                $this->offset += strlen($undotted);
                $bytes[] = (int)($thisq->qtype / 256);
                $bytes[] = $thisq->qtype % 256;
                $this->offset += 2;
                $bytes[] = (int)($thisq->qclass / 256);
                $bytes[] = $thisq->qclass % 256;
                $this->offset += 2;
            }
        }
        // Questions are done. Others go here.
        // Maybe do this later, but for now we're only asking questions!
        return $bytes;
    }
}