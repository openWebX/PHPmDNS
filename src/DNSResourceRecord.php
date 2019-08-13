<?php


namespace PHPmDNS;


/**
 * Class DNSResourceRecord
 * @package PHPmDNS
 */
class DNSResourceRecord {

    /**
     * @var
     */
    public $name; // String
    /**
     * @var
     */
    public $qtype; // UInt16
    /**
     * @var
     */
    public $qclass; // UInt16
    /**
     * @var
     */
    public $ttl; // UInt32
    /**
     * @var
     */
    public $data; // Byte ()

}