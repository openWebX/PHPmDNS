<?php
namespace mDNS;

class DNSResourceRecord {
    public string $name;
    public int $qtype;
    public int $qclass;
    public int $ttl;
    public array $data;
}