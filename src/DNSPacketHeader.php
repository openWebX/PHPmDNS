<?php
namespace mDNS;

/**
 * Class DNSPacketHeader
 */
class DNSPacketHeader {
    // Represents the 12 byte packet header of a DNS request or response
    /**
     * @var int[]
     */
    private array $contents = []; // Byte() - in reality use an array of integers here

    /**
     *
     */
    public function clear(): void {
        $this->contents = [0,0,0,0,0,0,0,0,0,0,0,0];
    }

    /**
     * @return array
     */
    public function getBytes() : array {
        return $this->contents;
    }

    /**
     * @param $data
     */
    public function load($data): void {
        // Assume we're passed an array of bytes
        $this->clear();
        $this->contents = $data;
    }

    /**
     * @return int
     */
    public function getTransactionID() : int {
        return ($this->contents[0] * 256) + $this->contents[1];
    }

    /**
     * @param $value
     */
    public function setTransactionID($value): void {
        $this->contents[0] = (int)($value / 256);
        $this->contents[1] = $value % 256;
    }

    /**
     * @return float|int
     */
    public function getMessageType() {
        return ($this->contents[2] & 128) / 128;
    }

    /**
     * @param $value
     */
    public function setMessageType($value): void {
        $value *= 128;
        $this->contents[2] &= 127;
        $this->contents[2] |= $value;
    }

    // As far as I know the opcode is always zero. But code it anyway (just in case)

    /**
     * @return float|int
     */
    public function getOpCode() {
        return ($this->contents[2] & 120) / 8;
    }

    /**
     * @param $value
     */
    public function setOpCode($value): void {
        $value *= 8;
        $this->contents[2] &= 135;
        $this->contents[2] |= $value;
    }

    /**
     * @return float|int
     */
    public function getAuthorative() {
        return ($this->contents[2] & 4) / 4;
    }

    /**
     * @param $value
     */
    public function setAuthorative($value): void {
        $value *= 4;
        $this->contents[2] &= 251;
        $this->contents[2] |= $value;
    }

    // We always want truncated to be 0 as this class doesn't support multi packet.
    // But handle the value anyway
    /**
     * @return float|int
     */
    public function getTruncated() {
        return ($this->contents[2] & 2) / 2;
    }

    /**
     * @param $value
     */
    public function setTruncated($value): void {
        $value *= 2;
        $this->contents[2] &= 253;
        $this->contents[2] |= $value;
    }

    // We return this but we don't handle it!

    /**
     * @return int
     */
    public function getRecursionDesired(): int {
        return ($this->contents[2] & 1);
    }

    /**
     * @param $value
     */
    public function setRecursionDesired($value): void {
        $this->contents[2] &= 254;
        $this->contents[2] |= $value;
    }

    // We also return this but we don't handle it

    /**
     * @return float|int
     */
    public function getRecursionAvailable() {
        return ($this->contents[3] & 128)/128;
    }

    /**
     * @param $value
     */
    public function setRecursionAvailable($value): void {
        $value *= 128;
        $this->contents[3] &= 127;
        $this->contents[3] |= $value;
    }

    /**
     * @return float|int
     */
    public function getReserved() {
        return ($this->contents[3] & 64) / 64;
    }

    /**
     * @param $value
     */
    public function setReserved($value): void {
        $value *= 64;
        $this->contents[3] &= 191;
        $this->contents[3] |= $value;
    }

    // This always seems to be 0, but handle anyway

    /**
     * @return float|int
     */
    public function getAnswerAuthenticated() {
        return ($this->contents[3] & 32) / 32;
    }

    /**
     * @param $value
     */
    public function setAnswerAuthenticated($value): void {
        $value *= 32;
        $this->contents[3] &= 223;
        $this->contents[3] |= $value;
    }

    // This always seems to be 0, but handle anyway

    /**
     * @return float|int
     */
    public function getNonAuthenticatedData() {
        return ($this->contents[3] & 16) / 16;
    }

    /**
     * @param $value
     */
    public function setNonAuthenticatedData($value): void {
        $value *= 16;
        $this->contents[3] &= 239;
        $this->contents[3] |= $value;
    }

    // We want this to be zero
    // 0 : No error condition
    // 1 : Format error - The name server was unable to interpret the query.
    // 2 : Server failure - The name server was unable to process this query due to a problem with the name server.
    // 3 : Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    // 4 : Not Implemented - The name server does not support the requested kind of query.
    // 5 : Refused - The name server refuses to perform the specified operation for policy reasons. You should set this field to 0, and should assert an error if you receive a response indicating an error condition. You should treat 3 differently, as this represents the case where a requested name doesn’t exist.
    /**
     * @return int
     */
    public function getReplyCode(): int {
        return ($this->contents[3] & 15);
    }

    /**
     * @param $value
     */
    public function setReplyCode($value): void {
        $this->contents[3] &= 240;
        $this->contents[3] |= $value;
    }

    // The number of Questions in the packet

    /**
     * @return float|int|mixed
     */
    public function getQuestions() {
        return ($this->contents[4] * 256) + $this->contents[5];
    }

    /**
     * @param $value
     */
    public function setQuestions($value): void {
        $this->contents[4] = (int)($value / 256);
        $this->contents[5] = $value % 256;
    }

    // The number of AnswerRRs in the packet

    /**
     * @return float|int|mixed
     */
    public function getAnswerRRs() {
        return ($this->contents[6] * 256) + $this->contents[7];
    }

    /**
     * @param $value
     */
    public function setAnswerRRs($value): void {
        $this->contents[6] = (int)($value / 256);
        $this->contents[7] = $value % 256;
    }

    // The number of AuthorityRRs in the packet

    /**
     * @return float|int|mixed
     */
    public function getAuthorityRRs() {
        return ($this->contents[8] * 256) + $this->contents[9];
    }

    /**
     * @param $value
     */
    public function setAuthorityRRs($value): void {
        $this->contents[8] = (int)($value / 256);
        $this->contents[9] = $value % 256;
    }

    // The number of AdditionalRRs in the packet

    /**
     * @return float|int|mixed
     */
    public function getAdditionalRRs() {
        return ($this->contents[10] * 256) + $this->contents[11];
    }

    /**
     * @param $value
     */
    public function setAdditionalRRs($value): void {
        $this->contents[10] = (int)($value / 256);
        $this->contents[11] = $value % 256;
    }
}