<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class DKIM
{
    /**
     * Carriage return, line feed; the standard RFC822 line break
     */
    public const CRLF = "\r\n";

    /**
     * Line feed character; standard unix line break
     */
    public const LF = "\n";

    /**
     * Carriage return character
     */
    public const CR = "\r";

    /**
     * Default whitespace string
     */
    public const SPACE = ' ';

    /**
     * A regex pattern to validate DKIM selectors
     *
     * @see self::validateSelector() for how this pattern is constructed
     */
    public const SELECTOR_VALIDATION =
        '[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*(\.[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*)*';

    /**
     * Algorithms for header and body canonicalization are constant
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4
     */
    public const CANONICALIZATION_BODY_SIMPLE = 'simple';
    public const CANONICALIZATION_BODY_RELAXED = 'relaxed';
    public const CANONICALIZATION_HEADERS_SIMPLE = 'simple';
    public const CANONICALIZATION_HEADERS_RELAXED = 'relaxed';

    public const DEFAULT_HASH_FUNCTION = 'sha256';

    public const STATUS_FAIL_PERMANENT = 'PERMFAIL';
    public const STATUS_FAIL_TEMPORARY = 'TEMPFAIL';
    public const STATUS_SUCCESS_INFO = 'INFO';

    /**
     * The original, unaltered message
     *
     * @var string
     */
    protected $raw = '';
    /**
     * Message headers, as a string with CRLF line breaks
     *
     * @var string
     */
    protected $headers = '';
    /**
     * Message headers, parsed into an array
     *
     * @var Header[]
     */
    protected $parsedHeaders = [];
    /**
     * Message body, as a string with CRLF line breaks
     *
     * @var string
     */
    protected $body = '';
    /**
     * @var array
     */
    private $publicKeys = [];

    /**
     * Constructor
     *
     * @param string $rawMessage
     *
     * @throws DKIMException
     */
    public function __construct(string $rawMessage = '')
    {
        //Ensure all processing uses UTF-8
        mb_internal_encoding('UTF-8');
        $this->raw = $rawMessage;
        if ($this->raw === '') {
            throw new DKIMException('No message content provided');
        }
        //Normalize line breaks to CRLF
        $message = str_replace([self::CRLF, self::CR, self::LF], [self::LF, self::LF, self::CRLF], $this->raw);
        //Split out headers and body, separated by the first double line break
        [$headers, $body] = explode(self::CRLF . self::CRLF, $message, 2);
        $this->body = $body;
        //The last header retains a trailing line break
        $this->headers = $headers . self::CRLF;
        $this->parsedHeaders = $this->parseHeaders($this->headers);
    }

    /**
     * Parse a complete header block in a CRLF-delimited string into an array.
     *
     * @param string $headers
     *
     * @return array
     */
    protected function parseHeaders(string $headers): array
    {
        $matches = [];
        preg_match_all('/(^(?:[^ \t].*[\r\n]+(?:[ \t].*[\r\n]+)*))/m', $headers, $matches);
        $parsedHeaders = [];
        foreach ($matches[0] as $match) {
            $parsedHeaders[] = HeaderFactory::create($match);
        }

        return $parsedHeaders;
    }

    /**
     * Validation wrapper - return boolean true/false about validation success/failure
     *
     * @return bool
     */
    public function validateBoolean(): bool
    {
        //Execute original validation method
        try {
            $res = $this->validate();
        } catch (DKIMException $e) {
            return false;
        } catch (HeaderException $e) {
            return false;
        }

        //Only return true in this case
        return (count($res) === 1)
            && (count($res[0]) === 1)
            && ($res[0][0]['status'] === 'SUCCESS');
    }

    /**
     * Validate all DKIM signatures found in the message.
     *
     * @return array
     *
     * @throws DKIMException|HeaderException
     */
    public function validate(): array
    {
        $output = [];

        //Find all DKIM signatures amongst the headers (there may be more than one)
        $signatures = $this->getDKIMHeaders();

        //Validate each signature in turn
        foreach ($signatures as $signatureIndex => $signature) {
            //Split into tags
            $dkimTags = $signature->extractDKIMTags();

            //Verify all required values are present
            //http://tools.ietf.org/html/rfc4871#section-6.1.1
            $required = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];
            foreach ($required as $tagIndex) {
                if (! array_key_exists($tagIndex, $dkimTags)) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Signature missing required tag: ${tagIndex}",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => "Required DKIM tag present: ${tagIndex}",
                    ];
                }
            }

            //Validate DKIM version number
            if (array_key_exists('v', $dkimTags) && (int) $dkimTags['v'] !== 1) {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_FAIL_PERMANENT,
                    'reason' => "Incompatible DKIM version: ${dkimTags['v']}",
                ];
            } else {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => "Compatible DKIM version found: ${dkimTags['v']}",
                ];
            }

            //Validate canonicalization algorithms for header and body
            [$headerCA, $bodyCA] = explode('/', $dkimTags['c']);
            if (
                $headerCA !== self::CANONICALIZATION_HEADERS_RELAXED &&
                $headerCA !== self::CANONICALIZATION_HEADERS_SIMPLE
            ) {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_FAIL_PERMANENT,
                    'reason' => "Unknown header canonicalization algorithm: ${headerCA}",
                ];
            }
            if (
                $bodyCA !== self::CANONICALIZATION_BODY_RELAXED &&
                $bodyCA !== self::CANONICALIZATION_BODY_SIMPLE
            ) {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_FAIL_PERMANENT,
                    'reason' => "Unknown body canonicalization algorithm: ${bodyCA}",
                ];
            } else {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => "Valid body canonicalization algorithm: ${bodyCA}",
                ];
            }

            //Canonicalize body
            $canonicalBody = $this->canonicalizeBody($this->body, $bodyCA);

            //Validate optional body length tag
            //If this is present, the canonical body should be *at least* this long,
            //though it may be longer, which is a minor security risk,
            //so it's common not to use the `l` tag
            if (array_key_exists('l', $dkimTags)) {
                $bodyLength = strlen($canonicalBody);
                if ((int) $dkimTags['l'] > $bodyLength) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Body too short: ' . $dkimTags['l'] . '/' . $bodyLength,
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => "Optional body length tag is present and valid: ${bodyLength}",
                    ];
                }
            }

            //Ensure the optional user identifier ends in the signing domain
            if (array_key_exists('i', $dkimTags)) {
                if (substr($dkimTags['i'], -strlen($dkimTags['d'])) !== $dkimTags['d']) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Agent or user identifier does not match domain: ' . $dkimTags['i'],
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Agent or user identifier matches domain: ' . $dkimTags['i'],
                    ];
                }
            }

            //Ensure the signature includes the From field
            if (array_key_exists('h', $dkimTags)) {
                if (stripos($dkimTags['h'], 'From') === false) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'From header not included in signed header list: ' . $dkimTags['h'],
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'From header is included in signed header list.',
                    ];
                }
            }

            //Validate and check expiry time
            if (array_key_exists('x', $dkimTags)) {
                if ((int) $dkimTags['x'] < time()) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Signature has expired.',
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Signature has not expired',
                    ];
                }
                if ((int) $dkimTags['x'] < (int) $dkimTags['t']) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Expiry time is before signature time.',
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Expiry time is after signature time.',
                    ];
                }
            }

            //The 'q' tag may be empty - fall back to default if it is
            if (! array_key_exists('q', $dkimTags) || $dkimTags['q'] === '') {
                $dkimTags['q'] = 'dns/txt';
            }

            //Abort if we have any errors at this point
            if (count($output) > 0) {
                continue;
            }

            //Fetch public keys from DNS using the domain and selector from the signature
            //May return multiple keys
            [$qType, $qFormat] = explode('/', $dkimTags['q'], 2);
            if ($qType . '/' . $qFormat === 'dns/txt') {
                try {
                    $dnsKeys = self::fetchPublicKeys($dkimTags['d'], $dkimTags['s']);
                } catch (ValidatorException $e) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_TEMPORARY,
                        'reason' => 'Invalid selector: ' . $dkimTags['s'] . ' for domain: ' . $dkimTags['d'],
                    ];
                    continue;
                } catch (DNSException $e) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_TEMPORARY,
                        'reason' => 'Public key not found in DNS, skipping signature',
                    ];
                    continue;
                }
                $this->publicKeys[$dkimTags['d']] = $dnsKeys;
            } else {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_FAIL_PERMANENT,
                    'reason' => 'Public key unavailable (unknown q= query format), skipping signature',
                ];
                continue;
            }

            //http://tools.ietf.org/html/rfc4871#section-6.1.3
            //Select signed headers and canonicalize
            $signedHeaderNames = array_unique(explode(':', $dkimTags['h']));
            $headersToCanonicalize = [];
            foreach ($signedHeaderNames as $headerName) {
                $matchedHeaders = $this->getHeadersNamed($headerName);
                foreach ($matchedHeaders as $header) {
                    $headersToCanonicalize[] = $header;
                }
            }
            //Need to remove the `b` value from the signature header before checking the hash
            $headersToCanonicalize[] = new DKIMSignatureHeader(
                'DKIM-Signature: ' .
                preg_replace('/b=(.*?)(;|$)/s', 'b=$2', $signature->getValue())
            );

            [$alg, $hash] = explode('-', $dkimTags['a']);

            //Canonicalize the headers
            $canonicalHeaders = $this->canonicalizeHeaders($headersToCanonicalize, $headerCA);

            //Calculate the body hash
            $bodyHash = self::hashBody($canonicalBody, $hash);

            if (! hash_equals($bodyHash, $dkimTags['bh'])) {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_FAIL_PERMANENT,
                    'reason' => 'Computed body hash does not match signature body hash',
                ];
            } else {
                $output[$signatureIndex][] = [
                    'status' => self::STATUS_SUCCESS_INFO,
                    'reason' => 'Body hash matches signature.',
                ];
            }

            //Iterate over keys
            foreach ($this->publicKeys[$dkimTags['d']] as $keyIndex => $publicKey) {
                //Confirm that pubkey version matches sig version (v=)
                if (array_key_exists('v', $publicKey) && $publicKey['v'] !== 'DKIM' . $dkimTags['v']) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Public key version does not match signature' .
                            " version (${dkimTags['d']} key #${keyIndex})",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key version matches signature.',
                    ];
                }

                //Confirm that published hash algorithm matches sig hash
                if (array_key_exists('h', $publicKey) && $publicKey['h'] !== $hash) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Public key hash algorithm does not match signature' .
                            " hash algorithm (${dkimTags['d']} key #${keyIndex})",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key hash algorithm matches signature.',
                    ];
                }

                //Confirm that the key type matches the sig key type
                if (array_key_exists('k', $publicKey) && $publicKey['k'] !== $alg) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Public key type does not match signature' .
                            " key type (${dkimTags['d']} key #${keyIndex})",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key type matches signature.',
                    ];
                }

                //Ensure the service type tag allows email usage
                if (array_key_exists('s', $publicKey) && $publicKey['s'] !== '*' && $publicKey['s'] !== 'email') {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'Public key service type does not permit email usage' .
                            " (${dkimTags['d']} key #${keyIndex}) ${publicKey['s']}",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'Public key service type permits email usage.',
                    ];
                }

                //@TODO check t= flags

                # Check that the hash algorithm is available in openssl
                if (! in_array($hash, openssl_get_md_methods(true), true)) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => "Signature algorithm ${hash} is not available for openssl_verify(), key #${keyIndex})",
                    ];
                    continue;
                }
                //Validate the signature
                $validationResult = self::validateSignature(
                    $publicKey['p'],
                    $dkimTags['b'],
                    $canonicalHeaders,
                    $hash
                );

                if (! $validationResult) {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_FAIL_PERMANENT,
                        'reason' => 'DKIM signature did not verify ' .
                            "(${dkimTags['d']}/${dkimTags['s']} key #${keyIndex})",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => self::STATUS_SUCCESS_INFO,
                        'reason' => 'DKIM signature verified successfully!',
                    ];
                }
            }
        }

        return $output;
    }

    /**
     * Get all DKIM signature headers.
     *
     * @return DKIMSignatureHeader[]
     */
    protected function getDKIMHeaders(): array
    {
        $matchedHeaders = [];
        foreach ($this->parsedHeaders as $header) {
            //Don't exit early as there may be multiple signature headers
            if ($header instanceof DKIMSignatureHeader) {
                $matchedHeaders[] = $header;
            }
        }

        return $matchedHeaders;
    }

    /**
     * Canonicalize a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param string $body The message body
     * @param string $algorithm 'relaxed' or 'simple' canonicalization algorithm
     * @param int $length Restrict the output length to this to match up with the `l` tag
     *
     * @return string
     */
    public function canonicalizeBody(
        string $body,
        string $algorithm = self::CANONICALIZATION_BODY_RELAXED,
        int $length = 0
    ): string {
        if ($body === '') {
            return self::CRLF;
        }

        //Convert CRLF to LF breaks for convenience
        $canonicalBody = str_replace(self::CRLF, self::LF, $body);
        if ($algorithm === self::CANONICALIZATION_BODY_RELAXED) {
            //http://tools.ietf.org/html/rfc4871#section-3.4.4
            //Remove trailing space
            $canonicalBody = preg_replace('/[ \t]+$/m', '', $canonicalBody);
            //Replace runs of whitespace with a single space
            $canonicalBody = preg_replace('/[ \t]+/m', self::SPACE, (string) $canonicalBody);
        }
        //Always perform rules for "simple" canonicalization as well
        //http://tools.ietf.org/html/rfc4871#section-3.4.3
        //Remove any trailing empty lines
        $canonicalBody = preg_replace('/\n+$/', '', (string) $canonicalBody);
        //Convert line breaks back to CRLF
        $canonicalBody = str_replace(self::LF, self::CRLF, (string) $canonicalBody);

        //Add last trailing CRLF
        $canonicalBody .= self::CRLF;

        //If we've been asked for a substring, return that, otherwise return the whole body
        return $length > 0 ? substr($canonicalBody, 0, $length) : $canonicalBody;
    }

    /**
     * Fetch the public key(s) for a domain and selector.
     *
     * @param string $domain
     * @param string $selector
     *
     * @return array
     *
     * @throws DNSException
     * @throws ValidatorException
     */
    public static function fetchPublicKeys(string $domain, string $selector): array
    {
        if (! self::validateSelector($selector)) {
            throw new ValidatorException('Invalid selector: ' . $selector);
        }
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        $textRecords = dns_get_record($host, DNS_TXT);

        if ($textRecords === false) {
            throw new DNSException('Domain has no TXT records available in DNS, or fetching them failed');
        }

        $publicKeys = [];
        foreach ($textRecords as $textRecord) {
            //Long keys may be split into pieces
            if (array_key_exists('entries', $textRecord)) {
                $textRecord['txt'] = implode('', $textRecord['entries']);
            }
            $parts = explode(';', trim($textRecord['txt']));
            $record = [];
            foreach ($parts as $part) {
                //Last record is empty if there is a trailing semicolon
                $part = trim($part);
                if ($part === '') {
                    continue;
                }
                if (strpos($part, '=') === false) {
                    throw new DNSException('DKIM TXT record has invalid format');
                }
                [$key, $val] = explode('=', $part, 2);
                $record[$key] = $val;
            }
            $publicKeys[] = $record;
        }

        return $publicKeys;
    }

    /**
     * Validate a DKIM selector.
     * DKIM selectors have the same rules as sub-domain names, as defined in RFC5321 4.1.2.
     * For example `march-2005.reykjavik` is valid.
     *
     * @see https://tools.ietf.org/html/rfc5321#section-4.1.2
     * @see https://tools.ietf.org/html/rfc6376#section-3.1
     *
     * @param string $selector
     *
     * @return bool
     */
    public static function validateSelector(string $selector): bool
    {
        /*
        //From RFC5321 4.1.2
        $let_dig = '[a-zA-Z\d]';
        $ldh_str = '([a-zA-Z\d-])*' . $let_dig;
        $sub_domain = $let_dig . '(' . $ldh_str . ')*';
        //From RFC6376 3.1
        $selectorpat = $sub_domain . '(\.' . $sub_domain . ')*';
        */

        return (bool) preg_match('/^' . self::SELECTOR_VALIDATION . '$/', $selector);
    }

    /**
     * Find message headers that match a given name.
     * May include multiple headers with the same name.
     *
     * @param string $headerName
     *
     * @return Header[]
     */
    protected function getHeadersNamed(string $headerName): array
    {
        $headerName = strtolower($headerName);
        $matchedHeaders = [];
        foreach ($this->parsedHeaders as $header) {
            //Don't exit early as there may be multiple headers with the same name
            if ($header->getLowerLabel() === $headerName) {
                $matchedHeaders[] = $header;
            }
        }

        return $matchedHeaders;
    }

    /**
     * Canonicalize message headers using either `relaxed` or `simple` algorithms.
     * The relaxed algorithm is more complex, but is more robust
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4
     *
     * @param Header[] $headers
     * @param string $algorithm 'relaxed' or 'simple'
     *
     * @return string
     *
     * @throws DKIMException
     */
    public function canonicalizeHeaders(
        array $headers,
        string $algorithm = self::CANONICALIZATION_HEADERS_RELAXED
    ): string {
        if (count($headers) === 0) {
            throw new DKIMException('Attempted to canonicalize empty header array');
        }

        $canonical = '';
        switch ($algorithm) {
            case self::CANONICALIZATION_HEADERS_SIMPLE:
                foreach ($headers as $header) {
                    $canonical .= $header->getSimpleCanonicalizedHeader();
                }
                break;
            case self::CANONICALIZATION_HEADERS_RELAXED:
            default:
                foreach ($headers as $header) {
                    $canonical .= $header->getRelaxedCanonicalizedHeader();
                }
                break;
        }

        return $canonical;
    }

    /**
     * Calculate the hash of a message body.
     *
     * @param string $body
     * @param string $hashAlgo Which hash algorithm to use
     *
     * @return string
     */
    protected static function hashBody(string $body, string $hashAlgo = self::DEFAULT_HASH_FUNCTION): string
    {
        return base64_encode(hash($hashAlgo, $body, true));
    }

    /**
     * Check whether a signed string matches its key.
     *
     * @param string $publicKey
     * @param string $signature
     * @param string $signedString
     * @param string $hashAlgo Any of the algos returned by openssl_get_md_methods()
     *
     * @return bool
     *
     * @throws DKIMException
     */
    protected static function validateSignature(
        string $publicKey,
        string $signature,
        string $signedString,
        string $hashAlgo = self::DEFAULT_HASH_FUNCTION
    ): bool {
        //Convert key back into PEM format
        $key = sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
            trim(chunk_split($publicKey, 64, self::LF))
        );

        $decodedSignature = base64_decode($signature, true);
        if ($decodedSignature === false) {
            throw new DKIMException('DKIM signature contains invalid base64 data');
        }
        $verified = openssl_verify($signedString, $decodedSignature, $key, $hashAlgo);
        switch ($verified) {
            case 1:
                return true;
            case 0:
                return false;
            case -1:
                $message = '';
                //There may be multiple errors; fetch them all
                while ($error = openssl_error_string() !== false) {
                    $message .= $error . self::LF;
                }
                throw new DKIMException('OpenSSL verify error: ' . $message);
        }

        //Code will never get here!
        return false;
    }

    /**
     * Return the message body.
     *
     * @return string
     */
    public function getBody(): string
    {
        return $this->body;
    }

    /**
     * Return the original message headers as a raw string.
     *
     * @return string
     */
    public function getRawHeaders(): string
    {
        return $this->headers;
    }

    /**
     * Return the parsed message headers.
     *
     * @return Header[]
     */
    public function getHeaders(): array
    {
        return $this->parsedHeaders;
    }
}
