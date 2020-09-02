<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class Validator
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
     * @var Message
     */
    protected $message;

    /**
     * An instance used for resolving DNS records.
     *
     * @var ResolverInterface
     */
    protected $resolver;

    /**
     * @var array
     */
    private $publicKeys = [];

    /**
     * Constructor
     *
     * @param Message $message
     * @param ResolverInterface|null $resolver
     */
    public function __construct(Message $message, ResolverInterface $resolver = null)
    {
        $this->message = $message;
        //Injecting a DNS resolver allows this to be pluggable, which also helps with testing
        if ($resolver === null) {
            $this->resolver = new Resolver();
        } else {
            $this->resolver = $resolver;
        }
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
            $analysis = $this->validate();
        } catch (DKIMException $e) {
            return false;
        } catch (HeaderException $e) {
            return false;
        }

        return (bool)$analysis->isValid();
    }

    /**
     * Validate all DKIM signatures found in the message.
     *
     * @return ValidationResults
     *
     * @throws DKIMException|HeaderException
     */
    public function validate(): ValidationResults
    {
        $validationResults = new ValidationResults();

        //Find all DKIM signatures amongst the headers (there may be more than one)
        $signatures = $this->message->getDKIMHeaders();

        if (empty($signatures)) {
            $validationResult = new ValidationResult();
            $validationResult->addFail('Message does not contain a DKIM signature.');
            $validationResults->addResult($validationResult);
            return $validationResults;
        }
        //Validate each signature in turn
        $sigIndex = 0;
        foreach ($signatures as $signatureIndex => $signature) {
            $validationResult = new ValidationResult();
            try {
                //Split into tags
                $dkimTags = self::extractDKIMTags($signature);

                //Verify all required tags are present
                //http://tools.ietf.org/html/rfc4871#section-6.1.1
                $required = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];
                foreach ($required as $tagIndex) {
                    if (! array_key_exists($tagIndex, $dkimTags)) {
                        throw new ValidatorException("DKIM signature missing required tag: ${tagIndex}" . '.');
                    }
                    $validationResult->addPass("Required DKIM tag present: ${tagIndex}" . '.');
                }

                //Validate the domain
                if (! self::validateDomain($dkimTags['d'])) {
                    throw new ValidatorException("Signing domain is invalid: ${dkimTags['d']}" . '.');
                }
                $validationResult->setDomain($dkimTags['d']);
                $validationResult->addPass("Signing domain is valid: ${dkimTags['d']}" . '.');

                //Validate the selector
                if (! self::validateSelector($dkimTags['s'])) {
                    throw new ValidatorException("Signing selector is invalid: ${dkimTags['s']}" . '.');
                }
                $validationResult->setSelector($dkimTags['s']);
                $validationResult->addPass("Signing selector is valid: ${dkimTags['s']}");

                //Validate DKIM version number
                if (array_key_exists('v', $dkimTags) && (int)$dkimTags['v'] !== 1) {
                    throw new ValidatorException("Incompatible DKIM version: ${dkimTags['v']}" . '.');
                }
                $validationResult->addPass("Compatible DKIM version: ${dkimTags['v']}" . '.');

                //Validate canonicalization algorithms for header and body
                [$headerCA, $bodyCA] = explode('/', $dkimTags['c'], 2);
                if (
                    $headerCA !== self::CANONICALIZATION_HEADERS_RELAXED &&
                    $headerCA !== self::CANONICALIZATION_HEADERS_SIMPLE
                ) {
                    throw new ValidatorException("Unknown header canonicalization algorithm: ${headerCA}" . '.');
                }
                $validationResult->addPass("Valid header canonicalization algorithm: ${headerCA}" . '.');
                if (
                    $bodyCA !== self::CANONICALIZATION_BODY_RELAXED &&
                    $bodyCA !== self::CANONICALIZATION_BODY_SIMPLE
                ) {
                    throw new ValidatorException("Unknown body canonicalization algorithm: ${bodyCA}" . '.');
                }
                $validationResult->addPass("Valid body canonicalization algorithm: ${bodyCA}" . '.');

                //Canonicalize body
                $canonicalBody = $this->canonicalizeBody($bodyCA);

                //Validate optional body length tag
                //If this is present, the canonical body should be *at least* this long,
                //though it may be longer, which is a minor security risk,
                //so it's common not to use the `l` tag
                if (array_key_exists('l', $dkimTags)) {
                    $bodyLength = strlen($canonicalBody);
                    if ((int)$dkimTags['l'] > $bodyLength) {
                        throw new ValidatorException('Body too short: ' . $dkimTags['l'] . '/' . $bodyLength . '.');
                    }
                    $validationResult->addPass("Optional body length tag is present and valid: ${bodyLength}" . '.');
                }

                //Ensure the optional user identifier ends in the signing domain
                if (array_key_exists('i', $dkimTags)) {
                    if (substr($dkimTags['i'], -strlen($dkimTags['d'])) !== $dkimTags['d']) {
                        throw new ValidatorException(
                            'Agent or user identifier does not match domain: ' . $dkimTags['i'] . '.'
                        );
                    }
                    $validationResult->addPass('Agent or user identifier matches domain: ' . $dkimTags['i'] . '.');
                }

                //Ensure the signature includes the From field
                if (stripos($dkimTags['h'], 'From') === false) {
                    throw new ValidatorException(
                        'From header not included in signed header list: ' . $dkimTags['h'] . '.'
                    );
                }
                $validationResult->addPass('From header is included in signed header list.');

                //Validate and check expiry time
                if (array_key_exists('x', $dkimTags)) {
                    if ((int)$dkimTags['x'] < time()) {
                        throw new ValidatorException('Signature has expired.');
                    }
                    $validationResult->addPass('Signature has not expired');
                    if ((int)$dkimTags['x'] < (int)$dkimTags['t']) {
                        throw new ValidatorException('Expiry time is before signature time.');
                    }
                    $validationResult->addPass('Expiry time is after signature time.');
                }

                //The 'q' tag may be empty - add a default value if it is
                if (! array_key_exists('q', $dkimTags) || $dkimTags['q'] === '') {
                    $dkimTags['q'] = 'dns/txt';
                    $validationResult->addWarning('Added missing optional \'q\' tag.');
                }

                //Fetch public keys from DNS using the domain and selector from the signature
                //May return multiple keys
                [$qType, $qFormat] = explode('/', $dkimTags['q'], 2);
                if ($qType . '/' . $qFormat === 'dns/txt') {
                    try {
                        $dnsKeys = $this->fetchPublicKeys($dkimTags['d'], $dkimTags['s']);
                    } catch (ValidatorException $e) {
                        throw new ValidatorException(
                            'Invalid selector: ' . $dkimTags['s'] . ' for domain: ' . $dkimTags['d'] . '.'
                        );
                    } catch (DNSException $e) {
                        throw new ValidatorException('Public key not found in DNS, skipping signature.');
                    }
                    $this->publicKeys[$dkimTags['d']] = $dnsKeys;
                } else {
                    throw new ValidatorException(
                        'Public key unavailable (unknown q= query format), skipping signature.'
                    );
                }

                //http://tools.ietf.org/html/rfc4871#section-6.1.3
                //Select signed headers and canonicalize
                $signedHeaderNames = array_unique(explode(':', $dkimTags['h']));
                $headersToCanonicalize = [];
                foreach ($signedHeaderNames as $headerName) {
                    //TODO Deal with duplicate signed header values
                    //and extra blank headers used to force invalidation
                    $matchedHeaders = $this->message->getHeadersNamed($headerName);
                    foreach ($matchedHeaders as $header) {
                        $headersToCanonicalize[] = $header;
                    }
                }
                //A DKIM signature needs to be included in the verification, but it won't appear in the `h` tag
                //, and Need to remove the `b` value from the signature header before checking the hash
                $headersToCanonicalize[] = new Header(
                    'DKIM-Signature: ' .
                    preg_replace('/b=(.*?)(;|$)/s', 'b=$2', $signature->getValue())
                );

                //Extract the encryption algorithm and hash function and validate according to the
                //https://tools.ietf.org/html/rfc6376#section-3.5 definition of the `a` tag
                $matches = [];
                if (
                    preg_match(
                        '/^(rsa|[a-zA-Z][a-zA-Z\d]*)-(sha1|sha256|[a-zA-Z][a-zA-Z\d]*)$/',
                        $dkimTags['a'],
                        $matches
                    )
                ) {
                    $alg = $matches[1];
                    $hash = $matches[2];
                } else {
                    throw new ValidatorException('\'a\' tag uses an invalid signature algorithm specifier');
                }

                # Check that the hash algorithm is available in openssl
                if (! in_array($hash, openssl_get_md_methods(true), true)) {
                    throw new ValidatorException("Signature algorithm ${hash} is not available in" . ' openssl');
                }

                //Canonicalize the headers for this signature
                $canonicalHeaders = $this->canonicalizeHeaders($headersToCanonicalize, $headerCA, $sigIndex);

                //Calculate the body hash
                $bodyHash = self::hashBody($canonicalBody, $hash);

                if (! hash_equals($bodyHash, $dkimTags['bh'])) {
                    throw new ValidatorException('Computed body hash does not match signature body hash');
                }
                $validationResult->addPass('Body hash matches signature.');

                //Iterate over keys
                /** @psalm-suppress MixedAssignment */
                foreach ($this->publicKeys[$dkimTags['d']] as $keyIndex => $publicKey) {
                    //Confirm that pubkey version matches sig version (v=)
                    /** @var string[] $publicKey */
                    /** @psalm-suppress MixedArgument */
                    if (array_key_exists('v', $publicKey) && $publicKey['v'] !== 'DKIM' . $dkimTags['v']) {
                        throw new ValidatorException(
                            'Public key version does not match signature' .
                            " version (${dkimTags['d']} key #${keyIndex})"
                        );
                    }
                    $validationResult->addPass('Public key version matches signature.');

                    //Confirm that published hash algorithm matches sig hash
                    //The h tag in DKIM DNS records is optional, and defaults to sha256
                    if (array_key_exists('h', $publicKey) && $publicKey['h'] !== $hash) {
                        throw new ValidatorException(
                            'Public key hash algorithm does not match signature' .
                            " hash algorithm (${dkimTags['d']} key #${keyIndex})"
                        );
                    }
                    $validationResult->addPass('Public key hash algorithm (' . $hash . ') matches signature.');

                    //Confirm that the DNS key type matches the signature key type
                    if (array_key_exists('k', $publicKey) && $publicKey['k'] !== $alg) {
                        throw new ValidatorException(
                            'Public key type does not match signature' .
                            " key type (${dkimTags['d']} key #${keyIndex})"
                        );
                    }
                    $validationResult->addPass('Public key type(' . $alg . ') matches signature.');

                    //Ensure the service type tag allows email usage
                    if (array_key_exists('s', $publicKey) && $publicKey['s'] !== '*' && $publicKey['s'] !== 'email') {
                        throw new ValidatorException(
                            'Public key service type does not permit email usage' .
                            " (${dkimTags['d']} key #${keyIndex}) ${publicKey['s']}"
                        );
                    }
                    $validationResult->addPass('Public key service type permits email usage.');

                    //@TODO check t= flags

                    // Same as the earlier check for the DKIM a tag, but for the DNS record
                    if (! in_array($hash, openssl_get_md_methods(true), true)) {
                        throw new ValidatorException(
                            "Signature algorithm ${hash} is not available in openssl, key #${keyIndex}"
                        );
                    }

                    //Validate the signature
                    $signatureResult = self::validateSignature(
                        (string)$publicKey['p'],
                        $dkimTags['b'],
                        $canonicalHeaders,
                        $hash
                    );

                    if (! $signatureResult) {
                        throw new ValidatorException(
                            'DKIM signature did not verify ' .
                            "(${dkimTags['d']}/${dkimTags['s']} key #${keyIndex})"
                        );
                    }
                    $validationResult->addPass('DKIM signature verified successfully!');
                }
            } catch (ValidatorException $e) {
                $validationResult->addFail($e->getMessage());
            }
            $validationResults->addResult($validationResult);
            ++$sigIndex;
        }

        return $validationResults;
    }

    /**
     * Canonicalize a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param string $algorithm 'relaxed' or 'simple' canonicalization algorithm
     * @param int $length Restrict the output length to this to match up with the `l` tag
     *
     * @return string
     */
    public function canonicalizeBody(
        string $algorithm = self::CANONICALIZATION_BODY_RELAXED,
        int $length = 0
    ): string {
        if ($this->message->getBody() === '') {
            return self::CRLF;
        }

        //Convert CRLF to LF breaks for convenience
        $canonicalBody = str_replace(self::CRLF, self::LF, $this->message->getBody());
        if ($algorithm === self::CANONICALIZATION_BODY_RELAXED) {
            //http://tools.ietf.org/html/rfc4871#section-3.4.4
            //Remove trailing space
            $canonicalBody = preg_replace('/[ \t]+$/m', '', $canonicalBody);
            //Replace runs of whitespace with a single space
            $canonicalBody = preg_replace('/[ \t]+/m', self::SPACE, (string)$canonicalBody);
        }
        //Always perform rules for "simple" canonicalization as well
        //http://tools.ietf.org/html/rfc4871#section-3.4.3
        //Remove any trailing empty lines
        $canonicalBody = preg_replace('/\n+$/', '', (string)$canonicalBody);
        //Convert line breaks back to CRLF
        $canonicalBody = str_replace(self::LF, self::CRLF, (string)$canonicalBody);

        //Add last trailing CRLF
        $canonicalBody .= self::CRLF;

        //If we've been asked for a substring, return that, otherwise return the whole body
        return $length > 0 ? substr($canonicalBody, 0, $length) : $canonicalBody;
    }

    /**
     * Fetch the public key(s) for a domain and selector.
     * Return value is usually (records may vary or have optional tags) of the format:
     * [['v' => <DKIM version>, 'k' => <keytype>, 'p' => <key>]*]
     *
     * @param string $domain
     * @param string $selector
     *
     * @return array
     *
     * @throws DNSException
     * @throws ValidatorException
     */
    public function fetchPublicKeys(string $domain, string $selector): array
    {
        if (! self::validateSelector($selector)) {
            throw new ValidatorException('Invalid selector: ' . $selector);
        }
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        //The resolver takes care of merging if the record has been split into multiple strings
        $textRecords = $this->resolver->getTextRecords($host);

        if ($textRecords === []) {
            throw new DNSException('Domain has no DKIM records in DNS, or fetching them failed');
        }

        $publicKeys = [];
        foreach ($textRecords as $textRecord) {
            //Dismantle the DKIM record
            /** @var string $textRecord */
            $parts = explode(';', trim($textRecord));
            $record = [];
            foreach ($parts as $part) {
                //Last entry will be empty if there is a trailing semicolon, so skip it
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

        return (bool)preg_match('/^' . self::SELECTOR_VALIDATION . '$/', $selector);
    }

    /**
     * Validate a domain name.
     *
     * @param string $domain
     *
     * @return bool
     */
    public static function validateDomain(string $domain): bool
    {
        //FILTER_FLAG_HOSTNAME can't be used because it denies using `_`, which is needed for DKIM
        return (bool)filter_var($domain, FILTER_VALIDATE_DOMAIN);
    }

    /**
     * Canonicalize message headers using either `relaxed` or `simple` algorithms.
     * The relaxed algorithm applies more complex normalisation, but is more robust as a result
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4
     *
     * @param Header[] $headers
     * @param string $algorithm 'relaxed' or 'simple'
     *
     * @param int $forSignature the index of the DKIM signature to canonicalize for
     *
     * @return string
     *
     * @throws DKIMException
     */
    public function canonicalizeHeaders(
        array $headers,
        string $algorithm = self::CANONICALIZATION_HEADERS_RELAXED,
        int $forSignature = 0
    ): string {
        if (count($headers) === 0) {
            throw new DKIMException('Attempted to canonicalize empty header array');
        }

        $canonical = '';
        $sigIndex = 0;
        foreach ($headers as $header) {
            $stripBvalue = false;
            if ($header->isDKIMSignature()) {
                if ($forSignature === $sigIndex) {
                    //This is the signature we are canonicalizing for, so we need to remove its b tag value
                    $stripBvalue = true;
                }
                ++$sigIndex;
            }
            if ($algorithm === self::CANONICALIZATION_HEADERS_SIMPLE) {
                $canonical .= $header->getSimpleCanonicalizedHeader($stripBvalue);
            } elseif ($algorithm === self::CANONICALIZATION_HEADERS_RELAXED) {
                $canonical .= $header->getRelaxedCanonicalizedHeader($stripBvalue);
            }
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
     * Check whether a signed string matches its signature.
     *
     * @param string $publicKeyB64 A base64-encoded public key obtained from DNS
     * @param string $signatureB64 A base64-encoded openssl signature, as found in a DKIM 'b' tag
     * @param string $text The message to verify; usually a canonicalized email message
     * @param string $hashAlgo Any of the algorithms returned by openssl_get_md_methods(),
     *   but must be supported by DKIM; usually 'sha256'
     *
     * @return bool
     *
     * @throws DKIMException
     */
    public static function validateSignature(
        string $publicKeyB64,
        string $signatureB64,
        string $text,
        string $hashAlgo = self::DEFAULT_HASH_FUNCTION
    ): bool {
        //Convert key from DNS format into PEM format if its not already wrapped
        $key = $publicKeyB64;
        if (strpos($publicKeyB64, '-----BEGIN PUBLIC KEY-----') !== 0) {
            $key = sprintf(
                "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n",
                trim(chunk_split($publicKeyB64, 64, self::LF))
            );
        }

        $signature = base64_decode($signatureB64, true);
        if ($signature === false) {
            throw new DKIMException('DKIM signature contains invalid base64 data');
        }
        try {
            $verified = openssl_verify($text, $signature, $key, $hashAlgo);
        } catch (\ErrorException $e) {
            //Things like incorrectly formatted keys will trigger this
            throw new DKIMException('Could not verify signature: ' . $e->getMessage());
        }
        if ($verified === 1) {
            return true;
        }
        if ($verified === -1) {
            $message = '';
            //There may be multiple errors; fetch them all
            while ($error = openssl_error_string() !== false) {
                $message .= $error . self::LF;
            }
            throw new DKIMException('OpenSSL verify error: ' . $message);
        }

        return false;
    }

    /**
     * Extract DKIM parameters from a DKIM signature header value.
     *
     * @param Header $header
     *
     * @return string[]
     */
    public static function extractDKIMTags(Header $header): array
    {
        if (!$header->isDKIMSignature()) {
            throw new \InvalidArgumentException('Attempted to extract DKIM tags from a non-DKIM header');
        }
        $dkimTags = [];
        //DKIM-Signature headers ignore all internal spaces, which may have been added by folding
        $tagParts = explode(';', $header->getValueWithoutSpaces());
        foreach ($tagParts as $tagIndex => $tagContent) {
            if (trim($tagContent) === '') {
                //Ignore any extra or trailing ; separators resulting in empty tags
                continue;
            }
            [$tagName, $tagValue] = explode('=', trim($tagContent), 2);
            if ($tagName === '') {
                continue;
            }
            $dkimTags[$tagName] = $tagValue;
        }

        return $dkimTags;
    }

    /**
     * @return Message
     */
    public function getMessage(): Message
    {
        return $this->message;
    }
}
