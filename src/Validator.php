<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

use PHPMailer\DKIMValidator\DKIMHeader;

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
    public const WSP = ' ';

    /**
     * A regex pattern to validate DKIM selectors
     *
     * @see self::validateSelector() for how this pattern is constructed
     */
    public const SELECTOR_VALIDATION =
        '[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*(\.[a-zA-Z\d](([a-zA-Z\d-])*[a-zA-Z\d])*)*';

    /**
     * Tags that must be present in a DKIM-Signature header
     *
     * @see https://tools.ietf.org/html/rfc6376#section-6.1.1
     */
    public const DKIM_REQUIRED_TAGS = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];

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
     * Headers that must be included in a DKIM signature
     */
    public const MUST_SIGN_HEADERS = [
        'from',
    ];

    /**
     * Headers that should be included in a DKIM signature
     */
    public const SHOULD_SIGN_HEADERS = [
        'from',
        'sender',
        'reply-to',
        'subject',
        'date',
        'message-id',
        'to',
        'cc',
        'mime-version',
        'content-type',
        'content-transfer-encoding',
        'content-id',
        'content-description',
        'resent-date',
        'resent-from',
        'resent-sender',
        'resent-to',
        'resent-cc',
        'resent-message-id',
        'in-reply-to',
        'references',
        'list-id',
        'list-help',
        'list-unsubscribe',
        'list-subscribe',
        'list-post',
        'list-owner',
        'list-archive',
    ];

    /**
     * Headers that should not be included in a DKIM signature
     */
    public const SHOULD_NOT_SIGN_HEADERS = [
        'return-path',
        'received',
        'comments',
        'keywords',
        'bcc',
        'resent-bcc',
        'dkim-signature'
    ];

    /**
     * @var DKIMMessage
     */
    protected DKIMMessage $message;

    /**
     * An instance used for resolving DNS records.
     *
     * @var ResolverInterface
     */
    protected $resolver;

    /**
     * @var array
     */
    private array $publicKeys = [];

    /**
     * Constructor
     *
     * @param Message $message
     * @param ResolverInterface|null $resolver
     */
    public function __construct(Message $message, ResolverInterface $resolver = null)
    {
        $this->message = new DKIMMessage($message);
        //Injecting a DNS resolver allows this to be pluggable, which also helps with testing
        if ($resolver === null) {
            $this->resolver = new Resolver();
        } else {
            $this->resolver = $resolver;
        }
    }

    /**
     * Simple static wrapper – return boolean true/false for validation success/failure, and don't throw any exceptions.
     *
     * @param string $message
     *
     * @return bool
     */
    public static function isValid(string $message): bool
    {
        $validator = new self(new Message($message));
        //Execute original validation method
        try {
            $analysis = $validator->validate();
        } catch (DKIMException $e) {
            return false;
        } catch (HeaderException $e) {
            return false;
        }

        return $analysis->isValid();
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
        $signatures = $this->message->getDKIMSignatures();

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
                foreach (self::DKIM_REQUIRED_TAGS as $tag) {
                    if (! array_key_exists($tag, $dkimTags)) {
                        throw new ValidatorException("DKIM signature missing required tag: ${tag}" . '.');
                    }
                    $validationResult->addPass("Required DKIM tag present: ${tag}" . '.');
                }

                //Extract a list of lower-cased signed header names from the `h` tag
                //The content of the h tag has already been cleaned up in self::extractDKIMTags()
                $signedHeaderNames = array_map('strtolower', explode(':', $dkimTags['h']));
                if (count($signedHeaderNames) < 1) {
                    throw new ValidatorException(
                        "DKIM h tag does not include any header names: ${dkimTags['h']}" . '.'
                    );
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
                [$headerCA, $bodyCA] = explode('/', $dkimTags['c'], 2) + [1 => 'simple'];
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
                    $validationResult->addWarning(
                        'The optional `l` body length tag is considered a security weakness and should be avoided.'
                    );
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

                //Check that the signature signs headers that must be signed
                foreach (self::MUST_SIGN_HEADERS as $mustSignThis) {
                    if (! in_array($mustSignThis, $signedHeaderNames, true)) {
                        throw new ValidatorException(
                            'Header that must be signed is not signed: ' . $mustSignThis . '.'
                        );
                    }
                }
                $validationResult->addPass('All headers that must be signed are signed.');

                //Check whether the signature signs all headers that should be signed
                $noShould = true;
                foreach (self::SHOULD_SIGN_HEADERS as $shouldSignThis) {
                    $headersOfThisType = $this->message->getMessage()->getHeadersNamed($shouldSignThis);
                    if (count($headersOfThisType) > 0 && ! in_array($shouldSignThis, $signedHeaderNames, true)) {
                        $validationResult->addWarning(
                            'Header that should be signed is not signed: ' . $shouldSignThis . '.'
                        );
                        $noShould = false;
                    }
                }
                if ($noShould) {
                    $validationResult->addPass(
                        'All headers that should be signed are signed.'
                    );
                }

                //Check whether the signature signs headers that should not be signed
                $noShouldNot = true;
                foreach (self::SHOULD_NOT_SIGN_HEADERS as $shouldNotSignThis) {
                    if (in_array($shouldNotSignThis, $signedHeaderNames, true)) {
                        $validationResult->addWarning(
                            'Header that should not be signed is signed: ' . $shouldNotSignThis . '.'
                        );
                        $noShouldNot = false;
                    }
                }
                if ($noShouldNot) {
                    $validationResult->addPass(
                        'No headers that that should not be signed are signed.'
                    );
                }

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
                    } catch (DNSException $e) {
                        throw new ValidatorException('Public key not found in DNS, skipping signature.');
                    }
                    $this->publicKeys[$dkimTags['d']] = $dnsKeys;
                } else {
                    throw new ValidatorException(
                        'Public key unavailable (unknown q= query format), skipping signature.'
                    );
                }

                //https://tools.ietf.org/html/rfc6376#section-6.1.3
                //Select signed headers and canonicalize
                $headersToCanonicalize = [];
                foreach ($signedHeaderNames as $headerName) {
                    //TODO Deal with duplicate signed header values
                    //and extra blank headers used to force invalidation
                    $matchedHeaders = $this->message->getMessage()->getHeadersNamed($headerName);
                    foreach ($matchedHeaders as $header) {
                        $headersToCanonicalize[] = new DKIMHeader($header);
                    }
                }
                //Though it's not listed in the `h` tag, the DKIM signature needs to be included in the verification
                $headersToCanonicalize[] = new DKIMHeader(
                    new Header(
                        'DKIM-Signature: ' . $signature->getHeader()->getValue()
                    )
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

                    //We don't need to check whether the signature algorithm is available in openssl
                    //because we already checked that when looking at the signature, and we checked that
                    //it's the same value in DNS

                    //@TODO check t= flags

                    //Validate the signature
                    /** @psalm-suppress MixedArgument */
                    $signatureResult = self::validateSignature(
                        $publicKey['p'],
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
        //Convert CRLF to LF breaks for convenience
        $canonicalBody = str_replace(self::CRLF, self::LF, $this->message->getMessage()->getBody());
        if ($algorithm === self::CANONICALIZATION_BODY_RELAXED) {
            //http://tools.ietf.org/html/rfc6376#section-3.4.4
            //Remove trailing space
            $canonicalBody = preg_replace('/[ \t]+$/m', '', $canonicalBody);
            //Replace runs of whitespace with a single space
            $canonicalBody = preg_replace('/[ \t]+/m', self::WSP, (string)$canonicalBody);
        }
        //Always perform rules for "simple" canonicalization as well
        //http://tools.ietf.org/html/rfc6376#section-3.4.3
        //Remove any trailing empty lines
        $canonicalBody = preg_replace('/\n+$/', '', (string)$canonicalBody);
        //Convert line breaks back to CRLF
        $canonicalBody = str_replace(self::LF, self::CRLF, (string)$canonicalBody);

        //If the body is non-empty but does not end with a CRLF, add a CRLF
        //https://tools.ietf.org/html/rfc6376#section-3.4.4 (b)
        if (! empty($canonicalBody) && substr($canonicalBody, -2) !== self::CRLF) {
            $canonicalBody .= self::CRLF;
        }

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
     * @param array<int,Header> $headers
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
        foreach ($headers as $header) {
            $dkimheader = new DKIMHeader($header);
            if ($algorithm === self::CANONICALIZATION_HEADERS_SIMPLE) {
                $canonical .= DKIMHeader::removeBValue($dkimheader->getSimpleCanonicalizedHeader());
            } elseif ($algorithm === self::CANONICALIZATION_HEADERS_RELAXED) {
                $canonical .= DKIMHeader::removeBValue($dkimheader->getRelaxedCanonicalizedHeader());
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
        //Can return false if the $hashAlgo hash function doesn't exist
        if (! in_array($hashAlgo, hash_algos(), true)) {
            return '';
        }
        $hash = (string)hash($hashAlgo, $body, true);

        return base64_encode($hash);
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
     * @param DKIMHeader $header
     *
     * @return string[]
     */
    public static function extractDKIMTags(DKIMHeader $header): array
    {
        if (! $header->isDKIMSignature()) {
            throw new \InvalidArgumentException('Attempted to extract DKIM tags from a non-DKIM header');
        }
        $dkimTags = [];
        //DKIM-Signature headers ignore all internal spaces, which may have been added by unfolding
        $tagParts = explode(';', $header->getHeader()->getValueWithoutSpaces());
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
     * Filter the full list of headers against the list of headers signed by a DKIM signature.
     * Needs to be done backwards to ensure duplicate headers occur in the correct order.
     *
     * @param array<int,Header> $headers
     * @param array<int,string> $signedHeaderList
     *
     * @return array<int,Header>
     */
    public static function extractSignedHeaders(array $headers, array $signedHeaderList): array
    {
        $signedHeaders = [];
        $headers = array_reverse($headers);
        foreach ($signedHeaderList as $signedHeaderName) {
            foreach ($headers as $headerIndex => $header) {
                if ($header->getLowerLabel() === strtolower($signedHeaderName)) {
                    //We want this header, so add it to the output
                    $signedHeaders[] = $header;
                    //Remove this header from the source list
                    unset($headers[$headerIndex]);
                    //Skip the rest of this loop and start searching for the next signed header
                    break;
                }
            }
        }
        return $signedHeaders;
    }

    /**
     * @return Message
     */
    public function getMessage(): Message
    {
        return $this->message->getMessage();
    }
}
