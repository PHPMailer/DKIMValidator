<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

class Validator extends DKIM
{

    /**
     * @var array
     */
    private $publicKeys = [];

    /**
     * Validation wrapper - return boolean true/false about validation success/failure
     *
     * @return bool
     *
     * @throws DKIMException
     */
    public function validateBoolean(): bool
    {
        // Execute original validation method
        $res = $this->validate();

        // Only return true in this case
        return (count($res) === 1)
            && (count($res[0]) === 1)
            && ($res[0][0]['status'] === 'SUCCESS');
    }

    /**
     * Validate all DKIM signatures found in the message.
     *
     * @return array
     *
     * @throws DKIMException
     */
    public function validate(): array
    {
        $output = [];

        //Find any DKIM signatures amongst the headers (there may be more than 1)
        $signatures = $this->getHeadersNamed('DKIM-Signature', 'raw');

        // Validate the Signature Header Field
        foreach ($signatures as $signatureIndex => $signature) {
            //Strip all internal spaces
            $signatureToProcess = preg_replace('/\s+/', '', $signature);
            //Split into tags
            $dkimTags = explode(';', $signatureToProcess);
            //Drop an empty last element caused by a trailing semi-colon
            if (end($dkimTags) === '') {
                array_pop($dkimTags);
            }
            foreach ($dkimTags as $tagIndex => $tagContent) {
                [$tagName, $tagValue] = explode('=', trim($tagContent), 2);
                unset($dkimTags[$tagIndex]);
                if ($tagName === '') {
                    continue;
                }
                $dkimTags[$tagName] = $tagValue;
            }

            // Verify all required values are present
            // http://tools.ietf.org/html/rfc4871#section-6.1.1
            $required = ['v', 'a', 'b', 'bh', 'd', 'h', 's'];
            foreach ($required as $tagIndex) {
                if (! array_key_exists($tagIndex, $dkimTags)) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => "Signature missing required tag: $tagIndex",
                    ];
                }
            }

            //Validate DKIM version number
            if ((int) $dkimTags['v'] !== 1) {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Incompatible DKIM version: ' . $dkimTags['v'],
                ];
            }

            //Validate optional canonicalization algorithms for header and body
            //Use simple/simple as default unless defined differently
            $headerCA = 'simple';
            $bodyCA = 'simple';

            if (array_key_exists('c', $dkimTags)) {
                $containsBodyAndHeaderAlgorithm = strpos($dkimTags['c'], '/') !== false;

                if ($containsBodyAndHeaderAlgorithm) {
                    $rules = explode('/', $dkimTags['c']);

                    $headerCA = $rules[0];
                    $bodyCA = $rules[1];
                } else {
                    $headerCA = $dkimTags['c'];
                }
            }

            if ($headerCA !== 'relaxed' && $headerCA !== 'simple') {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Unknown header canonicalization algorithm: ' . $headerCA,
                ];
            }
            if ($bodyCA !== 'relaxed' && $bodyCA !== 'simple') {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Unknown body canonicalization algorithm: ' . $bodyCA,
                ];
            }

            //Canonicalize body
            $canonicalBody = $this->canonicalizeBody($this->body, $bodyCA);

            //Validate optional body length tag
            //If this is present, the canonical body should be *at least* this long,
            //though it may be longer
            if (array_key_exists('l', $dkimTags)) {
                $bodyLength = strlen($canonicalBody);
                if ((int) $dkimTags['l'] > $bodyLength) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Body too short: ' . $dkimTags['l'] . '/' . $bodyLength,
                    ];
                }
            }

            //Ensure the user identifier ends in the signing domain
            if (array_key_exists('i', $dkimTags) &&
                substr($dkimTags['i'], -strlen($dkimTags['d'])) !== $dkimTags['d']
            ) {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Agent or user identifier does not match domain: ' . $dkimTags['i'],
                ];
            }

            //Ensure the signature includes the From field
            if (array_key_exists('h', $dkimTags) &&
                stripos($dkimTags['h'], 'From') === false) {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'From header not included in signed header list: ' . $dkimTags['h'],
                ];
            }

            //Validate and check expiry time
            if (array_key_exists('x', $dkimTags)) {
                if ((int) $dkimTags['x'] < time()) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Signature has expired.',
                    ];
                }
                if (isset($dkimTags['t']) && ((int) $dkimTags['x'] < (int) $dkimTags['t']) ) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Expiry time is before signature time.',
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
                $dnsKeys = self::fetchPublicKeys($dkimTags['d'], $dkimTags['s']);
                if ($dnsKeys === false) {
                    $output[$signatureIndex][] = [
                        'status' => 'TEMPFAIL',
                        'reason' => 'Public key not found in DNS',
                    ];
                    continue;
                }
                $this->publicKeys[$dkimTags['d']] = $dnsKeys;
            } else {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Public key unavailable (unknown q= query format)',
                ];
                continue;
            }

            //http://tools.ietf.org/html/rfc4871#section-6.1.3
            //Select signed headers and canonicalize
            $signedHeaderNames = array_unique(explode(':', $dkimTags['h']));
            $headersToCanonicalize = [];
            foreach ($signedHeaderNames as $headerName) {
                $matchedHeaders = $this->getHeadersNamed($headerName, 'label_raw');
                foreach ($matchedHeaders as $header) {
                    $headersToCanonicalize[] = $header;
                }
            }
            //Need to remove the `b` value from the signature header before checking the hash
            $headersToCanonicalize[] = 'DKIM-Signature: ' .
                preg_replace('/b=(.*?)(;|$)/s', 'b=$2', $signature);

            [$alg, $hash] = explode('-', $dkimTags['a']);

            //Canonicalize the headers
            $canonicalHeaders = $this->canonicalizeHeaders($headersToCanonicalize, $headerCA);

            //Calculate the body hash
            $bodyHash = self::hashBody($canonicalBody, $hash);

            if ($bodyHash !== $dkimTags['bh']) {
                $output[$signatureIndex][] = [
                    'status' => 'PERMFAIL',
                    'reason' => 'Computed body hash does not match signature body hash',
                ];
            }

            // Iterate over keys
            foreach ($this->publicKeys[$dkimTags['d']] as $keyIndex => $publicKey) {
                // Validate key
                // confirm that pubkey version matches sig version (v=)
                if (array_key_exists('v', $publicKey) && $publicKey['v'] !== 'DKIM' . $dkimTags['v']) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Public key version does not match signature' .
                            " version ({$dkimTags['d']} key #$keyIndex)",
                    ];
                }

                //Confirm that published hash algorithm matches sig hash
                if (array_key_exists('h', $publicKey) && $publicKey['h'] !== $hash) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Public key hash algorithm does not match signature' .
                            " hash algorithm ({$dkimTags['d']} key #$keyIndex)",
                    ];
                }

                //Confirm that the key type matches the sig key type
                if (array_key_exists('k', $publicKey) && $publicKey['k'] !== $alg) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Public key type does not match signature' .
                            " key type ({$dkimTags['d']} key #$keyIndex)",
                    ];
                }

                //Ensure the service type tag allows email usage
                if (array_key_exists('s', $publicKey) && $publicKey['s'] !== '*' && $publicKey['s'] !== 'email') {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'Public key service type does not permit email usage' .
                            " ({$dkimTags['d']} key #$keyIndex)" . $publicKey['s'],
                    ];
                }

                // @TODO check t= flags

                # Check that the hash algorithm is available in openssl
                if (! in_array($hash, openssl_get_md_methods(true), true)) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => "Signature algorithm $hash is not available" .
                            " for openssl_verify(), key #$keyIndex)",
                    ];
                    continue;
                }
                // Validate the signature
                $validationResult = self::validateSignature(
                    $publicKey['p'],
                    $dkimTags['b'],
                    $canonicalHeaders,
                    $hash
                );

                if (! $validationResult) {
                    $output[$signatureIndex][] = [
                        'status' => 'PERMFAIL',
                        'reason' => 'DKIM signature did not verify ' .
                            "({$dkimTags['d']}/{$dkimTags['s']} key #$keyIndex)",
                    ];
                } else {
                    $output[$signatureIndex][] = [
                        'status' => 'SUCCESS',
                        'reason' => 'DKIM signature verified successfully!',
                    ];
                }
            }
        }

        return $output;
    }

    /**
     * Fetch the public key(s) for a domain and selector.
     *
     * @param string $domain
     * @param string $selector
     *
     * @return array|bool
     */
    public static function fetchPublicKeys(string $domain, string $selector)
    {
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        $textRecords = dns_get_record($host, DNS_TXT);


        if ($textRecords === false) {
            return false;
        }

        $publicKeys = [];
        foreach ($textRecords as $record) {
            //Long keys may be split into pieces
            if (array_key_exists('entries', $record) && is_array($record)) {
                $record['txt'] = implode('', $record['entries']);
            }
            $parts = explode(';', trim($record['txt']));
            $record = [];
            foreach ($parts as $part) {
                // Last record is empty if there is trailing semicolon
                $part = trim($part);
                if ($part === '') {
                    continue;
                }
                [$key, $val] = explode('=', $part, 2);
                $record[$key] = $val;
            }
            $publicKeys[] = $record;
        }

        return $publicKeys;
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
        string $hashAlgo = 'sha256'
    ): bool {
        // Convert key back into PEM format
        $key = sprintf(
            "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----",
            trim(chunk_split($publicKey, 64, "\n"))
        );

        $verified = openssl_verify($signedString, base64_decode($signature), $key, $hashAlgo);
        switch ($verified) {
            case 1:
                return true;
            case 0:
                return false;
            case -1:
                $message = '';
                //There may be multiple errors; fetch them all
                while ($error = openssl_error_string() !== false) {
                    $message .= $error . "\n";
                }
                throw new DKIMException('OpenSSL verify error: ' . $message);
        }

        //Code will never get here!
        return false;
    }
}
