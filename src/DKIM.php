<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

abstract class DKIM
{
    /**
     * We use this a lot, so make it a constant
     */
    public const CRLF = "\r\n";

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
     * @var array
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
    protected $params = [];

    /**
     * Initializes required variables and creates/returns a DKIM object
     *
     * @param string $rawMessage
     * @param array $params
     *
     * @throws DKIMException
     */
    public function __construct(string $rawMessage = '', array $params = [])
    {
        //Ensure all processing uses UTF-8
        mb_internal_encoding('UTF-8');
        $this->raw = $rawMessage;
        if (! $this->raw) {
            throw new DKIMException('No message content provided');
        }
        //Normalize line breaks to CRLF
        $message = str_replace([self::CRLF, "\r", "\n"], ["\n", "\n", self::CRLF], $this->raw);
        //Split out headers and body, separated by the first double line break
        [$headers, $body] = explode(self::CRLF . self::CRLF, $message, 2);
        $this->body = $body;
        $this->headers = $headers;
        $this->parsedHeaders = $this->parseHeaders($this->headers);

        $this->params = $params;
    }

    /**
     * Canonicalize a header in either "relaxed" or "simple" modes.
     * Requires an array of headers (header names are part of array values)
     *
     * @param array $headers
     * @param string $style 'relaxed' or 'simple'
     *
     * @return string
     *
     * @throws DKIMException
     */
    protected function canonicalizeHeaders(array $headers, string $style): string
    {
        if (count($headers) === 0) {
            throw new DKIMException('Attempted to canonicalize empty header array');
        }

        switch ($style) {
            case 'simple':
                return implode(self::CRLF, $headers);
            case 'relaxed':
            default:
                $new = [];
                foreach ($headers as $header) {
                    //Split off header name
                    [$name, $val] = explode(':', $header, 2);

                    //Lowercase field name
                    $name = strtolower(trim($name));

                    //Unfold header value
                    $val = preg_replace('/\r\n[ \t]+/', ' ', $val);

                    //Collapse whitespace to a single space
                    $val = trim(preg_replace('/\s+/', ' ', $val));

                    $new[] = "$name:$val";
                }

                return implode(self::CRLF, $new);
        }
    }

    /**
     * Canonicalize a message body in either "relaxed" or "simple" modes.
     * Requires a string containing all body content, with an optional byte-length
     *
     * @param string $body The message body
     * @param string $style 'relaxed' or 'simple' canonicalization algorithm
     * @param int $length Restrict the output length to this to match up with the `l` tag
     *
     * @return string
     */
    protected function canonicalizeBody(string $body, string $style, int $length = -1): string
    {
        if ($body === '') {
            return self::CRLF;
        }

        //Convert CRLF to LF breaks for convenience
        $canonicalBody = str_replace(self::CRLF, "\n", $body);
        if ($style === 'relaxed') {
            //http://tools.ietf.org/html/rfc4871#section-3.4.4
            //Remove trailing space
            $canonicalBody = preg_replace('/[ \t]+$/m', '', $canonicalBody);
            //Replace runs of whitespace with a single space
            $canonicalBody = preg_replace('/[ \t]+/m', ' ', $canonicalBody);
        }
        //Always perform rules for "simple" canonicalization as well
        //http://tools.ietf.org/html/rfc4871#section-3.4.3
        //Remove any trailing empty lines
        $canonicalBody = preg_replace('/\n+$/', '', $canonicalBody);
        //Convert line breaks back to CRLF
        $canonicalBody = str_replace("\n", self::CRLF, $canonicalBody);

        //Add last trailing CRLF
        $canonicalBody .= self::CRLF;

        //If we've been asked for a substring, return that, otherwise return the whole body
        return $length > 0 ? substr($canonicalBody, 0, $length) : $canonicalBody;
    }

    /**
     * Extract the headers from a message.
     *
     * @param $headerName
     * @param string $format
     *
     * @return array
     *
     * @throws DKIMException
     */
    protected function getHeadersNamed(string $headerName, string $format = 'raw'): array
    {
        $headerName = strtolower($headerName);
        $matchedHeaders = [];
        foreach ($this->parsedHeaders as $header) {
            //Don't exit early in case there are multiple headers with the same name
            if ($header['lowerlabel'] === $headerName) {
                switch ($format) {
                    case 'label':
                        //Only the header label
                        $matchedHeaders[] = $header['label'];
                        break;
                    case 'raw':
                        //Complete header value without label, may contain line breaks and folding
                        $matchedHeaders[] = $header['raw'];
                        break;
                    case 'label_raw':
                        //Complete header including label, may contain line breaks and folding
                        $matchedHeaders[] = $header['label'] . ': ' . $header['raw'];
                        break;
                    case 'array':
                        //Complete header including label, may be folded, with each line as an array element
                        $matchedHeaders[] = $header['rawarray'];
                        break;
                    case 'unfolded':
                        //Just the value, unfolded
                        $matchedHeaders[] = $header['unfolded'];
                        break;
                    case 'label_unfolded':
                        //Label and value, unfolded
                        $matchedHeaders[] = $header['label'] . ': ' . $header['unfolded'];
                        break;
                    case 'decoded':
                        //Just the value, unfolded and decoded; may contain UTF-8
                        $matchedHeaders[] = $header['decoded'];
                        break;
                    case 'label_decoded':
                        //Label and value, unfolded and decoded; may contain UTF-8
                        $matchedHeaders[] = $header['label'] . ': ' . $header['decoded'];
                        break;
                    default:
                        throw new DKIMException('Invalid header format requested');
                }
            }
        }

        return $matchedHeaders;
    }

    /**
     * Parse a set of headers in a CRLF-delimited string into an array.
     * Each entry contains the header name as a `label` element and three variants of the value:
     * * `raw`: a complete copy of the whole header as a single string, with FWS and CRLF breaks if folded
     * * `rawarray` as raw, but with each line of the header as a separate array element
     * * `value` the unfolded value, without a label.
     *
     * @param string $headers
     *
     * @return array
     *
     * @throws DKIMException
     */
    protected function parseHeaders(string $headers): array
    {
        $headerLines = explode(self::CRLF, $headers);
        $headerLineCount = count($headerLines);
        $headerLineIndex = 0;
        $parsedHeaders = [];
        $currentHeaderLabel = '';
        $currentHeaderValue = '';
        $currentRawHeaderLines = [];
        foreach ($headerLines as $headerLine) {
            $matches = [];
            if (preg_match('/^([^ \t]*?)(?::[ \t]*)(.*)$/', $headerLine, $matches)) {
                //This is a line that does not start with FWS, so it's the start of a new header
                if ($currentHeaderLabel !== '') {
                    $parsedHeaders[] = [
                        'label'      => $currentHeaderLabel,
                        'lowerlabel' => strtolower($currentHeaderLabel),
                        'unfolded'   => $currentHeaderValue,
                        'decoded'    => self::rfc2047Decode($currentHeaderValue),
                        'rawarray'   => $currentRawHeaderLines,
                        'raw'        => implode(self::CRLF, $currentRawHeaderLines), //Refold lines
                    ];
                }
                $currentHeaderLabel = $matches[1];
                $currentHeaderValue = $matches[2];
                $currentRawHeaderLines = [$currentHeaderValue];
            } elseif (preg_match('/^[ \t]+(.*)$/', $headerLine, $matches)) {
                if ($headerLineIndex === 0) {
                    throw new DKIMException('Invalid headers starting with a folded line');
                }
                //This is a folded continuation of the current header
                $currentHeaderValue .= $matches[1];
                $currentRawHeaderLines[] = $matches[0];
            }
            ++$headerLineIndex;
            if ($headerLineIndex >= $headerLineCount) {
                //This was the last line, so finish off this header
                $parsedHeaders[] = [
                    'label'      => $currentHeaderLabel,
                    'lowerlabel' => strtolower($currentHeaderLabel),
                    'unfolded'   => $currentHeaderValue,
                    'decoded'    => self::rfc2047Decode($currentHeaderValue),
                    'rawarray'   => $currentRawHeaderLines,
                    'raw'        => implode(self::CRLF, $currentRawHeaderLines),
                ];
            }
        }

        return $parsedHeaders;
    }

    /**
     * Decode a header encoded with RFC2047 Q or B encoding.
     *
     * @param $header
     *
     * @return string
     */
    protected static function rfc2047decode(string $header): string
    {
        return mb_decode_mimeheader($header);
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
    public function getHeaders(): string
    {
        return $this->headers;
    }

    /**
     * Calculate the hash of a message body.
     *
     * @param string $body
     * @param string $hashAlgo Which hash algorithm to use
     *
     * @return string
     */
    protected static function hashBody(string $body, string $hashAlgo = 'sha256'): string
    {
        return base64_encode(hash($hashAlgo, $body, true));
    }
}
