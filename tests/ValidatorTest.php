<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\DKIMException;
use PHPMailer\DKIMValidator\Validator;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\PhpUnit\DnsMock;

class ValidatorTest extends TestCase {
    public function setUp(): void
    {
        parent::setUp();
        DnsMock::register(Validator::class);
    }

    public static function canonicalTestMails(): array {
        $testMails = glob('./tests/data/canonicalFlag/*.eml');
        $tests = array();

        foreach ($testMails as $mail) {
            $tests[basename($mail, '.eml')] = [
                file_get_contents($mail),
                json_decode(file_get_contents("{$mail}.domainkey"), true)
            ];
        }

        return $tests;
    }

    /**
     * @dataProvider canonicalTestMails
     * @throws DKIMException
     */
    public function testCanonicalVerification(string $message, array $dkimEntry) {
        DnsMock::withMockedHosts($dkimEntry);
        $validator = new Validator($message);

        $result = $validator->validateBoolean();

        $this->assertTrue($result);
    }
}