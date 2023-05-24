<?php

/**
 * Mini librería para realizar el proceso de regenerar el certificado 
 *
 * @author     KuroNeko
 * @license    🦄 Thei licensed this
 * @version    Release: 1.0.0
 */ 

class MiniLetsEncrypt {

    public $domain;
    public $publicPath;

    public $tempCertPrivate;
    public $tempCertSignRequest;
    public $challengeUrl;
    public $challengeToken;


    function __construct() {}

    public function setDomain($domain) {
        if(is_null($domain) || empty(trim($domain))) { throw new Exception('No se ha recibido el dominio al cual generar el SSL'); }

        $this->domain = $domain;
    }

    public function setPublicPath($publicPath) {
        if(is_null($publicPath) || empty(trim($publicPath))) { throw new Exception('No se ha recibido el dominio al cual generar el SSL'); }

        $this->publicPath = $publicPath;
    }

    public function generateSignCerts() {
        $key = openssl_pkey_new(array(
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ));
        
        $csr = openssl_csr_new([ 'commonName' => $this->domain ], $key);
        
        openssl_pkey_export($key, $privateKey);
        openssl_csr_export($csr, $csr);

        $this->tempCertPrivate     = $privateKey;
        $this->tempCertSignRequest = $csr;
    }

    public function requestNewCert() {
        $ch = curl_init('https://acme-v02.api.letsencrypt.org/acme/new-order');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [ 'Content-Type: application/json' ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode([
            'identifiers' => [ [ 'type' => 'dns', 'value' => $this->domain ] ],
            'challenges'  => [ [ 'type' => 'http-01' ] ],
            'csr'         => rtrim(strtr(base64_encode($this->tempCertSignRequest), '+/', '-_'), '=') 
        ]));

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        if($httpCode === 201) {
            $responseBody = substr($response, curl_getinfo($ch, CURLINFO_HEADER_SIZE));
            $responseData = json_decode($responseBody, true);

            $this->challengeUrl   = $responseData['challenges'][0]['url'];
            $this->challengeToken = $responseData['challenges'][0]['token'];
        } else {
            throw new Exception("No se pudo procesar la solicitud con Let's Encrypt. Error Code: {$httpCode}");
        }
    }

    public function resolveChallenge() {
        if(is_null($this->publicPath) || empty(trim($this->publicPath))) { throw new Exception('No se ha definido la carpeta pública'); }

        $key = openssl_pkey_get_private($this->tempCertPrivate);
        $details = openssl_pkey_get_details($key);

        $thumbprint = hash('sha256', $details['key']);

        file_put_contents(
            "{$this->publicPath}/.well-known/acme-challenge/{$this->challengeToken}",
            "{$this->challengeToken}.{$thumbprint}"
        );

        $ch = curl_init($this->challengeUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');

        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        curl_close($ch);

        if($httpCode === 200) {
            return true;
        } else {
            @unlink("{$this->publicPath}/.well-known/acme-challenge/{$this->challengeToken}");
            throw new Exception("No se pudo procesar el challenge de Let's Encrypt. Error Code: {$httpCode}");
        }
    }

    // por hacer:
    //  1. verificar el resultado de la verificacion
    //  2. obtener el contenido del certificado solicitado

}
