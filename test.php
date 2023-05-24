<?php

try {
    # Cargar la mini librería
    require_once('./letsencrypt.class.php');

    # Invocar a la mini librería
    $le = new MiniLetsEncrypt();

    # Definir el dominio para el que se creará el certificado
    $le->setDomain('example.com');

    # Definir el path publico (accesible desde la web); esto para el challenge tipo HTTP-01 para el certificado
    $le->setPublicPath('/var/html/www'); # sin '/' al final


    # Generar certificados para emitir la solicitud a Let's Encrypt 
    $le->generateSignCerts();

    # Enviar los datos de los certificados a Let's Encrypt
    $le->requestNewCert();

    # Resolver el challenge
    $le->resolveChallenge();

} catch (\Throwable $th) {
    var_dump($th->getMessage());
}
