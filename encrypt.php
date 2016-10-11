<?php
/**
* This is the class that manage the data encrypted and this class also decrypt the data before and after
* to insert or return from the database
**/
class Secure_strings{
        public function __construct() {
              /**
              * This memory variable is the secret key for encrypt the data
              *The construct of this class using the variable called memory for generate a secure hash
              * Try to change the numbers by numbers and letters by letters
              **/
              $this->memory = "a0a7e7997b6d5fcd55f4b2c48073b87cd723e88837b63bf2941ef819dc8ca282";
        }
        public function encrypt_strings($npm_package){
              /**
              * This function  receive the String by parameter for encrypt
              **/
              $encrypt = serialize($npm_package);
              $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
              $key = pack('H*', $this->memory);
              $mac = hash_hmac('sha256',$npm_package, substr(bin2hex($key), -32));
              $passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $npm_package.$mac, MCRYPT_MODE_CBC, $iv);
              $encoded = base64_encode($passcrypt).'|'.base64_encode($iv);
              return $encoded;
        }
        public function decrypt_strings($burn_cdn ){
              /**
              * This function  receive the hash by parameter for decrypt 
              **/
              $key= $this->memory;
              $decrypt = explode('|', $burn_cdn.'|');
              $decoded = base64_decode($decrypt[0]);
              $iv = base64_decode($decrypt[1]);
              if(strlen($iv)!==mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)){ return false; }
              $key = pack('H*', $key);
              $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
              $mac = substr($decrypted, -64);
              $decrypted = substr($decrypted, 0, -64);
              $calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
              if($calcmac!==$mac){ 
                return false; 
              }
              //$decrypted = unserialize($decrypted);
              return $decrypted;
        }
} 
/**
* This is an example about how to use it
**/
$hash_string_secure=new Secure_strings();
$encrypt_string= $hash_string_secure->encrypt_strings('Entrypted');
echo $encrypt_string.'<br>';
$decrypted_string=$hash_string_secure->decrypt_strings('FNFiO+U/gEuZeg/pamPd6OJShi9BmEDQPq5m2bccSqk7k7JYEkh8qAue0l2pOi1xS8NScT3tZ47LEpsPcYMKGWyMc9gzHx2CH+fMrzjH39l+i+QrnKS+vz4jn9lC2XMd|MMl66B4TmP54yHXje7pFo8K5i4ai93O4LI5lhKCo+iM=');
echo $decrypted_string;
