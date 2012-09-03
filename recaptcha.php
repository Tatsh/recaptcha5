<?php
/**
 * A PHP 5 version of the reCAPTCHA PHP plugin.
 * 
 * This is based on the original recaptchalib.php written by Mike Crawford and Ben Maurer.
 *
 * @copyright 2012 Andrew Udvare
 * @author Andrew Udvare [au] <audvare@gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.php
 *
 * @package recaptcha
 * @link http://www.sutralib.com/
 * @link http://code.google.com/p/recaptcha/source/browse/trunk/recaptcha-plugins/php/recaptchalib.php
 *
 * @version 1.0
 */
class recaptcha {
  /**
   * The normal API server.
   *
   * @var string
   */
  const RECAPTCHA_API_SERVER = 'http://www.google.com/recaptcha/api';

  /**
   * The SSL API server.
   *
   * @var string
   */
  const RECAPTCHA_API_SECURE_SERVER = 'https://www.google.com/recaptcha/api';

  /**
   * The verification server.
   *
   * @var string
   */
  const RECAPTCHA_VERIFY_SERVER = 'www.google.com';

  /**
   * The current public key set.
   *
   * @var string
   */
  private static $public_key = NULL;

  /**
   * The current private key set.
   *
   * @var string
   */
  private static $private_key = NULL;

  /**
   * Composition callbacks for translation purposes.
   *
   * @var array
   */
  private static $compose_callbacks = array();

  /**
   * Sets the public key.
   *
   * @param string $key The key to set.
   * @return void
   */
  public static function setPublicKey($key) {
    self::$public_key = $key;
  }

  /**
   * Sets the private key.
   *
   * @param string $key The key to set.
   * @return void
   */
  public static function setPrivateKey($key) {
    self::$private_key = $key;
  }

  /**
   * Resets the class.
   *
   * @return void
   */
  public static function reset() {
    self::$public_key = NULL;
    self::$private_key = NULL;
    self::$compose_callbacks = array();
  }

  /**
   * Gets the public key.
   *
   * @return string|null The key value.
   */
  public static function getPublicKey() {
    return self::$public_key;
  }

  /**
   * Gets the private key.
   *
   * @return string|null The key value.
   */
  public static function getPrivateKey() {
    return self::$private_key;
  }

  /**
   * Gets the compose callbacks.
   *
   * @return array The compose callbacks.
   */
  public static function getComposeCallbacks() {
    return self::$compose_callbacks;
  }

  /**
   * Validates the keys.
   *
   * @throws recaptchaException If any keys are false-like.
   *
   * @return void
   */
  private static function validateKeys() {
    if (!self::$private_key) {
      throw new recaptchaException('To use this class a private key must be set with ::setPrivateKey(). An API key can be obtained at https://www.google.com/recaptcha/admin/create');
    }
    if (!self::$public_key) {
      throw new recaptchaException('To use this class a public key must be set with ::setPublicKey(). An API key can be obtained at https://www.google.com/recaptcha/admin/create');
    }
  }

  /**
   * Fixes query string values to be sent over a POST request.
   * 
   * @internal
   *
   * @return string The encoded value.
   */
  public static function encodeQueryStringValue($value) {
    return urlencode(stripslashes($value));
  }

  /**
   * Encodes the query string parameters.
   *
   * @param array $data The data to encode.
   * @return string The query data as a string.
   */
  private static function encodeQueryString(array $data) {
    $items = array();
    foreach ($data as $key => $value) {
      $items[] = $key.'='.self::encodeQueryStringValue($value);
    }
    return join('&', $items);
  }

  /**
   * Internal error handler. Does nothing but this prevents error messages
   *   without having to use the @ symbol.
   * 
   * @internal
   *
   * @return void
   */
  public static function errorHandler() {}

  /**
   * Makes a POST request.
   *
   * @param string $host Host name.
   * @param string $path Path name.
   * @param array $data Data to post.
   * @param integer $port Port to use.
   * @return array Response data.
   */
  private static function post($host, $path, array $data, $port = 80) {
    $data = self::encodeQueryString($data);
    $context = stream_context_create(array(
      'http' => array(
        'method' => 'POST',
        'user_agent' => 'recaptcha/PHP',
        'content' => $data,
        'header' => join("\r\n", array(
          'Content-Length: '.strlen($data),
          'Content-Type: application/x-www-form-urlencoded;',
          'Host: '.$host,
        )),
      )
    ));
    $url = $host.$path;
    $port = (int)$port;

    if ($port != 80) {
      $url .= ':'.$port;
    }

    set_error_handler(array(__CLASS__, 'errorHandler'));
    $response = file_get_contents('http://'.$url, FALSE, $context);
    restore_error_handler();

    if ($response === FALSE) {
      throw new recaptchaException('The URI, "%s", could not be loaded.', $url);
    }

    return explode("\n", $response, 2);
  }

  /**
   * Gets the HTML for reCAPTCHA.
   *
   * @param string $error_part The error given by reCAPTCHA.
   * @param boolean $use_ssl Whether or not to use SSL.
   * @return string HTML for use with a form.
   */
  public static function getHTML($error_part = NULL, $use_ssl = FALSE) {
    self::validateKeys();
    
    $server = self::RECAPTCHA_API_SERVER;
    $public_key = self::$public_key;

    if ($use_ssl) {
      $server = self::RECAPTCHA_API_SECURE_SERVER;
    }

    if ($error_part) {
      $error_part = '&amp;error='.$error_part;
    }

    return <<<HTML
      <script type="text/javascript" src="{$server}/challenge?k={$public_key}{$error_part}"></script>
      <noscript>
        <iframe src="{$server}/noscript?k={$public_key}{$error_part}" height="300" width="500"></iframe>
        <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
        <input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>
      </noscript>
HTML;
  }

  /**
   * Validates a response to a CAPTCHA.
   *
   * @param string $remote_ip Remote IP.
   * @param string $challenge The challenge text.
   * @param string $response The response text.
   * @param array $extra Extra GET parameters.
   * @return array Array with keys 'is_valid' (boolean) and if an error
   *   occurred, 'error' (string).
   */
  public static function checkAnswer($remote_ip, $challenge, $response, array $extra = array()) {
    self::validateKeys();

    if (!$remote_ip) {
      throw new recaptchaException('For security reasons, you must pass the remote ip to reCAPTCHA');
    }

    // Discard spam submissions
    if (!$challenge || !$response) {
      return array('is_valid' => FALSE, 'error' => 'incorrect-captcha-sol');
    }

    $response = self::post(self::RECAPTCHA_VERIFY_SERVER, '/recaptcha/api/verify', array_merge(array(
      'privatekey' => self::$private_key,
      'remoteip' => $remote_ip,
      'challenge' => $challenge,
      'response' => $response,
    ), $extra));
    $returned_response = array('is_valid' => false);

    if (strtolower(trim($response[0])) === 'true') {
      $returned_response['is_valid'] = true;
    }
    else {
      $returned_response['error'] = isset($response[1]) ? $response[1] : 'No error text';
    }

    return $returned_response;
  }

  /**
   * Gets the registration URL for an application.
   *
   * @param string $domain The domain where the page is hosted.
   * @param string $app_name The name of the application.
   * @return string The URL to visit.
   */
  public static function getRegistrationURL($domain = NULL, $app_name = NULL) {
    return 'https://www.google.com/recaptcha/admin/create?'.self::encodeQueryString(array(
      'domains' => $domain,
      'app' => $app_name
    ));
  }

  /**
   * Pads an AES-encrypted string.
   *
   * @param string $value Value to pad.
   * @return string Padded string.
   */
  private static function aesPad($value) {
    $block_size = 16;
    $numpad = $block_size - (strlen($value) % $block_size);
    return str_pad($value, strlen($value) + $numpad, chr($numpad));
  }

  /**
   * Encrypts a string with AES.
   *
   * @throws recaptchaException If mcrypt extension is not available.
   *
   * @param string $value Value to encrypt.
   * @param string $key Key to use.
   * @return string The encrypted string.
   */
  private static function aesEncrypt($value, $key) {
    if (!function_exists('mcrypt_encrypt')) {
      throw new recaptchaException('To use reCAPTCHA Mailhide, you need to have the mcrypt PHP extension installed.');
    }

    $mode = MCRYPT_MODE_CBC;
    $cipher = MCRYPT_RIJNDAEL_128;
    $value = self::aesPad($value);

    return mcrypt_encrypt($cipher, $key, $value, $mode, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
  }

  /**
   * Part of the mailhide API.
   *
   * @param string $value Value to encode.
   * @return string The encoded string.
   */
  private static function mailhideURLBase64($value) {
    return strtr(base64_encode($value), '+/', '-_');
  }

  /**
   * Gets the URL for the mailhide API.
   *
   * @param string $email E-mail address to hide.
   * @return string URL to use.
   */
  public static function getMailhideURL($email) {
    self::validateKeys();

    $key = pack('H*', self::$private_key);
    $cryptmail = self::aesEncrypt($email, $key);

    return 'http://www.google.com/recaptcha/mailhide/d?k='.self::$public_key.'&c='.self::mailhideURLBase64($cryptmail);
  }

  /**
   * Gets parts of the email address.
   *
   * @param string $email E-mail address.
   * @return array E-mail string split into pieces.
   */
  private static function mailHideEmailParts($email) {
    $arr = preg_split('/@/', $email);

    if (strlen ($arr[0]) <= 4) {
      $arr[0] = substr ($arr[0], 0, 1);
    }
    else if (strlen ($arr[0]) <= 6) {
      $arr[0] = substr ($arr[0], 0, 3);
    }
    else {
      $arr[0] = substr ($arr[0], 0, 4);
    }

    return $arr;
  }

  /**
   * Composes text. For translation purposes mainly.
   *
   * @param string $str String to translate.
   * @return string The translated string.
   */
  private static function compose($str) {
    foreach (self::$compose_callbacks as $callback) {
      $str = call_user_func($callback, $str);
    }
    return $str;
  }

  /**
   * Registers a composition callback. The argument for the callback is the
   *   string.
   *
   * @param callable $callback The callback to use.
   * @return void
   */
  public static function registerComposeCallback($callback) {
    self::$compose_callbacks[] = $callback;
  }

  /**
   * Gets the mailhide HTML.
   *
   * @param string $email E-mail address to hide.
   * @return string The HTML to use.
   */
  public static function getMailhideHTML($email) {
    self::validateKeys();
    
    $email_parts = self::mailHideEmailParts($email);
    $url = htmlentities(self::getMailhideURL($email));

    $email_part_0 = htmlentities($email_parts[0]);
    $email_part_1 = htmlentities($email_parts[1]);

    $js =<<<JS
      window.open('{$url}', '', toolbar=0,scrollbars=0,location=0,statusbar=0,menubar=0,resizable=0,width=500,height=300');
      return false;
JS;
    $js = trim(str_replace("\n", '', $js));
    $text = self::compose('Reveal this e-mail address');

    return <<<HTML
      {$email_part_0}<a href="{$url}" onclick="{$js}" title="{$text}">...</a>@{$email_part_1}
HTML;
  }
}

if (!class_exists('recaptchaException', FALSE)) {
  require 'recaptchaException.php';
}
