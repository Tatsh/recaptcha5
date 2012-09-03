<?php
/**
 * Exceptions specific to recaptcha.
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
class recaptchaException extends Exception {
  public function __construct($message = '', $code = 0, Exception $previous = NULL) {
    $this->message = call_user_func_array('sprintf', func_get_args());
  }
}
