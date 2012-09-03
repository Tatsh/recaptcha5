# Extremely basic usage

```php
<?php
require 'recaptcha.php';

function add_error_message_to_form(&$form, $field, $message) {
  $form['errors'][$field] = $message;
}

function some_bootstrap_call() {
  recaptcha::setPublicKey($my_public_key);
  recaptcha::setPrivateKey($my_private_key);

  // If translation is necessary
  recaptcha::registerComposeCallback('my_translator');
}

function my_translator($str) {
  return isset($translations[$str]) ? $translations[$str] : $str;
}

function some_action() {
  $html = recaptcha::getHTML();
  my_template_system_render(array('recaptcha' => $html));
}

function some_action_post_handler($form) {
  try {
    $response = recaptcha::checkAnswer(
      $_SERVER['REMOTE_ADDR'],
      $_POST['recaptcha_challenge_field'],
      $_POST['recaptcha_response_field']
    );

    if (isset($response['is_valid']) && $response['is_valid'] !== TRUE) {
      // Handle if there is an error
      // An 'error' key will exist
      my_logger_log($response['error']);
      add_error_message_to_form($form, 'verification', 'Please enter the letters in the image');
    }
  }
  catch (recaptchaException $e) {
    // Handle exception, caused by HTTP request falure or other issue (like not configuring)
  }
}
```
