<?php

/**
 * Entity class representing the oauth2_context entity type.
 */
class OAuth2Context extends Entity {

  /**
   * The machine name of the context.
   *
   * @var string
   */
  public $name;

  /**
   * The label of the context.
   *
   * @var string
   */
  public $label;

  /**
   * An array of settings passed to the OAuth2 server.
   *
   * @var array
   */
  public $settings = array(
    'default_scope' => 'basic',
    'allow_implicit' => FALSE,
    'grant_types' => array(
      'authorization_code' => 'authorization_code',
      'refresh_token' => 'refresh_token',
    ),
  );

  public function __construct($values = array()) {
    parent::__construct($values, 'oauth2_context');
  }
}
