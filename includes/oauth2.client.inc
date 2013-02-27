<?php

/**
 * Entity class representing the oauth2_client entity type.
 */
class OAuth2Client extends Entity {

  /**
   * The id of the parent context.
   *
   * @var integer
   */
  public $context_id;

  /**
   * The label of the client.
   *
   * @var string
   */
  public $label;

  /**
   * The client key.
   *
   * @var string
   */
  public $client_key;

  /**
   * The client secret.
   *
   * @var string
   */
  public $client_secret;

  /**
   * The absolute URI to redirect to after authorization.
   *
   * @var string
   */
  public $redirect_uri;

  /**
   * Whether authorization should be completed without user confirmation.
   *
   * @var boolean
   */
  public $automatic_authorization = FALSE;

  public function __construct($values = array()) {
    parent::__construct($values, 'oauth2_client');
  }
}
