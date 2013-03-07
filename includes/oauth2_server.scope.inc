<?php

/**
 * Entity class representing the oauth2_server_scope entity type.
 */
class OAuth2ServerScope extends Entity {

  /**
   * The machine name of the parent server.
   *
   * @var string
   */
  public $server;

  /**
   * The machine name of the scope.
   *
   * @var string
   */
  public $name;

  /**
   * The label of the scope.
   *
   * @var string
   */
  public $label;

  public function __construct($values = array()) {
    parent::__construct($values, 'oauth2_server_scope');
  }
}
