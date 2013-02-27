<?php

/**
 * Entity class representing the oauth2_scope entity type.
 */
class OAuth2Scope extends Entity {

  /**
   * The id of the parent context.
   *
   * @var integer
   */
  public $context_id;

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
    parent::__construct($values, 'oauth2_scope');
  }
}
