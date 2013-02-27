<?php

/**
 * @file
 * Provides Entity metadata integration.
 */

class OAuth2ScopeMetadataController extends EntityDefaultMetadataController {

  public function entityPropertyInfo() {
    $info = parent::entityPropertyInfo();
    $properties = &$info[$this->type]['properties'];

    unset($properties['context_id']);
    $properties['context'] = array(
      'label' => t("Context"),
      'type' => 'oauth2_context',
      'description' => t("The parent context."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => 'context_id',
    );
    return $info;
  }
}

class OAuth2ClientMetadataController extends EntityDefaultMetadataController {

  public function entityPropertyInfo() {
    $info = parent::entityPropertyInfo();
    $properties = &$info[$this->type]['properties'];

    unset($properties['context_id']);
    $properties['context'] = array(
      'label' => t("Context"),
      'type' => 'oauth2_context',
      'description' => t("The parent context."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => 'context_id',
    );
    return $info;
  }
}

class OAuth2TokenMetadataController extends EntityDefaultMetadataController {

  public function entityPropertyInfo() {
    $info = parent::entityPropertyInfo();
    $properties = &$info[$this->type]['properties'];

    unset($properties['client_id']);
    $properties['client'] = array(
      'label' => t("Client"),
      'type' => 'oauth2_client',
      'description' => t("The associated client."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => 'client_id',
    );
    unset($properties['uid']);
    $properties['user'] = array(
      'label' => t("User"),
      'type' => 'user',
      'description' => t("The resource owner."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => 'uid',
    );

    $expires = !empty($properties['expires']) ? $properties['expires'] : array();
    $properties['expires'] = array(
      'type' => 'date',
      'setter callback' => 'entity_property_verbatim_set',
      'description' => t('The time when the token expires.'),
    ) + $expires;

    return $info;
  }
}

class OAuth2AuthorizationCodeMetadataController extends EntityDefaultMetadataController {

  public function entityPropertyInfo() {
    $info = parent::entityPropertyInfo();
    $properties = &$info[$this->type]['properties'];

    unset($properties['client_id']);
    $properties['client'] = array(
      'label' => t("Client"),
      'type' => 'oauth2_client',
      'description' => t("The associated client."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => array('client_id'),
    );
    unset($properties['uid']);
    $properties['user'] = array(
      'label' => t("User"),
      'type' => 'user',
      'description' => t("The resource owner."),
      'getter callback' => 'oauth2_get_properties',
      'setter callback' => 'oauth2_set_properties',
      'required' => TRUE,
      'schema field' => 'uid',
    );

    $expires = !empty($properties['expires']) ? $properties['expires'] : array();
    $properties['expires'] = array(
      'type' => 'date',
      'setter callback' => 'entity_property_verbatim_set',
      'description' => t('The time when the token expires.'),
    ) + $expires;

    return $info;
  }
}
