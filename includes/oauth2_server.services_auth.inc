<?php

/**
 * @file
 * Provides an authentication method to Services.
 */

/**
 * Authenticates a call using OAuth to verify the request.
 *
 * @param array $settings
  *  The settings for the authentication module.
 * @param array $method
 *  The method that's being called.
 * @param array $args
 *  The arguments used to call the method.
 *
 * @return
 *  Returns nothing, or a error message if authentication fails.
 */
function oauth2_server_services_authenticate_call($settings, $method, $args) {
  $endpoint = array();
  if (isset($method['endpoint']['oauth2'])) {
    $endpoint += array_filter($method['endpoint']['oauth2']);
  }
  $endpoint += $settings;

  // Authentication is disabled, do nothing.
  if (empty($endpoint['require_authentication'])) {
    return FALSE;
  }

  // No server specified, cannot proceed.
  if (empty($settings['server'])) {
    throw new Exception('No server configured for Services OAuth2 authentication.');
  }

  oauth2_server_verify_access($settings['server']);
}

function oauth2_server_services_security_settings_authorization($settings) {
  return isset($settings['authorization']) ? $settings['authorization'] : '';
}

function oauth2_server_services_security_settings($settings, &$form_state) {
  if (isset($form_state['values']['oauth2']['server'])) {
    $settings['server'] = $form_state['values']['oauth2']['server'];
  }

  $options = array('' => t('- Select -'));
  $servers = entity_load('oauth2_server');
  foreach ($servers as $server) {
    $options[$server->name] = $server->label;
  }

  $form = array();
  $form['server'] = array(
    '#type' => 'select',
    '#options' => $options,
    '#default_value' => isset($settings['server']) ? $settings['server'] : '',
    '#title' => t('OAuth2 server'),
    '#required' => TRUE,
  );

  return $form;
}

function oauth2_server_services_default_security_settings() {
  return array(
    'server' => '',
  );
}

function oauth2_server_services_controller_settings($settings, $controller, $endpoint, $class, $name) {
  $form = array();
  $form['require_authentication'] = array(
    '#type'          => 'checkbox',
    '#title'         => t('Require authentication'),
    '#default_value' => isset($settings['require_authentication']) ? $settings['require_authentication'] : FALSE,
  );

  return $form;
}
