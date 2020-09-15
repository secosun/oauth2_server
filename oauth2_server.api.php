<?php

/**
 * @file
 * OAuth2 Server API documentation.
 */

/**
 * @addtogroup hooks
 * @{
 */

use Drupal\oauth2_server\ServerInterface;

/**
 * Inform other modules that an authorization process is going to happen.
 */
function hook_oauth2_server_pre_authorize() {
}

/**
 * Allow modules to supply additional claims.
 *
 * @param array[] $context
 *   Array of account and requested scopes.
 *
 * @return array
 *   An array of additional claims.
 */
function hook_oauth2_server_user_claims(array &$context) {
  /** @var \Drupal\user\UserInterface $account */
  $account = $context['account'];
  return [
    'mobile_number' => $account->get('field_mobile_number')->getValue(),
    'mobile_number_verified' => $account->get('mobile_number_verified')->getValue(),
  ];
}

/**
 * Perform alterations on the available claims.
 *
 * @param array[] $context
 *   Array of claims, account and requested scopes.
 */
function hook_oauth2_server_user_claims_alter(array &$context) {
  if (in_array('phone', $context['requested_scopes'])) {
    $context['claims']['phone_number'] = '123456';
    $context['claims']['phone_number_verified'] = FALSE;
  }
}

/**
 * Supply a default scope from a module.
 *
 * Allow any hook_oauth2_server_default_scope() implementations to supply the
 * default scope. The first one to return a scope wins.
 *
 * @param \Drupal\oauth2_server\ServerInterface $server
 *   An OAuth2 Server instance.
 *
 * @return string[]
 *   An array of scope strings.
 */
function hook_oauth2_server_default_scope(ServerInterface $server) {
  // Grant "basic" and "admin" scopes by default.
  if ($server->id() == 'test_server') {
    return ['basic', 'admin'];
  }
}

/**
 * Perform alterations on the available scopes.
 *
 * @param array[] $context
 *   Array of scopes and OAuth2 Server.
 */
function hook_oauth2_server_scope_access_alter(array &$context) {
  if ($context['server']->id() == 'test_server') {
    // We have to loop through the scopes because the actual ids are
    // prefixed with the server id.
    foreach ($context['scopes'] as $id => $scope) {
      if ($scope->scope_id == 'forbidden') {
        unset($context['scopes'][$id]);
      }
    }
  }
}

/**
 * @} End of "addtogroup hooks".
 */
