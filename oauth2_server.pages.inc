<?php

/**
 * @file
 * Page callbacks for the OAuth2 Server module.
 */

/**
 * Page callback: Authenticates the user and redirect back to the client
 * with an authorization code.
 */
function oauth2_server_authorize() {
  global $user;

  // The user is not logged in. Redirect to login.
  if (!user_is_logged_in()) {
    // Save the parameters in session so that they can be fetched later.
    $parameters = drupal_get_query_parameters();
    $_SESSION['oauth2_server_authorize'] = $parameters;

    $query = array(
      'destination' => 'oauth2/authorize',
    );
    drupal_goto('user/login', array('query' => $query));
  }

  // Iniitialize the autoloader in order to create the request object.
  oauth2_server_register_autoloader();

  // A login happened. Create the request with parameters from the session.
  if (!empty($_SESSION['oauth2_server_authorize'])) {
    $request = new OAuth2_Request($_SESSION['oauth2_server_authorize']);
  }
  else {
    $request = OAuth2_Request::createFromGlobals();
  }

  $client_id = $request->query('client_id');
  $client = NULL;
  $server = NULL;
  // Get the client and use it to load the server and initialize the server.
  if ($client_id) {
    $client = oauth2_server_client_load($client_id);
    if ($client) {
      $server = oauth2_server_load($client->server);
    }
  }

  // Initialize the server.
  $oauth2_server = oauth2_server_start($server);

  // Automatic authorization is enabled for this client. Finish authorization.
  // handleAuthorizeRequest() will call validateAuthorizeRequest().
  $response = new OAuth2_Response();
  if ($client && $client->automatic_authorization) {
    unset($_SESSION['oauth2_server_authorize']);
    $oauth2_server->handleAuthorizeRequest($request, $response, TRUE, $user->name);
    return oauth2_server_send_response($response);
  }
  else {
    // Validate the request.
    if (!$oauth2_server->validateAuthorizeRequest($request, $response)) {
      return oauth2_server_send_response($response);
    }

    // Determine the scope for this request.
    $scope_util = new OAuth2_Scope_Drupal($server);
    if (!$scope = $scope_util->getScopeFromRequest($request)) {
      $scope = $scope_util->getDefaultScope();
    }
    // Convert the scope string to a set of entities.
    $scope_names = explode(' ', $scope);
    $scopes = oauth2_server_scope_load_multiple($server->name, $scope_names);

    // Show the authorize form.
    return drupal_get_form('oauth2_server_authorize_form', $client, $server, $scopes);
  }
}

/**
 * Form callback: Returns the authorize form.
 *
 * @param $client
 *   The client entity for this request.
 * @param $server
 *   The server entity for this request.
 * @param $scopes
 *   An array of scope entities representing scopes to be granted by the user.
 */
function oauth2_server_authorize_form($form, &$form_state, $client, $server, $scopes) {
  drupal_set_title(t('Authorize @client to use your account?', array('@client' => $client->label)));

  $list = array(
    'title' => t('This application will be able to:'),
    'items' => array(),
    'type' => 'ul',
  );
  foreach ($scopes as $scope) {
    $list['items'][] = array('data' => $scope->getTranslation('description'));
  }

  $form['scopes'] = array(
    '#markup' => theme('item_list', $list),
  );
  $form['authorize'] = array(
    '#type' => 'submit',
    '#value' => t('Yes, I authorize this request.'),
    '#suffix' => l(t('Cancel'), '<front>'),
  );

  return $form;
}

/**
 * Submit callback for oauth2_server_authorize_form.
 *
 * Completes authorization and redirects back to the client.
 */
function oauth2_server_authorize_form_submit($form, &$form_state) {
  global $user;

  // Iniitialize the autoloader in order to create the request object.
  oauth2_server_register_autoloader();

  // A login happened. Create the request with parameters from the session.
  if (!empty($_SESSION['oauth2_server_authorize'])) {
    $request = new OAuth2_Request($_SESSION['oauth2_server_authorize']);
    unset($_SESSION['oauth2_server_authorize']);
  }
  else {
    $request = OAuth2_Request::createFromGlobals();
  }

  $server = $form_state['build_info']['args'][1];
  // Finish the authorization request.
  $response = new OAuth2_Response();
  $oauth2_server = oauth2_server_start($server);
  $oauth2_server->handleAuthorizeRequest($request, $response, TRUE, $user->name);
  return oauth2_server_send_response($response);
}

/**
 * Page callback: exchanges an authorization code for an access token.
 */
function oauth2_server_token() {
  oauth2_server_register_autoloader();
  $request = OAuth2_Request::createFromGlobals();

  $client_credentials = oauth2_server_get_client_credentials($request);
  $server = NULL;
  // Get the client and use it to load the server and initialize the server.
  if ($client_credentials) {
    $client = oauth2_server_client_load($client_credentials['client_id']);
    if ($client) {
      $server = oauth2_server_load($client->server);
    }
  }

  // Initialize the server.
  $response = new OAuth2_Response();
  $oauth2_server = oauth2_server_start($server);
  $oauth2_server->handleTokenRequest($request, $response);
  return oauth2_server_send_response($response);
}

/**
 * Page callback: Return information about the provided token.
 *
 * @param $token
 *   The token to verify.
 *
 * @return
 *   404 if the token was not found or has expired.
 *   Otherwise, if a valid token was found, a json encoded array with the keys:
 *     - client_id: The client ID who issued the token.
 *     - user_id: The username of the resource owner, or NULL if not known.
 *     - access_token: The access token.
 *     - expires: The unix timestamp of token expiration.
 *     - scope: Scopes in a space-separated string.
 */
function oauth2_server_tokens($token) {
  drupal_page_is_cacheable(FALSE);

  // Initialize the storage and try to load the requested token.
  oauth2_server_register_autoloader();
  $storage = new OAuth2_Storage_Drupal();
  $token = $storage->getAccessToken($token);
  // No token found. Stop here.
  if (!$token || $token['expires'] <= time()) {
    $response = new OAuth2_Response(array(), 404);
    return oauth2_server_send_response($response);
  }

  // Return the token, without the server and client_id keys.
  unset($token['server']);
  return drupal_json_output($token);
}
