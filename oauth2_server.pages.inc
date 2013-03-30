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
  if ($client && $client->automatic_authorization) {
    unset($_SESSION['oauth2_server_authorize']);
    $response = $oauth2_server->handleAuthorizeRequest($request, TRUE, $user->name);
    return oauth2_server_send_response($response);
  }
  else {
    // Validate the request.
    if (!$oauth2_server->validateAuthorizeRequest($request)) {
      return oauth2_server_send_response($oauth2_server->getResponse());
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
  $oauth2_server = oauth2_server_start($server);
  $response = $oauth2_server->handleAuthorizeRequest($request, TRUE, $user->name);
  return oauth2_server_send_response($response);
}

/**
 * Page callback: exchanges an authorization code for an access token.
 */
function oauth2_server_token() {
  $client_id = isset($_POST['client_id']) ? $_POST['client_id'] : 0;
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
  $response = $oauth2_server->handleTokenRequest(OAuth2_Request::createFromGlobals());
  return oauth2_server_send_response($response);
}

/**
 * Page callback: verifies the provided token for the provided client_id.
 */
function oauth2_server_verify_token($token) {
  $data = array(
    'verified' => FALSE,
    'scope' => '',
  );
  // If one of the parameters is missing, we can stop here.
  if (empty($token) || empty($_GET['client_id'])) {
    return drupal_json_output($data);
  }

  $token = oauth2_server_token_load($token);
  $client = oauth2_server_client_load($_GET['client_id']);
  // The token exists, hasn't expired, and belongs to the provided client.
  if ($token && $client && $token->expires > time() && $token->client_id == $client->client_id) {
    $token_wrapper = entity_metadata_wrapper('oauth2_server_token', $token);
    $scopes = array();
    foreach ($token_wrapper->scopes as $scope_wrapper) {
      $scopes[] = $scope_wrapper->name->value();
    }

    $data = array(
      'verified' => TRUE,
      'scope' => implode(' ', $scopes),
    );
  }

  return drupal_json_output($data);
}
