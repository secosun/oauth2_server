<?php

/**
 * Provides Drupal storage (through the underlying Entity API) for the library.
 */
class OAuth2_Storage_Drupal implements OAuth2_Storage_AuthorizationCodeInterface,
    OAuth2_Storage_AccessTokenInterface, OAuth2_Storage_ClientCredentialsInterface,
    OAuth2_Storage_UserCredentialsInterface, OAuth2_Storage_RefreshTokenInterface
{

  /* ClientCredentialsInterface */
  public function checkClientCredentials($client_key, $client_secret = null) {
    $client = $this->getClientDetails($client_key);
    return $client['client_secret'] == $client_secret;
  }

  public function getClientDetails($client_key) {
    $client = oauth2_server_client_load($client_key);
    if ($client) {
      // Return a client array in the format expected by the library.
      $client = array(
        'client_id' => $client->client_key,
        'client_secret' => $client->client_secret,
        'redirect_uri' => $client->redirect_uri,
      );
    }

    return $client;
  }

  public function checkRestrictedGrantType($client_key, $grant_type) {
    // The oauth2 module implements grant types on the server level,
    // not on the client level.
    $client = oauth2_server_client_load($client_key);
    $server = oauth2_server_load($client->server);
    $grant_types = array_filter($server->settings['grant_types']);
    // Implicit flow is enabled by a different setting, so it needs to be
    // added to the check separately.
    if ($server->settings['allow_implicit']) {
      $grant_types['implicit'] = 'implicit';
    }

    return in_array($grant_type, $grant_types);
  }

  /* AccessTokenInterface */
  public function getAccessToken($access_token) {
    $token = oauth2_server_token_load($access_token);
    if ($token) {
      $token_wrapper = entity_metadata_wrapper('oauth2_server_token', $token);
      $scopes = array();
      foreach ($token_wrapper->scopes as $scope_wrapper) {
        $scopes[] = $scope_wrapper->name->value();
      }
      // Return a token array in the format expected by the library.
      $token = array(
        'server' => $token_wrapper->client->server->raw(),
        'client_id' => $token_wrapper->client->client_key->value(),
        'user_id' => $token->uid ? $token_wrapper->user->name->value() : NULL,
        'access_token' => $token_wrapper->token->value(),
        'expires' => (int) $token_wrapper->expires->value(),
        'scope' => implode(' ', $scopes),
      );
    }

    return $token;
  }

  public function setAccessToken($access_token, $client_key, $username, $expires, $scope = null) {
    $client = oauth2_server_client_load($client_key);
    if (!$client) {
      throw new InvalidArgumentException("The supplied client couldn't be loaded.");
    }

    // If no token was found, start with a new entity.
    $token = oauth2_server_token_load($access_token);
    if (!$token) {
      // The username is not required, the "Client credentials" grant type
      // doesn't provide it, for instance.
      $uid = 0;
      if ($username) {
        $user = user_load_by_name($username);
        $uid = $user->uid;
      }

      $token = entity_create('oauth2_server_token', array('type' => 'access'));
      $token->client_id = $client->client_id;
      $token->uid = $uid;
      $token->token = $access_token;
    }

    $token->expires = $expires;
    $this->setScopeData($token, $client->server, $scope);

    $status = $token->save();
    return $status;
  }

  /* AuthorizationCodeInterface */
  public function getAuthorizationCode($code) {
    $code = oauth2_server_authorization_code_load($code);
    if ($code) {
      $code_wrapper = entity_metadata_wrapper('oauth2_server_authorization_code', $code);
      $scopes = array();
      foreach ($code_wrapper->scopes as $scope_wrapper) {
        $scopes[] = $scope_wrapper->name->value();
      }
      // Return a code array in the format expected by the library.
      $code = array(
        'server' => $code_wrapper->client->server->raw(),
        'client_id' => $code_wrapper->client->client_key->value(),
        'user_id' => $code_wrapper->user->name->value(),
        'authorization_code' => $code_wrapper->code->value(),
        'redirect_uri' => $code_wrapper->redirect_uri->value(),
        'expires' => (int) $code_wrapper->expires->value(),
        'scope' => implode(' ', $scopes),
      );
    }

    return $code;
  }

  public function setAuthorizationCode($code, $client_key, $username, $redirect_uri, $expires, $scope = null) {
    $client = oauth2_server_client_load($client_key);
    if (!$client) {
      throw new InvalidArgumentException("The supplied client couldn't be loaded.");
    }

    // If no code was found, start with a new entity.
    $authorization_code = oauth2_server_authorization_code_load($code);
    if (!$authorization_code) {
      $user = user_load_by_name($username);
      if (!$user) {
        throw new InvalidArgumentException("The supplied user couldn't be loaded.");
      }

      $authorization_code = entity_create('oauth2_server_authorization_code', array());
      $authorization_code->client_id = $client->client_id;
      $authorization_code->uid = $user->uid;
      $authorization_code->code = $code;
    }

    $authorization_code->redirect_uri = $redirect_uri;
    $authorization_code->expires = $expires;
    $this->setScopeData($authorization_code, $client->server, $scope);

    $status = $authorization_code->save();
    return $status;
  }

  public function expireAuthorizationCode($code) {
    $code = oauth2_server_authorization_code_load($code);
    $code->delete();
  }

  /* UserCredentialsInterface */
  public function checkUserCredentials($username, $password) {
    return user_authenticate($username, $password);
  }

  public function getUserDetails($username) {
    // @todo Revisit this, it is super-weird.
    $user = user_load_by_name($username);
    if ($user) {
      return array('user_id' => $user->name);
    }

    return FALSE;
  }

  /* RefreshTokenInterface */
  public function getRefreshToken($refresh_token) {
    $token = oauth2_server_token_load($refresh_token);
    if ($token) {
      $token_wrapper = entity_metadata_wrapper('oauth2_server_token', $token);
      $scopes = array();
      foreach ($token_wrapper->scopes as $scope_wrapper) {
        $scopes[] = $scope_wrapper->name->value();
      }
      // Return a token array in the format expected by the library.
      $token = array(
        'server' => $token_wrapper->client->server->raw(),
        'client_id' => $token_wrapper->client->client_key->value(),
        'user_id' => $token_wrapper->user->name->value(),
        'refresh_token' => $token_wrapper->token->value(),
        'expires' => (int) $token_wrapper->expires->value(),
        'scope' => implode(' ', $scopes),
      );
    }

    return $token;
  }

  public function setRefreshToken($refresh_token, $client_key, $username, $expires, $scope = null) {
    // If no token was found, start with a new entity.
    $token = oauth2_server_token_load($refresh_token);
    if (!$token) {
      $client = oauth2_server_client_load($client_key);
      if (!$client) {
        throw new InvalidArgumentException("The supplied client couldn't be loaded.");
      }
      $user = user_load_by_name($username);
      if (!$user) {
        throw new InvalidArgumentException("The supplied user couldn't be loaded.");
      }

      $token = entity_create('oauth2_server_token', array('type' => 'refresh'));
      $token->client_id = $client->client_id;
      $token->uid = $user->uid;
      $token->token = $refresh_token;
    }

    $token->expires = $expires;
    $this->setScopeData($token, $client->server, $scope);

    $status = $token->save();
    return $status;
  }

  public function unsetRefreshToken($refresh_token) {
    $token = oauth2_server_token_load($refresh_token);
    $token->delete();
  }

  /**
   * Sets the "scopes" entityreference field on the passed entity.
   *
   * @param $entity
   *   The entity containing the "scopes" entityreference field.
   * @param $server
   *   The machine name of the server.
   * @param $scope
   *   Scopes in a space-separated string.
   */
  private function setScopeData($entity, $server, $scope) {
    $entity->scopes = array();
    if ($scope) {
      $scopes = preg_split('/\s+/', $scope);
      $loaded_scopes = oauth2_server_scope_load_multiple($server, $scopes);
      foreach ($loaded_scopes as $loaded_scope) {
        $entity->scopes[LANGUAGE_NONE][] = array(
          'target_id' => $loaded_scope->scope_id,
        );
      }
    }
  }
}
