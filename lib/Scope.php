<?php

/**
 * Provides a scope-checking utility to the library.
 */
class OAuth2_Scope_Drupal implements OAuth2_ScopeInterface
{
  private $server;

  public function __construct($server) {
    $this->server = $server;
  }

  /**
   * Check if everything in required scope is contained in available scope.
   *
   * @param $required_scope
   *   Required scope to be check with.
   *
   * @return
   * TRUE if everything in required scope is contained in available scope,
   * and FALSE if it isn't.
   *
   * @see http://tools.ietf.org/html/rfc6749#section-7
   *
   * @ingroup oauth2_server_section_7
   */
  public function checkScope($required_scope, $available_scope) {
    // The required scope should match or be a subset of the available scope
    if (!is_array($required_scope)) {
      $required_scope = explode(' ', trim($required_scope));
    }

    if ($available_scope == '*') {
      // Get all scope entities that match the provided scope.
      // Compare the difference.
      $scopes = oauth2_server_scope_load_multiple($this->server->name, $required_scope);
      if ($scopes) {
        $found_scope = array();
        foreach ($scopes as $scope) {
          $found_scope[] = $scope->name;
        }

        return (count(array_diff($required_scope, $found_scope)) == 0);
      }
      else {
        // No matching scopes found.
        return FALSE;
      }
    }
    else {
      if (!is_array($available_scope)) {
        $available_scope = explode(' ', trim($available_scope));
      }

      return (count(array_diff($required_scope, $available_scope)) == 0);
    }
  }

  public function getScopeFromRequest(OAuth2_RequestInterface $request) {
    // "scope" is valid if passed in either POST or QUERY
    return $request->request('scope', $request->query('scope'));
  }

  public function getDefaultScope() {
    // If there's a valid default scope set, return it.
    $default_scope = $this->server->settings['default_scope'];
    if (!empty($default_scope) && $scope = oauth2_server_scope_load($this->server->name, $default_scope)) {
      return $default_scope;
    }

    return FALSE;
  }

  public function getSupportedScopes($client_key = null) {
    // The OAuth2 module is designed for an unbounded number of scopes, so it
    // is not feasible to return them all. Instead, we return a magic value
    // that tells checkScope() to query against the database.
    return '*';
  }
}
