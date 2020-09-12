<?php

namespace Drupal\oauth2_server\PageCache;

use Symfony\Component\HttpFoundation\Request;

/**
 * Do not serve a page from cache if OAuth2 authentication is applicable.
 *
 * @internal
 */
class DisallowOauth2Requests implements Oauth2RequestPolicyInterface {

  /**
   * {@inheritdoc}
   */
  public function isOauth2Request(Request $request) {
    return \Drupal::service('authentication.oauth2_server')->applies($request);
  }

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    return $this->isOauth2Request($request) ? static::DENY : NULL;
  }

}
