<?php

/**
 * @file
 * Provides Services integration for OAuth2.
 */

/**
 * Implements hook_services_resources().
 */
function oauth2_services_resources() {
  $resources["scopes"]['retrieve'] = array(
    'file' => array('type' => 'inc', 'module' => 'oauth2', 'name' => 'oauth2.resources'),
    'callback' => '_oauth2_scope_resource_retrieve',
    'args' => array(
      array(
        'name' => 'context',
        'optional' => FALSE,
        'source' => array('path' => 0),
        'type' => 'string',
        'description' => 'The machine-name of the context',
      ),
      array(
        'name' => 'name',
        'optional' => FALSE,
        'source' => array('path' => 1),
        'type' => 'string',
        'description' => 'The machine-name of the scope',
      ),
    ),
   'access arguments' => array('access content'),
   'access arguments append' => FALSE,
  );
  $resources["scopes"]['index'] = array(
    'file' => array('type' => 'inc', 'module' => 'oauth2', 'name' => 'oauth2.resources'),
    'callback' => '_oauth2_scope_resource_index',
    'args' => array(
      array(
        'name' => 'context',
        'optional' => FALSE,
        'source' => array('path' => 0),
        'type' => 'string',
        'description' => 'The machine-name of the context',
      ),
      array(
        'name' => 'sort_by',
        'optional' => TRUE,
        'type' => 'string',
        'description' => 'The name of the field to sort on ("created", for example)',
        'default value' => '',
        'source' => array('param' => 'sort_by'),
      ),
      array(
        'name' => 'sort_order',
        'optional' => TRUE,
        'type' => 'string',
        'description' => 'Sort direction, defaults to ASC.',
        'default value' => 'ASC',
        'source' => array('param' => 'sort_order'),
      ),
      array(
        'name' => 'limit',
        'optional' => TRUE,
        'type' => 'int',
        'description' => 'The number of items to return.',
        'default value' => 20,
        'source' => array('param' => 'limit'),
      ),
      array(
        'name' => 'offset',
        'optional' => TRUE,
        'type' => 'int',
        'description' => 'The number of items to skip from the beginning.',
        'default value' => 0,
        'source' => array('param' => 'offset'),
      ),
    ),
   'access arguments' => array('access content'),
   'access arguments append' => FALSE,
  );
  $resources["scopes"]['create'] = array(
    'file' => array('type' => 'inc', 'module' => 'oauth2', 'name' => 'oauth2.resources'),
    'callback' => '_oauth2_scope_resource_create',
    'args' => array(
      array(
        'name' => 'values',
        'optional' => FALSE,
        'source' => 'data',
        'description' => 'The values used to create the scope',
        'type' => 'struct',
      ),
    ),
    'access arguments' => array('access content'),
    'access arguments append' => FALSE,
  );

  $resources["scopes"]['update'] = array(
    'file' => array('type' => 'inc', 'module' => 'oauth2', 'name' => 'oauth2.resources'),
    'callback' => '_oauth2_scope_resource_update',
    'args' => array(
      array(
        'name' => 'context',
        'optional' => FALSE,
        'source' => array('path' => 0),
        'type' => 'string',
        'description' => 'The machine-name of the context',
      ),
      array(
        'name' => 'name',
        'optional' => FALSE,
        'source' => array('path' => 1),
        'type' => 'string',
        'description' => 'The machine-name of the scope',
      ),
      array(
        'name' => 'values',
        'optional' => FALSE,
        'source' => 'data',
        'description' => 'The scope values to update',
        'type' => 'struct',
      ),
    ),
    'access arguments' => array('access content'),
    'access arguments append' => FALSE,
  );
  $resources["scopes"]['delete'] = array(
    'file' => array('type' => 'inc', 'module' => 'oauth2', 'name' => 'oauth2.resources'),
    'callback' => '_oauth2_scope_resource_delete',
    'args' => array(
      array(
        'name' => 'context',
        'optional' => FALSE,
        'source' => array('path' => 0),
        'type' => 'string',
        'description' => 'The machine-name of the context',
      ),
      array(
        'name' => 'name',
        'optional' => FALSE,
        'source' => array('path' => 1),
        'type' => 'string',
        'description' => 'The machine-name of the scope',
      ),
    ),
    'access arguments' => array('access content'),
    'access arguments append' => FALSE,
  );

  return $resources;
}
