<?php

/**
 * @file
 * Callbacks for resources provided by OAuth2.
 */

/**
 * Services callback: Retrieves a scope.
 *
 * @param $context
 *   The machine-name of the context.
 * @param $name
 *   The machine-name of the scope.
 *
 * @return
 *   The requested scope, or 404 if not found.
 */
function _oauth2_scope_resource_retrieve($context, $name) {
  $context = oauth2_context_load($context);
  if (!$context) {
    return services_error(t('No context found.'), 404);
  }
  $scope = oauth2_scope_load($context->context_id, $name);
  if (!$scope) {
    return services_error(t('No scope found.'), 404);
  }

  return _oauth2_scope_resource_prepare_structure($scope, $context);
}

/**
 * Services callback: Returns a collection of scopes.
 *
 * @param $context
 *   The machine-name of the context.
 * @param $sort_by
 *   The field to sort by.
 * @param $sort_order
 *   The sort order for the field specified in $sort_by. Defaults to 'ASC'.
 * @param $limit
 *   The number of items to show. Defaults to 20.
 * @param $offset
 *   The number of items to skip. Defaults to 0.
 *
 * @return
 *   A collection of scopes.
 */
function _oauth2_scope_resource_index($context, $sort_by, $sort_order, $limit, $offset) {
  $context = oauth2_context_load($context);

  $query = new EntityFieldQuery();
  $query
      ->entityCondition('entity_type', 'oauth2_scope')
      ->propertyCondition('context_id', $context->context_id)
      ->range($offset, $limit);
  // Add the sort, if valid.
  if (!empty($sort_by) && in_array($sort_by, array('scope_id', 'name', 'label'))) {
    $query->propertyOrderBy($sort_by, $sort_order);
  }

  $results = $query->execute();
  if (empty($results)) {
    return services_error(t('No scopes found.'), 404);
  }

  $scopes = entity_load('oauth2_scope', array_keys($results['oauth2_scope']));
  $data = array();
  foreach ($scopes as $scope) {
    $data[] = _oauth2_scope_resource_prepare_structure($scope, $context);
  }

  return $data;
}

/**
 * Services callback: Converts the provided scope into an expected format.
 *
 * @param $scope
 *   The scope entity.
 * @param $context
 *   The associated context entity.
 *
 * @return
 *   An array containing the scope values.
 */
function _oauth2_scope_resource_prepare_structure($scope, $context) {
  $data = array(
    'context' => $context->name,
    'name' => $scope->name,
    'label' => $scope->label,
  );
  // Allow the structure to be altered by other modules.
  drupal_alter('oauth2_scope_resource_structure', $data, $scope);

  return $data;
}

/**
 * Services callback: Creates a scope from the provided values.
 *
 * @param $values
 *   An array of values used to create the scope.
 *   The following keys are required:
 *   - context: The machine-name of the context.
 *   - name: The machine-name of the scope.
 *   - label: The label of the scope.
 *   The following key is optional:
 *   - default: Sets the newly created scope as default for the parent context.
 */
function _oauth2_scope_resource_create($values) {
  // Validate presence of required keys.
  $required_keys = array('context', 'name', 'label');
  foreach ($required_keys as $key) {
    if (empty($values[$key])) {
      return services_error(t('Missing parameter @param', array('@param' => $key)), 406);
    }
  }
  // Load and validate scope.
  $context = oauth2_context_load($values['context']);
  if (!$context) {
    return services_error(t('The provided context is invalid.'), 406);
  }
  // Validate the scope name.
  $scope = oauth2_scope_load($context->context_id, $values['name']);
  if ($scope) {
    return services_error(t('A scope with the provided name already exists.'), 406);
  }

  $scope = entity_create('oauth2_scope', array());
  $scope->context_id = $context->context_id;
  // Remove the context from the values array, it doesn't get set on the scope.
  unset($values['context']);
  // Set all other values on the entity.
  foreach ($values as $key => $value) {
    $scope->{$key} = $value;
  }

  try {
    $scope->save();

    // Set the new scope as default, if requested.
    if (!empty($values['default'])) {
      $context->settings['default_scope'] = $scope->name;
      $context->save();
    }
  }
  catch (Exception $e) {
    return services_error($e->getMessage(), 500);
  }
}

/**
 * Services callback: Updates a scope with the provided values.
 *
 * @param $context
 *   The machine-name of the context.
 * @param $name
 *   The machine-name of the scope.
 * @param $values
 *   An array of values used to update the scope.
 */
function _oauth2_scope_resource_update($context, $name, $values) {
  $context = oauth2_context_load($context);
  if (!$context) {
    return services_error(t('No context found.'), 404);
  }
  $scope = oauth2_scope_load($context->context_id, $name);
  if (!$scope) {
    return services_error(t('No scope found.'), 404);
  }

  // The context value isn't updatable.
  unset($values['context']);
  unset($values['context_id']);
  // Update the scope with the other provided values.
  foreach ($values as $key => $value) {
    $scope->{$key} = $value;
  }

  try {
    $scope->save();
  }
  catch (Exception $e) {
    return services_error($e->getMessage(), 500);
  }
}

/**
 * Services callback: Deletes a scope.
 *
 * @param $context
 *   The machine-name of the context.
 * @param $name
 *   The machine-name of the scope.
 */
function _oauth2_scope_resource_delete($context, $name) {
  $context = oauth2_context_load($context);
  if (!$context) {
    return services_error(t('No context found.'), 404);
  }
  $scope = oauth2_scope_load($context->context_id, $name);
  if (!$scope) {
    return services_error(t('No scope found.'), 404);
  }

  return $scope->delete();
}
