<?php
/**
 * @file
 * Admin UI for contexts.
 */

/**
 * UI controller.
 */
class OAuth2ContextUIController extends EntityDefaultUIController {

  /**
   * Overrides hook_menu() defaults.
   */
  public function hook_menu() {
    $items = parent::hook_menu();
    $items[$this->path]['description'] = 'Manage contexts and their associated clients and scopes.';

    // Fix the "Add oauth2 context" and "Import oauth2 context" titles.
    unset($items[$this->path . '/add']['title callback']);
    unset($items[$this->path . '/add']['title arguments']);
    unset($items[$this->path . '/import']['title callback']);
    unset($items[$this->path . '/import']['title arguments']);
    $items[$this->path . '/add']['title'] = 'Add context';
    $items[$this->path . '/import']['title'] = 'Import context';

    return $items;
  }

  /**
   * Overrides EntityDefaultUIController::overviewTableHeaders().
   */
  protected function overviewTableHeaders($conditions, $rows, $additional_header = array()) {
    $additional_header[] = t('Clients');
    $additional_header[] = t('Scopes');
    return parent::overviewTableHeaders($conditions, $rows, $additional_header);
  }

  /**
   * Overrides EntityDefaultUIController::overviewTableRow().
   */
  protected function overviewTableRow($conditions, $id, $entity, $additional_cols = array()) {
    $additional_cols[] = l(t('clients'), $this->path . '/manage/' . $id . '/clients');
    $additional_cols[] = l(t('scopes'), $this->path . '/manage/' . $id . '/scopes');
    return parent::overviewTableRow($conditions, $id, $entity, $additional_cols);
  }

  /**
   * Overrides EntityDefaultUIController::operationForm().
   */
  public function operationForm($form, &$form_state, $entity, $op) {
    if ($op == 'delete') {
      $query = new EntityFieldQuery;
      $query->entityCondition('entity_type', 'oauth2_scope');
      $query->propertyCondition('context_id', $entity->context_id);
      $query->count();
      $num_scopes = $query->execute();

      $num_clients = 0;
      // If there's at least one scope, we know the delete can't proceed,
      // so no need to count clients.
      if ($num_scopes == 0) {
        $query = new EntityFieldQuery;
        $query->entityCondition('entity_type', 'oauth2_client');
        $query->propertyCondition('context_id', $entity->context_id);
        $query->count();
        $num_clients = $query->execute();
      }

      if ($num_scopes > 0 || $num_clients > 0) {
        drupal_set_message(t('This context has associated scopes and/or clients, it cannot be deleted.'), 'error');
        return array();
      }
    }

    return parent::operationForm($form, $form_state, $entity, $op);
  }
}

/**
 * Generates the context editing form.
 */
function oauth2_context_form($form, &$form_state, $context, $op = 'edit') {
  if ($op == 'clone') {
    $context->label .= ' (cloned)';
  }

  $form['#tree'] = TRUE;
  $form['label'] = array(
    '#title' => t('Label'),
    '#type' => 'textfield',
    '#default_value' => $context->label,
    '#description' => t('The human-readable name of this context.'),
    '#required' => TRUE,
  );
  $form['name'] = array(
    '#type' => 'machine_name',
    '#default_value' => $context->name,
    '#disabled' => entity_has_status('oauth2_context', $context, ENTITY_IN_CODE),
    '#machine_name' => array(
      'exists' => 'oauth2_context_exists',
      'source' => array('label'),
    ),
    '#description' => t('A unique machine-readable name for this context. It must only contain lowercase letters, numbers, and underscores.'),
  );

  field_attach_form('oauth2_context', $context, $form, $form_state);

  $form['settings'] = array(
    '#type' => 'fieldset',
    '#title' => t('Settings'),
  );
  // Make sure the default_scope setting is not lost when saving the form.
  // It is actually edited from the Scope UI to avoid showing a select box
  // with potentially thousands of options here.
  $form['settings']['default_scope'] = array(
    '#type' => 'value',
    '#value' => $context->settings['default_scope'],
  );
  $form['settings']['allow_implicit'] = array(
    '#type' => 'checkbox',
    '#title' => t('Allow the implicit flow'),
    '#description' => t('Allows clients to receive an access token without the need for an authorization request token.'),
    '#default_value' => $context->settings['allow_implicit'],
  );
  $grant_types = oauth2_grant_types();
  // Prepare a list of available grant types.
  $grant_type_options = array();
  foreach ($grant_types as $type => $grant_type) {
    $grant_type_options[$type] = $grant_type['name'];
  }
  $form['settings']['grant_types'] = array(
    '#type' => 'checkboxes',
    '#title' => t('Enabled grant types'),
    '#options' => $grant_type_options,
    '#default_value' => $context->settings['grant_types'],
  );
  // Add any grant type specific settings.
  foreach ($grant_types as $type => $grant_type) {
    // Merge-in any provided defaults.
    if (isset($grant_type['default settings'])) {
      $context->settings += $grant_type['default settings'];
    }
    // Add the form elements.
    if (isset($grant_type['settings callback'])) {
      // Pass along the id of the grant type checkbox, so that the settings
      // callback can use it in #states if desired.
      $dom_id = 'edit-settings-grant-types-' . str_replace('_', '-', $type);
      $form['settings'] += $grant_type['settings callback']($context->settings, $dom_id);
    }
  }

  $form['actions'] = array('#type' => 'actions');
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save context'),
    '#weight' => 40,
  );

  if (!entity_has_status('oauth2_context', $context, ENTITY_IN_CODE)
      && !in_array($op, array('add', 'clone'))) {
    $form['actions']['delete'] = array(
      '#type' => 'submit',
      '#value' => t('Delete context'),
      '#weight' => 45,
      '#limit_validation_errors' => array(),
      '#submit' => array('oauth2_context_form_submit_delete')
    );
  }
  return $form;
}

/**
 * Validation callback.
 */
function oauth2_context_form_validate($form, &$form_state) {
  entity_form_field_validate('oauth2_context', $form, $form_state);
}

/**
 * Form API submit callback for the type form.
 */
function oauth2_context_form_submit(&$form, &$form_state) {
  // Save the context.
  $context = entity_ui_form_submit_build_entity($form, $form_state);
  $context->save();
  // If this was a new context, create a default scope as well.
  if ($form_state['op'] == 'add') {
    $scope = entity_create('oauth2_scope', array());
    $scope->context_id = $context->context_id;
    $scope->name = 'basic';
    $scope->label = 'Basic';
    $scope->save();
  }

  $form_state['redirect'] = 'admin/config/services/oauth2-contexts';
}

/**
 * Form API submit callback for the delete button.
 */
function oauth2_context_form_submit_delete(&$form, &$form_state) {
  $form_state['redirect'] = 'admin/config/services/oauth2-contexts/manage/' . $form_state['oauth2_context']->name . '/delete';
}

/**
 * Check whether a given context exists.
 *
 * @param $name
 *   The name of the context.
 * @return
 *   TRUE if the given context exists. FALSE otherwise.
 */
function oauth2_context_exists($name) {
  return entity_load_multiple_by_name('oauth2_context', array($name));
}
