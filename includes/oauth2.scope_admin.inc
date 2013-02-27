<?php
/**
 * @file
 * Admin UI for scopes.
 */

/**
 * UI controller.
 */
class OAuth2ScopeUIController extends EntityDefaultUIController {

  public function __construct($entity_type, $entity_info) {
    $this->statusKey = 'status';
    $this->entityType = $entity_type;
    $this->entityInfo = $entity_info;
    // Stop the UI from mentioning "OAuth2 scope" everywhere.
    $this->entityInfo['label'] = 'Scope';
    // Replace the % placeholder with the context name, since the path
    // is used for links and redirects.
    $this->path = str_replace('%', arg(5), $this->entityInfo['admin ui']['path']);
  }

  /**
   * Overrides EntityDefaultUIController::hook_menu().
   */
  public function hook_menu() {
    $items = array();
    $path = 'admin/config/services/oauth2-contexts/manage/%/scopes';
    $id_pos = count(explode('/', $path));

    $items[$path] = array(
      'title' => 'Scopes',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('oauth2_scope_overview_form', 'oauth2_scope'),
      'description' => 'Manage scopes.',
      'access callback' => 'entity_access',
      'access arguments' => array('view', 'oauth2_scope'),
      'type' => MENU_LOCAL_TASK,
      'file' => 'includes/entity.ui.inc',
      'weight' => 9,
    );
    $items[$path . '/add'] = array(
      'title' => 'Add scope',
      'page callback' => 'entity_ui_get_form',
      'page arguments' => array('oauth2_scope', NULL, 'add'),
      'access callback' => 'entity_access',
      'access arguments' => array('create', 'oauth2_scope'),
      'type' => MENU_LOCAL_ACTION,
      'file' => $this->entityInfo['admin ui']['file'],
      'file path' => drupal_get_path('module', 'oauth2'),
    );
    // The regular Entity API way would be to use
    // $path . '/manage/%entity_object' here, but Drupal's Menu API is limited
    // to 9 levels, one too little for that to work.
    $items[$path . '/%entity_object'] = array(
      'title' => 'Edit',
      'title callback' => 'entity_label',
      'title arguments' => array('oauth2_scope', $id_pos),
      'page callback' => 'entity_ui_get_form',
      'page arguments' => array('oauth2_scope', $id_pos),
      'load arguments' => array('oauth2_scope'),
      'access callback' => 'entity_access',
      'access arguments' => array('update', 'oauth2_scope', $id_pos),
      'file' => $this->entityInfo['admin ui']['file'],
      'file path' => drupal_get_path('module', 'oauth2'),
    );
    $items[$path . '/%entity_object/edit'] = array(
      'title' => 'Edit',
      'load arguments' => array('oauth2_scope'),
      'type' => MENU_DEFAULT_LOCAL_TASK,
    );
    $items[$path . '/%entity_object/delete'] = array(
      'page callback' => 'drupal_get_form',
      'page arguments' => array('oauth2_scope_operation_form', 'oauth2_scope', $id_pos, 'delete'),
      'load arguments' => array('oauth2_scope'),
      'access callback' => 'entity_access',
      'access arguments' => array('delete', 'oauth2_scope', $id_pos),
      'file' => 'includes/entity.ui.inc',
    );

    return $items;
  }

  /**
   * Overrides EntityDefaultUIController::overviewTable().
   */
  public function overviewTable($conditions = array()) {
    $this->context = oauth2_entity_load_by_property('oauth2_context', array('name' => arg(5)));
    $conditions = array();
    if ($this->context) {
      $conditions['context_id'] = $this->context->context_id;
    }
    else {
      // The parent context wasn't found, add a dummy filter for no results.
      $conditions['context_id'] = -1;
    }

    return parent::overviewTable($conditions);
  }

  /**
   * Overrides EntityDefaultUIController::overviewTableRow().
   */
  protected function overviewTableRow($conditions, $id, $entity, $additional_cols = array()) {
    $entity_uri = entity_uri($this->entityType, $entity);
    $entity_label = entity_label($this->entityType, $entity);
    if ($this->context && $this->context->settings['default_scope'] == $entity->name) {
      $entity_label .= ' (' . t('Default') . ')';
    }

    $row[] = array('data' => array(
      '#theme' => 'entity_ui_overview_item',
      '#label' => $entity_label,
      '#name' => FALSE,
      '#url' => $entity_uri ? $entity_uri : FALSE,
      '#entity_type' => $this->entityType),
    );
    // Add in any passed additional cols.
    foreach ($additional_cols as $col) {
      $row[] = $col;
    }

    // Add the edit and delete links.
    $row[] = l(t('edit'), $this->path . '/' . $id);
    $row[] = l(t('delete'), $this->path . '/' . $id . '/delete', array('query' => drupal_get_destination()));

    return $row;
  }

  /**
   * Overrides EntityDefaultUIController::overviewTableRow().
   */
  public function applyOperation($op, $entity) {
    // Make sure the parent context always has a valid default scope.
    if ($op == 'delete') {
      $context = oauth2_entity_load_by_property('oauth2_context', array('name' => arg(5)));
      if ($context && $context->settings['default_scope'] == $entity->name) {
        $context->settings['default_scope'] = 'default';
        $context->save();
      }
    }

    return parent::applyOperation($op, $entity);
  }
}

/**
 * Generates the scope editing form.
 */
function oauth2_scope_form($form, &$form_state, $scope, $op = 'edit') {
  // Load the parent context.
  $context = oauth2_entity_load_by_property('oauth2_context', array('name' => arg(5)));
  if (!$context) {
    return $form;
  }
  $form_state['context'] = $context;

  $form['label'] = array(
    '#title' => t('Label'),
    '#type' => 'textfield',
    '#default_value' => $scope->label,
    '#description' => t('The human-readable name of this scope.'),
    '#required' => TRUE,
  );
  // Machine-readable type name.
  $form['name'] = array(
    '#type' => 'machine_name',
    '#default_value' => $scope->name,
    '#disabled' => entity_has_status('oauth2_scope', $scope, ENTITY_IN_CODE),
    '#machine_name' => array(
      'exists' => 'oauth2_scope_exists',
      'source' => array('label'),
    ),
    '#description' => t('A unique machine-readable name for this scope. It must only contain lowercase letters, numbers, and underscores.'),
  );

  field_attach_form('oauth2_scope', $scope, $form, $form_state);

  $is_default = FALSE;
  if (!empty($scope->name) && $context->settings['default_scope'] == $scope->name) {
    $is_default = TRUE;
  }
  $form['default'] = array(
    '#type' => 'checkbox',
    '#title' => t('Default'),
    '#default_value' => $is_default,
  );

  $form['actions'] = array('#type' => 'actions');
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save scope'),
    '#weight' => 40,
  );

  if ($op != 'add') {
    $form['actions']['delete'] = array(
      '#type' => 'submit',
      '#value' => t('Delete scope'),
      '#weight' => 45,
      '#limit_validation_errors' => array(),
      '#submit' => array('oauth2_scope_form_submit_delete')
    );
  }
  return $form;
}

/**
 * Validation callback.
 */
function oauth2_scope_form_validate($form, &$form_state) {
  entity_form_field_validate('oauth2_scope', $form, $form_state);
}

/**
 * Form API submit callback for the type form.
 */
function oauth2_scope_form_submit(&$form, &$form_state) {
  $context = $form_state['context'];
  $previous_scope = $form_state['build_info']['args'][0];
  // The default scope is stored on the context. Update it there.
  $default = $form_state['values']['default'];
  if ($default) {
    $context->settings['default_scope'] = $form_state['values']['name'];
    $context->save();
  }
  elseif (!$default && $context->settings['default_scope'] == $previous_scope->name) {
    // This scope is no longer marked as Default, revert the context setting
    // to its initial state.
    $context->settings['default_scope'] = 'default';
    $context->save();
  }
  // Unset the value of "Default" so that it doesn't get set on the entity.
  unset($form_state['values']['default']);

  $scope = entity_ui_form_submit_build_entity($form, $form_state);
  $scope->context_id = $context->context_id;
  // Save and go back.
  $scope->save();

  $context = arg(5);
  $form_state['redirect'] = 'admin/config/services/oauth2-contexts/manage/' . $context . '/scopes';
}

/**
 * Form API submit callback for the delete button.
 */
function oauth2_scope_form_submit_delete(&$form, &$form_state) {
  $context = arg(5);
  $form_state['redirect'] = 'admin/config/services/oauth2-contexts/manage/' . $context
                             . '/scopes/' . $form_state['oauth2_scope']->scope_id . '/delete';
}

/**
 * Check whether a given scope exists.
 *
 * @param $name
 *   The name of the scope.
 * @return
 *   TRUE if the given scope exists. FALSE otherwise.
 */
function oauth2_scope_exists($name) {
  $scope = oauth2_entity_load_by_property('oauth2_scope', array('name' => $name));
}
