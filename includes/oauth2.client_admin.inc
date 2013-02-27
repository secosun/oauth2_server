<?php
/**
 * @file
 * Admin UI for clients.
 */

/**
 * UI controller.
 */
class OAuth2ClientUIController extends EntityDefaultUIController {

  public function __construct($entity_type, $entity_info) {
    $this->statusKey = 'status';
    $this->entityType = $entity_type;
    $this->entityInfo = $entity_info;
    // Stop the UI from mentioning "OAuth2 client" everywhere.
    $this->entityInfo['label'] = 'Client';
    // Replace the % placeholder with the context name, since the path
    // is used for links and redirects.
    $this->path = str_replace('%', arg(5), $this->entityInfo['admin ui']['path']);
  }

  /**
   * Overrides EntityDefaultUIController::hook_menu().
   */
  public function hook_menu() {
    $items = array();
    $path = 'admin/config/services/oauth2-contexts/manage/%/clients';
    $id_pos = count(explode('/', $path));

    $items[$path] = array(
      'title' => 'Clients',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('oauth2_client_overview_form', 'oauth2_client'),
      'description' => 'Manage clients.',
      'access callback' => 'entity_access',
      'access arguments' => array('view', 'oauth2_client'),
      'type' => MENU_LOCAL_TASK,
      'file' => 'includes/entity.ui.inc',
      'weight' => 10,
    );
    $items[$path . '/add'] = array(
      'title' => 'Add client',
      'page callback' => 'entity_ui_get_form',
      'page arguments' => array('oauth2_client', NULL, 'add'),
      'access callback' => 'entity_access',
      'access arguments' => array('create', 'oauth2_client'),
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
      'title arguments' => array('oauth2_client', $id_pos),
      'page callback' => 'entity_ui_get_form',
      'page arguments' => array('oauth2_client', $id_pos),
      'load arguments' => array('oauth2_client'),
      'access callback' => 'entity_access',
      'access arguments' => array('update', 'oauth2_client', $id_pos),
      'file' => $this->entityInfo['admin ui']['file'],
      'file path' => drupal_get_path('module', 'oauth2'),
    );
    $items[$path . '/%entity_object/edit'] = array(
      'title' => 'Edit',
      'load arguments' => array('oauth2_client'),
      'type' => MENU_DEFAULT_LOCAL_TASK,
    );
    $items[$path . '/%entity_object/delete'] = array(
      'page callback' => 'drupal_get_form',
      'page arguments' => array('oauth2_client_operation_form', 'oauth2_client', $id_pos, 'delete'),
      'load arguments' => array('oauth2_client'),
      'access callback' => 'entity_access',
      'access arguments' => array('delete', 'oauth2_client', $id_pos),
      'file' => 'includes/entity.ui.inc',
    );

    return $items;
  }

  /**
   * Overrides EntityDefaultUIController::overviewTable().
   */
  public function overviewTable($conditions = array()) {
    $context = oauth2_entity_load_by_property('oauth2_context', array('name' => arg(5)));
    $conditions = array();
    if ($context) {
      $conditions['context_id'] = $context->context_id;
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

    $row[] = array('data' => array(
      '#theme' => 'entity_ui_overview_item',
      '#label' => entity_label($this->entityType, $entity),
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
}

/**
 * Generates the client editing form.
 */
function oauth2_client_form($form, &$form_state, $client, $op = 'edit') {
  // Load the parent context.
  $context = oauth2_entity_load_by_property('oauth2_context', array('name' => arg(5)));
  if (!$context) {
    return $form;
  }

  $form['context_id'] = array(
    '#type' => 'value',
    '#value' => $context->context_id,
  );
  $form['label'] = array(
    '#title' => t('Label'),
    '#type' => 'textfield',
    '#default_value' => $client->label,
    '#description' => t('The human-readable name of this client.'),
    '#required' => TRUE,
  );
  $form['client_key'] = array(
    '#title' => t('Client ID'),
    '#type' => 'textarea',
    '#default_value' => $client->client_key,
    '#required' => TRUE,
  );
  $form['client_secret'] = array(
    '#title' => t('Client secret'),
    '#type' => 'textarea',
    '#default_value' => $client->client_secret,
    '#required' => TRUE,
  );
  $form['redirect_uri'] = array(
    '#title' => t('Redirect URI'),
    '#type' => 'textfield',
    '#default_value' => $client->redirect_uri,
    '#description' => t('The absolute URI to redirect to after authorization'),
  );
  $form['automatic_authorization'] = array(
    '#title' => t('Automatically authorize this client'),
    '#type' => 'checkbox',
    '#default_value' => $client->automatic_authorization,
    '#description' => t('This will cause the authorization form to be skipped. <b>Warning:</b> Give to trusted clients only!'),
  );

  field_attach_form('oauth2_client', $client, $form, $form_state);

  $form['actions'] = array('#type' => 'actions');
  $form['actions']['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save client'),
    '#weight' => 40,
  );

  if ($op != 'add') {
    $form['actions']['delete'] = array(
      '#type' => 'submit',
      '#value' => t('Delete client'),
      '#weight' => 45,
      '#limit_validation_errors' => array(),
      '#submit' => array('oauth2_client_form_submit_delete')
    );
  }
  return $form;
}

/**
 * Validation callback.
 */
function oauth2_client_form_validate($form, &$form_state) {
  entity_form_field_validate('oauth2_client', $form, $form_state);
}

/**
 * Form API submit callback for the type form.
 */
function oauth2_client_form_submit(&$form, &$form_state) {
  $client = entity_ui_form_submit_build_entity($form, $form_state);
  // Save and go back.
  $client->save();

  $context = arg(5);
  $form_state['redirect'] = 'admin/config/services/oauth2-contexts/manage/' . $context . '/clients';
}

/**
 * Form API submit callback for the delete button.
 */
function oauth2_client_form_submit_delete(&$form, &$form_state) {
  $context = arg(5);
  $form_state['redirect'] = 'admin/config/services/oauth2-contexts/manage/' . $context
                             . '/clients/' . $form_state['oauth2_client']->client_id . '/delete';
}
