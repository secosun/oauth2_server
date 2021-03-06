<?php

namespace Drupal\oauth2_server\Form;

use Drupal\Core\Form\FormBase;
use Drupal\Core\Form\FormStateInterface;
use OAuth2\HttpFoundationBridge\Response as BridgeResponse;
use OAuth2\HttpFoundationBridge\Request as BridgeRequest;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\oauth2_server\OAuth2StorageInterface;
use Drupal\oauth2_server\Utility;

/**
 * Class Authorize Form.
 *
 * @package Drupal\oauth2_server\Form
 */
class AuthorizeForm extends FormBase {

  /**
   * The OAuth2Storage.
   *
   * @var \Drupal\oauth2_server\OAuth2StorageInterface
   */
  protected $storage;

  /**
   * Authorize Form constructor.
   *
   * @param \Drupal\oauth2_server\OAuth2StorageInterface $oauth2_storage
   *   The OAuth2 storage object.
   */
  public function __construct(OAuth2StorageInterface $oauth2_storage) {
    $this->storage = $oauth2_storage;
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('oauth2_server.storage')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'oauth2_server_authorize_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state, $context = []) {
    $form['#title'] = $this->t('Authorize @client to use your account?', ['@client' => $context['client']->label()]);

    $list = [];
    foreach ($context['scopes'] as $scope) {
      // phpcs:ignore Drupal.Semantics.FunctionT.NotLiteralString
      $list[] = $this->t($scope->description);
    }

    $form['client'] = [
      '#type' => 'value',
      '#value' => $context['client'],
    ];
    $form['scopes'] = [
      '#title' => $this->t('This application will be able to:'),
      '#theme' => 'item_list',
      '#items' => $list,
      '#type' => 'ul',
    ];
    $form['actions'] = [
      '#type' => 'actions',
    ];
    $form['actions']['submit'] = [
      '#type' => 'submit',
      '#value' => t('Yes, I authorize this request.'),
      '#authorized' => TRUE,
    ];
    $form['actions']['cancel'] = [
      '#type' => 'submit',
      '#value' => t('Cancel'),
      '#authorized' => FALSE,
    ];
    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    // A login happened. Create the request with parameters from the session.
    if (!empty($_SESSION['oauth2_server_authorize'])) {
      $bridgeRequest = $_SESSION['oauth2_server_authorize'];
      unset($_SESSION['oauth2_server_authorize']);
    }
    else {
      $bridgeRequest = BridgeRequest::createFromRequest($this->getRequest());
    }

    $authorized = $form_state->getTriggeringElement()['#authorized'];
    $server = $form_state->getValue('client')->getServer();

    // Finish the authorization request.
    $response = new BridgeResponse();
    $oauth2_server = Utility::startServer($server, $this->storage);
    $oauth2_server->handleAuthorizeRequest($bridgeRequest, $response, $authorized, $this->currentUser()->id());
    $form_state->setResponse($response);
  }

}
