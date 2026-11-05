<?php
namespace OPNsense\Monit2Max;

class IndexController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->generalForm = $this->getForm('general');
        $this->view->notificationForm = $this->getForm('notifications');
        $this->view->hardwareForm = $this->getForm('hardware');
        $this->view->temperatureForm = $this->getForm('temperature');
        $this->view->networkForm = $this->getForm('network');
        $this->view->securityForm = $this->getForm('security');
        $this->view->servicesForm = $this->getForm('services');
        $this->view->dyndnsForm = $this->getForm('dyndns');
        $this->view->maxForm = $this->getForm('max');
        $this->view->telegramForm = $this->getForm('telegram');
        $this->view->gotifyForm = $this->getForm('gotify');
        $this->view->pick('OPNsense/Monit2Max/index');
    }
}
