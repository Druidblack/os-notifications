<?php
namespace OPNsense\Monit2Max\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    public function reloadAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $backend = new Backend();
        $result = strtolower(trim($backend->configdRun('template reload OPNsense/Monit2Max')));
        if ($result !== 'ok') {
            return ['status' => 'failed', 'message' => 'Could not generate settings'];
        }
        $result = strtolower(trim($backend->configdRun('monit2max protect')));
        if ($result !== 'ok') {
            return ['status' => 'failed', 'message' => 'Could not secure settings file'];
        }
        $result = json_decode(trim($backend->configdRun('monit2max apply')), true);
        return is_array($result) && isset($result['status'], $result['message'])
            ? $result
            : ['status' => 'failed', 'message' => 'Could not apply watcher settings; check backend log'];
    }

    public function testAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        // configd action has errors:no so JSON errors survive non-zero exit codes.
        $output = trim((new Backend())->configdRun('monit2max test'));
        $result = json_decode($output, true);
        if (is_array($result) && isset($result['status'], $result['message']) &&
            in_array($result['status'], ['ok', 'failed'], true) && is_string($result['message'])) {
            return $result;
        }
        // Never expose raw backend output: it may contain sensitive information.
        return ['status' => 'failed', 'message' =>
            'MAX test could not return its result. Run: configctl monit2max test'];
    }
    public function testTelegramAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $output = trim((new Backend())->configdRun('monit2max telegramtest'));
        $result = json_decode($output, true);
        return is_array($result) && isset($result['status'], $result['message']) &&
            in_array($result['status'], ['ok', 'failed'], true) && is_string($result['message'])
            ? $result
            : ['status' => 'failed', 'message' => 'Telegram test failed. Run: configctl monit2max telegramtest'];
    }

    public function testGotifyAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $output = trim((new Backend())->configdRun('monit2max gotifytest'));
        $result = json_decode($output, true);
        return is_array($result) && isset($result['status'], $result['message']) &&
            in_array($result['status'], ['ok', 'failed'], true) && is_string($result['message'])
            ? $result
            : ['status' => 'failed', 'message' => 'Gotify test failed. Run: configctl monit2max gotifytest'];
    }

    public function statusAction()
    {
        $output = trim((new Backend())->configdRun('monit2max status'));
        $result = json_decode($output, true);
        return is_array($result) && isset($result['status']) ? $result
            : ['status' => 'failed', 'message' => 'Could not retrieve watcher status'];
    }

    public function pipelineAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => 'POST required'];
        }
        $output = trim((new Backend())->configdRun('monit2max pipeline'));
        $result = json_decode($output, true);
        return is_array($result) && isset($result['status'], $result['message']) ? $result
            : ['status' => 'failed', 'message' => 'Notification delivery test could not return a result; check monitoring status'];
    }

}
