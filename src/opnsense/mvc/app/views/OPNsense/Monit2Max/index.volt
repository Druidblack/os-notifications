<script type="text/javascript">
    $(document).ready(function () {
        const forms = ['frm_General', 'frm_Notifications', 'frm_Hardware', 'frm_Temperature', 'frm_Network', 'frm_Security', 'frm_Services', 'frm_DynDNS', 'frm_MAX', 'frm_Telegram', 'frm_Gotify'];
        const $controls = $('.monit-notify-action');
        function report(status, message) {
            $('#resultMsg').removeClass('hidden alert-info alert-success alert-danger')
                .addClass(status === 'ok' ? 'alert-success' : (status === 'info' ? 'alert-info' : 'alert-danger'))
                .text(message || 'No response. See System → Log Files → Backend.');
        }
        function busy(on) { $controls.prop('disabled', on); }
        mapDataToFormUI({
            'frm_General': '/api/monit2max/settings/get',
            'frm_Notifications': '/api/monit2max/settings/get',
            'frm_Hardware': '/api/monit2max/settings/get',
            'frm_Temperature': '/api/monit2max/settings/get',
            'frm_Network': '/api/monit2max/settings/get',
            'frm_Security': '/api/monit2max/settings/get',
            'frm_Services': '/api/monit2max/settings/get',
            'frm_DynDNS': '/api/monit2max/settings/get',
            'frm_MAX': '/api/monit2max/settings/get',
            'frm_Telegram': '/api/monit2max/settings/get',
            'frm_Gotify': '/api/monit2max/settings/get'
        });
        function saveAll(done) {
            busy(true);
            report('info', 'Saving settings…');
            let index = 0;
            function next() {
                if (index === forms.length) {
                    ajaxCall('/api/monit2max/service/reload', {}, function (data, status) {
                        if (status !== 'success' || !data || data.status !== 'ok') {
                            busy(false);
                            report('failed', data && data.message ? data.message : 'Could not apply settings');
                        } else if (done) {
                            done();
                        } else {
                            busy(false);
                            report('ok', 'Settings saved and applied');
                        }
                    });
                    return;
                }
                const form = forms[index++];
                saveFormToEndpoint('/api/monit2max/settings/set', form, next, false, function () {
                    busy(false);
                    report('failed', 'Could not save settings in ' + form + '. Check highlighted fields.');
                });
            }
            next();
        }
        $('.saveAct').on('click', function () { saveAll(null); });
        function test(api, label) {
            saveAll(function () {
                report('info', 'Sending test message to ' + label + '…');
                ajaxCall(api, {}, function (data, status) {
                    busy(false);
                    report(status === 'success' && data && data.status === 'ok' ? 'ok' : 'failed',
                           data && data.message ? data.message : label + ' test failed.');
                });
            });
        }
        $('#testMaxAct').on('click', function () {
            test('/api/monit2max/service/test', 'MAX');
        });
        $('#testTelegramAct').on('click', function () {
            test('/api/monit2max/service/test_telegram', 'Telegram');
        });
        $('#testGotifyAct').on('click', function () {
            test('/api/monit2max/service/test_gotify', 'Gotify');
        });
        $('#statusAct').on('click', function () {
            busy(true);
            ajaxCall('/api/monit2max/service/status', {}, function (data) {
                busy(false);
                if (data && data.status === 'ok') {
                    let message = 'Event monitor: ' + (data.watcher_running ? 'running' : 'not running') +
                        '; log access: ' + (data.log_available ? 'available' : 'missing') +
                        '; notifications enabled: ' + (data.enabled ? 'yes' : 'no') +
                        '; active messengers: ' + (data.channels || []).join(', ') +
                        '; queued events: ' + data.queued +
                        '; delivery test inbox: ' + (data.delivery_test_ready ? 'ready' : 'not initialized') +
                        '; sources: ' + data.log_file +
                        '; additional log sources: ' + (data.additional_sources || []).join(', ');
                    if (data.cpu_temperature && data.cpu_temperature.enabled) {
                        if (data.cpu_temperature.highest !== undefined) {
                            message += '; CPU temperature: ' + data.cpu_temperature.highest + ' °C';
                            message += '; temperature limit: ' + data.cpu_temperature.threshold + ' °C';
                            if (data.cpu_temperature.hottest_sensor) {
                                message += '; hottest sensor: ' + data.cpu_temperature.hottest_sensor;
                            }
                            message += '; over limit: ' + (data.cpu_temperature.alert_active ? 'yes' : 'no');
                        }
                        if (data.cpu_temperature.error) {
                            message += '; CPU temperature error: ' + data.cpu_temperature.error;
                        }
                    }
                    if (data.health_checks) {
                        Object.keys(data.health_checks).forEach(function (group) {
                            const item = data.health_checks[group];
                            if (!item || !item.enabled) { return; }
                            message += '; ' + group + ': ' + (item.sources !== undefined ? item.sources + ' checked' : 'waiting for first check');
                            if (item.error) { message += ', ' + item.error; }
                            if (item.items) {
                                const warnings = Object.keys(item.items).filter(function (name) { return item.items[name].bad || item.items[name].level;  });
                                if (warnings.length) { message += ', warnings: ' + warnings.slice(0, 5).join(', '); }
                            }
                        });
                    }
                    if (data.last_error_by) {
                        Object.keys(data.last_error_by).forEach(function (name) {
                            message += '; ' + name + ' error: ' + data.last_error_by[name];
                        });
                    }
                    if (data.last_source_event && data.last_source_event.category) {
                        message += '; latest service event: ' + data.last_source_event.category +
                                   ' (' + data.last_source_event.source + ')';
                    }
                    report(data.watcher_running && data.log_available && data.cursor_initialized ? 'ok' : 'failed', message);
                } else {
                    report('failed', data && data.message ? data.message : 'Could not read watcher status');
                }
            });
        });
        $('#pipelineAct').on('click', function () {
            saveAll(function () {
                report('info', 'Checking the notification watcher and delivery to all enabled channels…');
                ajaxCall('/api/monit2max/service/pipeline', {}, function (data, status) {
                    busy(false);
                    report(status === 'success' && data && data.status === 'ok' ? 'ok' : 'failed',
                           data && data.message ? data.message : 'Pipeline test failed.');
                });
            });
        });
        // Remember the selected tab when returning to this page.
        if (['#notifications', '#max', '#telegram', '#gotify'].indexOf(window.location.hash.toLowerCase()) !== -1) {
            $('#maintabs a[href="' + window.location.hash.toLowerCase() + '"]').tab('show');
        }
        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (event) {
            history.replaceState(null, '', event.target.hash);
        });
    });
</script>

<div class="content-box">
    <div class="col-md-12">
        <h3>{{ lang._('OPNsense notifications') }}</h3>
        <p>{{ lang._('Choose the system events you want to receive, then set up MAX, Telegram or Gotify. Each destination can be enabled independently. Notifications read service logs and supported system sensors; they do not change service configuration.') }}</p>
        <div id="resultMsg" class="alert alert-info hidden" role="alert"></div>
    </div>
</div>
<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#notifications">{{ lang._('Notifications') }}</a></li>
    <li><a data-toggle="tab" href="#max">MAX</a></li>
    <li><a data-toggle="tab" href="#telegram">Telegram</a></li>
    <li><a data-toggle="tab" href="#gotify">Gotify</a></li>
</ul>
<div class="tab-content content-box">
    <div id="notifications" class="tab-pane fade in active">
        <h4>{{ lang._('General settings') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': generalForm, 'id': 'frm_General']) }}
        <h4>{{ lang._('System health and availability') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': notificationForm, 'id': 'frm_Notifications']) }}
        <h4>{{ lang._('Hardware and storage') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': hardwareForm, 'id': 'frm_Hardware']) }}
        <h4>{{ lang._('CPU temperature') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': temperatureForm, 'id': 'frm_Temperature']) }}
        <h4>{{ lang._('Network and gateways') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': networkForm, 'id': 'frm_Network']) }}
        <h4>{{ lang._('Security') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': securityForm, 'id': 'frm_Security']) }}
        <h4>{{ lang._('DNS, DHCP, firmware and backups') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': servicesForm, 'id': 'frm_Services']) }}
        <h4>{{ lang._('Dynamic DNS') }}</h4>
        {{ partial('layout_partials/base_form', ['fields': dyndnsForm, 'id': 'frm_DynDNS']) }}
        <div class="col-md-12">
            <button class="btn btn-primary monit-notify-action saveAct" type="button">{{ lang._('Save') }}</button>
            <button class="btn btn-default monit-notify-action" id="statusAct" type="button">{{ lang._('Check monitoring status') }}</button>
            <button class="btn btn-default monit-notify-action" id="pipelineAct" type="button">{{ lang._('Test notification delivery') }}</button>
            <h4>{{ lang._('Examples of notifications') }}</h4>
            <p>{{ lang._('System resource alerts depend on existing health checks, such as those configured in Monit. Network, security, Dynamic DNS and other service alerts are read from their own journals. Separate optional health checks read system measurements or local files without altering services.') }}</p>
            <table class="table table-striped table-condensed">
                <thead><tr><th>Notification</th><th>When it is sent</th></tr></thead>
                <tbody>
                    <tr><td>System health problems</td><td>A configured health check reports high CPU or memory usage, a full disk or a failed monitored service.</td></tr>
                    <tr><td>Disk health and SSD wear</td><td>SMART health failure, high NVMe lifetime usage or drive overheating (requires smartctl).</td></tr>
                    <tr><td>Swap and firewall resources</td><td>Swap, firewall state table or mbuf usage reaches its configured percentage.</td></tr>
                    <tr><td>Firewall Alias updates</td><td>A URL Table download is empty, missing or out of date.</td></tr>
                    <tr><td>Certificate expiry</td><td>A monitored local certificate expires in 30, 7, 1 or 0 days.</td></tr>
                    <tr><td>Local backup freshness</td><td>No recent local configuration snapshot exists in the selected folder.</td></tr>
                    <tr><td>CPU temperature alerts</td><td>The hottest detected CPU core exceeds your limit twice; after cooling 5 °C below the limit for two readings, a recovery message is sent.</td></tr>
                    <tr><td>System health recovered</td><td>The monitored resource or service returns to a healthy state.</td></tr>
                    <tr><td>Monitored service actions</td><td>A health check logs starting, stopping or restarting a process.</td></tr>
                    <tr><td>Other check changes</td><td>A monitoring check changes state without a clear failure or recovery.</td></tr>
                    <tr><td>System started</td><td>OPNsense finishes startup. Delivery may be retried if the network is not yet ready.</td></tr>
                    <tr><td>System shutdown or restart</td><td>OPNsense starts a normal shutdown or reboot, while the network is still available.</td></tr>
                    <tr><td>Gateway connection status</td><td>A WAN gateway goes offline or becomes reachable again.</td></tr>
                    <tr><td>Gateway latency and packet loss</td><td>Monitoring reports degraded WAN connectivity.</td></tr>
                    <tr><td>Administrator and SSH logins</td><td>An administrator signs in or an authentication attempt fails.</td></tr>
                    <tr><td>CrowdSec security and errors</td><td>CrowdSec logs a blocking decision or a service problem.</td></tr>
                    <tr><td>VPN and DNS</td><td>A VPN disconnects or a DNS service reports a fault.</td></tr>
                    <tr><td>Dynamic DNS</td><td>A DNS record is updated or the provider rejects an update.</td></tr>
                    <tr><td>Firewall block summaries</td><td>At least ten blocked packets are logged in five minutes.</td></tr>
                </tbody>
            </table>
            <p>{{ lang._('The delivery test creates a safe event in a private local test inbox and verifies processing and delivery to each enabled channel. It does not test system log routing or individual WAN, CrowdSec and Dynamic DNS sources. Real alerts require matching entries in readable system logs. Firewall summaries and new DHCP devices are disabled by default.') }}</p>
        </div>
    </div>
    <div id="max" class="tab-pane fade">
        {{ partial('layout_partials/base_form', ['fields': maxForm, 'id': 'frm_MAX']) }}
        <div class="col-md-12">
            <p>{{ lang._('Official MAX API or notify.a161.ru. Keep your existing token and recipient ID; the update preserves them. The external notify.a161.ru service receives messages sent through it.') }}</p>
            <button class="btn btn-primary monit-notify-action saveAct" type="button">{{ lang._('Save') }}</button>
            <button class="btn btn-default monit-notify-action" id="testMaxAct" type="button">{{ lang._('Send MAX test message') }}</button>
        </div>
    </div>
    <div id="telegram" class="tab-pane fade">
        {{ partial('layout_partials/base_form', ['fields': telegramForm, 'id': 'frm_Telegram']) }}
        <div class="col-md-12">
            <p>{{ lang._('Create a bot using @BotFather, then open the bot chat and press Start. To send to a group or channel, add the bot and grant the necessary permissions. Enter the chat ID, not your phone number.') }}</p>
            <button class="btn btn-primary monit-notify-action saveAct" type="button">{{ lang._('Save') }}</button>
            <button class="btn btn-default monit-notify-action" id="testTelegramAct" type="button">{{ lang._('Send Telegram test message') }}</button>
        </div>
    </div>
    <div id="gotify" class="tab-pane fade">
        {{ partial('layout_partials/base_form', ['fields': gotifyForm, 'id': 'frm_Gotify']) }}
        <div class="col-md-12">
            <p>{{ lang._('Create an application in the Gotify Web UI and copy its application token. Enter the base server URL and desired priority. HTTPS is recommended for remote servers.') }}</p>
            <button class="btn btn-primary monit-notify-action saveAct" type="button">{{ lang._('Save') }}</button>
            <button class="btn btn-default monit-notify-action" id="testGotifyAct" type="button">{{ lang._('Send Gotify test message') }}</button>
        </div>
    </div>
</div>
