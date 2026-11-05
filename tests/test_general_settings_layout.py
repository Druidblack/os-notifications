"""The general settings appear first without changing persisted IDs."""
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max'
VIEW = ROOT / 'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt'

class LayoutTests(unittest.TestCase):
    def test_general_only_contains_two_existing_settings(self):
        general = ET.parse(BASE / 'forms/general.xml').getroot()
        fields = [x.findtext('id') for x in general.findall('field')]
        self.assertEqual(fields, ['monit2max.general.Enabled', 'monit2max.general.Title'])
        remaining = ET.parse(BASE / 'forms/notifications.xml').getroot()
        others = [x.findtext('id') for x in remaining.findall('field')]
        self.assertFalse(set(fields).intersection(others))
        self.assertIn('monit2max.general.NotifyFailures', others)

    def test_general_block_precedes_others_and_saves(self):
        source = VIEW.read_text()
        self.assertLess(source.index("lang._('General settings')"), source.index("lang._('System health and availability')"))
        self.assertLess(source.index("'frm_General'"), source.index("'frm_Notifications'"))
        self.assertIn("'id': 'frm_General'", source)
        self.assertIn("'frm_General': '/api/monit2max/settings/get'", source)
        controller = (BASE/'IndexController.php').read_text()
        self.assertIn("$this->view->generalForm = $this->getForm('general')", controller)

    def test_installer_keeps_new_general_form(self):
        installer = (ROOT/'install.sh').read_text()
        self.assertNotIn('/bin/rm -f /usr/local/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms/general.xml',installer)

if __name__ == '__main__':
    unittest.main()
