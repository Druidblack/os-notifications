"""Non-interactive regression checks for the public menu and UI text."""
import re
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'src/opnsense/mvc/app/models/OPNsense/Monit2Max'
FORMS = ROOT / 'src/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms'
VIEW = ROOT / 'src/opnsense/mvc/app/views/OPNsense/Monit2Max/index.volt'


class MenuTextTests(unittest.TestCase):
    def test_menu_is_direct_child_of_services(self):
        root = ET.parse(MODEL / 'Menu/Menu.xml').getroot()
        node = root.find('./Services/SystemNotifications')
        self.assertIsNotNone(node)
        self.assertEqual(node.get('VisibleName'), 'Notifications')
        self.assertEqual(node.get('url'), '/ui/monit2max')
        self.assertIsNone(root.find('./Services/Monit'))

    def test_installer_invalidates_real_cache(self):
        install = (ROOT / 'install.sh').read_text()
        self.assertIn('/var/lib/php/tmp/opnsense_menu_cache.xml', install)
        self.assertIn('/var/lib/php/tmp/opnsense_acl_cache.json', install)
        self.assertIn('SystemNotifications', install)

    def test_no_parenthetical_field_labels(self):
        for xmlfile in FORMS.glob('*.xml'):
            root = ET.parse(xmlfile).getroot()
            for field in root.findall('field'):
                label = field.findtext('label')
                with self.subTest(file=xmlfile.name, label=label):
                    self.assertFalse(re.search(r'\([^)]*\)', label or ''))
                    self.assertTrue(field.findtext('help'))

    def test_no_old_branding_on_page(self):
        s = VIEW.read_text()
        self.assertNotIn('Test Monit event pipeline', s)
        self.assertNotIn('System and Monit', s)
        self.assertNotIn('Monit to MAX', s)
        self.assertIn('Test notification delivery', s)
        self.assertIn('Dynamic DNS', s)

    def test_acl_uses_new_name(self):
        root = ET.parse(MODEL / 'ACL/ACL.xml').getroot()
        self.assertIn('Services: Notifications', ''.join(root.itertext()))

if __name__ == '__main__':
    unittest.main()
