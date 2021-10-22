# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

from .common import SpreadsheetTestCommon
from odoo.tests.common import new_test_user
from odoo.addons.mail.tests.common import MailCase
from odoo.addons.documents_spreadsheet.controllers.bus import SpreadsheetCollaborationController


class TestSpreadsheetBus(SpreadsheetTestCommon, MailCase):

    def poll(self, *channels, last=0, options=None):
        # Simulates what's done in the /longpolling/poll controller.
        # MockRequest would be usefull, but it's currently only defined with website
        channels = SpreadsheetCollaborationController._add_spreadsheet_collaborative_bus_channels(self.env, channels)
        return self.env["bus.bus"].poll(channels, last, options)

    def poll_spreadsheet(self, spreadsheet_id):
        external_channel = f"spreadsheet_collaborative_session_{spreadsheet_id}"
        communication_channel = [self.cr.dbname, "spreadsheet", spreadsheet_id]
        notifs = self.poll(external_channel)
        return [
            m["message"]
            for m in notifs
            if m["channel"] == communication_channel
        ]

    def test_simple_bus_message_still_works(self):
        self.env["bus.bus"].sendone("a-channel", "a message")
        message = self.poll("a-channel")
        self.assertEqual(message[0]["channel"], "a-channel")
        self.assertEqual(message[0]["message"], "a message")

    def test_active_spreadsheet(self):
        spreadsheet = self.create_spreadsheet()
        spreadsheet.join_spreadsheet_session()
        commands = self.new_revision_data(spreadsheet)
        spreadsheet.dispatch_spreadsheet_message(commands)
        self.assertEqual(
            self.poll_spreadsheet(spreadsheet.id),
            [commands],
            "It should have received the revision"
        )

    def test_archived_active_spreadsheet(self):
        spreadsheet = self.create_spreadsheet()
        spreadsheet.active = False
        spreadsheet.join_spreadsheet_session()
        commands = self.new_revision_data(spreadsheet)
        spreadsheet.dispatch_spreadsheet_message(commands)
        self.assertEqual(
            self.poll_spreadsheet(spreadsheet.id),
            [commands],
            "It should have received the revision"
        )

    def test_inexistent_spreadsheet(self):
        spreadsheet = self.env["documents.document"].browse(9999999)
        self.assertFalse(spreadsheet.exists())
        self.assertEqual(
            self.poll_spreadsheet(spreadsheet.id),
            [],
            "It should have ignored the wrong spreadsheet"
        )

    def test_wrong_active_spreadsheet(self):
        self.assertEqual(
            self.poll_spreadsheet("a-wrong-spreadsheet-id"),
            [],
            "It should have ignored the wrong spreadsheet"
        )

    def test_poll_access(self):
        group = self.env["res.groups"].create({"name": "test group"})
        spreadsheet = self.create_spreadsheet()
        spreadsheet.join_spreadsheet_session()
        commands = self.new_revision_data(spreadsheet)
        spreadsheet.dispatch_spreadsheet_message(commands)
        spreadsheet.folder_id.read_group_ids = group
        raoul = new_test_user(self.env, login="Raoul")
        new_test_user(self.env, login="John")
        raoul.groups_id |= group
        with self.with_user("John"):
            self.assertEqual(
                self.poll_spreadsheet(spreadsheet.id),
                [],
                "He should not be able to poll the spreadsheet"
            )
        with self.with_user("Raoul"):
            self.assertEqual(
                self.poll_spreadsheet(spreadsheet.id),
                [commands],
                "He should be able to poll the spreadsheet"
            )