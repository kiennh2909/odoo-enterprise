# Part of Odoo. See LICENSE file for full copyright and licensing details.
from odoo import models, fields, api, _
from odoo.exceptions import UserError
from OpenSSL import crypto
import base64
import logging

_logger = logging.getLogger(__name__)


class ResConfigSettings(models.TransientModel):

    _inherit = 'res.config.settings'

    l10n_ar_country_code = fields.Char(related='company_id.country_id.code', string='Country Code')
    l10n_ar_afip_verification_type = fields.Selection(related='company_id.l10n_ar_afip_verification_type', readonly=False)

    l10n_ar_afip_ws_environment = fields.Selection(related='company_id.l10n_ar_afip_ws_environment', readonly=False)
    l10n_ar_afip_ws_key = fields.Binary(related='company_id.l10n_ar_afip_ws_key', readonly=False)
    l10n_ar_afip_ws_crt = fields.Binary(related='company_id.l10n_ar_afip_ws_crt', readonly=False)

    l10n_ar_afip_ws_key_fname = fields.Char('Private Key name', default='private_key.pem')
    l10n_ar_afip_ws_crt_fname = fields.Char(related='company_id.l10n_ar_afip_ws_crt_fname')

    def l10n_ar_action_create_certificate_request(self):
        self.ensure_one()
        if not self.company_id.partner_id.city:
            raise UserError(_('The company city must be defined before this action'))
        if not self.company_id.partner_id.country_id:
            raise UserError(_('The company country must be defined before this action'))
        if not self.company_id.partner_id.l10n_ar_vat:
            raise UserError(_('The company CUIT must be defined before this action'))

        return {'type': 'ir.actions.act_url', 'url': '/l10n_ar_edi/download_csr?', 'target': 'new'}

    def l10n_ar_connection_test(self):
        self.ensure_one()
        error = ''
        if not self.l10n_ar_afip_ws_crt:
            error += '\n* ' + _('Please set a certificate in order to make the test')
        if not self.l10n_ar_afip_ws_key:
            error += '\n* ' + _('Please set a private key in order to make the test')
        if error:
            raise UserError(error)

        res = ''
        for webservice in ['wsfe', 'wsfex', 'wsbfe', 'wscdc']:
            try:
                self.company_id._l10n_ar_get_connection(webservice)
                res += ('\n* %s: ' + _('Connection is available')) % webservice
            except Exception as error:
                res += ('\n* %s: ' + _('Connection failed. This is what we get') + ' %s') % (webservice, repr(error))
        raise UserError(res)

    @api.onchange('l10n_ar_afip_ws_crt')
    def _l10n_ar_onchange_afip_certificate(self):
        """ Verify if certificate uploaded is well formed before saving """
        if self.l10n_ar_afip_ws_crt:
            error = False
            try:
                content = base64.decodebytes(self.l10n_ar_afip_ws_crt).decode('ascii')
                crypto.load_certificate(crypto.FILETYPE_PEM, content)
            except Exception as exc:
                if 'Expecting: CERTIFICATE' in repr(exc) or "('PEM routines', 'get_name', 'no start line')" in repr(exc):
                    error = _('Wrong certificate file format.\nPlease upload a valid PEM certificate.')
                else:
                    error = _('Not a valid certificate file')
                _logger.warning('%s %s' % (error, repr(exc)))
            if error:
                self.l10n_ar_afip_ws_crt = False
                return {'warning': {'title': _('Error uploading the certificate'), 'message': '\n'.join([
                    _('The certificate can not be uploaded!'), error])}}

    @api.onchange('l10n_ar_afip_ws_key')
    def _l10n_ar_onchange_afip_private_key(self):
        """ Verify if private key uploaded is well formed before saving """
        if self.l10n_ar_afip_ws_key:
            error = False
            try:
                content = base64.decodebytes(self.l10n_ar_afip_ws_key).decode('ascii').strip()
                crypto.load_privatekey(crypto.FILETYPE_PEM, content)
            except Exception as exc:
                error = _('Not a valid private key file')
                _logger.warning('%s %s' % (error, repr(exc)))
            if error:
                self.l10n_ar_afip_ws_key = False
                return {'warning': {'title': _('Error uploading the private key'), 'message': '\n'.join([
                    _('The private key can not be uploaded!'), error])}}

    def random_demo_cert(self):
        self.company_id.set_demo_random_cert()
