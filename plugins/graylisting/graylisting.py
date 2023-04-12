import logging

from alerta.app import alarm_model
from alerta.models.alarms.alerta import SEVERITY_MAP
from alerta.models.enums import Status, Action
from alerta.models.filter import Filter
from alerta.plugins import PluginBase

LOG = logging.getLogger('alerta.plugins')


class GrayHandler(PluginBase):

    def pre_receive(self, alert, **kwargs):
        return alert

    def post_receive(self, alert, **kwargs):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        return

    def take_action(self, alert, action, text, **kwargs):
        raise NotImplementedError

    def delete(self, alert, **kwargs) -> bool:
        raise NotImplementedError

    def create_blackout(self, blackout: 'Blackout', **kwargs) -> 'Blackout':
        LOG.debug(f'Blackout that is used: {blackout}')
        raise NotImplementedError

    def update_blackout(self, blackout: 'Blackout', update: 'json', **kwargs) -> Any:
        LOG.debug(f'Blackout that it matches: {blackout}')
        LOG.debug(f'Blackout update: {update}')
        raise NotImplementedError

    def delete_blackout(self, blackout: 'Blackout', **kwargs) -> bool:
        LOG.debug(f'Blackout that is deleted: {blackout}')
        raise NotImplementedError

    def create_filter(self, filter: 'Filter', **kwargs) -> 'Filter':
        LOG.debug(f'Filter that is used: {filter}')
        raise NotImplementedError

    def update_filter(self, filter: 'Filter', update: 'json', **kwargs) -> Any:
        LOG.debug(f'Filter that is matches: {filter}')
        LOG.debug(f'Filter update: {update}')
        raise NotImplementedError

    def delete_filter(self, filter: 'Filter', **kwargs) -> bool:
        LOG.debug(f'Filter that is deleted: {filter}')
        raise NotImplementedError