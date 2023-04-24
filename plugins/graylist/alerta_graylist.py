import logging
from dataclasses import dataclass
from typing import Any

from alerta.exceptions import RejectException
from alerta.models.alert import Alert
from alerta.models.blackout import Blackout
from alerta.models.filter import Filter
from alerta.plugins import PluginBase, app

LOG = logging.getLogger('alerta.plugins')

HOST_TAGS = app.config.get('HOST_TAGS', ['targethost', 'host'])
REPORTER_TAGS = app.config.get(
    'REPORTER_TAGS', ['pamola_host', 'pamola_externalid', 'pamola_customerprefix'])
CUSTOMER_TAGS = app.config.get(
    'CUSTOMER_TAGS', ['externalid', 'customerprefix'])


@dataclass
class GrayAttributes:
    pamola: dict[str, Any]
    roles: list[str]
    host: str


class GrayHandler(PluginBase):

    def pre_receive(self, alert, **kwargs):
        # Create a dict (Much faster than list)
        tags = {}
        for tag in alert.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
            else:
                tags[tag] = None

        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'[Graylist] Missing {REPORTER_TAGS} in alert: {alert}')
            return alert

        if (not tags.get('targethost') and tags.get('host') == tags['pamola_host']):
            LOG.debug(
                f'[Graylist] host matches pamola_host in alert: {alert}')

            # Insert customerprefix, externalid.
            for key in CUSTOMER_TAGS:
                tags[key] = tags['pamola' + '_' + key]

            # Remove reporter tags
            for key in REPORTER_TAGS:
                tags.pop(key, None)

            alert.tags = self.dict_to_list(tags)
            return alert

        filters = Filter.find_matching_filters(alert, 'graylist')
        if not filters:
            # Impersonate (Amogus)
            LOG.warning(
                f'[Graylist] Filter does not match alert. Amogus SUS alert: {alert} tags: {alert.tags}')
            # Remove targethost
            tags.pop('targethost', None)
            for key in REPORTER_TAGS:
                # Insert/Overrride host, externalid, customerprefix
                tags[key.split('_', 1)[1]] = tags[key]
                # Remove reporter tags
                tags.pop(key, None)
            LOG.debug(f'[Graylist] Return Amogus SUS alert object: {alert} tags: {alert.tags}')

            alert.tags = self.dict_to_list(tags)
            return alert

        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'[Graylist] filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags['pamola_host']:
                if 'alert' in grayattr.roles:
                    for key in REPORTER_TAGS:
                        tags.pop(key, None)
                    
                    alert.tags = self.dict_to_list(tags)
                    return alert

        raise RejectException(f"[Graylist] rejected alert '{alert}'")

    def post_receive(self, alert, **kwargs):
        return alert

    def status_change(self, alert, status, text, **kwargs):
        return

    def take_action(self, alert, action, text, **kwargs):
        raise NotImplementedError

    def delete(self, alert, **kwargs) -> bool:
        raise NotImplementedError

    def receive_blackout(self, blackout: 'Blackout', **kwargs) -> 'Blackout':
        # Create a dict (Much faster than list)
        tags = {}
        for tag in blackout.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
            else:
                tags[tag] = None

        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'[Graylist] Missing {REPORTER_TAGS} in blackout: {blackout}')
            return blackout

        if any(tag.startswith(tags['pamola_host']) for tag in blackout.tags):
            if not tags.get('targethost'):
                for key in CUSTOMER_TAGS:
                    tags[key] = tags['pamola' + '_' + key]
                
                for key in REPORTER_TAGS:
                    tags.pop(key, None)

                blackout.tags = self.dict_to_list(tags)
                return blackout

        # Check if blackout matches anything:
        filters = Filter.find_matching_filters(blackout, 'graylist')

        if not filters:
            raise RejectException(f"[Graylist] rejected blackout '{blackout}'")

        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'[Graylist] filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags['pamola_host']:
                if 'blackout' in grayattr.roles:
                    for key in REPORTER_TAGS:
                        tags.pop(key, None)              
                    blackout.tags = self.dict_to_list(tags)
                    return blackout

        raise RejectException(f"[Graylist] rejected blackout '{blackout}'")

    def delete_blackout(self, blackout: 'Blackout', **kwargs) -> bool:
        raise NotImplementedError

    def create_filter(self, filter: 'Filter', **kwargs) -> 'Filter':
        raise NotImplementedError

    def receive_filter(self, filter: 'Filter', **kwargs) -> 'Filter':
        raise NotImplementedError

    def delete_filter(self, filter: 'Filter', **kwargs) -> bool:
        raise NotImplementedError

    @staticmethod
    def dict_to_list(tags: dict) -> list:
        tags_list = []
        for key, value in tags.items():
            if value is None:
                tags_list.append(key)
            else:
                tags_list.append(key + '=' + value)
        return tags_list
