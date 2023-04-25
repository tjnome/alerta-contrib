import logging
from dataclasses import dataclass
from typing import Any

from alerta.exceptions import RejectException
from alerta.models.alert import Alert
from alerta.models.blackout import Blackout
from alerta.models.filter import Filter
from alerta.plugins import PluginBase, app

LOG = logging.getLogger('alerta.plugins')

HOST_TAGS = app.config.get('HOST_TAGS', ['host'])
TARGET_TAGS = app.config.get('TARGET_TAGS', ['targethost'])
REPORTER_TAGS = app.config.get('REPORTER_TAGS', ['reporter:host', 'reporter:externalid', 'reporter:customerprefix'])
CUSTOMER_TAGS = app.config.get('CUSTOMER_TAGS', ['externalid', 'customerprefix'])
REPORTER_PREFIX = app.config.get('REPORTER_PREFIX', 'reporter:')


@dataclass
class GrayAttributes:
    pamola: dict[str, Any]
    roles: list[str]
    host: str


class GrayHandler(PluginBase):

    def pre_receive(self, alert, **kwargs):
        # Create a dict (Much faster than list)
        plain_tags = []
        tags = {}
        for tag in alert.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
            else:
                plain_tags.append(tag)

        # Check if reporter tags exists
        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'[Graylist] Missing {REPORTER_TAGS} in alert: {alert}')
            return alert
        
        # Set host tags if missing
        for tag in HOST_TAGS:
            if tag not in tags:
                tags[tag] = tags[REPORTER_PREFIX + tag]
                LOG.debug(f'[Graylist] Added missing {tag} in alert: {alert}, tags {tags}')

        # Set customer tags if missing
        if not all([tags.get(tag) for tag in CUSTOMER_TAGS]):
            for tag in CUSTOMER_TAGS:
                tags[tag] = tags[REPORTER_PREFIX + tag]
                LOG.debug(f'[Graylist] Added missing {tag} in alert: {alert}, tags {tags}')

        # Check if target is used
        if not any([tag in tags for tag in TARGET_TAGS]):
            match_host = True
            for tag in HOST_TAGS:
                if not tags.get(tag) == tags[REPORTER_PREFIX + tag]:
                    match_host = False
            if match_host:
                for tag in CUSTOMER_TAGS:
                    tags[tag] = tags[REPORTER_PREFIX + tag]

                LOG.debug(f'[Graylist] Added customer tags to alert: {alert}, tags {tags}')
                alert.tags = self.dict_to_list(tags, plain_tags)
                return alert

        else:
             # Allow targethost if host and customer_tags
            match = True
            for tag in HOST_TAGS:
                if not tags.get(tag) == tags[REPORTER_PREFIX + tag]:
                    match = False
            for tag in CUSTOMER_TAGS:
                if not tags.get[tag] == tags[REPORTER_PREFIX + tag]:
                    match = False
            if match:
                LOG.debug(f'[Graylist] Allowed targethost for: {alert}, tags {tags}')
                alert.tags = self.dict_to_list(tags, plain_tags)
                return alert

        filters = Filter.find_matching_filters(alert, 'graylist')
        if not filters:
            # Impersonate (Amogus)
            LOG.warning(f'[Graylist] Filter does not match alert. Amogus SUS alert: {alert} tags: {tags}')

            # Overwrite host tags
            for tag in HOST_TAGS:
                tags[tag] = tags[REPORTER_PREFIX + tag]

            # Overwrite customer tags
            for tag in CUSTOMER_TAGS:
                # NB!! SUS TAG????
                tags[tag] = tags[REPORTER_PREFIX + tag]

            # Remove target tags
            for tag in TARGET_TAGS:
                tags.pop(tag, None)

            LOG.debug(f'[Graylist] Return Amogus SUS alert object: {alert} tags: {tags}')
            alert.tags = self.dict_to_list(tags, plain_tags)
            return alert

        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'[Graylist] filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags[REPORTER_PREFIX + 'host']:
                if 'alert' in grayattr.roles:
                    for tag in REPORTER_TAGS:
                        tags.pop(tag, None)
                    
                    alert.tags = self.dict_to_list(tags, plain_tags)
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
        plain_tags = []
        tags = {}
        for tag in blackout.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
            else:
                plain_tags.append(tag)

        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(f'[{__name__}] Missing {REPORTER_TAGS} in blackout: {blackout}')
            return blackout

        # Host tags value need to be defined in tags or plain_tags
        if 
        host_match = True
        for tag in HOST_TAGS:
            if tags.get(tag) != tags[REPORTER_PREFIX + tag] and tags[REPORTER_PREFIX + tag] not in plain_tags:
                host_match = False
                break

        if host_match:
            # Enforced customer tags
            for tag in CUSTOMER_TAGS:
                tags[tag] = tags[REPORTER_PREFIX + tag]

            # Remove reporter tags
            for key in REPORTER_TAGS:
                    tags.pop(key, None)
            blackout.tags = self.dict_to_list(tags, plain_tags)
            return blackout


        if any(tag.startswith(tags['pamola_host']) for tag in blackout.tags):
            if not tags.get('targethost'):
                for key in CUSTOMER_TAGS:
                    tags[key] = tags['pamola' + '_' + key]
                
                for key in REPORTER_TAGS:
                    tags.pop(key, None)

                blackout.tags = self.dict_to_list(tags, plain_tags)
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
                    blackout.tags = self.dict_to_list(tags, plain_tags)
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
    def dict_to_list(tags: dict[str, str], tags_list: list[str]) -> list[str]:
        for key, value in tags.items():
            if value is None:
                tags_list.append(key)
            else:
                tags_list.append(key + '=' + value)
        return tags_list
