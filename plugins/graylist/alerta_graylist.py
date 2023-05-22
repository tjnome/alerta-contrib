import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from alerta.exceptions import RejectException
from alerta.models.alert import Alert
from alerta.models.blackout import Blackout
from alerta.models.filter import Filter
from alerta.plugins import PluginBase, app
from alerta.utils.audit import write_audit_trail
from flask import current_app, g, request

LOG = logging.getLogger('alerta.plugins')

HOST_TAGS = app.config.get('HOST_TAGS', ['host'])
TARGET_TAGS = app.config.get('TARGET_TAGS', ['targethost'])
REPORTER_TAGS = app.config.get('REPORTER_TAGS', [
                               'reporter:host', 'reporter:externalid', 'reporter:customerprefix'])
CUSTOMER_TAGS = app.config.get(
    'CUSTOMER_TAGS', ['externalid', 'customerprefix'])
REPORTER_PREFIX = app.config.get('REPORTER_PREFIX', 'reporter:')


@dataclass
class GrayAttributes:
    pamola: dict[str, Any]
    roles: list[str]
    host: str


class Role(Enum):
    ALERT = 'alert'
    BLACKOUT = 'blackout'


class GrayHandler(PluginBase):

    def pre_receive(self, alert: Alert, **kwargs: Any) -> Alert:
        # Create a dict (Much faster than list)
        plain_tags: list[str] = []
        tags = {}
        for tag in alert.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags[key] = value
            else:
                plain_tags.append(tag)

        # Check if reporter tags exists
        if not all([tag in tags for tag in REPORTER_TAGS]):
            LOG.debug(
                f'[{__name__}] Missing {REPORTER_TAGS} in alert: {alert}')
            return alert

        # Set host tags if missing
        for tag in HOST_TAGS:
            if tag not in tags:
                tags[tag] = tags[REPORTER_PREFIX + tag]
                LOG.debug(
                    f'[{__name__}] Added missing {tag} in alert: {alert}, tags {tags}')

        # Set customer tags if missing
        if not all([tags.get(tag) for tag in CUSTOMER_TAGS]):
            for tag in CUSTOMER_TAGS:
                tags[tag] = tags[REPORTER_PREFIX + tag]
                LOG.debug(
                    f'[{__name__}] Added missing {tag} in alert: {alert}, tags {tags}')

        # targethost
        # Allow targethost if host and customer_tags
        if any([tag in tags for tag in TARGET_TAGS]):
            match = True
            for tag in HOST_TAGS:
                if tags.get(tag) != tags[REPORTER_PREFIX + tag]:
                    match = False
            for tag in CUSTOMER_TAGS:
                if tags.get(tag) != tags[REPORTER_PREFIX + tag]:
                    match = False
            if match:
                LOG.debug(
                    f'[{__name__}] Allowed targethost for: {alert}, tags {tags}')
                alert.tags = self.dict_to_list(tags, plain_tags)
                return alert
        else:
            match_host = True
            for tag in HOST_TAGS:
                if tags.get(tag) != tags[REPORTER_PREFIX + tag]:
                    match_host = False
            if match_host:
                for tag in CUSTOMER_TAGS:
                    tags[tag] = tags[REPORTER_PREFIX + tag]

                LOG.debug(
                    f'[{__name__}] Added customer tags to alert: {alert}, tags {tags}')
                alert.tags = self.dict_to_list(tags, plain_tags)
                return alert

        filters = Filter.find_matching_filters(alert, 'graylist')
        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'[{__name__}] filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags[REPORTER_PREFIX + 'host']:
                if Role.ALERT.value in grayattr.roles:
                    alert.tags = self.dict_to_list(tags, plain_tags)
                    write_audit_trail.send(current_app._get_current_object(), event='alert-graylisted', message='graylist matches alert',
                                           user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request, filter=repr(f))
                    return alert

        # Impersonate (Amongus)
        LOG.warning(
            f'[{__name__}] No graylist matches alert. Amongus SUS alert: {alert} tags: {tags}')
        write_audit_trail.send(current_app._get_current_object(), event='alert-sus', message='No graylist matches alert. Amongus SUS alert',
                               user=g.login, customers=g.customers, scopes=g.scopes, resource_id=alert.id, type='alert', request=request)

        # Overwrite host tags
        for tag in HOST_TAGS:
            tags[tag] = tags[REPORTER_PREFIX + tag]

        # Overwrite customer tags
        for tag in CUSTOMER_TAGS:
            tags[tag] = tags[REPORTER_PREFIX + tag]

        # Remove target tags
        for tag in TARGET_TAGS:
            tags.pop(tag, None)

        LOG.debug(
            f'[{__name__}] Return Amongus SUS alert object: {alert} tags: {tags}')
        alert.tags = self.dict_to_list(tags, plain_tags)
        return alert

    def post_receive(self, alert: Alert, **kwargs: Any) -> Optional[Alert]:
        return alert

    def status_change(self, alert: Alert, status: str, text: str, **kwargs: Any) -> Any:
        return

    def take_action(self, alert: Alert, action: str, text: str, **kwargs: Any) -> Any:
        raise NotImplementedError

    def delete(self, alert: Alert, **kwargs: Any) -> bool:
        raise NotImplementedError

    def receive_blackout(self, blackout: Blackout, **kwargs: Any) -> Blackout:
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
            LOG.debug(
                f'[{__name__}] Missing {REPORTER_TAGS} in blackout: {blackout}')
            return blackout

        # Host tags value need to be defined in tags or plain_tags
        host_match = True
        for tag in HOST_TAGS:
            if tags.get(tag) != tags[REPORTER_PREFIX + tag] and tags[REPORTER_PREFIX + tag] not in plain_tags:
                host_match = False
                break

        if host_match:
            # Enforced customer tags
            for tag in CUSTOMER_TAGS:
                tags[tag] = tags[REPORTER_PREFIX + tag]

            blackout.tags = self.dict_to_list(tags, plain_tags)
            return blackout

        # Check if blackout matches anything:
        filters = Filter.find_matching_filters(blackout, 'graylist')
        for f in filters:
            try:
                grayattr = GrayAttributes(**f.attributes)
            except Exception as e:
                LOG.warning(
                    f'[{__name__}] filter has invalid attributes: {f.id} error: {e}')
                continue

            if grayattr.host == tags[REPORTER_PREFIX + 'host']:
                if Role.BLACKOUT.value in grayattr.roles:
                    blackout.tags = self.dict_to_list(tags, plain_tags)
                    write_audit_trail.send(current_app._get_current_object(), event='blackout-graylisted', message='graylist matches blackout',
                                           user=g.login, customers=g.customers, scopes=g.scopes, resource_id=blackout.id, type='blackout', request=request, filter=repr(f))
                    return blackout

        raise RejectException(f'[{__name__}] rejected blackout. Not allowed')

    def delete_blackout(self, blackout: Blackout, **kwargs: Any) -> bool:
        raise NotImplementedError

    def create_filter(self, filter: Filter, **kwargs: Any) -> 'Filter':
        raise NotImplementedError

    def receive_filter(self, filter: Filter, **kwargs: Any) -> 'Filter':
        raise NotImplementedError

    def delete_filter(self, filter: Filter, **kwargs: Any) -> bool:
        raise NotImplementedError

    @classmethod
    def dict_to_list(cls, tags: dict[str, str], tags_list: list[str]) -> list[str]:
        for key, value in tags.items():
            tags_list.append(key + '=' + value)
        return cls.remove_report(tags_list)

    @staticmethod
    def remove_report(tags: list[str]) -> list[str]:
        return [tag for tag in tags if not tag.startswith(REPORTER_PREFIX)]
